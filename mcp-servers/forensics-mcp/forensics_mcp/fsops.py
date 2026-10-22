"""pweh-forensics 의 이미지 해석 작업 (pweh.fs 위): 볼륨 고르기, 목록 요약, 호스트 오염 흔적, 추출.

녹화 내용(프레임·썸네일·오디오)은 읽어서 돌려주지 않는다. 목록 요약은 개수·범위·이름(메타데이터)만, 추출은 파일로만 쓰고
응답에는 해시·크기만 싣는다. 모든 해석은 pweh.fs 의 한도(Limits)와 **호출 전체**의 예산 안에서 한다:
- 목록·오염 검사: 항목 수 합계(max_entries), 걸린 시간(max_seconds), 순회할 파티션 수(Limits.max_partitions), 경로 글자 수 합계
  (Limits.max_path_chars). 같은 (시작, 크기) 구간을 가리키는 파티션은 한 번만 본다. 볼륨은 하나씩 열어 요약·기록한 뒤 버린다
  (모든 볼륨의 목록을 한꺼번에 들고 있지 않는다). 볼륨 하나의 열기·정보·순회는 엔진 예산(pweh.fs.Budget) 하나를 함께 쓴다.
- 추출: job 하나의 마감 시각(deadline)·취소 함수 안에서 엔진 호출마다 예산을 새로 만든다(단계 상한은 그 볼륨의 것).
  ref 는 중복을 없애고, 그 ref 의 디렉터리를 ``reachable_dirspecs`` (검증한 디렉터리만 따라가는 순회, 찾으면 바로 멈춤)가 찾았을
  때만 받는다.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import re
import time
from collections import Counter
from typing import Any, Callable, Iterable, Iterator

from pweh import safeio
from pweh.fs import (SUPPORTED_FS, Budget, FsError, ImageReader, Limits, detect_partitions, display_name, open_volume,
                     partition_source)

log = logging.getLogger("pweh.forensics")

#: 목록 한도 (도구 인자로 더 줄일 수 있다) — 호출 하나의 항목 수 합계·시간
LIST_MAX_ENTRIES = 200_000
LIST_MAX_SECONDS = 180.0
#: 두 번째 볼륨부터: 남은 호출 시간이 이보다 적으면 그 파티션은 열지 않는다(budget.skipped['time']).
#: 처음 여는 볼륨은 시간이 조금이라도 남아 있으면 연다 — max_seconds 가 작아도(하한 1초) 목록이 비지 않게.
LATER_VOLUME_MIN_SECONDS = 0.25
#: 추출에서 디렉터리 항목을 건너뛰는 사유
_DIR_SKIP_REASON = "디렉터리는 추출하지 않는다(파일 ref 를 주세요)"
#: 응답에 싣는 표본·상위 목록 크기
SAMPLE_ENTRIES = 20
TOP_DIRS = 20
TOP_EXTS = 15
#: 응답에 싣는 잘린 디렉터리(cut_dirs) 수, 응답의 경로 문자열 길이 상한(깊은 나무의 경로는 수만 글자 — 전체는 목록 파일에)
CUT_DIRS_SHOWN = 10
RESPONSE_PATH_CHARS = 300
#: 추출 한도
EXTRACT_MAX_FILES = 1000
EXTRACT_MAX_BYTES = 4 << 30
EXTRACT_MAX_SECONDS = 300.0
#: 파티션 상한·경로 글자 수 상한의 기본값 (Limits 에 그 필드가 없는 엔진용)
DEFAULT_MAX_PARTITIONS = 64
DEFAULT_MAX_PATH_CHARS = 1 << 28
OPENABLE = set(SUPPORTED_FS) | {"exfat-invalid"}
_SAFE_NAME_RX = re.compile(r"[^0-9A-Za-z._-]+")
_DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
#: ref 모양 (엔진의 '<dirspec>/<slot>' — 모양이 다르면 확인 순회 없이 bad_ref)
_REF_RX = re.compile(r"^([0-9a-z+]{1,40})/([0-9]{1,9})$")
#: 호출(CallBudget)이 건너뛴 사유 → 순회(walk)의 잘림 사유와 같은 이름
_SKIP_AS_REASON = {"entries": "max_entries", "path_chars": "max_path_chars", "partitions": "max_partitions"}
#: 추출 미해결(unresolved) 코드 중 결과를 불완전하게 만드는 것(한도·예산·취소·끝까지 읽지 못한 디렉터리) — 매니페스트
#: truncated_reasons 에 더한다
LIMIT_CODES = frozenset({"time", "steps", "cancelled", "refs_unverifiable", "max_depth", "max_dir_slots", "beyond_image",
                         "dir_chain_broken", "dir_unreadable", "dir_unvalidated"})
#: 경로 찾기 오류 코드별 덧붙임 안내
_CODE_HINT = {
    "ambiguous_path": "대소문자까지 정확한 이름을 쓰거나 forensics_fs_list 결과 JSON 의 ref 로 고르세요.",
    "max_depth": "목록도 이 깊이 아래로는 내려가지 않는 고정 한도입니다 — 사람에게 알리세요.",
    "max_dir_slots": "디렉터리가 슬롯 한도에서 잘린 고정 한도입니다 — 사람에게 알리세요.",
    "beyond_image": "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있습니다 — 사람에게 알리세요.",
    "dir_chain_broken": "디렉터리 체인이 손상돼 뒤쪽을 읽지 못했습니다 — 사람에게 알리세요.",
    "dir_unvalidated": "디렉터리의 뒤쪽이 검증되지 않아 읽지 않았습니다(손상·교차 연결 가능) — 사람에게 알리세요.",
}


def limits_for(max_entries: int | None = None, max_seconds: float | None = None) -> Limits:
    return dataclasses.replace(Limits(), max_entries=max(1, min(int(max_entries or LIST_MAX_ENTRIES), LIST_MAX_ENTRIES)),
                               max_seconds=max(1.0, min(float(max_seconds or LIST_MAX_SECONDS), 600.0)))


def max_partitions(limits: Limits) -> int:
    return int(getattr(limits, "max_partitions", DEFAULT_MAX_PARTITIONS) or DEFAULT_MAX_PARTITIONS)


def max_path_chars(limits: Limits) -> int:
    return int(getattr(limits, "max_path_chars", DEFAULT_MAX_PATH_CHARS) or DEFAULT_MAX_PATH_CHARS)


def engine_budget(vol: Any, limits: Limits, *, deadline: float | None = None,
                  cancel: Callable[[], Any] | None = None) -> Budget:
    """엔진에 넘길 예산 하나: limits.max_seconds 와 마감 시각(deadline, time.monotonic 기준) 중 이른 쪽, 취소 함수(cancel),
    작업 단계 상한은 그 볼륨의 상한(vol.step_cap(limits)). vol 이 None 이면(볼륨을 열기 전) 바닥값으로 만들고 open_volume 이
    그 볼륨의 상한까지 올린다. 볼륨마다·엔진 호출마다 새로 만든다(단계는 쌓이므로 다른 볼륨·다른 호출과 함께 쓰지 않는다)."""
    b = Budget.for_limits(limits, cancel=cancel, deadline=deadline)
    if vol is not None:
        b.raise_steps(vol.step_cap(limits))
    return b


def image_reader(fd: int, path: str | None = None) -> ImageReader:
    """open_checked 가 검증하고 지문을 본 바로 그 fd 로 이미지를 읽는다(ImageReader.from_fd 가 fd 를 dup 한다 — 경로를 다시 열지 않음)."""
    return ImageReader.from_fd(fd, path=path)


#: 파티션이 통째로 이미지 끝 너머라 볼 수 없다는 파티션 경고 (pweh.fs detect_partitions 가 partitions[].warnings 에 남긴다)
_PART_BEYOND = "partition_beyond_image"
#: 확장 파티션의 EBR 사슬이 이미지 끝 너머에서 끊겼다는 경고(그 뒤 논리 파티션을 모른다 — 레이아웃 warnings)
_EBR_BEYOND = "ebr_beyond_image"


def _codes(warnings: Any) -> set[str]:
    return {str(w.get("code")) for w in (warnings or []) if isinstance(w, dict)}


def beyond_image(p: dict[str, Any]) -> bool:
    """파티션 시작이 이미지 끝 너머다(잘린 이미지 — 그 파티션은 볼 수 없다)."""
    return _PART_BEYOND in _codes(p.get("warnings"))


def layout_reasons(layout: dict[str, Any], partition: int | None = None) -> list[str]:
    """파티션 표로 보이는 이미지 잘림 → ['image_truncated'] 또는 []: 고른 파티션(partition=None 이면 전부)의 시작이 이미지 끝
    너머이거나, 전부를 볼 때 EBR 사슬이 이미지 끝 너머에서 끊겼다(논리 파티션을 잃음). 파티션 끝만 이미지 밖인 것(partition_truncated)은
    여기서 세지 않는다 — 파일 시스템이 이미지 안에서 끝날 수 있으니, 연 볼륨이 이미지 끝 너머까지 이어질 때만 볼륨 사유(coverage_reason)가
    된다."""
    parts = layout.get("partitions") or []
    scope = parts if partition is None else [p for p in parts if p.get("index") == partition]
    hit = any(beyond_image(p) for p in scope)
    if not hit and partition is None:
        hit = _EBR_BEYOND in _codes(layout.get("warnings")) or any(_EBR_BEYOND in _codes(p.get("warnings")) for p in parts)
    return ["image_truncated"] if hit else []


def pick_partitions(layout: dict[str, Any], partition: int | None) -> list[dict[str, Any]]:
    """해석할 파티션: partition=None 이면 지원하는 파일 시스템 전부, 아니면 그 index 하나(지원하지 않으면 FsError — 시작이 이미지 끝
    너머인 파티션은 unsupported_fs 가 아니라 beyond_image)."""
    parts = layout.get("partitions") or []
    if partition is None:
        return [p for p in parts if p.get("fs_hint") in OPENABLE]
    for p in parts:
        if p.get("index") == partition:
            if beyond_image(p):
                raise FsError(f"파티션 {partition} 의 시작이 이미지 끝 너머라 볼 수 없습니다(잘린 이미지).", reason="beyond_image",
                              hint="이미징이 끝까지 됐는지 사람에게 확인하고, 필요하면 다시 이미징한다(forensics_partitions 의 warnings).")
            if p.get("fs_hint") not in OPENABLE:
                raise FsError(f"파티션 {partition} 의 파일 시스템({p.get('fs_hint')})은 아직 해석하지 못합니다.", reason="unsupported_fs",
                              hint="지원: FAT12/16/32, exFAT (ext4·NTFS 는 아직 없음)")
            return [p]
    raise FsError(f"파티션 {partition} 이 없습니다.", reason="not_found", hint="forensics_partitions 의 index 를 쓰세요.")


def partition_brief(p: dict[str, Any]) -> dict[str, Any]:
    keys = ("index", "scheme", "role", "start_offset", "size_bytes", "start_lba", "type_id", "type_name", "bootable", "fs_hint",
            "beyond_image")
    out = {k: p.get(k) for k in keys if k in p}
    name = p.get("gpt_name", p.get("name"))
    guid = p.get("gpt_guid", p.get("guid"))
    if name is not None:
        out["name"] = display_name(str(name), 72)
    if guid is not None:
        out["guid"] = str(guid)
    if "warnings" in p:
        out["warnings"] = list(p.get("warnings") or [])[:10]
    return out


def volume_brief(info: dict[str, Any]) -> dict[str, Any]:
    keys = ("fs_type", "volume_label", "volume_id", "volume_serial", "cluster_size", "cluster_count", "volume_size", "available_size", "truncated",
            "bytes_per_sector", "percent_in_use", "fs_revision")
    out = {k: info.get(k) for k in keys if info.get(k) is not None}
    st = info.get("state") or {}
    out["dirty"] = st.get("dirty")
    if st.get("media_failure") is not None:
        out["media_failure"] = st.get("media_failure")
    if st.get("hard_error") is not None:
        out["hard_error"] = st.get("hard_error")
    return out


def clip_text(text: Any, n: int = RESPONSE_PATH_CHARS) -> Any:
    """응답에 싣는 긴 문자열(깊은 나무의 경로)을 앞·뒤만 남겨 줄인다(표시 전용 — 전체는 목록 파일에 있다)."""
    if not isinstance(text, str) or len(text) <= n:
        return text
    half = max(1, (n - 1) // 2)
    return text[:half] + "…" + text[-half:]


def _modified(e: dict[str, Any]) -> dict[str, Any] | None:
    t = (e.get("times") or {}).get("modified") or {}
    return t if t.get("valid") and t.get("iso") else None


def coverage_reason(info: dict[str, Any] | None, part: dict[str, Any] | None = None, image_size: int | None = None) -> str | None:
    """볼륨이 읽을 수 있는 범위(엔진의 src — 파티션 구간을 이미지 끝에서 자른 것) 너머까지 이어지면(info.truncated) 그 원인:
    - 'image_truncated': 볼륨 끝(파티션 시작 + volume_size)이 이미지 끝 너머 — 이미징이 끊겼거나 용량을 속인 카드,
    - 'volume_exceeds_partition': 이미지는 이어지지만 파티션 표 항목이 파일 시스템보다 작다 — 항목 밖으로 이어지는 부분은 이 파티션
      범위로 읽지 않았다(다른 파티션의 데이터를 이 볼륨 것으로 잘못 읽지 않게).
    아니면 None. part(partition_brief)·image_size 를 모르면 image_truncated 로 본다."""
    if not info or not info.get("truncated"):
        return None
    try:
        start = int((part or {}).get("start_offset") or 0)
        vsize = int(info.get("volume_size") or 0)
    except (TypeError, ValueError):
        return "image_truncated"
    if image_size is not None and vsize > 0 and start + vsize <= int(image_size):
        return "volume_exceeds_partition"
    return "image_truncated"


def walk_reasons(walk: dict[str, Any], info: dict[str, Any] | None = None, *, part: dict[str, Any] | None = None,
                 image_size: int | None = None) -> list[str]:
    """볼륨 하나의 불완전 사유 목록: 엔진 순회의 truncated_reasons(전역 멈춤 사유가 먼저, 그다음 디렉터리별 사유) 뒤에
    - 'dir_unvalidated': 살아 있는 디렉터리 중 검증하지 못한 단위에서 멈춘 것이 있다(unvalidated_dirs_live — 그 뒤쪽 항목은 목록에
      없다. 삭제된 디렉터리는 원래 최선 노력이라 세지 않는다),
    - 볼륨이 읽을 수 있는 범위 너머까지 이어지면 그 원인 'image_truncated' | 'volume_exceeds_partition'(coverage_reason — 그 너머의
      디렉터리·파일 내용·삭제 흔적은 볼 수 없다)
    를 더한다."""
    reasons = list(walk.get("truncated_reasons") or [])
    if not reasons and walk.get("truncated_reason"):
        reasons = [str(walk["truncated_reason"])]
    if int(walk.get("unvalidated_dirs_live") or 0) > 0 and "dir_unvalidated" not in reasons:
        reasons.append("dir_unvalidated")
    cov = coverage_reason(info, part, image_size)
    if cov is not None and cov not in reasons:
        reasons.append(cov)
    return reasons


def cut_dirs_brief(walk: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """응답용 잘린 디렉터리 목록 ([{path, reason}] CUT_DIRS_SHOWN 개, 경로는 줄임)과 전체 개수. 전체 목록(dirspec 포함, 최대
    Limits.max_report_items 개)은 목록 파일의 walk.cut_dirs 에 있다."""
    cuts = walk.get("cut_dirs") or []
    shown = [{"path": clip_text(str(c.get("path") or "")), "reason": c.get("reason")} for c in cuts[:CUT_DIRS_SHOWN]]
    return shown, int(walk.get("cut_dirs_total", len(cuts)) or 0)


def summarize_walk(walk: dict[str, Any], info: dict[str, Any] | None = None, *, part: dict[str, Any] | None = None,
                   image_size: int | None = None) -> dict[str, Any]:
    """전체 목록 → 응답용 요약: 개수, 시간 범위(바탕별·살아 있음/삭제), 상위 디렉터리·확장자, 표본, 불완전 사유·잘린 디렉터리.

    엔진이 검증하지 못해 목록에서 뺀 디렉터리(unvalidated_dirs — 녹화 데이터를 디렉터리로 잘못 읽은 것 등)는 개수만 싣는다(이름 없음).
    info(볼륨 정보)·part·image_size 를 주면 볼륨이 읽을 수 있는 범위 너머까지 이어지는지(image_truncated·volume_exceeds_partition)도
    사유에 넣는다 — walk_reasons."""
    entries = walk.get("entries") or []
    ranges: dict[tuple[str, str], list[Any]] = {}
    top_dirs: Counter[str] = Counter()
    top_dirs_deleted: Counter[str] = Counter()
    exts: Counter[str] = Counter()
    bases: set[str] = set()
    residual = 0
    for e in entries:
        if e.get("is_dir"):
            continue
        dp = str(e.get("display_path") or "")
        cut = dp.find("/", 1)
        top = dp[1:cut] if cut > 1 else "/"
        (top_dirs_deleted if e.get("deleted") else top_dirs)[top] += 1
        name = str(e.get("display_name") or "")
        if "." in name[1:]:
            exts[name.rsplit(".", 1)[-1].lower()[:12]] += 1
        if e.get("residual_bytes"):
            residual += 1
        t = _modified(e)
        if t is None:
            continue
        bases.add(t["time_basis"])
        key = ("deleted" if e.get("deleted") else "live", t["time_basis"])
        r = ranges.setdefault(key, [t["iso"], t["iso"], 0])
        r[0] = min(r[0], t["iso"])
        r[1] = max(r[1], t["iso"])
        r[2] += 1
    sample = []
    for e in entries[:SAMPLE_ENTRIES]:
        t = _modified(e)
        sample.append({"path": clip_text(e.get("display_path")), "is_dir": e.get("is_dir"), "deleted": e.get("deleted"),
                       "size": e.get("size"), "modified": t["iso"] if t else None, "ref": e.get("ref")})
    unvalidated = int(walk.get("unvalidated_dirs_total", len(walk.get("unvalidated_dirs") or [])) or 0)
    cuts, cuts_total = cut_dirs_brief(walk)
    reasons = walk_reasons(walk, info, part=part, image_size=image_size)
    return {
        "stats": walk.get("stats"),
        "truncated": bool(walk.get("truncated")) or bool(reasons),
        "truncated_reason": walk.get("truncated_reason") or (reasons[0] if reasons else None),
        "truncated_reasons": reasons,
        "cut_dirs": cuts,
        "cut_dirs_total": cuts_total,
        "time_ranges": [{"state": k[0], "time_basis": k[1], "first": v[0], "last": v[1], "files": v[2]} for k, v in sorted(ranges.items())],
        "time_basis": (next(iter(bases)) if len(bases) == 1 else ("mixed" if bases else "unknown")),
        "top_dirs": [{"dir": d, "files": n, "deleted_files": top_dirs_deleted.get(d, 0)} for d, n in top_dirs.most_common(TOP_DIRS)]
        + [{"dir": d, "files": 0, "deleted_files": n} for d, n in top_dirs_deleted.most_common(TOP_DIRS) if d not in top_dirs][:5],
        "extensions": [{"ext": x, "files": n} for x, n in exts.most_common(TOP_EXTS)],
        "files_with_residual": residual,
        "orphans": len(walk.get("orphans") or []),
        "unvalidated_dirs": unvalidated,
        "unvalidated_dirs_live": int(walk.get("unvalidated_dirs_live") or 0),
        "warnings_count": len(walk.get("warnings") or []) + int(walk.get("warnings_suppressed") or 0),
        "sample": sample,
    }


# ---------------------------------------------------------------------------
# 잘림 사유 → 다음 단계 안내
# ---------------------------------------------------------------------------


def call_reasons(skip_reasons: Iterable[str], walks: Iterable[Iterable[str]]) -> list[str]:
    """호출 전체의 잘림 사유 (중복 없이 처음 나온 순서): 호출이 건너뛴 파티션의 사유(이름을 순회의 사유와 맞춘다 — entries →
    max_entries, path_chars → max_path_chars, partitions → max_partitions)와 볼륨마다 순회의 사유."""
    out: list[str] = []
    for r in list(skip_reasons) + [x for w in walks for x in w]:
        r = _SKIP_AS_REASON.get(r, r)
        if r and r not in out:
            out.append(r)
    return out


def limit_hints(reasons: Iterable[str], *, tool: str) -> list[str]:
    """잘림·불완전 사유마다 다음 단계 안내 (tool: 'fs_list' | 'image_check' | 'extract' — 늘릴 수 있는 인자가 다르다).
    max_depth·max_dir_slots 는 고정 한도, beyond_image·dir_chain_broken·dir_unreadable·dir_unvalidated·image_truncated·
    volume_exceeds_partition 은 이미지·카드 상태라 늘리라고 하지 않는다 — 사람에게 알리고 잘린 디렉터리(cut_dirs)·검증하지 못한
    디렉터리를 보고서 한계에 적게 한다."""
    secs = {"fs_list": "max_seconds 를 늘리거나(최대 600초) 여러 파티션이면 partition=<index> 로 나눠 다시 본다",
            "image_check": "여러 파티션이면 partition=<index> 로 나눠 다시 본다(이 도구의 시간 예산은 120초로 고정)",
            "extract": "남은 ref·paths 로 다시 추출한다(job 시간 예산 300초)"}.get(tool, "범위를 줄여 다시 본다")
    texts = {
        "time": f"시간 한도에 닿았다 — {secs}.",
        "steps": "작업 단계 상한에 닿았다 — 정상적으로 꽉 찬 볼륨은 닿지 않는다(같은 긴 체인을 여러 항목이 가리키는 조작·손상 이미지일 수 "
                 "있다). 사람에게 알리고 보고서 한계에 적는다.",
        "max_entries": ("항목 수 상한(max_entries, 호출 전체 합계·최대 200000)에 닿았다 — max_entries 를 늘리거나 여러 파티션이면 "
                        "partition=<index> 로 나눠 다시 본다." if tool == "fs_list"
                        else "항목 수 상한(호출 하나 200000)에 닿았다 — 여러 파티션이면 partition=<index> 로 나눠 다시 본다."),
        "max_partitions": "열 파티션 수 상한(64)에 닿았다 — 나머지는 partition=<index> 로 따로 본다(call.partitions_skipped.partitions).",
        "max_path_chars": "경로 글자 수 상한(호출 전체 268,435,456 글자)에 닿았다 — 깊고 긴 경로가 아주 많다(조작 의심). 여러 파티션이면 "
                          "partition=<index> 로 나눠 보고, 사람에게 알린다.",
        "max_total_slots": "디렉터리 슬롯 합계 상한(8,388,608)에 닿았다 — 디렉터리가 아주 많거나 크다(조작 의심). 사람에게 알리고 보고서 "
                           "한계에 적는다.",
        "max_depth": "디렉터리 깊이 한도(64)에서 더 내려가지 않았다(cut_dirs) — 그 아래 항목은 목록·ref 가 없어 추출할 수도 없다. 고정 "
                     "한도다(max_seconds 로 바뀌지 않음) — 사람에게 알리고 보고서 한계에 적는다.",
        "max_dir_slots": "디렉터리가 슬롯 한도에서 잘렸다(cut_dirs, 경고 dir_slot_limit) — 그 디렉터리의 뒤쪽 항목은 목록에 없다. 고정 "
                         "한도다 — 사람에게 알리고 보고서 한계에 적는다.",
        "beyond_image": "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있어 그 디렉터리를 끝까지 읽지 못했다(cut_dirs) "
                        "— 원인은 볼륨 사유(image_truncated·volume_exceeds_partition)를 본다. 시간을 늘려도 바뀌지 않는다 — 사람에게 "
                        "알리고 보고서 한계에 적는다.",
        "dir_chain_broken": "살아 있는 디렉터리의 클러스터 체인이 끝 표시 전에 비정상으로 끝나 뒤쪽 항목을 읽지 못했다(cut_dirs, 경고 "
                            "dir_chain_*) — 카드 손상일 수 있다. 시간을 늘려도 바뀌지 않는다 — 사람에게 알리고 보고서 한계에 적는다.",
        "dir_unreadable": "살아 있는 디렉터리를 읽지 못했다(cut_dirs, 경고 dir_unreadable) — 카드 손상일 수 있다. 사람에게 알리고 보고서 "
                          "한계에 적는다.",
        "dir_unvalidated": "살아 있는 디렉터리 일부가 디렉터리 데이터로 검증되지 않아 그 뒤쪽 항목은 목록에 없다(unvalidated_dirs, 경고 "
                           "dir_unvalidated) — 카드 손상·교차 연결이거나 엔진이 일부러 엄격하게 거르는 형식일 수 있다. 사람에게 알리고 "
                           "보고서 한계에 적는다.",
        "image_truncated": "이미지가 카드보다 짧다 — 볼륨이 이미지 끝 너머까지 이어지거나(volume.truncated) 파티션이 통째로 이미지 끝 "
                           "너머다(forensics_partitions 의 partition_beyond_image·ebr_beyond_image). 이미징이 중간에 끊겼거나 용량을 속인 "
                           "카드일 수 있다. 끝 너머의 파티션·디렉터리·파일 내용·삭제 흔적은 볼 수 없다. 시간을 늘려도 바뀌지 않는다 — 사람에게 "
                           "알리고, 이미징이 끝까지 됐는지 확인해 필요하면 다시 이미징하며, 보고서 한계에 적는다.",
        "volume_exceeds_partition": "파일 시스템이 파티션 표 항목보다 크다(volume.truncated, 이미지는 이어짐) — 파티션 표가 줄었거나 "
                                    "손상됐을 수 있다. 항목 밖으로 이어지는 부분은 이 파티션 범위로 읽지 않았다(그 부분의 디렉터리·파일 내용은 "
                                    "볼 수 없다). 시간을 늘려도 바뀌지 않는다 — 사람에게 알리고 보고서 한계에 적는다.",
        "cancelled": "취소되어 끝까지 하지 못했다 — 필요하면 다시 부른다.",
        "max_files": "파일 수 상한(max_files, 최대 1000)에 닿았다 — 나머지 ref 로 다시 추출한다.",
        "max_bytes": "바이트 상한(max_bytes, 최대 4 GiB)에 닿았다 — max_bytes 를 늘리거나 나눠 추출한다.",
        "refs_unverifiable": "확인 순회가 한도나 끝까지 읽지 못한 디렉터리 때문에 끝까지 가지 못해 디렉터리를 검증하지 못한 ref 가 "
                             "있다(skipped 의 code refs_unverifiable) — 살아 있는 파일은 paths= 로 고르거나 partition 을 지정해 다시 "
                             "하고, 계속되면 사람에게 알린다.",
    }
    out: list[str] = []
    for r in reasons:
        t = texts.get(_SKIP_AS_REASON.get(r, r))
        if t and t not in out:
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# 볼륨 순회 (호출 전체 예산)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CallBudget:
    """목록·오염 검사 호출 하나의 예산: 항목 수 합계, 마감 시각(monotonic), 순회할 파티션 수, 경로 글자 수 합계.
    해석하지 못한 볼륨 수도 센다."""

    max_entries: int
    deadline: float
    max_partitions: int
    max_path_chars: int = DEFAULT_MAX_PATH_CHARS
    used_entries: int = 0
    used_path_chars: int = 0
    path_chars_spent: bool = False  # 앞 볼륨의 순회가 경로 글자 수 상한으로 멈췄다 → 뒤 파티션은 건너뛴다
    walked: int = 0
    skipped: Counter = dataclasses.field(default_factory=Counter)
    skipped_examples: dict[str, list[Any]] = dataclasses.field(default_factory=dict)
    failed: int = 0
    failed_examples: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    unexamined: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    @classmethod
    def from_limits(cls, limits: Limits) -> "CallBudget":
        return cls(max_entries=int(limits.max_entries), deadline=time.monotonic() + float(limits.max_seconds or LIST_MAX_SECONDS),
                   max_partitions=max_partitions(limits), max_path_chars=max_path_chars(limits))

    def skip(self, reason: str, index: Any) -> None:
        self.skipped[reason] += 1
        ex = self.skipped_examples.setdefault(reason, [])
        if len(ex) < 20:
            ex.append(index)

    def fail(self, index: Any, error: dict[str, Any]) -> None:
        """열었지만 해석하지 못한 볼륨(오류)을 센다 — 그 볼륨은 목록·흔적 검사에서 빠졌다(결과가 불완전하다)."""
        self.failed += 1
        if len(self.failed_examples) < 20:
            self.failed_examples.append({"partition": index, "reason": (error.get("data") or {}).get("reason") or error.get("code")})

    def summary(self) -> dict[str, Any]:
        """응답·목록 파일에 싣는 호출 예산 요약 (건너뛴 파티션은 사유별 개수 + 예시 index 20개 — 열었지만 엔진 예산이 다 돼 오류가 난
        볼륨도 그 사유(time·steps)로 센다, 해석하지 못한 볼륨은 volumes_failed {count, examples:[{partition, reason}] 20개})."""
        return {"max_entries": self.max_entries, "entries_used": self.used_entries, "max_partitions": self.max_partitions,
                "max_path_chars": self.max_path_chars, "path_chars_used": self.used_path_chars,
                "partitions_walked": self.walked,
                "partitions_unexamined": self.unexamined,
                "partitions_skipped": {k: {"count": n, "examples": self.skipped_examples.get(k, [])} for k, n in sorted(self.skipped.items())},
                "volumes_failed": {"count": self.failed, "examples": list(self.failed_examples)}}

    @property
    def limited(self) -> list[str]:
        """한도 때문에 보지 못한 파티션이 있는 사유 (중복 구간은 한도가 아니다). 해석하지 못한 볼륨은 따로 센다(failed)."""
        return sorted(k for k in self.skipped if k != "duplicate")


def _unexpected_volume_error(exc: Exception) -> dict[str, Any]:
    """엔진이 FsError 로 바꾸지 못한 예외 → 볼륨 오류 dict (엔진의 internal_error 와 같은 모양: FsError.to_dict())."""
    return FsError(f"볼륨을 해석하는 중 예상하지 못한 오류가 났습니다: {type(exc).__name__}: {exc}"[:400], reason="internal_error",
                   data={"exception": type(exc).__name__},
                   hint="이 볼륨은 결과에서 빠졌다. 이미지가 심하게 손상됐을 수 있다 — 사람에게 알린다.").to_dict()


def iter_volumes(img: Any, layout: dict[str, Any], partition: int | None, limits: Limits, budget: CallBudget, *,
                 include_deleted: bool, cancel: Callable[[], Any] | None = None) -> Iterator[dict[str, Any]]:
    """고른 파티션을 하나씩 열어 {partition, info, walk} 또는 {partition, error} 를 낸다(받는 쪽이 요약·기록하고 버린다).

    - 같은 (start_offset, size_bytes) 구간은 한 번만 순회한다(뒤의 것은 budget.skipped['duplicate']).
    - 볼륨마다 엔진 예산(pweh.fs.Budget) 하나를 새로 만들어 open_volume·info·walk 에 함께 넘긴다: 호출의 마감 시각, 그 볼륨의 단계
      상한(open_volume 이 올린다), 취소 함수(cancel — 동기 도구는 없음). 순회는 budget 의 남은 항목 수·남은 경로 글자 수로도 묶는다
      (엔진의 walk['path_chars'] 를 빼 나간다).
    - 처음 여는 볼륨은 시간이 조금이라도 남으면 열고, 그 뒤 볼륨은 남은 시간이 LATER_VOLUME_MIN_SECONDS 미만이면 건너뛴다. 항목·
      파티션·경로 글자 수 상한에 닿았거나(앞 순회가 max_path_chars 로 멈춤) 취소됐으면 남은 파티션은 건너뛴다
      (budget.skipped['time'|'entries'|'partitions'|'path_chars'|'cancelled']).
    - 오류가 난 볼륨(엔진의 FsError, 엔진이 바꾸지 못한 예외도)은 {partition, error} 로 내고 budget.fail 로 센다 — 나머지 볼륨은 계속
      본다. 엔진 예산이 다 돼 난 오류(budget_exceeded)는 손상이 아니라 한도다: budget.skipped[data.limit] 로 센다.
    """
    if partition is None:
        seen_unexamined = set()
        supported = {(p.get("start_offset"), p.get("size_bytes")) for p in pick_partitions(layout, None)}
        for p in layout.get("partitions") or []:
            key = (p.get("start_offset"), p.get("size_bytes"))
            if p.get("fs_hint") not in OPENABLE and key not in supported and key not in seen_unexamined:
                seen_unexamined.add(key)
                reason = "image_truncated" if beyond_image(p) else "unsupported_partitions"
                budget.skip(reason, p.get("index"))
                budget.unexamined.append({**partition_brief(p), "reason": reason})
    seen: dict[tuple[Any, Any], Any] = {}
    for p in pick_partitions(layout, partition):
        idx = p.get("index")
        key = (p.get("start_offset"), p.get("size_bytes"))
        if key in seen:
            budget.skip("duplicate", idx)
            continue
        seen[key] = idx
        if cancel is not None and cancel():
            budget.skip("cancelled", idx)
            continue
        if budget.walked >= budget.max_partitions:
            budget.skip("partitions", idx)
            continue
        remaining_s = budget.deadline - time.monotonic()
        # 0 이하는 엔진에 넘기지 않는다 — pweh.fs 의 Budget(max_seconds=0) 은 '제한 없음'이다
        if remaining_s <= 0 or (budget.walked and remaining_s < LATER_VOLUME_MIN_SECONDS):
            budget.skip("time", idx)
            continue
        remaining_e = budget.max_entries - budget.used_entries
        if remaining_e <= 0:
            budget.skip("entries", idx)
            continue
        remaining_c = budget.max_path_chars - budget.used_path_chars
        if remaining_c <= 0 or budget.path_chars_spent:
            budget.skip("path_chars", idx)
            continue
        lim = dataclasses.replace(limits, max_seconds=remaining_s, max_entries=remaining_e, max_path_chars=remaining_c)
        eb = engine_budget(None, lim, deadline=budget.deadline, cancel=cancel)  # 이 볼륨 하나의 예산 (open_volume 이 단계 상한을 올린다)
        budget.walked += 1
        item: dict[str, Any] = {"partition": partition_brief(p)}
        vol = None
        try:
            vol = open_volume(partition_source(img, p), limits=lim, fs_hint=p.get("fs_hint"), budget=eb)
            item["info"] = vol.info(budget=eb)
            walk = vol.walk(include_deleted=include_deleted, max_entries=remaining_e, limits=lim, budget=eb)
            item["walk"] = walk
            budget.used_entries += len(walk.get("entries") or [])
            budget.used_path_chars += int(walk.get("path_chars") or 0)
            if walk.get("truncated_reason") == "max_path_chars":
                budget.path_chars_spent = True
            del walk
        except FsError as exc:
            item["error"] = exc.to_dict()
        except Exception as exc:  # noqa: BLE001 - 이 볼륨만 실패로 남기고 나머지 볼륨은 계속 본다
            log.warning("볼륨 해석 중 예상하지 못한 오류 (partition=%s)", idx, exc_info=True)
            item["error"] = _unexpected_volume_error(exc)
        finally:
            vol = None  # 다음 볼륨을 열기 전에 놓는다(실패한 볼륨의 캐시도 들고 있지 않게)
        if "error" in item:
            data = item["error"].get("data") or {}
            if data.get("reason") == "budget_exceeded":
                budget.skip(str(data.get("limit") or "time"), idx)  # 한도(시간·단계·취소)에 닿은 것 — 해석하지 못한 볼륨이 아니다
            else:
                budget.fail(idx, item["error"])
        yield item
        del item


def open_partition_volume(img: Any, partition: int | None, limits: Limits | None = None, *,
                          budget: Budget | None = None) -> tuple[dict[str, Any], Any]:
    """추출용: 파티션 하나의 볼륨. partition=None 이면 지원하는 파티션이 하나뿐일 때만(같은 구간을 가리키는 파티션은 하나로 센다).
    budget 을 주면 볼륨을 열 때(exFAT 은 루트 디렉터리를 읽는다) 그 예산(마감·취소)을 쓴다."""
    layout = detect_partitions(img, limits=limits)
    parts = pick_partitions(layout, partition)
    if partition is None:
        uniq: dict[tuple[Any, Any], dict[str, Any]] = {}
        for p in parts:
            uniq.setdefault((p.get("start_offset"), p.get("size_bytes")), p)
        parts = list(uniq.values())
    if not parts:
        if layout_reasons(layout, partition):
            raise FsError("해석할 수 있는 FAT/exFAT 파티션이 없습니다 — 파티션이 이미지 끝 너머에 있습니다(잘린 이미지).", reason="beyond_image",
                          hint="이미징이 끝까지 됐는지 사람에게 확인하고, 필요하면 다시 이미징한다(forensics_partitions 의 warnings).")
        raise FsError("해석할 수 있는 FAT/exFAT 파티션이 없습니다.", reason="unsupported_fs")
    if len(parts) > 1:
        shown = ", ".join(str(p["index"]) for p in parts[:20]) + (" …" if len(parts) > 20 else "")
        raise FsError(f"FAT/exFAT 파티션이 여럿입니다({shown}) — partition 을 지정하세요.", reason="bad_argument")
    p = parts[0]
    return p, open_volume(partition_source(img, p), limits=limits, fs_hint=p.get("fs_hint"), budget=budget)


# ---------------------------------------------------------------------------
# 호스트 오염 흔적 (설계 §4 오염 검사)
# ---------------------------------------------------------------------------
_ROOT_STRONG = {
    "$recycle.bin": "Windows 휴지통 폴더($RECYCLE.BIN) — Windows 가 쓰기 가능한 상태로 마운트했다",
    ".spotlight-v100": "macOS Spotlight 색인 폴더",
    ".fseventsd": "macOS 파일 시스템 이벤트 폴더",
    ".trashes": "macOS 휴지통 폴더",
}
_ANY_STRONG = {
    ".ds_store": "macOS Finder 메타데이터(.DS_Store)",
    "thumbs.db": "Windows 탐색기 미리보기 캐시(Thumbs.db)",
    "desktop.ini": "Windows 탐색기 폴더 설정(desktop.ini)",
}
_SVI_STRONG = {"indexervolumeguid": "Windows 검색 색인 볼륨 GUID", "wpsettings.dat": "Windows 저장소 설정(WPSettings.dat)"}


def contamination(walk: dict[str, Any], info: dict[str, Any], acquisition_date: str | None) -> list[dict[str, Any]]:
    """보관 기간에 호스트(분석 PC)가 만든 흔적. strong = 이 이름의 파일은 호스트 OS 가 만든다, weak = 정황, ambiguous = 해석이 갈린다.

    카메라가 만들 수 없는 것은 아니므로 판단은 '흔적'이다. 삭제된 항목도 보고한다(삭제돼도 쓴 사실은 남는다). 응답의 경로는 줄인다
    (깊은 나무 — 전체는 forensics_fs_list 의 목록 파일).
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(indicator: str, strength: str, path: str | None, note: str, deleted: bool = False) -> None:
        key = (indicator, path or "")
        if key in seen or len(out) >= 200:
            return
        seen.add(key)
        out.append({"indicator": indicator, "strength": strength, "path": clip_text(path), "deleted": deleted, "note": note})

    entries = walk.get("entries") or []
    svi_dirs = 0
    for e in entries:
        name = str(e.get("name") or "").lower()
        path = e.get("display_path")
        depth = e.get("depth") or 0
        deleted = bool(e.get("deleted"))
        if depth == 1 and name in _ROOT_STRONG:
            add(name, "strong", path, _ROOT_STRONG[name], deleted)
        elif depth == 1 and name.startswith(".trash-"):
            add(".trash-<uid>", "strong", path, "리눅스 데스크톱 휴지통 폴더", deleted)
        elif depth == 1 and name == "system volume information" and e.get("is_dir"):
            svi_dirs += 1
            add("system-volume-information", "weak", path, "Windows 가 만드는 폴더 — 안의 IndexerVolumeGuid·WPSettings.dat 이 있으면 strong", deleted)
        elif depth == 2 and str(e.get("display_path") or "").lower().startswith("/system volume information/") and name in _SVI_STRONG:
            add(name, "strong", path, _SVI_STRONG[name], deleted)
        elif name in _ANY_STRONG:
            add(name, "strong", path, _ANY_STRONG[name], deleted)
        elif name.startswith("._") and not e.get("is_dir"):
            add("appledouble", "strong", path, "macOS AppleDouble 메타데이터(._*)", deleted)
    if acquisition_date and _DATE_RX.match(acquisition_date):
        same = [e for e in entries if not e.get("is_dir") and not e.get("deleted")
                and ((e.get("times") or {}).get("accessed") or {}).get("iso") == acquisition_date]
        if same:
            add("fat-access-date-equals-acquisition", "weak", None,
                f"마지막 접근 날짜가 획득일({acquisition_date})과 같은 파일 {len(same)}개 — 획득 때 읽혔을 수 있다(접근 날짜는 장치 현지 날짜·호스트 시간대 차이를 고려)")
    st = info.get("state") or {}
    if st.get("dirty"):
        add("volume-dirty", "ambiguous", None, "깨끗하지 않게 분리된 상태 비트 — 카메라가 전원 차단 뒤 남기기도 하고, Windows 는 기존 dirty 비트를 지우지 않는다")
    return out


# ---------------------------------------------------------------------------
# 추출
# ---------------------------------------------------------------------------


def safe_output_name(seq: int, name: str, suffix: str = "") -> str:
    base = _SAFE_NAME_RX.sub("_", name or "").strip("._-")[:80] or "file"
    return f"{seq:04d}-{base}{suffix}"


def _join_display(parent: str | None, name: Any) -> str:
    return (parent or "").rstrip("/") + "/" + str(name or "")


def _err_code(exc: FsError) -> str:
    """미해결 항목의 code: 엔진 FsError 의 reason (예산이면 data.limit — time/steps/cancelled, 슬롯 한도에서 잘린 디렉터리의 뒤쪽을
    가리키는 ref 면 max_dir_slots)."""
    data = exc.data or {}
    if exc.reason == "budget_exceeded":
        return str(data.get("limit") or "time")
    if data.get("dir_cut"):
        return str(data["dir_cut"])
    return str(exc.reason or "malformed")


def merge_reasons(reasons: Iterable[str], unresolved: Iterable[dict[str, Any]]) -> list[str]:
    """추출 결과의 잘림 사유 + 한도·예산·취소 때문에 찾지 못한 요청(unresolved 의 code 가 LIMIT_CODES)의 사유 (정렬)."""
    out = set(reasons)
    out.update(str(u["code"]) for u in unresolved if u.get("code") in LIMIT_CODES)
    return sorted(out)


def resolve_targets(vol: Any, refs: Iterable[str], paths: Iterable[str], *, limits: Limits, deadline: float,
                    check: Callable[[], None] | None = None,
                    cancel: Callable[[], Any] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """refs·paths → (추출할 항목, 찾지 못한 것 [{ref|path, code, reason}]). 중복을 없앤다(순서 유지, 같은 항목을 가리키는 ref·path 도).

    엔진 호출(reachable_dirspecs·entry·lookup)마다 예산을 새로 만든다: job 마감(deadline)·취소 함수(cancel)를 함께 쓰고 단계 상한은
    이 볼륨의 것. 남은 시간이 1초 미만이면 더 하지 않는다(code time). 엔진이 취소로 멈추면 check()(job 의 check_cancelled)를 바로
    불러 job 을 취소로 끝낸다(출력·보관 기록 없음).

    ref 는 그 디렉터리(dirspec)를 ``vol.reachable_dirspecs(targets=…)`` — 루트에서 검증한 디렉터리만 따라가는 순회, 요청한
    dirspec 을 모두 찾으면 바로 멈춤 — 가 찾았을 때만 받는다(지어낸 dirspec 으로 아무 클러스터나 디렉터리로 읽게 하지 않는다). 순회
    status 로 판단한다: complete 인데 없으면 bad_ref, truncated(한도·예산에서 잘림, 끝까지 읽지 못한 살아 있는 디렉터리) 인데
    없으면 그 ref 만 refs_unverifiable(찾은 dirspec 의 ref 는 검증된 것이라 받는다). 검증된 ref 가 하나도 없고 paths 도 없으면
    FsError(refs_unverifiable) — job 실패.
    모양이 다른 ref 는 순회 없이 bad_ref. ref 항목의 display_path 는 순회의 디렉터리 경로 + '/' + 표시 이름이다.

    paths 는 검증한 디렉터리만 지나는 ``vol.lookup`` 으로 찾는다(정확히 같은 이름이 먼저, 없으면 대소문자 무시 — 여럿이면
    ambiguous_path). 항목의 display_path 는 lookup 이 돌려준 디스크의 이름(8.3 별칭·대소문자 변형이 아닌)이고, 호출자가 쓴 철자가
    다르면 requested_path 로 남긴다. unresolved 에는 이미지에서 읽은 이름을 싣지 않는다(요청한 ref·path, code, 사유만).
    """
    refs = list(dict.fromkeys(str(r) for r in refs))
    paths = list(dict.fromkeys(str(p) for p in paths))
    targets: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    seen_refs: set[Any] = set()

    def checkpoint() -> None:
        if check is not None:
            check()

    def call_budget() -> Budget | None:
        """엔진 호출 하나의 예산 (남은 job 시간이 1초 미만이면 None — 더 하지 않는다)."""
        if deadline - time.monotonic() < 1.0:
            return None
        return engine_budget(vol, limits, deadline=deadline, cancel=cancel)

    if refs:
        parsed: list[tuple[str, str | None]] = []
        for r in refs:
            m = _REF_RX.match(r)
            parsed.append((r, m.group(1) if m else None))
        specs = {s for _, s in parsed if s is not None}
        status, why = "complete", None
        dirspecs: set[str] = set()
        dpaths: dict[str, str] = {}
        if specs:
            b = call_budget()
            if b is None:
                status, why = "truncated", "time"
            else:
                reach = vol.reachable_dirspecs(limits=limits, budget=b, targets=sorted(specs))
                why = reach.get("truncated_reason")
                if why == "cancelled":
                    checkpoint()
                status = str(reach.get("status") or ("truncated" if reach.get("truncated") else "complete"))
                dirspecs = set(reach.get("dirspecs") or ())
                dpaths = dict(reach.get("paths") or {})
        verified = [r for r, s in parsed if s is not None and s in dirspecs]
        missing = [r for r, s in parsed if s is not None and s not in dirspecs]
        if status == "truncated" and missing and not verified and not paths:
            raise FsError(f"디렉터리 확인 순회가 끝까지 가지 못해(사유 {why}) ref 의 디렉터리를 하나도 검증하지 못했습니다 — ref 를 받지 않습니다.",
                          reason="refs_unverifiable", data={"truncated_reason": why, "refs": len(missing)},
                          hint="partition 을 지정하거나 paths= 로 살아 있는 파일을 고르세요. 볼륨이 매우 크거나 깊으면 사람에게 알리고 범위를 줄인다.")
        for r, spec in parsed:
            checkpoint()
            if spec is None or spec not in dirspecs:
                if spec is not None and status == "truncated":
                    unresolved.append({"ref": r, "code": "refs_unverifiable",
                                       "reason": f"디렉터리 확인 순회가 끝까지 가지 못해(사유 {why}) 이 ref 의 디렉터리를 검증하지 못했습니다(refs_unverifiable) "
                                                 "— 받지 않습니다."})
                else:
                    unresolved.append({"ref": r, "code": "bad_ref",
                                       "reason": "목록 순회가 검증한 디렉터리의 ref 가 아닙니다(bad_ref) — forensics_fs_list 결과 JSON 의 ref 를 쓰세요."})
                continue
            b = call_budget()
            if b is None:
                unresolved.append({"ref": r, "code": "time", "reason": "작업 시간 한도에 닿아 보지 못함"})
                continue
            try:
                e = vol.entry(r, budget=b)
            except FsError as exc:
                code = _err_code(exc)
                if code == "cancelled":
                    checkpoint()
                unresolved.append({"ref": r, "code": code, "reason": exc.message})
                continue
            if e.get("ref") in seen_refs:
                continue
            seen_refs.add(e.get("ref"))
            e["display_path"] = _join_display(dpaths.get(spec), e.get("display_name"))
            targets.append(e)
    for ptxt in paths:
        checkpoint()
        b = call_budget()
        if b is None:
            unresolved.append({"path": ptxt, "code": "time", "reason": "작업 시간 한도에 닿아 보지 못함"})
            continue
        try:
            e = vol.lookup(ptxt, limits=limits, budget=b)
        except FsError as exc:
            code = _err_code(exc)
            if code == "cancelled":
                checkpoint()
            hint = _CODE_HINT.get(code)
            unresolved.append({"path": ptxt, "code": code, "reason": exc.message + (f" {hint}" if hint else "")})
            continue
        if e is None:
            unresolved.append({"path": ptxt, "code": "not_found", "reason": "살아 있는 항목을 찾지 못함(삭제 파일은 refs 로)"})
            continue
        if e.get("ref") in seen_refs:
            continue
        seen_refs.add(e.get("ref"))
        asked = "/" + "/".join(p for p in ptxt.split("/") if p)
        if asked != e.get("display_path"):
            e["requested_path"] = asked  # 호출자가 쓴 철자(8.3 별칭·대소문자 변형) — 경로는 디스크의 이름(display_path)으로 남긴다
        targets.append(e)
    return targets, unresolved


def read_selected_image(img: ImageReader, *, partition: int | None, ref: str | None, path: str | None,
                        method: str, max_bytes: int, deadline: float, cancel: Callable[[], bool]) -> tuple[bytes, dict[str, Any]]:
    """FAT/exFAT 의 검증된 파일 1개를 읽는다. 디렉터리 도달 가능성·완전한 복구 계획을 먼저 확인한다.

    ref 는 목록과 같은 검증 순회를 거치고 path 는 검증된 디렉터리 lookup 을 쓴다. 삭제 파일은 선택한 복구 방법·신뢰도를
    출처에 남긴다. 잘린/예산 부족 계획을 완전한 정지이미지로 넘기지 않는다. 호스트 추출 파일을 만들거나 다시 열지 않는다.
    """
    from pweh.evidence import image_hints_checkpoint

    def check() -> None:
        image_hints_checkpoint(deadline, cancel)

    left = image_hints_checkpoint(deadline, cancel)
    limits = dataclasses.replace(Limits(), max_seconds=left, max_read_bytes=max_bytes)
    p, vol = open_partition_volume(img, partition, limits=limits,
                                    budget=engine_budget(None, limits, deadline=deadline, cancel=cancel))
    check()
    entries, unresolved = resolve_targets(vol, [ref] if ref else [], [path] if path else [], limits=limits,
                                           deadline=deadline, check=check, cancel=cancel)
    if unresolved or len(entries) != 1:
        reason = str(unresolved[0].get("code")) if unresolved else "not_found"
        raise FsError("이미지 파일 1개를 검증해 선택하지 못했습니다.", reason=reason, data={"unresolved": unresolved})
    entry = entries[0]
    if entry.get("is_dir"):
        raise FsError("디렉터리는 이미지로 분석하지 않습니다.", reason="bad_argument")
    check()
    plan = vol.content_plan(entry["ref"], method, "data", limits=limits,
                            budget=engine_budget(vol, limits, deadline=deadline, cancel=cancel))
    pd = plan.to_dict(max_runs=0)
    check()
    if not pd.get("complete") or pd.get("limit_reason") or pd.get("status") == "limit" or pd.get("bytes_beyond_image"):
        raise FsError("파일 내용 계획이 불완전해 이미지 분석에 넘기지 않습니다.", reason="incomplete_file",
                       data={k: pd.get(k) for k in ("complete", "status", "limit_reason", "bytes_beyond_image")})
    if not 0 < plan.size <= max_bytes:
        raise FsError(f"이미지는 0 바이트 초과, {max_bytes} 바이트 이하여야 합니다.", reason="bad_argument")
    chunks: list[bytes] = []
    size = 0
    for chunk in vol.iter_plan(plan, max_bytes=max_bytes):
        check()
        size += len(chunk)
        if size > max_bytes:
            raise FsError("이미지 크기 상한을 넘었습니다.", reason="bad_argument")
        chunks.append(chunk)
    if size != plan.size:
        raise FsError("이미지 파일 내용을 끝까지 읽지 못했습니다.", reason="incomplete_file")
    data = b"".join(chunks)
    return data, {"partition": p.get("index"), "ref": entry.get("ref"), "path": entry.get("display_path"),
                  "requested_path": entry.get("requested_path"), "deleted": bool(entry.get("deleted")),
                  "method": pd.get("method"), "confidence": pd.get("confidence"), "complete": True,
                  "note": pd.get("note"), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def extract_entries(vol: Any, entries: Iterable[dict[str, Any]], out_dir_fd: int, *, method: str, region: str, max_bytes_total: int,
                    max_files: int, limits: Limits | None = None, deadline: float | None = None,
                    cancel: Callable[[], bool] | None = None,
                    seals: dict[str, os.stat_result] | None = None) -> dict[str, Any]:
    """항목들의 내용을 출력 디렉터리 fd 안에 0444 파일로 쓴다(O_CREAT|O_EXCL|O_NOFOLLOW, 실행 비트·링크 없음, fd 로 fchmod).
    반환: {files:[…], skipped:[…], bytes_total, truncated, truncated_reasons}.

    내용은 메모리에 모으지 않고 조각으로 쓰며 sha256 을 계산한다. 응답·매니페스트에는 해시·크기·방법·status 만 남긴다. 후보
    (content_plan)는 ref 마다 한 번만, job 마감(deadline)·취소 함수(cancel)를 함께 쓰는 새 예산(단계 상한은 이 볼륨의 것)으로 만든다.
    예산 때문에 덜 만든 계획(limit_reason: time/steps)은 있는 만큼 쓰고 그 사유를 truncated_reasons 에 더한다. truncated 는 상한(파일
    수·바이트·시간·단계)·취소로 덜 쓴 것이 있으면 참이다(내용이 이미지 끝 너머에 있어 덜 읽은 것은 상한이 아니다 — 파일 기록의
    complete=false·bytes_beyond_image). 취소되면(파일 사이·쓰는 도중·엔진이 후보를 만드는 도중) 쓰던 파일은
    complete=false 로 남기고, 시도하지 않은 항목은 모두 skipped 에 싣는다(파일은 사유 '취소됨', 디렉터리는 디렉터리 사유) —
    truncated_reasons 에 'cancelled'.
    """
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    reasons: set[str] = set()
    total = 0
    seq = 0
    plans: dict[str, Any] = {}
    base_limits = limits or Limits()
    entries = list(entries)

    def cancel_rest(k: int) -> None:
        """k 번째 항목부터 취소로 시도하지 않은 것도 매니페스트·응답에 남긴다(무엇을 받지 못했는지 알 수 있게)."""
        reasons.add("cancelled")
        for rest in entries[k:]:
            skipped.append({"ref": rest.get("ref"), "path": rest.get("display_path"),
                            "reason": _DIR_SKIP_REASON if rest.get("is_dir") else "취소됨"})

    for i, e in enumerate(entries):
        if cancel is not None and cancel():
            cancel_rest(i)
            break
        ref = e.get("ref")
        if e.get("is_dir"):
            skipped.append({"ref": ref, "path": e.get("display_path"), "reason": _DIR_SKIP_REASON})
            continue
        if seq >= max_files:
            reasons.add("max_files")
            skipped.append({"ref": ref, "path": e.get("display_path"), "reason": f"파일 수 상한({max_files})"})
            continue
        remaining = max_bytes_total - total
        if remaining <= 0:
            reasons.add("max_bytes")
            skipped.append({"ref": ref, "path": e.get("display_path"), "reason": "바이트 상한"})
            continue
        left_s = None if deadline is None else deadline - time.monotonic()
        if left_s is not None and left_s < 1.0:
            reasons.add("time")
            skipped.append({"ref": ref, "path": e.get("display_path"), "reason": "작업 시간 한도"})
            continue
        plan = plans.get(ref)
        if plan is None:
            try:
                plan = vol.content_plan(ref, method, region, limits=base_limits,
                                        budget=engine_budget(vol, base_limits, deadline=deadline, cancel=cancel))
            except FsError as exc:
                limit = str((exc.data or {}).get("limit") or "time") if exc.reason == "budget_exceeded" else None
                if limit == "cancelled":  # 엔진이 후보를 만드는 도중에 취소를 보았다
                    cancel_rest(i)
                    break
                if limit is not None:
                    reasons.add(limit)  # 시간·단계 예산 — 후보를 다 만들지 못했다
                skipped.append({"ref": ref, "path": e.get("display_path"), "reason": exc.message})
                continue
            plans[ref] = plan
        pd = plan.to_dict(max_runs=16)
        limit_reason = pd.get("limit_reason")
        if limit_reason == "cancelled":  # 취소로 덜 만든 계획 — 쓰지 않는다
            cancel_rest(i)
            break
        if limit_reason:
            reasons.add(str(limit_reason))  # 예산 때문에 덜 만든 계획(status 'limit') — 있는 만큼 쓰고 잘림으로 남긴다
        seq += 1
        name = safe_output_name(seq, str(e.get("display_name") or ""), ".residual" if region == "residual" else "")
        fd = safeio.create_excl(out_dir_fd, name, 0o644)
        h = hashlib.sha256()
        n = 0
        try:
            for chunk in vol.iter_plan(plan, max_bytes=remaining):
                if cancel is not None and cancel():
                    reasons.add("cancelled")
                    break
                safeio.write_all(fd, chunk)
                h.update(chunk)
                n += len(chunk)
            os.fsync(fd)
        finally:
            try:
                os.fchmod(fd, 0o444)
                if seals is not None:
                    from .outputs import seal_file
                    seals[name] = seal_file(out_dir_fd, name, fd)
            finally:
                os.close(fd)
        total += n
        available = int(pd.get("available") or 0)
        size = int(pd.get("size") or 0)
        if n >= remaining and remaining < available:
            reasons.add("max_bytes")  # 바이트 상한까지 썼는데 계획에 더 있었다 = 상한이 이 파일을 잘랐다(이미지 끝에서 멈춘 것은 상한이 아니다)
        rec = {
            "seq": seq,
            "file": name,
            "ref": ref,
            "path": e.get("display_path"),
            "deleted": bool(e.get("deleted")),
            "region": region,
            "method": pd.get("method"),
            "confidence": pd.get("confidence"),
            "status": pd.get("status"),
            "note": pd.get("note"),
            "expected_size": pd.get("expected_size"),
            "size": n,
            "complete": bool(pd.get("complete")) and n >= size,
            "sha256": h.hexdigest(),
            "runs_total": pd.get("runs_total"),
            "conflicts": pd.get("conflicts"),
        }
        if limit_reason:
            rec["limit_reason"] = limit_reason
        if pd.get("bytes_beyond_image"):
            rec["bytes_beyond_image"] = pd["bytes_beyond_image"]  # 계획 중 이미지 끝 너머라 읽을 수 없는 바이트(잘린 이미지)
        if e.get("requested_path"):
            rec["requested_path"] = e["requested_path"]
        files.append(rec)
    return {"files": files, "skipped": skipped, "bytes_total": total, "truncated": bool(reasons), "truncated_reasons": sorted(reasons)}


def archive_inventory(fd: int, *, max_entries: int = LIST_MAX_ENTRIES, deadline: float,
                      cancel: Callable[[], bool], hash_members: bool = False,
                      max_hash_bytes: int = 1 << 30) -> dict[str, Any] | None:
    """논리 아카이브 목록(비아카이브만 None). 메타데이터·해제 바이트·시간을 모두 제한한다."""
    from pweh.archive import Archive, kind
    if kind(fd) is None:
        return None
    return Archive(fd, max_entries=max_entries, deadline=deadline, cancel=cancel).inventory(
        hash_members=hash_members, max_hash_bytes=max_hash_bytes)


def read_selected_file(fd: int, *, partition: int | None = None, ref: str | None = None, path: str | None = None,
                       method: str = "auto", max_bytes: int, deadline: float,
                       cancel: Callable[[], bool]) -> tuple[bytes, dict[str, Any]]:
    """검증된 EV fd 자체 또는 FAT/exFAT·TAR/ZIP 항목 1개의 완전한 바이트를 반환한다.

    fd 의 소유/무결성 확인은 호출자가 E.open_checked 로 한다. 결과를 커밋할 때도 같은 fd 를 재검증해야 한다.
    """
    from pweh.archive import Archive, checkpoint, kind
    checkpoint(deadline, cancel)
    if ref is not None and path is not None:
        raise FsError("ref 와 path 를 동시에 지정할 수 없습니다.", reason="bad_argument")
    if ref is None and path is None:
        if partition is not None:
            raise FsError("EV 자체를 읽을 때 partition 을 지정할 수 없습니다.", reason="bad_argument")
        size = os.fstat(fd).st_size
        if size < 0 or size > max_bytes:
            raise FsError("파일 크기가 읽기 상한을 넘습니다.", reason="max_bytes")
        chunks = []
        for at in range(0, size, 65536):
            checkpoint(deadline, cancel)
            blob = os.pread(fd, min(65536, size - at), at)
            if len(blob) != min(65536, size - at):
                raise FsError("파일을 끝까지 읽지 못했습니다.", reason="incomplete_file")
            chunks.append(blob)
        data = b"".join(chunks)
        return data, {"container": "file", "member_selected": False, "complete": True, "size": len(data),
                      "method": "whole-file", "confidence": "high", "sha256": hashlib.sha256(data).hexdigest()}
    if kind(fd) is not None:
        if partition is not None or method != "auto":
            raise FsError("아카이브에는 partition·복구 method 를 지정하지 않습니다.", reason="bad_argument")
        arc = Archive(fd, deadline=deadline, cancel=cancel)
        entry = arc.select(ref, path)
        data = b"".join(arc.chunks(entry, max_bytes=max_bytes))
        return data, {"container": arc.format, "member_selected": True, "ref": entry["ref"], "path": entry["display_path"],
                      "deleted": False, "method": "archive-member", "confidence": "high", "complete": True,
                      "container_truncated": bool(arc.reasons), "container_truncated_reasons": sorted(arc.reasons),
                      "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    with image_reader(fd) as img:
        data, source = read_selected_image(img, partition=partition, ref=ref, path=path, method=method,
                                           max_bytes=max_bytes, deadline=deadline, cancel=cancel)
    return data, {"container": "filesystem", "member_selected": True, **source}


def extract_archive(fd: int, refs: list[str], paths: list[str], out_dir_fd: int, *, max_files: int,
                    max_bytes_total: int, deadline: float, cancel: Callable[[], bool],
                    seals: dict[str, os.stat_result] | None = None) -> dict[str, Any]:
    """선택한 아카이브 멤버를 평평한 생성 이름으로만 쓴다. CRC 실패·불완전 멤버는 파일을 지운다."""
    from pweh.archive import Archive
    arc = Archive(fd, deadline=deadline, cancel=cancel)
    targets, skipped, files = [], [], []
    seen = set()
    reasons = set(arc.reasons)
    for ref, path in [(r, None) for r in refs] + [(None, p) for p in paths]:
        try:
            e = arc.select(ref, path)
            if e["ref"] not in seen:
                targets.append(e)
                seen.add(e["ref"])
        except FsError as exc:
            skipped.append({"ref": ref, "path": path, "code": exc.reason, "reason": exc.message})
            reasons.add(exc.reason)
    total = 0
    for e in targets:
        reason = "cancelled" if cancel() else ("max_files" if len(files) >= max_files else ("max_bytes" if e["size"] > max_bytes_total - total else None))
        if reason:
            skipped.append({"ref": e["ref"], "path": e["display_path"], "code": reason})
            reasons.add(reason)
            continue
        name = safe_output_name(len(files) + 1, e["display_name"])
        out = safeio.create_excl(out_dir_fd, name, 0o600)
        h, size, complete = hashlib.sha256(), 0, False
        try:
            for blob in arc.chunks(e, max_bytes=max_bytes_total - total):
                safeio.write_all(out, blob)
                h.update(blob)
                size += len(blob)
            os.fchmod(out, 0o444)
            os.fsync(out)
            if seals is not None:
                from .outputs import seal_file
                seals[name] = seal_file(out_dir_fd, name, out)
            complete = True
        except FsError as exc:
            reasons.add(exc.reason)
            skipped.append({"ref": e["ref"], "path": e["display_path"], "code": exc.reason})
        finally:
            os.close(out)
            if not complete:
                os.unlink(name, dir_fd=out_dir_fd)
        if complete:
            total += size
            files.append({"seq": len(files) + 1, "file": name, "ref": e["ref"], "path": e["display_path"], "deleted": False,
                          "method": "archive-member", "confidence": "high", "status": "ok", "size": size,
                          "complete": True, "sha256": h.hexdigest()})
    return {"format": arc.format, "files": files, "skipped": skipped, "bytes_total": total,
            "truncated": bool(reasons), "truncated_reasons": sorted(reasons)}
