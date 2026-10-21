"""명시된 시간 단위·출처를 보존하는 제한된 타임라인. 호스트 시간대를 적용하지 않는다."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import itertools
import json
import math
import time

from .errors import ValidationFailed


@dataclass(frozen=True)
class TimelineLimits:
    """타임라인 최대치는 이벤트 100,000개·JSON 16 MiB·45초다."""
    max_events: int = 10000
    max_output_bytes: int = 16 * 1024 * 1024
    max_seconds: float = 45.0


def normalize_timestamp(value, *, unit, epoch="unix", zero_unset=False, basis=None):
    """숫자 자릿수 추정 없이 지정한 epoch/단위를 정수 산술로 변환한다."""
    result = {"raw": value, "unit": unit, "epoch": epoch, "iso_utc": None,
              "time_basis": "utc", "precision": unit, "conversion_basis": basis,
              "valid": False}
    if not isinstance(value, int) or isinstance(value, bool):
        result["reason"] = "not_integer_timestamp"
        return result
    if value == 0 and zero_unset:
        result["unset"] = True
        return result
    multiplier = {"seconds": 1000000, "milliseconds": 1000, "microseconds": 1}.get(unit)
    if multiplier is None or epoch not in ("unix", "windows-1601"):
        result["reason"] = "unknown_time_contract"
        return result
    micros = value * multiplier - (11644473600000000 if epoch == "windows-1601" else 0)
    try:
        when = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=micros)
        result.update(iso_utc=when.isoformat(timespec="microseconds").replace("+00:00", "Z"), valid=True)
    except (OverflowError, ValueError):
        result["reason"] = "timestamp_out_of_range"
    return result


def normalize_filesystem_time(value):
    """FAT/exFAT/TAR/ZIP reader의 raw·basis를 유지하며 offset 있는 시각만 정렬한다."""
    result = dict(value) if isinstance(value, dict) else {"raw": value}
    result["iso_utc"] = None
    result.setdefault("precision", "date" if result.get("date_only") else "unknown")
    if result.get("valid") is False or result.get("unset"):
        return result
    candidate = (value.get("iso_utc") or value.get("utc") or value.get("iso")) if isinstance(value, dict) else None
    if not isinstance(candidate, str) or len(candidate) > 128:
        return result
    try:
        when = dt.datetime.fromisoformat(candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate)
        if when.tzinfo is None:
            result.setdefault("time_basis", "local-unknown-tz")
            return result
        result["iso_utc"] = when.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        result.setdefault("conversion_basis", "explicit-offset")
    except (ValueError, OverflowError):
        result["conversion_error"] = "invalid_or_out_of_range_iso"
    return result


def build_timeline(filesystem_events, artifact_events, *, limits=None, deadline=None, cancel_event=None):
    """입력 사건을 UTC 확정/시간대 미확정으로 나누고 동일 출처 중복만 제거한다."""
    limits = limits or TimelineLimits()
    if not isinstance(limits, TimelineLimits):
        raise ValidationFailed("limits는 TimelineLimits여야 합니다.")
    for field, maximum in (("max_events", 100000), ("max_output_bytes", 16 * 1024 * 1024), ("max_seconds", 45)):
        val = getattr(limits, field)
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val) or not 0 < val <= maximum:
            raise ValidationFailed("타임라인 한도가 허용 범위를 벗어났습니다.")
        if field != "max_seconds" and not isinstance(val, int):
            raise ValidationFailed("타임라인 개수·크기는 정수여야 합니다.")
    if limits.max_output_bytes < 2048:
        raise ValidationFailed("결과 메타데이터를 위해 max_output_bytes는 2048 이상이어야 합니다.")
    if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
        raise ValidationFailed("deadline은 monotonic 시각이어야 합니다.")
    deadline = min(time.monotonic() + limits.max_seconds, deadline if deadline is not None else math.inf)
    out = {"schema": "pweh.timeline/v1", "status": "ok", "events": [], "undated_events": [],
           "coverage": {"inputs_seen": 0, "included": 0, "duplicates": 0, "invalid_events": 0},
           "limits": asdict(limits), "truncated": False, "truncated_reasons": [], "warnings": []}
    seen, total = set(), 0
    for source in itertools.chain(filesystem_events, artifact_events):
        reason = "cancelled" if cancel_event is not None and cancel_event.is_set() else "time" if time.monotonic() >= deadline else None
        if reason:
            out["truncated_reasons"].append(reason)
            break
        out["coverage"]["inputs_seen"] += 1
        if not isinstance(source, dict) or not isinstance(source.get("kind"), str):
            out["coverage"]["invalid_events"] += 1
            continue
        event = dict(source)
        event["time"] = normalize_filesystem_time(event.get("time"))
        try:
            encoded = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            out["coverage"]["invalid_events"] += 1
            continue
        identity = {key: event.get(key) for key in ("kind", "source_ref", "record_ref", "record_state", "time")}
        # 출처 없는 두 사건의 내용까지 같아야 중복으로 본다.
        if not identity["source_ref"] and not identity["record_ref"]:
            identity = event
        digest = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        if digest in seen:
            out["coverage"]["duplicates"] += 1
            continue
        if out["coverage"]["included"] >= limits.max_events:
            out["truncated_reasons"].append("max_events")
            break
        if total + len(encoded) + 2048 > limits.max_output_bytes:
            out["truncated_reasons"].append("max_output_bytes")
            break
        total += len(encoded)
        seen.add(digest)
        out["coverage"]["included"] += 1
        out["events" if event["time"].get("iso_utc") else "undated_events"].append(event)
    # 정렬 key가 고정 길이 UTC이므로 소수점 유무의 문자열 역전이 없다.
    out["events"].sort(key=lambda event: event["time"]["iso_utc"])
    if time.monotonic() >= deadline and "time" not in out["truncated_reasons"]:
        out["truncated_reasons"].append("time")
    out["truncated"] = bool(out["truncated_reasons"])
    if out["truncated"] or out["coverage"]["invalid_events"]:
        out["status"] = "partial"
    if out["truncated"]:
        out["warnings"].append("수집한 부분만 정렬했으며 전체 자료의 최초·최종 사건을 뜻하지 않습니다.")
    return out
