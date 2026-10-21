"""명시적 시간 변환과 미확정 현지 시각 분리, 출처 및 상한 시험."""
from dataclasses import replace
import threading
import time

import pytest

from pweh.errors import ValidationFailed
from pweh.timeline import TimelineLimits, build_timeline, normalize_timestamp


def event(ref, timestamp, **extra):
    return {"kind": "synthetic", "source_ref": {"evidence_id": "EV-0001", "ref": ref},
            "record_ref": ref, "record_state": "current", "confidence": "high", "time": timestamp, **extra}


def test_exact_epoch_units_negative_sentinel_and_range():
    assert normalize_timestamp(0, unit="seconds")["iso_utc"] == "1970-01-01T00:00:00.000000Z"
    assert normalize_timestamp(-1, unit="microseconds")["iso_utc"] == "1969-12-31T23:59:59.999999Z"
    assert normalize_timestamp(11644473600000001, unit="microseconds", epoch="windows-1601")["iso_utc"] == "1970-01-01T00:00:00.000001Z"
    assert normalize_timestamp(0, unit="microseconds", epoch="windows-1601", zero_unset=True)["unset"]
    assert normalize_timestamp(2**63, unit="seconds")["reason"] == "timestamp_out_of_range"
    assert not normalize_timestamp(1.5, unit="seconds")["valid"]


def test_fs_local_unknown_offsets_and_date_only_preserved():
    local = {"raw": {"date": 12}, "iso": "2024-02-29T01:02:03", "valid": True, "time_basis": "local-unknown-tz"}
    offset = {**local, "utc": "2024-02-28T16:02:03Z", "time_basis": "local+offset"}
    date = {"raw": {"date": 10}, "iso": "2024-02-29", "valid": True, "time_basis": "local-unknown-tz", "date_only": True}
    result = build_timeline([event("a", local), event("b", offset), event("c", date)], [])
    assert len(result["events"]) == 1 and len(result["undated_events"]) == 2
    assert result["events"][0]["time"]["iso_utc"] == "2024-02-28T16:02:03.000000Z"
    assert result["undated_events"][1]["time"]["precision"] == "date"
    assert result["undated_events"][0]["time"]["raw"] == local["raw"]


def test_sort_fractional_same_time_distinct_provenance_and_dedup():
    zero = normalize_timestamp(0, unit="seconds")
    later = normalize_timestamp(1, unit="microseconds")
    result = build_timeline([], [event("later", later), event("zero", zero), event("also-zero", zero), event("zero", zero)])
    assert [e["record_ref"] for e in result["events"]] == ["zero", "also-zero", "later"]
    assert result["coverage"]["duplicates"] == 1


def test_invalid_time_and_historical_never_turned_into_current():
    timestamp = {"raw": "invalid", "iso": "2020-99-01T00:00:00Z", "valid": True}
    report = build_timeline([], [event("old", timestamp, record_state="historical", confidence="possible")])
    assert not report["events"] and report["undated_events"][0]["record_state"] == "historical"
    assert report["undated_events"][0]["time"]["conversion_error"]


def test_limits_deadline_cancel_and_bounded_output():
    events = [event(str(i), normalize_timestamp(i, unit="seconds")) for i in range(10)]
    report = build_timeline(events, [], limits=TimelineLimits(max_events=2))
    assert len(report["events"]) == 2 and report["truncated_reasons"] == ["max_events"]
    assert "time" in build_timeline(events, [], deadline=time.monotonic() - 1)["truncated_reasons"]
    cancelled = threading.Event()
    cancelled.set()
    assert "cancelled" in build_timeline(events, [], cancel_event=cancelled)["truncated_reasons"]
    report = build_timeline(events, [], limits=TimelineLimits(max_output_bytes=2500))
    assert len(report["events"]) <= 1 and report["truncated"]
    with pytest.raises(ValidationFailed):
        build_timeline([], [], limits=TimelineLimits(max_events=100001))
