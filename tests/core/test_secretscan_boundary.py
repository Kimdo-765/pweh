"""합성 명시 구간의 논리 줄 경계·예산·비노출 회귀."""
from __future__ import annotations

import hashlib
import itertools
import json
import time
from dataclasses import FrozenInstanceError

import pytest

from pweh import secretscan as S
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate


def scan(data, prefix=True, suffix=True, *, seen=None, **kw):
    def digest(value):
        if seen is not None:
            seen.append(value)
        return "sha256:" + hashlib.sha256(b"SYNTHETIC" + value).hexdigest()[:16]
    return S.scan_secrets(data, digest=kw.pop("digest", digest), deadline=kw.pop("deadline", time.monotonic() + 45),
                          cancel=kw.pop("cancel", lambda: False),
                          boundary=kw.pop("boundary", S.SelectionBoundary(prefix, suffix)), **kw)


def full(report, data):
    prefix, suffix = report["params"]["prefix_complete"], report["params"]["suffix_complete"]
    offset = 0 if prefix else 7
    report["params"]["max_seconds"] = 45
    report["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                        "evidence_size": offset + len(data) + (0 if suffix else 5), "offset": offset,
                        "length": len(data), "selected_sha256": hashlib.sha256(data).hexdigest(),
                        "selected_size": len(data), "complete": True}
    validate("secrets-scan", report)
    S.validate_secrets_range_accounting(report)
    return report


@pytest.mark.parametrize("prefix,suffix", tuple(itertools.product((False, True), repeat=2)))
@pytest.mark.parametrize("newline", [b"\n", b"\r", b"\r\n"])
@pytest.mark.parametrize("terminated", [False, True])
@pytest.mark.parametrize("encoded", [False, True])
def test_complete_lines_only_and_original_coordinates(monkeypatch, prefix, suffix, newline, terminated, encoded):
    parts = [b"password=FirstSynthetic", b"password=MiddleSynthetic", b"password=LastSynthetic"]
    clear = b"\xef\xbb\xbf" + newline.join(parts) + (newline if terminated else b"")
    data = bytes(v ^ 144 for v in clear) if encoded else clear
    seen, called = [], []
    original = S.credential_spans
    def spans(line, *, check):
        called.append(line)
        return original(line, check=check)
    monkeypatch.setattr(S, "credential_spans", spans)
    report = full(scan(data, prefix, suffix, seen=seen, xor_key=144 if encoded else None), data)
    kept = [i for i in range(3) if not (i == 0 and not prefix or i == 2 and not suffix and not terminated)]
    assert called == [parts[i].decode() for i in kept]
    assert seen == [parts[i].split(b"=", 1)[1] for i in kept]
    assert [h["line"] for h in report["matches"]] == [i + 1 for i in kept]
    assert [h["offset"] for h in report["matches"]] == [clear.index(parts[i]) + 9 for i in kept]
    cov = report["coverage"]
    assert cov["lines_seen"] == 3 and cov["lines_skipped"] == 3 - len(kept)
    assert cov["scanned_bytes"] + cov["unscanned_bytes"] + cov["framing_bytes"] == len(data)
    assert report["status"] == ("ok" if len(kept) == 3 else "partial")
    assert all(value.decode() not in json.dumps(report) for value in seen)


@pytest.mark.parametrize("prefix,suffix", tuple(itertools.product((False, True), repeat=2)))
@pytest.mark.parametrize("ending", [b"", b"\r", b"\n", b"\r\n"])
def test_one_line_is_skipped_once(monkeypatch, prefix, suffix, ending):
    data = b"password=OneSynthetic" + ending
    seen = []
    report = full(scan(data, prefix, suffix, seen=seen), data)
    skipped = not prefix or (not suffix and not ending)
    assert report["coverage"]["lines_seen"] == 1
    assert report["coverage"]["lines_skipped"] == int(skipped)
    assert len(seen) == int(not skipped)
    assert report["coverage"]["unscanned_ranges"] == ([{"offset": 0, "length": len(data), "reason": "selection_boundary"}] if skipped else [])


@pytest.mark.parametrize("data", [b"\xef\xbb\xbf", b"\n", b"\r", b"\r\n", b"\xef\xbb\xbf\n", b"\n\n"])
def test_no_virtual_line_and_adjacent_boundary_merging(data):
    report = full(scan(data, False, False), data)
    expected_lines = 0 if data == b"\xef\xbb\xbf" else 2 if data == b"\n\n" else 1
    assert report["coverage"]["lines_seen"] == expected_lines
    assert report["coverage"]["lines_skipped"] == min(1, expected_lines)
    if not expected_lines:
        assert report["status"] == "ok" and report["coverage"]["framing_bytes"] == 3
    adjacent = b"password=FirstSynthetic\npassword=LastSynthetic"
    r = full(scan(adjacent, False, False), adjacent)
    assert r["coverage"]["unscanned_ranges"] == [{"offset": 0, "length": len(adjacent), "reason": "selection_boundary"}]


@pytest.mark.parametrize("data,reason", [(b"\x80secret\n", "invalid_utf8"), (b"secret\xe2\x82", "invalid_utf8"),
    (b"\xff\xfep\x00", "unsupported_encoding"), (b"DHAVsecret\n", "unsupported_media"),
    (b"\x00secret\n", "unsupported_unicode"), (b"\x89PNG\r\n\x1a\n", "unsupported_media")])
@pytest.mark.parametrize("xor_key", [None, 144])
def test_whole_selection_validation_precedes_boundary(monkeypatch, data, reason, xor_key):
    if xor_key:
        data = bytes(v ^ xor_key for v in data)
    def forbidden(*a, **kw):
        pytest.fail("경계 이전의 미지원 문법에서 패턴·지문을 호출함")
    monkeypatch.setattr(S, "credential_spans", forbidden)
    report = full(scan(data, False, False, xor_key=xor_key, digest=forbidden), data)
    assert report["status"] == "unsupported"
    assert report["coverage"]["reasons"] == [reason]


def test_boundary_wins_long_line_but_limits_win_boundary():
    data = b"password=" + b"a" * 100 + b"\npassword=MiddleSynthetic\npassword=LastSynthetic"
    report = full(scan(data, False, False, limits=S.ScanLimits(max_line_bytes=32)), data)
    assert report["coverage"]["reasons"] == ["selection_boundary"]
    assert report["summary"]["hits"] == 1
    for limits, reason in ((S.ScanLimits(max_lines=1), "line_limit"), (S.ScanLimits(max_ranges=2), "range_limit")):
        r = full(scan(data, False, False, limits=limits), data)
        assert r["coverage"]["reasons"] == ["selection_boundary", reason]
        assert r["coverage"]["unscanned_ranges"][-1]["reason"] == reason
    data = b"password=FirstSynthetic\npassword=LastSynthetic"
    r = full(scan(data, True, False, limits=S.ScanLimits(max_hits=1)), data)
    assert r["coverage"]["reasons"] == ["hit_limit"]


def test_midline_hits_may_belong_to_unscanned_range():
    data = b"plain\npassword=Alpha42 psk=Beta42 token=Gamma42\nlast"
    r = full(scan(data, False, False, limits=S.ScanLimits(max_hits=2)), data)
    assert r["summary"]["hits"] == 2
    assert r["coverage"]["reasons"] == ["selection_boundary", "hit_limit"]
    assert r["coverage"]["scanned_bytes"] == 0


def test_output_limit_preserves_reason_but_may_collapse_boundary_ranges():
    data = b"password=Alpha42\n" * 100
    r = full(scan(data, False, False, limits=S.ScanLimits(max_output_bytes=4096)), data)
    assert r["coverage"]["reasons"] == ["selection_boundary", "output_limit"]
    assert r["coverage"]["unscanned_ranges"] == [{"offset": 0, "length": len(data), "reason": "output_limit"}]
    assert len(json.dumps(r, ensure_ascii=True).encode()) < 4096


def test_time_before_lines_and_after_eof(monkeypatch):
    now = time.monotonic()
    clock = [now]
    monkeypatch.setattr(S.time, "monotonic", lambda: clock[0])
    data = b"plain\nlast\n"
    r = full(scan(data, False, False, deadline=now - 1), data)
    assert r["coverage"]["reasons"] == ["time_limit"] and r["coverage"]["lines_seen"] == 0
    original = S._scanned
    def finish_line(report, start, content_end, end):
        original(report, start, content_end, end)
        clock[0] = now + 2
    monkeypatch.setattr(S, "_scanned", finish_line)
    r = full(scan(data, False, False, deadline=now + 1), data)
    assert r["coverage"]["reasons"] == ["selection_boundary", "time_limit"]
    # 마지막 줄까지 완료한 후의 시간 초과도 새로운 미검사 bytes를 만들지 않는다.
    assert r["coverage"]["unscanned_bytes"] == len(b"plain\n")
    clock[0] = now
    r = full(scan(b"last\n", True, False, deadline=now + 1), b"last\n")
    assert r["coverage"]["unscanned_bytes"] == 0 and r["status"] == "partial"


def test_cancel_remains_fatal_on_boundary_only_input():
    with pytest.raises(PwehError) as exc:
        scan(b"password=SYNTHETIC_PRIVATE", False, False, cancel=lambda: True)
    assert exc.value.code == "cancelled" and "SYNTHETIC_PRIVATE" not in str(exc.value)


@pytest.mark.parametrize("boundary", [{}, (True, False), True, 0, "SYNTHETIC_PRIVATE",
    S.SelectionBoundary(1, True), S.SelectionBoundary(True, 0), S.SelectionBoundary(None, True)])
def test_boundary_rejects_coercion(boundary):
    with pytest.raises(ValidationFailed) as exc:
        scan(b"plain", boundary=boundary)
    assert "SYNTHETIC_PRIVATE" not in str(exc.value)


def test_boundary_is_frozen_and_exact_class():
    class Derived(S.SelectionBoundary):
        pass
    with pytest.raises(ValidationFailed):
        scan(b"plain", boundary=Derived(True, True))
    with pytest.raises(FrozenInstanceError):
        S.SelectionBoundary(True, True).prefix_complete = False


def test_none_preserves_old_shape_and_empty_range_core_is_supported():
    old = scan(b"plain", boundary=None)
    assert "profile" not in old and set(old["params"]) == {"xor_key", "max_hits", "decoder"}
    assert old["limitations"] == list(S.LIMITATIONS) and "selection_boundary" not in S.REASONS
    r = scan(b"", False, False)
    assert r["status"] == "ok" and r["coverage"]["lines_seen"] == 0
