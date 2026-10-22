"""실제 파일·기기 없이 합성 bytes만 쓰는 비밀값 검사·범위·비노출 회귀."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest

from pweh import secretscan as S
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate


def scan(data, *, seen=None, **kw):
    if isinstance(data, str):
        data = data.encode()
    def digest(value):
        if seen is not None:
            seen.append(value)
        return "sha256:" + hashlib.sha256(b"PWEH SYNTHETIC SALT" + value).hexdigest()[:16]
    return S.scan_secrets(data, digest=kw.pop("digest", digest), deadline=kw.pop("deadline", time.monotonic() + 45),
                          cancel=kw.pop("cancel", lambda: False), **kw)


def full_report(report):
    out = copy.deepcopy(report)
    out["params"]["max_seconds"] = 45
    out["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                     "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
                     "selected_size": report["coverage"]["input_bytes"], "complete": True,
                     "method": "whole-file", "confidence": "high"}
    return out


def invariant(report, data):
    if isinstance(data, str):
        data = data.encode()
    cov = report["coverage"]
    assert cov["input_bytes"] == cov["read_bytes"] == len(data)
    assert cov["scanned_bytes"] + cov["framing_bytes"] + cov["unscanned_bytes"] == len(data)
    assert sum(r["length"] - r["framing_bytes"] for r in cov["scanned_ranges"]) == cov["scanned_bytes"]
    assert sum(r["length"] for r in cov["unscanned_ranges"]) == cov["unscanned_bytes"]
    all_ranges = sorted([*cov["scanned_ranges"], *cov["unscanned_ranges"]], key=lambda r: r["offset"])
    pos = 0
    if all_ranges and all_ranges[0]["offset"] == 3:
        pos = 3
    for row in all_ranges:
        assert row["offset"] == pos
        pos += row["length"]
    assert pos == len(data) or data == b"\xef\xbb\xbf"
    assert cov["lines_scanned"] + cov["lines_skipped"] <= cov["lines_seen"]
    validate("secrets-scan", full_report(report))


@pytest.mark.parametrize("text,secret,kind", [
    ("wifi_password=AlphaSecret42", b"AlphaSecret42", "password"),
    ('password="Alpha Hidden 42"', b"Alpha Hidden 42", "password"),
    ("password AlphaSecret42", b"AlphaSecret42", "password"),
    ("<password>Alpha Hidden 42</password>", b"Alpha Hidden 42", "password"),
    ("api_key: AlphaSecret42", b"AlphaSecret42", "token"),
    ("psk=ab", b"ab", "password"),
    ("Authorization: Bearer abcDEF0123456789token", b"abcDEF0123456789token", "authorization"),
    ("Bearer abcDEF0123456789token", b"abcDEF0123456789token", "token"),
    ("eyJabc.defghi.sig_01", b"eyJabc.defghi.sig_01", "token"),
    ("rtsp://SyntheticAccount:AlphaSecret42@example.invalid/live", b"AlphaSecret42", "url-password"),
])
def test_supported_rules(text, secret, kind):
    seen = []
    report = scan(text, seen=seen)
    assert report["status"] == "ok"
    assert secret in seen
    assert any(hit["kind"] == kind for hit in report["matches"])
    assert len(seen) == len(set(seen)) == 1
    assert secret.decode() not in json.dumps(report)
    invariant(report, text)


@pytest.mark.parametrize("text", ["password incorrect", "password required", "password=false", "password=********",
                                  "password=$VARIABLE", "http://example.invalid:12345/path", "<token></token>", "normal text"])
def test_placeholders_and_no_credential(text):
    report = scan(text)
    assert report["matches"] == []
    assert report["status"] == "ok"
    invariant(report, text)


@pytest.mark.parametrize("size", [65, 257, 1025, 7000])
@pytest.mark.parametrize("template", ['password="{}"', "password={}", "http://account:{}@example.invalid/", "<token>{}</token>"])
def test_complete_long_values_not_prefix(size, template):
    secret = ("abCD23" * ((size + 5) // 6))[:size]
    seen = []
    report = scan(template.format(secret), seen=seen)
    assert seen == [secret.encode()]
    assert len(report["matches"]) == 1
    assert report["matches"][0]["length"] == size
    invariant(report, template.format(secret))


@pytest.mark.parametrize("text", ['password="AlphaSecret42', "<password>AlphaSecret42", '<token>eyJabc.defghi.sig_01', 'token="eyJabc.defghi.sig_01'])
def test_open_boundaries_and_overlapping_jwt_never_digest_prefix(text):
    seen = []
    report = scan(text, seen=seen)
    assert report["matches"] and seen == []
    assert all(not h["value_complete"] and h["digest"] is None for h in report["matches"])
    invariant(report, text)


def test_escape_quoted_boundary_and_xml_wrong_close():
    text = 'password="Alpha\\"Secret42"'
    seen = []
    report = scan(text, seen=seen)
    assert seen == [b'Alpha\\"Secret42']
    assert report["matches"][0]["length"] == len(seen[0])
    report = scan("<password>AlphaSecret42</token>", seen=[])
    assert all(h["digest"] is None for h in report["matches"])


def test_original_unicode_offsets_bom_crlf_and_format_characters():
    secret = "\u200b비밀\u200bAlpha42\u200b"
    text = "\ufeff제목\r\npass\u200bword=" + secret + "\r\n끝\r"
    data = text.encode()
    seen = []
    report = scan(data, seen=seen)
    assert seen == [secret.encode()]
    hit = report["matches"][0]
    assert hit["offset"] == data.index(secret.encode())
    assert data[hit["offset"]:hit["offset"] + hit["length"]] == secret.encode()
    assert hit["line"] == 2
    assert report["coverage"]["framing_bytes"] == 8
    assert report["coverage"]["lines_scanned"] == 3
    invariant(report, data)


@pytest.mark.parametrize("data", [b"", b"\n", b"\r\n\r\n", b"\xef\xbb\xbf", b"a\nb\rc\r\nd"])
def test_empty_and_line_framing(data):
    report = scan(data)
    assert report["status"] == "ok"
    invariant(report, data)


@pytest.mark.parametrize("suffix,reason", [(b"\xff", "invalid_utf8"), (b"\x00", "unsupported_unicode"),
    (b"\x1b[0m", "unsupported_unicode"), (b"\x7f", "unsupported_unicode"), ("\u0085".encode(), "unsupported_unicode"),
    ("\ue000".encode(), "unsupported_unicode"), ("\u0378".encode(), "unsupported_unicode"), (b"\xed\xa0\x80", "invalid_utf8")])
def test_entire_text_validation_before_matching(suffix, reason):
    data = b"password=AlphaSecret42\n" + suffix
    seen = []
    report = scan(data, seen=seen)
    assert report["status"] == "unsupported" and seen == []
    assert report["coverage"]["scanned_bytes"] == report["summary"]["hits"] == 0
    assert reason in report["coverage"]["reasons"]
    invariant(report, data)


@pytest.mark.parametrize("magic", [b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF89a", b"RIFF", b"\x00\x00\x00\x18ftyp", b"OggS", b"ID3", b"fLaC", b"DHAV", b"\x1aE\xdf\xa3"])
@pytest.mark.parametrize("xor", [None, 144])
def test_media_is_not_decoded(magic, xor):
    data = magic + b"password=AlphaSecret42"
    if xor:
        data = bytes(c ^ xor for c in data)
    report = scan(data, xor_key=xor)
    assert report["status"] == "unsupported"
    assert report["coverage"]["reasons"] == ["unsupported_media"]
    assert not report["matches"]
    invariant(report, data)


def test_utf16_and_explicit_xor():
    for encoding in ("utf-16", "utf-16-be"):
        data = "password=AlphaSecret42".encode(encoding)
        if encoding.endswith("be"):
            data = b"\xfe\xff" + data
        report = scan(data)
        assert report["coverage"]["reasons"] == ["unsupported_encoding"]
    clear = b"password=AlphaSecret42\n"
    data = bytes(c ^ 144 for c in clear)
    seen = []
    report = scan(data, xor_key=144, seen=seen)
    assert seen == [b"AlphaSecret42"]
    assert report["status"] == "ok"
    invariant(report, data)
    assert scan(data)["status"] == "unsupported"


@pytest.mark.parametrize("key", [True, False, 0, 256, 144.0, "144"])
def test_no_implicit_xor(key):
    with pytest.raises(ValidationFailed):
        scan(b"password=AlphaSecret42", xor_key=key)


def test_long_line_entirely_skipped_then_next_scanned():
    data = b"password=" + b"aB" * 10000 + b"\r\npassword=AlphaSecret42\n"
    seen = []
    report = scan(data, seen=seen)
    assert seen == [b"AlphaSecret42"]
    assert report["status"] == "partial"
    assert report["coverage"]["lines_scanned"] == report["coverage"]["lines_skipped"] == 1
    assert report["coverage"]["unscanned_ranges"] == [{"offset": 0, "length": 20011, "reason": "line_too_long"}]
    invariant(report, data)


@pytest.mark.parametrize("limit,reason", [(S.ScanLimits(max_lines=2), "line_limit"), (S.ScanLimits(max_hits=2), "hit_limit"),
    (S.ScanLimits(max_line_bytes=20, max_ranges=2), "range_limit")])
def test_limits_report_honest_coverage(limit, reason):
    data = b"password=Alpha42\npassword=" + b"aB" * 20 + b"\npassword=Beta42\npassword=Gamma42"
    report = scan(data, limits=limit)
    assert report["status"] == "partial"
    assert reason in report["coverage"]["reasons"]
    assert len(report["coverage"]["scanned_ranges"]) + len(report["coverage"]["unscanned_ranges"]) <= limit.max_ranges
    invariant(report, data)


def test_midline_hit_limit_not_claimed_scanned():
    data = b"plain\npassword=Alpha42 psk=Beta42 token=Gamma42\nend"
    report = scan(data, limits=S.ScanLimits(max_hits=2))
    assert len(report["matches"]) == 2
    assert report["coverage"]["scanned_bytes"] == len(b"plain")
    assert report["coverage"]["lines_skipped"] == 1
    invariant(report, data)


def test_many_short_lines_merge_ranges():
    data = b"plain\r\n" * 100_000
    report = scan(data)
    assert report["status"] == "ok"
    assert len(report["coverage"]["scanned_ranges"]) == 1
    invariant(report, data)


def test_output_limit_does_not_claim_full_scan():
    data = b"password=Alpha42\n" * 100
    limits = S.ScanLimits(max_output_bytes=4096)
    report = scan(data, limits=limits)
    assert report["status"] == "partial"
    assert "output_limit" in report["coverage"]["reasons"]
    assert report["coverage"]["scanned_bytes"] == 0
    assert len(json.dumps(full_report(report)).encode()) <= limits.max_output_bytes
    invariant(report, data)


def test_deadline_before_and_midline(monkeypatch):
    data = b"plain\npassword=Alpha42 psk=Beta42\nend"
    clock = [1.0]
    monkeypatch.setattr(S.time, "monotonic", lambda: clock[0])
    report = scan(data, deadline=0)
    assert report["coverage"]["scanned_bytes"] == 0
    invariant(report, data)
    def digest(value):
        clock[0] = 3
        return "sha256:" + "a" * 16
    report = scan(data, deadline=2, digest=digest)
    assert report["coverage"]["scanned_bytes"] == len(b"plain")
    assert report["coverage"]["reasons"] == ["time_limit"]
    assert len(report["matches"]) == 1
    invariant(report, data)


def test_deadline_after_limit_has_no_duplicate_suffix(monkeypatch):
    original = S._unscanned
    clock = [1.0]
    monkeypatch.setattr(S.time, "monotonic", lambda: clock[0])
    def expire(report, start, end, reason):
        original(report, start, end, reason)
        clock[0] = 3
    monkeypatch.setattr(S, "_unscanned", expire)
    data = b"plain\npassword=Alpha42\nend"
    report = scan(data, deadline=2, limits=S.ScanLimits(max_lines=1))
    invariant(report, data)


def test_cancel_at_start_or_during_scan_is_not_partial():
    with pytest.raises(PwehError) as error:
        scan(b"password=Alpha42", cancel=lambda: True)
    assert error.value.code == "cancelled"
    cancelled = [False]
    def digest(value):
        cancelled[0] = True
        return "sha256:" + "a" * 16
    with pytest.raises(PwehError) as error:
        scan(b"password=Alpha42", cancel=lambda: cancelled[0], digest=digest)
    assert error.value.code == "cancelled"


@pytest.mark.parametrize("failure", [ValueError("SYNTHETIC SECRET IN EXCEPTION"), PwehError("SYNTHETIC SECRET IN EXCEPTION", code="custom")])
def test_callback_exception_never_echoed(failure):
    def digest(value):
        raise failure
    with pytest.raises(PwehError) as error:
        scan(b"password=Alpha42", digest=digest)
    assert error.value.code == "secret_digest_failed"
    assert "SYNTHETIC SECRET" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("bad", [None, "clear-secret-value", "sha256:" + "A" * 16, "sha256:" + "a" * 64])
def test_bad_digest_never_returned(bad):
    with pytest.raises(PwehError) as error:
        scan(b"password=Alpha42", digest=lambda _: bad)
    assert error.value.code == "secret_digest_failed"
    assert "clear-secret" not in str(error.value)


def test_strict_schema_forbids_names_values_and_extra_fields():
    report = full_report(scan(b"password=Alpha42"))
    for target, key in [("source", "path"), ("source", "filename"), ("source", "note"), ("params", "pattern"), ("coverage", "excerpt")]:
        changed = copy.deepcopy(report)
        changed[target][key] = "SYNTHETIC_SECRET"
        with pytest.raises(ValidationFailed):
            validate("secrets-scan", changed)
    changed = copy.deepcopy(report)
    changed["matches"][0]["key"] = "SYNTHETIC_KEY"
    with pytest.raises(ValidationFailed):
        validate("secrets-scan", changed)


def test_all_raw_fragments_absent_and_salt_changes_digest():
    text = "rtsp://SynthUser_UNIQUE:Secret_FULL_UNIQUE_42@example.invalid/private"
    report = scan(text)
    rendered = json.dumps(report)
    for secret in ("SynthUser_UNIQUE", "Secret_FULL_UNIQUE_42", "Secret_FULL", "UNIQUE_42", "example.invalid", "rtsp://"):
        assert secret not in rendered
    other = scan(text, digest=lambda value: "sha256:" + hashlib.sha256(b"OTHER SALT" + value).hexdigest()[:16])
    assert report["matches"][0]["digest"] != other["matches"][0]["digest"]
    assert report == scan(text)


@pytest.mark.parametrize("limits", [S.ScanLimits(max_hits=True), S.ScanLimits(max_bytes=4 * 1024 * 1024 + 1),
                                    S.ScanLimits(max_line_bytes=16385), S.ScanLimits(max_output_bytes=1024), S.ScanLimits(max_ranges=1)])
def test_limits_cannot_increase_or_confuse_bool(limits):
    with pytest.raises(ValidationFailed):
        scan(b"x", limits=limits)


def test_input_bound_and_four_mib_adversarial():
    with pytest.raises(ValidationFailed):
        scan(b"a" * ((4 << 20) + 1))
    data = (b"password=" + b"A" * 16375) * 256
    assert len(data) == 4 << 20
    report = scan(data)
    assert report["status"] == "partial"
    assert report["coverage"]["reasons"] == ["line_too_long"]
    invariant(report, data)


def test_different_overlapping_spans_remain_distinct_candidates():
    """겹침을 합쳐 하나의 확정 자격증명으로 만들지 않는다."""
    seen = []
    report = scan('password="Alpha Secret 42"', seen=seen)
    assert set(seen) == {b"Alpha Secret 42", b"42"}
    assert len(report["matches"]) == 2
    assert all(hit["confidence"] == "possible" for hit in report["matches"])
