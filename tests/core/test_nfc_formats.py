"""실제 태그/덤프 없이 만든 v4 선언의 구조·상한·비공개 계약 회귀."""
from __future__ import annotations

import builtins
import json
import socket
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest

from pweh import nfc_formats as N
from pweh.errors import PwehError


def _hex(data: bytes) -> str:
    return data.hex(" ").upper()


def _header(uid: bytes = b"SYNTH01", device: str = "ISO14443-3A") -> list[str]:
    return ["Filetype: Flipper NFC device", "Version: 4", f"Device type: {device}",
            f"UID: {_hex(uid)}", "ATQA: 00 44", "SAK: 00"]


def _ntag(model: int = 213, *, uid: bytes = b"SYNTH01", read: int | None = None,
          pages: dict[int, bytes] | None = None, counters=(0, 0, 0)) -> bytes:
    total = {213: 45, 215: 135, 216: 231}[model]
    lines = _header(uid, "NTAG/Ultralight") + ["Data format version: 2", f"NTAG/Ultralight type: NTAG{model}",
                                             f"Signature: {_hex(bytes(32))}",
                                             f"Mifare version: {_hex(bytes(8))}"]
    for index in range(3):
        lines += [f"Counter {index}: {counters[index]}", f"Tearing {index}: 00"]
    lines += [f"Pages total: {total}", f"Pages read: {total if read is None else read}"]
    lines += [f"Page {index}: {_hex((pages or {}).get(index, bytes(4)))}" for index in range(total)]
    return ("\n".join(lines) + "\n").encode()


def _inspect(data: bytes, **kw) -> dict:
    return N.inspect_nfc(data, deadline=time.monotonic() + 5, **kw)


def _diff(one: bytes, two: bytes, **kw) -> dict:
    return N.diff_nfc(one, two, deadline=time.monotonic() + 5, **kw)


def _reason(result: dict, reason: str) -> None:
    assert reason in result["coverage"]["truncated_reasons"]


def _closed(result: dict) -> None:
    assert set(result) == {"schema_version", "operation", "status", "profile", "summary", "coverage", "limitations"}
    assert result["coverage"]["consumed_bytes"] + result["coverage"]["unexamined_bytes"] == result["coverage"]["input_bytes"]
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    assert len(encoded) <= 64 << 10


@pytest.mark.parametrize("uid", [bytes(4), b"SYNTH01", bytes(10)])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_header_profile_and_line_forms(uid, ending):
    raw = ending.join(line.encode() for line in _header(uid))
    for prefix in (b"", b"\xef\xbb\xbf"):
        for suffix in (b"", ending):
            result = _inspect(prefix + raw + suffix)
            assert result["status"] == "ok"
            assert result["profile"] == "iso14443-3a"
            assert result["summary"]["uid_length"] == len(uid)
            assert result["coverage"]["read_mapping"] == "not_applicable"
            _closed(result)
    result = _diff(raw, raw)
    assert result["status"] == "unsupported"
    assert result["summary"]["pages_compared"] == 0
    assert result["summary"]["stored_pages_equal"] is None
    _reason(result, "no_page_layout")


@pytest.mark.parametrize("model,total", [(213, 45), (215, 135), (216, 231)])
def test_complete_declared_profiles(model, total):
    raw = _ntag(model)
    one = _inspect(raw)
    assert one["status"] == "ok"
    assert one["summary"]["full_declared_pages"] is True
    assert one["summary"]["stored_valid_pages"] == total
    assert one["coverage"]["read_mapping"] == "all_declared"
    assert one["coverage"]["missing_pages_count"] == 0
    both = _diff(raw, raw)
    assert both["status"] == "ok"
    assert both["summary"]["pages_compared"] == total
    assert both["summary"]["stored_pages_equal"] is True
    assert both["summary"]["changed_pages_count"] == 0
    assert both["summary"]["counter_fields_changed"] is False
    assert both["summary"]["device_association_verified"] is False
    assert both["coverage"]["comparison_complete"] is True
    assert both["coverage"]["changes_complete"] is True
    _closed(one)
    _closed(both)


@pytest.mark.parametrize("read", [0, 1, 44])
def test_all_zero_stored_pages_do_not_identify_read_pages(read):
    raw = _ntag(read=read)
    result = _inspect(raw)
    assert result["status"] == "partial"
    assert result["summary"]["stored_valid_pages"] == 45
    assert result["summary"]["full_declared_pages"] is False
    assert result["coverage"]["input_exhausted"] is True
    assert result["coverage"]["missing_pages_count"] == 0
    assert result["coverage"]["read_mapping"] == "unknown"
    _reason(result, "partial_read_mapping_unknown")
    both = _diff(raw, raw)
    assert both["summary"]["pages_compared"] == 0
    assert both["summary"]["stored_pages_equal"] is None
    assert both["summary"]["changed_pages_count"] is None
    assert both["summary"]["counter_fields_changed"] is None


@pytest.mark.parametrize("old,new,reason", [
    (b"Page 5: 00 00 00 00\n", b"", "missing_pages"),
    (b"Page 5: 00 00 00 00", b"Page 5: 00 00 00", "invalid_hex_length"),
    (b"Page 5: 00 00 00 00", b"Page 5: 00 00 00 00 00", "invalid_hex_length"),
    (b"Page 5: 00 00 00 00", b"Page 5: 0G 00 00 00", "invalid_hex"),
    (b"Page 5:", b"Page 45:", "page_out_of_range"),
    (b"Page 5:", b"Page 512:", "number_out_of_range"),
    (b"Page 5:", b"Page -1:", "invalid_decimal"),
    (b"Pages read: 45", b"Pages read: 46", "read_out_of_range"),
    (b"Pages total: 45", b"Pages total: 46", "claimed_total_mismatch"),
    (b"Counter 0: 0", b"Counter 0: 4294967296", "number_out_of_range"),
    (b"Counter 0: 0", b"Counter 0: +0", "invalid_decimal"),
    (b"Counter 0: 0", b"Counter 0: 00000000000", "invalid_decimal"),
    (b"Counter 0: 0", b"Counter 3: 0", "invalid_field_index"),
    (b"Counter 0: 0\n", b"", "missing_required_fields"),
    (b"Tearing 0: 00", b"Tearing 0: 00 00", "invalid_hex_length"),
    (b"UID: 53 59 4E 54 48 30 31", b"UID: 00 00 00", "invalid_hex_length"),
])
def test_observed_malformed_is_distinct_from_partial(old, new, reason):
    raw = _ntag().replace(old, new)
    result = _inspect(raw)
    assert result["status"] == "malformed"
    assert result["summary"]["full_declared_pages"] is False
    _reason(result, reason)
    both = _diff(raw, _ntag())
    assert both["status"] == "malformed"
    assert both["summary"]["pages_compared"] == 0
    assert both["summary"]["same_uid_claim"] is None
    _closed(result)


@pytest.mark.parametrize("suffix,reason", [
    (b"Page 5: 00 00 00 00\n", "duplicate_page"),
    (b"Page 005: 00 00 00 00\n", "duplicate_page"),
    (b"UID: 53 59 4E 54 48 30 31\n", "duplicate_field"),
    (b"Version: 4\n", "duplicate_field"),
    (b"Page 2", "invalid_field"),
    (b"Page 2: F", "duplicate_page"),
    (b"\xff", "invalid_utf8"),
    (b"# secret\x00", "invalid_control"),
    (b"# secret\rnext", "invalid_control"),
    (b"# \xef\xbb\xbf", "invalid_control"),
    (b"\xef\xbb\xbfFiletype: Flipper NFC device", "invalid_control"),
])
def test_no_skip_over_malformed_or_duplicate(suffix, reason):
    result = _inspect(_ntag() + suffix + b"\n# ignored suffix\n")
    assert result["status"] == "malformed"
    _reason(result, reason)
    assert result["coverage"]["unexamined_bytes"] > 0
    assert result["coverage"]["missing_pages_count"] is None


@pytest.mark.parametrize("old,new,reason", [
    (b"Version: 4", b"Version: 3", "unsupported_version"),
    (b"Version: 4", b"Version: 2", "unsupported_version"),
    (b"Device type: NTAG/Ultralight", b"Device type: Mifare Classic", "unsupported_family"),
    (b"Device type: NTAG/Ultralight", b"Device type: ISO14443-4A", "unsupported_family"),
    (b"Data format version: 2", b"Data format version: 1", "unsupported_data_version"),
    (b"NTAG213", b"NTAG203", "unsupported_layout"),
    (b"Filetype: Flipper NFC device", b"Filetype: Other", "unsupported_filetype"),
])
def test_explicit_unsupported_claims_only(old, new, reason):
    result = _inspect(_ntag().replace(old, new))
    assert result["status"] == "unsupported"
    _reason(result, reason)
    assert result["summary"]["full_declared_pages"] is False


def test_unknown_keys_are_counted_without_echo_and_optional_attempts():
    raw = _ntag()
    optional = raw + b"Failed authentication attempts: 4294967295\n"
    assert _inspect(optional)["status"] == "ok"
    extra = _inspect(raw + b"PRIVATE_KEY_SENTINEL: PRIVATE_VALUE_SENTINEL\n")
    assert extra["status"] == "partial"
    assert extra["coverage"]["unknown_fields_count"] == 1
    assert "SENTINEL" not in json.dumps(extra)
    _reason(extra, "unknown_field")


@pytest.mark.parametrize("uid", [bytes(4), bytes(10)])
def test_generic_uid_length_does_not_confirm_ntag_layout(uid):
    result = _inspect(_ntag(uid=uid))
    assert result["status"] == "partial"
    _reason(result, "claimed_uid_length_mismatch")
    assert result["summary"]["full_declared_pages"] is False


def test_uid_claim_and_layout_are_independent():
    result = _diff(_ntag(), _ntag(uid=b"SYNTH02", pages={4: b"DIFF"}))
    assert result["status"] == "ok"
    assert result["summary"]["same_uid_claim"] is False
    assert result["summary"]["device_association_verified"] is False
    mismatch = _diff(_ntag(), _ntag(215))
    assert mismatch["status"] == "unsupported"
    assert mismatch["summary"]["pages_compared"] == 0
    _reason(mismatch, "layout_mismatch")


@pytest.mark.parametrize("model,total", [(213, 45), (215, 135), (216, 231)])
def test_changed_regions_do_not_claim_lock_from_reserved_byte(model, total):
    pages = {0: b"\1\0\0\0", 2: b"\1\0\0\0", 3: b"\1\0\0\0", 4: b"\1\0\0\0",
             total - 5: b"\0\0\0\1", total - 4: b"\1\0\0\0", total - 3: b"\1\0\0\0",
             total - 2: b"PWDS", total - 1: b"PA\0\0"}
    result = _diff(_ntag(model), _ntag(model, pages=pages))
    changes = {item["page"]: item["regions"] for item in result["summary"]["changes"]}
    assert changes[0] == changes[2] == ["manufacturer"]
    assert changes[3] == ["capability_container"]
    assert changes[4] == ["user_data"]
    assert changes[total - 5] == ["reserved"]
    assert changes[total - 4] == changes[total - 3] == ["configuration"]
    assert changes[total - 2] == changes[total - 1] == ["credential_storage"]
    locks = _diff(_ntag(model), _ntag(model, pages={2: b"\0\0\1\0", total - 5: b"\1\0\0\0",
                                                 total - 1: b"\0\0\1\0"}))
    assert [item["regions"] for item in locks["summary"]["changes"]] == [["static_lock"], ["dynamic_lock"], ["reserved"]]
    assert result["summary"]["changed_pages_count"] == len(pages)


def test_counter_changes_are_boolean_without_delta():
    result = _diff(_ntag(counters=(0xffffffff, 7, 1)), _ntag(counters=(2, 7, 1)))
    assert result["summary"]["counter_fields_changed"] is True
    assert result["summary"]["stored_pages_equal"] is True
    assert "4294967295" not in json.dumps(result)
    incomplete = _diff(_ntag(read=2), _ntag(counters=(2, 7, 1)))
    assert incomplete["summary"]["counter_fields_changed"] is None


@pytest.mark.parametrize("field,value,reason", [
    ("max_input_bytes", 64, "input_limit"), ("max_lines", 10, "line_limit"),
    ("max_line_bytes", 10, "line_bytes_limit"), ("max_pages", 10, "page_limit"),
])
def test_inspection_limits_leave_missing_unknown(field, value, reason):
    result = _inspect(_ntag(), limits=replace(N.NfcLimits(), **{field: value}))
    assert result["status"] == "partial"
    assert result["summary"]["full_declared_pages"] is False
    assert result["coverage"]["input_exhausted"] is False
    assert result["coverage"]["missing_pages_count"] is None
    _reason(result, reason)
    _closed(result)


def test_exact_caps_and_crlf_boundary():
    raw = _ntag()
    result = _inspect(raw, limits=N.NfcLimits(max_input_bytes=len(raw), max_lines=raw.count(b"\n"), max_pages=45))
    assert result["status"] == "ok"
    for size in (4096, 8192):
        result = _inspect(b"#" + b" " * (size - 1) + b"\r\n" + raw)
        assert result["status"] == "ok"
        result = _inspect(b"#" + b" " * size + b"\r\n" + raw, limits=N.NfcLimits(max_line_bytes=size))
        assert result["status"] == "partial"
        _reason(result, "line_bytes_limit")


def test_change_limit_preserves_exact_total_and_output_cap():
    changed = _ntag(216, pages={page: b"CHNG" for page in range(231)})
    result = _diff(_ntag(216), changed, limits=N.NfcLimits(max_changes=3))
    assert result["status"] == "partial"
    assert result["summary"]["changed_pages_count"] == 231
    assert result["summary"]["pages_compared"] == 231
    assert result["summary"]["changes_returned"] == 3
    assert result["summary"]["changes_omitted"] == 228
    assert result["summary"]["stored_pages_equal"] is False
    assert result["coverage"]["comparison_complete"] is True
    assert result["coverage"]["changed_pages_count_is_lower_bound"] is False
    assert result["coverage"]["changes_complete"] is False
    _reason(result, "change_limit")
    result = _diff(_ntag(216), changed, limits=N.NfcLimits(max_output_bytes=4096))
    assert result["summary"]["changed_pages_count"] == 231
    assert result["summary"]["changes_returned"] < 231
    assert result["summary"]["changes_omitted"] == 231 - result["summary"]["changes_returned"]
    _reason(result, "output_limit")
    assert len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) <= 4096


@pytest.mark.parametrize("deadline", [True, None, "5", float("nan"), float("inf"), -float("inf"), 10**400])
def test_bad_deadline_has_fixed_error(deadline):
    with pytest.raises(PwehError) as caught:
        N.inspect_nfc(b"", deadline=deadline)
    assert caught.value.code == "invalid_deadline"
    assert caught.value.__context__ is None


@pytest.mark.parametrize("kwargs", [{"max_lines": True}, {"max_pages": 513}, {"max_changes": 0},
                                   {"max_input_bytes": -1}, {"max_line_bytes": 1.1}, {"max_output_bytes": 4095}])
def test_invalid_limits(kwargs):
    with pytest.raises(PwehError) as caught:
        _inspect(_ntag(), limits=replace(N.NfcLimits(), **kwargs))
    assert caught.value.code == "invalid_limits"


@pytest.mark.parametrize("raw", [bytearray(b"secret"), memoryview(b"secret"), "secret", None])
def test_input_is_immutable_bytes_only(raw):
    with pytest.raises(PwehError) as caught:
        _inspect(raw)
    assert caught.value.code == "invalid_input"
    assert "secret" not in str(caught.value)


def test_callback_failures_cancel_and_no_secret_exception_chain():
    def explode():
        raise RuntimeError("CALLBACK_SECRET_SENTINEL")
    class Untrusted:
        def __bool__(self):
            pytest.fail("사용자 반환 객체를 bool로 실행했다")
    for callback in (explode, lambda: 1, lambda: Untrusted(), 1):
        with pytest.raises(PwehError) as caught:
            _inspect(_ntag(), cancel=callback)
        assert caught.value.code == "callback_error"
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert "SENTINEL" not in repr(caught.value.to_dict())
    with pytest.raises(PwehError) as caught:
        _diff(_ntag(), _ntag(), cancel=lambda: True)
    assert caught.value.code == "cancelled"
    def interrupt():
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        _inspect(_ntag(), cancel=interrupt)


def test_initial_expired_and_shared_deadline(monkeypatch):
    monkeypatch.setattr(N, "_clock", lambda: 10.0)
    result = N.diff_nfc(_ntag(), _ntag(), deadline=9.0)
    assert result["status"] == "partial"
    assert result["coverage"]["consumed_bytes"] == 0
    assert result["summary"]["pages_compared"] == 0
    _reason(result, "time_limit")
    now = [0.0]
    finish = N._Parsed.finish
    def expire_after_first_input(parsed):
        finish(parsed)
        now[0] = 1.0
    monkeypatch.setattr(N, "_clock", lambda: now[0])
    monkeypatch.setattr(N._Parsed, "finish", expire_after_first_input)
    result = N.diff_nfc(_ntag(), _ntag(), deadline=1.0)
    assert result["summary"]["before"]["coverage"]["input_exhausted"] is True
    assert result["summary"]["after"]["coverage"]["consumed_bytes"] == 0
    assert result["status"] == "partial"


def test_comparison_deadline_reports_lower_bound(monkeypatch):
    now = [0.0]
    region = N._region
    def expire_on_first_change(page, byte, total):
        now[0] = 1.0
        return region(page, byte, total)
    monkeypatch.setattr(N, "_clock", lambda: now[0])
    monkeypatch.setattr(N, "_region", expire_on_first_change)
    result = N.diff_nfc(_ntag(), _ntag(pages={0: b"CHNG", 1: b"CHNG"}), deadline=1.0)
    assert result["summary"]["pages_compared"] == 1
    assert result["summary"]["changed_pages_count"] == 1
    assert result["summary"]["stored_pages_equal"] is None
    assert result["coverage"]["comparison_complete"] is False
    assert result["coverage"]["changed_pages_count_is_lower_bound"] is True
    assert result["status"] == "partial"


def test_output_obeys_same_deadline(monkeypatch):
    now = [0.0]
    size = N._size
    def expire_on_size(value):
        now[0] = 1.0
        return size(value)
    monkeypatch.setattr(N, "_clock", lambda: now[0])
    monkeypatch.setattr(N, "_size", expire_on_size)
    result = N.diff_nfc(_ntag(), _ntag(pages={1: b"CHNG"}), deadline=1.0)
    assert result["status"] == "partial"
    assert result["coverage"]["comparison_complete"] is True
    assert result["summary"]["changed_pages_count"] == 1
    assert result["summary"]["changes"] == []
    assert result["coverage"]["changes_complete"] is False
    _reason(result, "time_limit")


def test_secret_sentinels_never_escape_and_core_does_no_io(monkeypatch):
    raw = _ntag(uid=b"SECRET!", pages={43: b"PWD!", 44: b"PACK"}, counters=(3735928559, 0, 0))
    raw = raw.replace(_hex(bytes(32)).encode(), _hex(b"SECRET_SIGNATURE" * 2).encode(), 1)
    def forbidden(*args, **kwargs):
        pytest.fail("순수 NFC 코어가 I/O를 호출했다")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    results = [_inspect(raw), _diff(_ntag(), raw)]
    for result in results:
        text = json.dumps(result)
        for secret in ("SECRET!", "SECRET_SIGNATURE", "PWD!", "PACK", "3735928559",
                       _hex(b"SECRET!"), _hex(b"PWD!"), _hex(b"PACK")):
            assert secret not in text
        _closed(result)
    parsed = N._parse(raw, N.NfcLimits(), N._Control(time.monotonic() + 5, None))
    assert "SECRET" not in repr(parsed)


def test_hard_time_cap_and_prefix_uid_not_promoted(monkeypatch):
    now = [0.0]
    finish = N._Parsed.finish
    def finish_after_cap(parsed):
        finish(parsed)
        now[0] = 6.0
    monkeypatch.setattr(N, "_clock", lambda: now[0])
    monkeypatch.setattr(N._Parsed, "finish", finish_after_cap)
    result = N.diff_nfc(_ntag(), _ntag(), deadline=1e30)
    assert result["status"] == "partial"
    assert result["summary"]["after"]["coverage"]["consumed_bytes"] == 0
    assert result["summary"]["same_uid_claim"] is None
    _reason(result, "time_limit")


def test_prefix_uid_declaration_cannot_hide_unexamined_duplicate():
    raw = _ntag()
    result = _diff(raw, raw + b"UID: 53 59 4E 54 48 30 31\n",
                   limits=N.NfcLimits(max_lines=raw.count(b"\n")))
    assert result["summary"]["before"]["coverage"]["input_exhausted"] is True
    assert result["summary"]["after"]["coverage"]["input_exhausted"] is False
    assert result["summary"]["same_uid_claim"] is None
    assert result["status"] == "partial"


def test_known_header_only_cannot_hide_page_fields():
    result = _inspect(("\n".join(_header()) + "\nPage 0: 00 00 00 00\n").encode())
    assert result["status"] == "malformed"
    _reason(result, "unexpected_page_fields")
