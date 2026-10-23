"""고정 보호 prefix의 합성 경계·실제 read 범위·원자 게시·부모 관계 회귀."""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import time

import pytest

from pweh import media as M
from pweh.errors import PwehError, ValidationFailed
from .test_media_inventory import box, check, envelope, ftyp, run

SECRET = b"SYNTHETIC_PRIVATE_PROTECTION"
KID = b"PRIVATE_KID_1234"


def fullbox(version=0, flags=0):
    return struct.pack(">I", version << 24 | flags)


def tenc(version=0, state=1, *, flags=0, tail=b"", extended=False):
    return box(b"tenc", fullbox(version, flags) + b"PQ" + bytes([state, 16]) + KID + tail, extended=extended)


def schm(scheme=b"cenc", *, version=0, flags=0, extended=False):
    return box(b"schm", fullbox(version, flags) + scheme + b"VERS", extended=extended)


def entry(children=b"", *, kind=b"encv", version=0, extended=False):
    prefix = (SECRET * 3)[:78] if kind == b"encv" else b"R" * 8 + struct.pack(">H", version) + b"A" * 18
    return box(kind, prefix + children, extended=extended)


def stsd(entries=(), *, count=None, version=0, flags=0, extended=False):
    payload = fullbox(version, flags) + struct.pack(">I", len(entries) if count is None else count) + b"".join(entries)
    return box(b"stsd", payload, extended=extended)


def movie(table, *, extra=b"", extended=False):
    payload = table
    for name in (b"stbl", b"minf", b"mdia", b"trak"):
        payload = box(name, payload, extended=extended)
    return ftyp() + box(b"moov", extra + payload, extended=extended)


def protected(*, kind=b"encv", version=0, scheme=b"cenc", state=1, extended=False, tail=SECRET):
    children = box(b"sinf", schm(scheme, extended=extended) +
                   box(b"schi", tenc(version, state, tail=tail, extended=extended), extended=extended), extended=extended)
    return movie(stsd([entry(children, kind=kind, extended=extended)], extended=extended), extended=extended)


def section(report):
    return report["declarations"]["protection"]


def examined(report, box_index):
    leaf = report["boxes"][box_index]
    return sum(max(0, min(r["offset"] + r["length"], leaf["offset"] + leaf["size"]) -
                   max(r["offset"], leaf["offset"])) for r in report["coverage"]["ranges"] if r["kind"] == "header")


@pytest.mark.parametrize("kind", [b"encv", b"enca"])
@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("scheme", [b"cenc", b"cbcs"])
@pytest.mark.parametrize("state", [0, 1])
@pytest.mark.parametrize("extended", [False, True])
def test_complete_prefixes_keep_exact_parent_and_field_ranges(kind, version, scheme, state, extended):
    data = protected(kind=kind, version=version, scheme=scheme, state=state, extended=extended)
    report = check(run(data))
    p = section(report)
    assert p["status"] == "complete" and report["status"] == "ok"
    assert report["summary"]["max_depth_seen"] == 10
    table, item, scheme_row, default = [p[key][0] for key in ("tables", "entries", "schemes", "track_defaults")]
    assert table["entries_declared"] == table["entries_reported"] == 1 and table["entries_complete"]
    assert item["parent_index"] == table["box_index"]
    assert item["prefix_kind"] == ("visual" if kind == b"encv" else "audio-v0")
    assert scheme_row["entry_index"] == default["entry_index"] == item["box_index"]
    assert scheme_row["scheme_type"] == scheme.decode() and default["version"] == version
    assert default["default_is_protected_state"] == ("zero" if state == 0 else "one")
    header = 16 if extended else 8
    assert examined(report, scheme_row["box_index"]) == header + 8
    assert examined(report, default["box_index"]) == header + 5
    # entry의 모든 후손 header는 제외하고 prefix 자체의 실제 읽기를 확인한다.
    item_box = report["boxes"][item["box_index"]]
    prefix_end = item_box["offset"] + header + (78 if kind == b"encv" else 28)
    prefix_header = sum(max(0, min(r["offset"] + r["length"], prefix_end) - max(r["offset"], item_box["offset"]))
                        for r in report["coverage"]["ranges"] if r["kind"] == "header")
    assert prefix_header == header + (0 if kind == b"encv" else 2)
    assert report["declarations"]["sample_entries_examined"] is True
    assert not any(p[k] for k in ("full_tenc_examined", "sample_auxiliary_examined", "identifiers_returned"))
    raw = json.dumps(report)
    for secret in (SECRET, KID, b"VERS"):
        assert secret.decode() not in raw and secret.hex() not in raw and hashlib.sha256(secret).hexdigest() not in raw
    M.validate_media_protection_accounting(envelope(report))


@pytest.mark.parametrize("depth", [6, 7, 8, 9, 10])
def test_depth_limit_reports_actual_unfinished_path(depth):
    report = check(run(protected(), limits=M.MediaLimits(max_depth=depth)))
    p = section(report)
    assert report["summary"]["max_depth_seen"] == depth
    assert p["coverage"]["traversal_complete"] == (depth == 10)
    assert len(p["track_defaults"]) == int(depth == 10)
    assert p["coverage"]["reasons"] == ([] if depth == 10 else ["depth_limit"])


@pytest.mark.parametrize("kind", [b"stsd", b"encv", b"enca", b"sinf", b"schm", b"schi", b"tenc"])
@pytest.mark.parametrize("parent", [None, b"moov", b"mdat"])
def test_wrong_parent_and_opaque_payload_never_search(kind, parent):
    payload = box(kind, protected())
    data = ftyp() + (payload if parent is None else box(parent, payload))
    report = check(run(data))
    assert all(section(report)[key] == [] for key in M._PROTECTION_KEYS)
    assert report["declarations"]["sample_entries_examined"] is False


@pytest.mark.parametrize("kind", [b"sinf", b"tenc", b"stsd", b"free", b"ZZZZ", b"moov", b"pssh"])
def test_any_known_or_unknown_other_entry_stays_opaque(kind):
    report = check(run(movie(stsd([box(kind, protected())]))))
    p = section(report)
    item, = p["entries"]
    assert item["kind"] == "other" and item["prefix_kind"] == "unsupported"
    assert item["issues"] == ["unsupported_sample_entry"]
    assert report["boxes"][item["box_index"]]["kind"] == ("unknown" if kind == b"ZZZZ" else kind.decode())
    assert p["schemes"] == p["track_defaults"] == []
    assert p["tables"][0]["entries_complete"] and not p["coverage"]["fields_complete"]
    assert p["coverage"]["traversal_complete"]


@pytest.mark.parametrize("count,entries,ok", [(0, (), True), (1, (entry(),), True), (2, (entry(), entry()), True),
    (0, (entry(),), False), (1, (), False), (2, (entry(),), False), (0xffffffff, (entry(),), False)])
def test_stsd_count_is_checked_without_count_based_allocation(count, entries, ok):
    data = movie(stsd(entries, count=count))
    report = check(run(data))
    p = section(report)
    table, = p["tables"]
    assert table["entries_reported"] == min(count, len(entries))
    assert table["entries_complete"] is ok
    assert table["issues"] == ([] if ok else ["stsd_entry_count_mismatch"])
    assert len(p["entries"]) == min(count, len(entries))
    assert p["coverage"]["traversal_complete"] is ok
    if not ok and len(entries) < count:
        assert report["coverage"]["unexamined_bytes"] == 0
    if count == 0 and entries:
        assert report["coverage"]["unexamined_bytes"] == len(entries[0])


@pytest.mark.parametrize("payload,issue", [(b"x", "truncated_base_header"),
    (struct.pack(">I4s", 100, b"encv"), "box_beyond_parent"), (struct.pack(">I4s", 7, b"encv"), "size_below_header")])
def test_stsd_child_header_failure_does_not_invent_entry(payload, issue):
    report = check(run(movie(box(b"stsd", fullbox() + struct.pack(">I", 1) + payload))))
    p = section(report)
    assert p["entries"] == [] and p["tables"][0]["entries_reported"] == 0
    assert p["tables"][0]["status"] == "complete" and not p["tables"][0]["entries_complete"]
    assert p["coverage"]["fields_complete"] and p["coverage"]["reasons"] == [issue]


@pytest.mark.parametrize("kind,sizes", [(b"stsd", (0, 1, 3, 4, 7, 8)), (b"schm", (0, 1, 3, 4, 11, 12, 13)),
                                       (b"tenc", (0, 1, 3, 4, 23, 24, 40))])
def test_fullbox_lengths_do_not_borrow_fields(kind, sizes):
    for size in sizes:
        base = (fullbox() + struct.pack(">I", 0) if kind == b"stsd" else
                fullbox() + b"cencVERS" if kind == b"schm" else fullbox() + b"PQ\x01\x10" + KID)
        payload = (base + SECRET)[:size]
        leaf = box(kind, payload)
        if kind == b"stsd":
            data, key = movie(leaf), "tables"
        else:
            child = leaf if kind == b"schm" else box(b"schi", leaf)
            data, key = movie(stsd([entry(box(b"sinf", child))])), "schemes" if kind == b"schm" else "track_defaults"
        report = check(run(data))
        row, = section(report)[key]
        minimum = {b"stsd": 8, b"schm": 12, b"tenc": 24}[kind]
        if size < minimum:
            assert row["issues"] == ["truncated_declaration_fields"]
            assert examined(report, row["box_index"]) == 8 + (4 if size >= 4 else 0)
        elif kind == b"schm" and size != 12:
            assert row["issues"] == ["unsupported_protection_shape"] and row["scheme_type"] == "unread"
            assert examined(report, row["box_index"]) == 12
        else:
            assert row["status"] == "complete"


@pytest.mark.parametrize("kind,size,version,issue,prefix", [
    (b"encv", 0, 0, "truncated_declaration_fields", "unread"), (b"encv", 77, 0, "truncated_declaration_fields", "unread"),
    (b"encv", 78, 0, None, "visual"), (b"enca", 9, 0, "truncated_declaration_fields", "unread"),
    (b"enca", 10, 0, "truncated_declaration_fields", "unread"), (b"enca", 27, 0, "truncated_declaration_fields", "unread"),
    (b"enca", 28, 0, None, "audio-v0"), (b"enca", 10, 1, "unsupported_audio_entry_version", "unsupported"),
    (b"enca", 28, 2, "unsupported_audio_entry_version", "unsupported"),
    (b"enca", 28, 65535, "unsupported_audio_entry_version", "unsupported")])
def test_visual_audio_prefix_bounds(kind, size, version, issue, prefix):
    payload = (b"R" * 8 + struct.pack(">H", version) + b"A" * 68)[:size]
    report = check(run(movie(stsd([box(kind, payload)]))))
    row, = section(report)["entries"]
    assert row["prefix_kind"] == prefix and row["issues"] == ([] if issue is None else [issue])
    assert report["declarations"]["sample_entries_examined"] == (issue is None)
    assert examined(report, row["box_index"]) == 8 + (2 if kind == b"enca" and size >= 10 else 0)


@pytest.mark.parametrize("kind", [b"stsd", b"schm", b"tenc"])
@pytest.mark.parametrize("version,flags", [(2, 0), (255, 1), (0, 1), (1, 1)])
def test_fullbox_variant_issues_are_protection_only_and_atomic(kind, version, flags):
    leaf = box(kind, fullbox(version, flags) + b"A" * 100)
    if kind == b"stsd":
        data, key = movie(leaf), "tables"
    else:
        nested = leaf if kind == b"schm" else box(b"schi", leaf)
        data, key = movie(stsd([entry(box(b"sinf", nested))])), "schemes" if kind == b"schm" else "track_defaults"
    report = check(run(data))
    row, = section(report)[key]
    allowed = (0, 1) if kind == b"tenc" else (0,)
    issue = "unsupported_declaration_version" if version not in allowed else "unsupported_declaration_flags"
    assert row["issues"] == [issue, "unsupported_protection_shape"]
    assert section(report)["coverage"]["reasons"] == row["issues"]
    assert examined(report, row["box_index"]) == 12


@pytest.mark.parametrize("scheme,state", [(b"PRIV", 1), (b"cenc", 2), (b"PRIV", 255)])
def test_unknown_values_are_fixed_enums(scheme, state):
    report = check(run(protected(scheme=scheme, state=state)))
    p = section(report)
    assert p["schemes"][0]["scheme_type"] == ("cenc" if scheme == b"cenc" else "other")
    assert p["track_defaults"][0]["default_is_protected_state"] == ("one" if state == 1 else "other")
    assert "PRIV" not in json.dumps(report)
    assert p["coverage"]["traversal_complete"] and not p["coverage"]["fields_complete"]


def test_duplicate_boxes_are_rows_not_active_or_inherited_selection():
    child = box(b"sinf", schm() + schm(b"cbcs") + box(b"schi", tenc() + tenc(1, 0)))
    report = check(run(movie(stsd([entry(child), entry(child, kind=b"enca")]))))
    p = section(report)
    assert [len(p[key]) for key in M._PROTECTION_KEYS] == [1, 2, 4, 4]
    assert len({row["box_index"] for key in M._PROTECTION_KEYS for row in p[key]}) == 11
    assert p["status"] == "complete"


@pytest.mark.parametrize("kind", [b"mvhd", b"pssh"])
@pytest.mark.parametrize("payload", [b"", b"\0\0\0\0", b"\x02\0\0\0", b"\0\0\0\x01"])
def test_timing_or_pssh_issue_does_not_leak_into_empty_protection(kind, payload):
    report = check(run(ftyp() + box(b"moov", box(kind, payload))))
    assert report["declarations"]["status"] == "partial"
    assert section(report)["coverage"] == {"traversal_complete": True, "fields_complete": True, "reasons": []}
    bad = copy.deepcopy(report)
    section(bad)["coverage"]["reasons"] = list(report["declarations"]["coverage"]["reasons"])
    with pytest.raises(ValidationFailed):
        M.validate_media_protection_accounting(bad)


def test_protection_reason_order_uses_own_committed_events():
    table = stsd([entry(box(b"sinf", schm(b"PRIV") + box(b"schi", tenc(2))))], count=2)
    report = check(run(movie(table, extra=box(b"mvhd", b""))))
    assert section(report)["coverage"]["reasons"] == ["unsupported_protection_scheme",
        "unsupported_declaration_version", "unsupported_protection_shape", "stsd_entry_count_mismatch"]
    assert "truncated_declaration_fields" in report["declarations"]["coverage"]["reasons"]


@pytest.mark.parametrize("at", [1, 2, 3, 4])
def test_deadline_in_tenc_keeps_unit_and_issue_atomic(monkeypatch, at):
    data = protected(state=2)
    target = data.index(b"tenc") - 4
    original = M._Parser.check
    now = time.monotonic()
    clock, count = [now], [0]
    def checkpoint(self, offset, *, deadline=True):
        if offset == target and deadline:
            count[0] += 1
            if count[0] == at:
                clock[0] = now + 2
        return original(self, offset, deadline=deadline)
    monkeypatch.setattr(M._Parser, "check", checkpoint)
    monkeypatch.setattr(M.time, "monotonic", lambda: clock[0])
    report = check(run(data, deadline=now + 1))
    assert section(report)["track_defaults"] == []
    assert "unsupported_protection_value" not in report["coverage"]["reasons"]
    assert report["coverage"]["ranges"][-1] == {"offset": target, "length": len(data) - target,
                                                "kind": "unexamined", "reason": "time_limit"}


@pytest.mark.parametrize("at", [1, 2])
def test_entry_emit_failure_does_not_increment_table(monkeypatch, at):
    data = protected()
    target = data.index(b"encv") - 4
    now = time.monotonic()
    clock, count = [now], [0]
    original = M._Parser.check
    def checkpoint(self, offset, *, deadline=True):
        if offset == target and deadline:
            count[0] += 1
            if count[0] == at:
                clock[0] = now + 2
        return original(self, offset, deadline=deadline)
    monkeypatch.setattr(M._Parser, "check", checkpoint)
    monkeypatch.setattr(M.time, "monotonic", lambda: clock[0])
    report = check(run(data, deadline=now + 1))
    assert section(report)["tables"][0]["entries_reported"] == 0
    assert section(report)["entries"] == [] and not report["declarations"]["sample_entries_examined"]


@pytest.mark.parametrize("limit", range(1, 20))
def test_ranges_remain_disjoint_under_every_small_limit(limit):
    report = check(run(protected(state=2), limits=M.MediaLimits(max_ranges=limit)))
    assert len(report["coverage"]["ranges"]) <= limit
    assert ("unsupported_protection_value" in report["coverage"]["reasons"]) == bool(section(report)["track_defaults"])


@pytest.mark.parametrize("limit", [4096, 8192, 16384, 32768])
def test_output_cost_reserves_each_mutable_table(limit):
    # 많은 부모가 각각 최종 count 자릿수를 늘려도 global reserve만 소비하지 않는다.
    data = movie(stsd([entry()] * 12) * 80)
    report = check(run(data, limits=M.MediaLimits(max_output_bytes=limit)))
    assert "output_limit" in report["coverage"]["reasons"]
    assert len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) <= limit
    p = section(report)
    assert sum(t["entries_reported"] for t in p["tables"]) == len(p["entries"])
    for table in p["tables"]:
        if table["entries_complete"]:
            assert table["entries_declared"] == table["entries_reported"] == 12


def test_per_table_reserve_includes_late_mismatch():
    data = movie(stsd([entry()] * 11, count=12))
    parser = M._Parser(data, M.MediaLimits(), time.monotonic() + 45, None)
    report = check(parser.parse())
    assert section(report)["tables"][0]["issues"] == ["stsd_entry_count_mismatch"]
    assert parser.cost + parser.reserve >= M._size(report)


@pytest.mark.parametrize("max_boxes", [1, 6, 7, 8, 9, 10])
def test_box_budget_never_reports_unpublished_row(max_boxes):
    report = check(run(protected(), limits=M.MediaLimits(max_boxes=max_boxes)))
    assert len(report["boxes"]) <= max_boxes
    assert sum(len(section(report)[key]) for key in M._PROTECTION_KEYS) <= len(report["boxes"])


def test_cancel_at_protection_emit_is_error_without_report(monkeypatch):
    data = protected()
    target = data.index(b"tenc") - 4
    original = M._Parser.check
    cancel = [False]
    def checkpoint(self, offset, *, deadline=True):
        if offset == target:
            cancel[0] = True
        return original(self, offset, deadline=deadline)
    monkeypatch.setattr(M._Parser, "check", checkpoint)
    with pytest.raises(PwehError) as exc:
        run(data, cancel=lambda: cancel[0])
    assert exc.value.code == "cancelled"


@pytest.mark.parametrize("mutation", [
    lambda r: section(r)["tables"][0].update(entries_reported=0),
    lambda r: section(r)["tables"][0].update(entries_complete=False),
    lambda r: section(r)["tables"][0].update(entries_declared=2),
    lambda r: section(r)["entries"][0].update(parent_index=0),
    lambda r: section(r)["entries"][0].update(prefix_kind="unsupported"),
    lambda r: section(r)["entries"][0].update(kind="other"),
    lambda r: section(r)["schemes"][0].update(entry_index=0),
    lambda r: section(r)["track_defaults"][0].update(parent_index=0),
    lambda r: section(r)["track_defaults"][0].update(version=True),
    lambda r: section(r)["tables"][0].update(entries_reported=1.0),
    lambda r: section(r)["entries"].append(copy.deepcopy(section(r)["entries"][0])),
    lambda r: section(r)["entries"].clear(),
    lambda r: section(r).update(full_tenc_examined=True),
    lambda r: r["declarations"].update(sample_entries_examined=False),
    lambda r: section(r)["coverage"].update(fields_complete=False),
    lambda r: r["boxes"][section(r)["entries"][0]["box_index"]].update(offset=1),
])
def test_relation_helper_rejects_cross_array_forgeries(mutation):
    report = run(protected())
    mutation(report)
    with pytest.raises(ValidationFailed) as exc:
        M.validate_media_protection_accounting(report)
    assert exc.value.data in (None, {}) and SECRET.decode() not in str(exc.value)


def test_helper_does_not_consume_source_params_or_accept_legacy_profile():
    report = run(protected())
    report.update(source=object(), params=object())
    M.validate_media_protection_accounting(report)
    report["profile"] = "mp4-quicktime-declarations-v1"
    with pytest.raises(ValidationFailed):
        M.validate_media_protection_accounting(report)
