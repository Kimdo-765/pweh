"""FIT 구조 metadata의 범위·부분 결과·출력 경계. 입력은 합성 bytes뿐이다."""

from __future__ import annotations

import json
import mmap
import random
import struct
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers/fwtriage-mcp"))
from fwtriage_mcp import fit_security as F
from fwtriage_mcp.common import Cancelled, Ctl
from pweh.errors import ValidationFailed


def fdt(children=(), props=None, *, version=17):
    """중복/외부 도구 없이 작은 v17 구조를 직접 만든다."""
    strings, offsets = bytearray(), {}

    def node(name, properties, kids):
        out = bytearray(struct.pack(">I", 1) + name.encode("latin1") + b"\0")
        out += b"\0" * (-len(out) % 4)
        for key, value in properties.items():
            if key not in offsets:
                offsets[key] = len(strings)
                strings.extend(key.encode("latin1") + b"\0")
            if isinstance(value, str):
                value = value.encode("latin1") + b"\0"
            out += struct.pack(">III", 3, len(value), offsets[key]) + value
            out += b"\0" * (-len(out) % 4)
        for child in kids:
            out += node(*child)
        return bytes(out) + struct.pack(">I", 2)

    body = node("", props or {}, children) + struct.pack(">I", 9)
    header = struct.pack(">10I", 0xD00DFEED, 56 + len(body) + len(strings),
                         56, 56 + len(body), 40, version, 16, 0, len(strings), len(body))
    return header + bytes(16) + body + bytes(strings)


def fit(n=1, *, signature_props=None, extra=()):
    sp = {"algo": "sha256,rsa2048", "value": b"x" * 256, "key-name-hint": "PRIVATE_HINT"}
    if signature_props is not None:
        sp = signature_props
    return fdt([
        ("images", {}, [("kernel", {"data": b"PAYLOAD"}, [
            (f"signature-{i}", sp, []) for i in range(n)
        ])]),
        ("configurations", {}, [("conf", {"kernel": "kernel"}, [])]),
        *extra,
    ])


def scan(data, **kwargs):
    return F.scan_fit_security(data, len(data), ctl=kwargs.pop("ctl", Ctl()),
                               max_scan_bytes=kwargs.pop("max_scan_bytes", len(data)), **kwargs)


def encoded(report):
    return json.dumps(report, ensure_ascii=False, indent=2).encode() + b"\n"


def test_closed_three_scopes_and_source_offsets():
    blob = fit(extra=[
        ("signature", {"required-mode": "all"}, [("SECRET_KEY", {
            "algo": "sha384,ecdsa256", "required": "conf", "ecdsa,x-point": b"SECRET_KEY_MATERIAL",
        }, [])]),
    ])
    # 설정의 서명은 별도 fixture에서 기존 config와 중복시키지 않는다.
    config = fdt([("configurations", {}, [("SECRET_CONF", {}, [
        ("signature-arbitrary", {"algo": "sha512,rsa4096", "value": b"SECRET_SIG",
                                 "sign-images": "kernel\0fdt", "hashed-nodes": "/\0/images",
                                 "hashed-strings": struct.pack(">II", 0, 0)}, []),
    ])])])
    report = scan(b"abc" + blob + config)
    assert report["status"] == "complete"
    assert [b["offset"] for b in report["blobs"]] == [3, 3 + len(blob)]
    assert report["summary"] == {"blobs_reported": 2, "entries_reported": 3,
        "image_signatures_observed": 1, "configuration_signatures_observed": 1, "control_keys_observed": 1}
    a, b = report["blobs"]
    assert a["signature_presence"] == a["control_key_presence"] == "present"
    assert a["required_mode"] == "all"
    assert a["entries"][1]["required"] == "conf" and a["entries"][1]["key_material_present"]
    e = b["entries"][0]
    assert e["scope"] == "configuration-signature"
    assert e["sign_images_count"] == e["hashed_nodes_count"] == 2
    assert e["hashed_strings_range_valid"] is True
    assert e["node_offset"] > b["offset"]
    for key in ("cryptographic_verification_performed", "key_trust_verified", "boot_enforcement_verified", "sd_route_link_verified"):
        assert report[key] is False
    assert b"SECRET" not in encoded(report) and b"PRIVATE_HINT" not in encoded(report) and b"PAYLOAD" not in encoded(report)


@pytest.mark.parametrize("data", [b"", b"\x00", b"abc", b"key-name-hint signature value"])
def test_empty_and_non_fdt_complete(data):
    report = scan(data)
    assert report["status"] == "complete" and report["blobs"] == []
    assert report["coverage"]["positions_examined_end"] == max(0, len(data) - 3)
    assert report["coverage"]["search_complete"] is True


def test_not_examined_is_fresh_and_not_empty_input():
    a, b = F.not_examined_fit_security(), F.not_examined_fit_security()
    a["coverage"]["reasons"].append("test")
    assert b["coverage"]["reasons"] == [] and b["coverage"]["input_bytes"] is None
    assert b["status"] == "not-examined" and scan(b"")["status"] == "complete"


def test_no_signatures_and_wrong_hierarchy():
    data = fdt([("images", {}, [("kernel", {}, [("hash-1", {"algo": "sha256"}, [])])]),
                ("arbitrary", {}, [("signature-1", {"key-name-hint": "SECRET"}, [])])])
    row = scan(data)["blobs"][0]
    assert row["signature_presence"] == row["control_key_presence"] == "absent"
    assert row["entries"] == [] and row["format"] == "fit"


@pytest.mark.parametrize("properties,digest,scheme,issue", [
    ({}, "absent", "absent", "missing_value"),
    ({"algo": b"sha256,rsa2048"}, "malformed", "malformed", "invalid_string"),
    ({"algo": b"sha256\0,rsa2048\0"}, "malformed", "malformed", "invalid_string"),
    ({"algo": "SECRET_ALGORITHM"}, "other", "other", "unsupported_declaration"),
    ({"algo": "sha1,rsa3072"}, "sha1", "rsa3072", "missing_value"),
    ({"algo": "sha256,SECRET"}, "sha256", "other", "unsupported_declaration"),
])
def test_algorithm_declarations_only(properties, digest, scheme, issue):
    report = scan(fit(signature_props=properties))
    e = report["blobs"][0]["entries"][0]
    assert (e["digest"], e["signature_scheme"]) == (digest, scheme)
    assert issue in e["field_issues"] and b"SECRET" not in encoded(report)


@pytest.mark.parametrize("value,expected", [(b"\0", None), (b"a", None), (b"a\0\0", None), (b"a\0b\0", 2)])
def test_list_shape(value, expected):
    report = scan(fit(signature_props={"hashed-nodes": value}))
    assert report["blobs"][0]["entries"][0]["hashed_nodes_count"] == expected


@pytest.mark.parametrize("key,value", [
    ("algo", "s" * 129), ("required", "s" * 129), ("hashed-nodes", b"a\0" * 101),
    ("sign-images", b"a" * 8192 + b"\0"),
])
def test_field_limit_never_claims_full_declaration(key, value):
    report = scan(fit(signature_props={key: value}))
    assert report["status"] == "partial" and "field_limit" in report["coverage"]["reasons"]
    assert report["coverage"]["structures_complete"] and report["coverage"]["search_complete"]


@pytest.mark.parametrize("value,expected,issue", [
    (struct.pack(">II", 0, 0), True, None),
    (struct.pack(">II", 0xFFFFFFFF, 2), False, "range_out_of_bounds"),
    (b"\0" * 4, None, "invalid_integer"),
])
def test_hashed_strings_declared_bounds(value, expected, issue):
    e = scan(fit(signature_props={"hashed-strings": value}))["blobs"][0]["entries"][0]
    assert e["hashed_strings_range_valid"] is expected
    if issue:
        assert issue in e["field_issues"]


def test_scan_cap_is_not_original_malformed():
    data = b".." + fit()
    report = scan(data, max_scan_bytes=len(data) - 1)
    c, row = report["coverage"], report["blobs"][0]
    assert c["reasons"] == ["scan_limit"]
    assert c["positions_examined_end"] == c["pending_offset"] == 2
    assert row["structure_status"] == "limited" and row["signature_presence"] == "unknown"
    truncated = scan(data[:-1])
    assert truncated["blobs"][0]["structure_status"] == "malformed"
    assert "malformed_fdt" in truncated["coverage"]["reasons"]


@pytest.mark.parametrize("prefix", [0, 1, 13, 14, 15, 16, 17, 31, 32, 33])
def test_chunk_boundary_magic_once(prefix):
    report = scan(b"x" * prefix + fit(), limits=replace(F.FitStructureLimits(), chunk_bytes=16))
    assert report["status"] == "complete" and report["coverage"]["candidates_examined"] == 1
    assert [r["offset"] for r in report["blobs"]] == [prefix]


@pytest.mark.parametrize("cap,reason", [("max_candidates", "candidate_limit"), ("max_blobs", "blob_limit")])
def test_next_anchor_limit_keeps_exact_prefix(cap, reason):
    first, second = fit(), fdt()
    offset = len(first) + 7
    report = scan(first + b"x" * 7 + second, limits=replace(F.FitStructureLimits(), **{cap: 1}))
    c = report["coverage"]
    assert c["candidates_examined"] == 1 and c["pending_offset"] == offset == c["positions_examined_end"]
    assert reason in c["reasons"] and not c["search_complete"]


def test_entry_limit_preserves_observed_counts_and_search_completion():
    report = scan(fit(3) + fit(2), limits=replace(F.FitStructureLimits(), max_entries=2))
    assert report["summary"]["image_signatures_observed"] == 5
    assert report["summary"]["entries_reported"] == 2
    assert report["coverage"]["search_complete"] and report["coverage"]["structures_complete"]
    assert not report["coverage"]["output_complete"] and report["status"] == "partial"
    assert all(r["signature_presence"] == "present" and not r["entries_complete"] for r in report["blobs"])


@pytest.mark.parametrize("field,value,reason", [
    ("max_nodes", 1, "node_limit"), ("max_depth", 1, "depth_limit"),
    ("max_properties", 1, "property_limit"), ("max_tokens", 1, "token_limit"),
    ("max_total_tokens", 1, "token_limit"), ("max_owned_bytes", 1, "owned_bytes_limit"),
    ("max_blob_bytes", 40, "field_limit"), ("max_strings_bytes", 1, "field_limit"),
])
def test_parser_limits_surface_without_absence(field, value, reason):
    report = scan(fit(), limits=replace(F.FitStructureLimits(), **{field: value}))
    row, c = report["blobs"][0], report["coverage"]
    assert row["signature_presence"] == "unknown" and row["image_nodes"] is None
    assert c["pending_offset"] == 0 and c["positions_examined_end"] == 0
    assert reason in c["reasons"] and not c["structures_complete"]


def test_shared_budget_not_reset_for_second_blob():
    blob = fdt()
    report = scan(blob + blob, limits=replace(F.FitStructureLimits(), max_total_tokens=4))
    assert report["blobs"][0]["structure_status"] == "complete"
    assert report["blobs"][1]["structure_status"] == "limited"
    assert report["coverage"]["pending_offset"] == len(blob)


@pytest.mark.parametrize("size", [2048, 4096, 65536])
def test_output_envelope_and_atomic_row_bound(size):
    report = scan(fit(128) + fdt(), limits=replace(F.FitStructureLimits(), max_output_bytes=size))
    assert len(encoded(report)) <= size
    assert report["summary"]["entries_reported"] == sum(len(r["entries"]) for r in report["blobs"])
    assert report["summary"]["blobs_reported"] == len(report["blobs"])
    assert "output_limit" in report["coverage"]["reasons"] and report["status"] == "partial"


def test_v16_is_unsupported_not_unsigned():
    report = scan(fdt(version=16))
    row = report["blobs"][0]
    assert row["structure_status"] == "unsupported" and row["signature_presence"] == "unknown"
    assert report["coverage"]["search_complete"] and report["status"] == "partial"


def test_large_values_are_not_read_for_projection(monkeypatch):
    data = fit(signature_props={"value": b"SECRET" * 10000})
    original = F._read_value
    seen = []
    def guarded(value, *args):
        seen.append(F._length(value))
        assert (F._length(value) or 0) <= 8192
        return original(value, *args)
    monkeypatch.setattr(F, "_read_value", guarded)
    report = scan(data)
    assert report["blobs"][0]["entries"][0]["value_bytes"] == 60000
    assert b"SECRET" not in encoded(report)


def test_deadline_and_cancellation_before_and_during_parser(monkeypatch):
    expired = Ctl()
    expired.deadline = -1
    report = scan(fit(), ctl=expired)
    assert report["coverage"]["reasons"] == ["time_limit"] and report["blobs"] == []
    event = threading.Event()
    event.set()
    with pytest.raises(Cancelled):
        scan(fit(), ctl=Ctl(event))
    event.clear()
    original = F.parse_fdt_tree
    def cancel(*args, **kwargs):
        event.set()
        return original(*args, **kwargs)
    monkeypatch.setattr(F, "parse_fdt_tree", cancel)
    with pytest.raises(Cancelled):
        scan(fit(), ctl=Ctl(event))


def test_deadline_during_projection_preserves_unknown_absence(monkeypatch):
    ctl = Ctl()
    original = F.parse_fdt_tree
    def expired_after_tree(*args, **kwargs):
        tree = original(*args, **kwargs)
        ctl.deadline = -1
        return tree
    monkeypatch.setattr(F, "parse_fdt_tree", expired_after_tree)
    report = scan(fit(), ctl=ctl)
    row = report["blobs"][0]
    assert row["signature_presence"] == "unknown" and not row["entries_complete"]
    assert report["coverage"]["pending_offset"] == 0 and "time_limit" in report["coverage"]["reasons"]


def test_small_random_header_positions_invariants():
    rng = random.Random(1931)
    for _ in range(30):
        prefix = b"z" * rng.randrange(40)
        data = prefix + (fit() if rng.randrange(2) else fdt()) + b"y" * rng.randrange(10)
        report = scan(data, limits=replace(F.FitStructureLimits(), chunk_bytes=rng.randrange(1, 20)))
        assert report["coverage"]["search_complete"]
        assert report["coverage"]["positions_examined_end"] == len(data) - 3
        assert [r["offset"] for r in report["blobs"]] == [len(prefix)]


@pytest.mark.parametrize("field,value", [("max_nodes", True), ("max_nodes", 0), ("max_nodes", 8193), ("max_output_bytes", 2047)])
def test_invalid_limits_fixed(field, value):
    with pytest.raises(ValidationFailed):
        replace(F.FitStructureLimits(), **{field: value})


@pytest.mark.parametrize("size,cap", [(True, 1), (-1, 1), (3, 1), (0, True), (0, -1)])
def test_invalid_input_fixed(size, cap):
    with pytest.raises(ValidationFailed):
        F.scan_fit_security(b"", size, ctl=Ctl(), max_scan_bytes=cap)


@pytest.mark.parametrize("access", [mmap.ACCESS_READ, mmap.ACCESS_WRITE, mmap.ACCESS_COPY])
def test_readonly_mmap_required_and_view_released(tmp_path, access):
    path = tmp_path / "synthetic-fdt"
    data = fit()
    path.write_bytes(data)
    with path.open("r+b") as stream:
        mm = mmap.mmap(stream.fileno(), 0, access=access)
        try:
            if access == mmap.ACCESS_READ:
                assert scan(mm)["status"] == "complete"
            else:
                with pytest.raises(ValidationFailed, match="입력이 올바르지"):
                    scan(mm)
        finally:
            # 임시 memoryview가 남았다면 BufferError가 발생한다.
            mm.close()


def test_closed_mmap_uses_fixed_validation_error(tmp_path):
    path = tmp_path / "synthetic-fdt"
    path.write_bytes(fit())
    with path.open("rb") as stream:
        mm = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
    mm.close()
    with pytest.raises(ValidationFailed) as caught:
        F.scan_fit_security(mm, 0, ctl=Ctl(), max_scan_bytes=1)
    assert str(caught.value) == "[validation_failed] FIT 구조 관찰 입력이 올바르지 않습니다."
