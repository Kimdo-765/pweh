"""합성 FDT의 strict 구조·공통 예산과 legacy parser 역호환 시험."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import common, signatures as S  # noqa: E402
from fwtriage_mcp.common import Cancelled, Ctl  # noqa: E402


CAPS = {
    "max_blob_bytes": 64 << 20, "max_strings_bytes": 1 << 20,
    "max_properties": 32768, "max_tokens": 65536,
    "max_total_tokens": 131072, "max_owned_bytes": 2 << 20,
    "max_reservations": 1024,
}


def budget(ctl=None, **overrides):
    return S.FdtParseBudget(ctl or Ctl(), **(CAPS | overrides))


def pack(structure, strings=b"", reserves=b"\0" * 16, *, version=17, gap=b""):
    """손상 시험도 만들 수 있는 작은 비실행 v17 컨테이너 작성기."""
    off_struct = 40 + len(reserves) + len(gap)
    off_strings = off_struct + len(structure)
    header = struct.pack(">10I", 0xD00DFEED, off_strings + len(strings), off_struct,
                         off_strings, 40, version, 16, 0, len(strings), len(structure))
    return header + reserves + gap + structure + strings


def fdt(props=(), children=(), *, root_name="", reserves=(), version=17):
    """순서와 중복 이름을 보존하는 합성 tree 작성기."""
    strings = bytearray()

    def node(name, properties, kids):
        out = bytearray(struct.pack(">I", 1) + name.encode("latin-1") + b"\0")
        out += b"\0" * (-len(out) % 4)
        for key, value in properties:
            off = len(strings)
            strings.extend(key.encode("latin-1") + b"\0")
            out += struct.pack(">III", 3, len(value), off) + value + b"\0" * (-len(value) % 4)
        for child in kids:
            out += node(*child)
        return out + struct.pack(">I", 2)

    structure = node(root_name, props, children) + struct.pack(">I", 9)
    reserve_bytes = b"".join(struct.pack(">QQ", a, n) for a, n in reserves) + b"\0" * 16
    return pack(structure, bytes(strings), reserve_bytes, version=version)


def fields(data):
    return struct.unpack(">10I", data[:40])


def structure(data):
    h = fields(data)
    return data[h[2]:h[2] + h[9]]


def strings(data):
    h = fields(data)
    return data[h[3]:h[3] + h[8]]


def header(data, index, value):
    out = bytearray(data)
    struct.pack_into(">I", out, index * 4, value)
    return bytes(out)


def strict(data, *, base=0, limit=None, shared=None, **kw):
    return S.parse_fdt_tree(data, base, len(data) if limit is None else limit,
                            budget=shared if shared is not None else budget(), **kw)


def rejected(data, reason="malformed_fdt", **kw):
    with pytest.raises(S.FdtStrictError) as exc:
        strict(data, **kw)
    assert exc.value.reason == reason
    assert str(exc.value) == "FDT 구조 검사를 완료하지 못했습니다."
    return exc.value


def test_none_legacy_shape_and_small_values_unchanged():
    data = fdt((("description", b"PWEH synthetic\0"), ("data", b"small")),
               (("images", (), (("one", (("load", struct.pack(">I", 123)),), ()),)),))
    legacy = S.parse_fdt_tree(data, 0, len(data))
    assert legacy == S.parse_fdt_tree(data, 0, len(data), budget=None)
    assert set(legacy) == {"totalsize", "version", "last_comp_version", "boot_cpuid", "root"}
    assert set(legacy["root"]) == {"name", "props", "children"}
    assert legacy["root"]["props"]["data"] == b"small"
    assert S.summarize_fdt(legacy)["images"][0]["load"] == "0x7b"


def test_strict_offsets_and_strings_metadata_are_absolute():
    data = fdt((("algo", b"sha256\0"),), (("signature-1", (("value", b"sig"),), ()),))
    base = 13
    tree = strict(b"x" * base + data + b"trailer", base=base)
    h = fields(data)
    assert tree["strings_offset"] == base + h[3]
    assert tree["strings_size"] == h[8]
    assert tree["root"]["_offset"] == base + h[2]
    child = tree["root"]["children"][0]
    assert data[child["_offset"] - base:child["_offset"] - base + 4] == struct.pack(">I", 1)
    marker, offset, size = child["props"]["value"]
    assert marker == "<blob>" and size == 3 and data[offset:offset + size] == b"sig"


@pytest.mark.parametrize("version", [0, 15, 16, 18, 0xFFFFFFFF])
def test_new_version_scope_does_not_change_legacy(version):
    data = fdt(version=version)
    rejected(data, "unsupported_fdt")
    if version == 16:
        assert S.parse_fdt_tree(data, 0, len(data))["version"] == 16


@pytest.mark.parametrize("index,value", [
    (0, 0), (1, 39), (1, 0xFFFFFFFF), (2, 0), (2, 41),
    (3, 0), (3, 0xFFFFFFFF), (4, 0), (4, 41), (4, 0xFFFFFFF8),
    (6, 0), (6, 18), (8, 0xFFFFFFFF), (9, 0), (9, 1), (9, 0xFFFFFFFC),
])
def test_header_bounds_and_alignment(index, value):
    rejected(header(fdt((("k", b"v"),)), index, value))


@pytest.mark.parametrize("cut", [0, 1, 3, 4, 39, 40, 55, 60, 71])
def test_truncated_input_never_returns_partial_tree(cut):
    rejected(fdt((("k", b"v"),))[:cut])


def test_declared_tail_required_only_in_strict_path():
    data = fdt() + b"unused tail"
    data = header(data, 1, len(data))
    assert S.parse_fdt_tree(data[:-1], 0, len(data) - 1)["root"]["name"] == ""
    rejected(data[:-1])
    strict(data)


@pytest.mark.parametrize("base,limit", [(True, 72), (0, True), (-1, 72), (0, 10000), (3, 2), (0.0, 72)])
def test_strict_input_ranges(base, limit):
    rejected(fdt(), base=base, limit=limit)


def test_struct_and_strings_overlap():
    data = fdt((("k", b"v"),))
    rejected(header(data, 3, fields(data)[2]))


def test_reserve_overlap_missing_terminator_and_pair_cap():
    data = fdt(reserves=((0x1000, 32),))
    ok = budget(max_reservations=1)
    strict(data, shared=ok)
    assert ok.blob_reservations == 1
    rejected(fdt(reserves=((0x1000, 1), (0x2000, 2))), "field_limit", shared=budget(max_reservations=1))
    no_terminator = pack(structure(fdt()), reserves=struct.pack(">QQ", 0x1000, 32))
    rejected(no_terminator)
    rejected(header(fdt(), 4, fields(fdt())[2]))
    data = fdt((("k", b"v"),))
    rejected(header(data, 4, fields(data)[3] & ~7))


def test_valid_block_order_need_not_be_canonical():
    original = fdt((("k", b"v"),))
    text = strings(original)
    pad = b"\0" * (-len(text) % 8)
    struct_data = structure(original)
    off_rsv = 40 + len(text) + len(pad)
    off_struct = off_rsv + 16
    data = struct.pack(">10I", 0xD00DFEED, off_struct + len(struct_data), off_struct,
                       40, off_rsv, 17, 16, 0, len(text), len(struct_data))
    data += text + pad + b"\0" * 16 + struct_data
    assert strict(data)["root"]["props"]["k"] == b"v"


@pytest.mark.parametrize("mutate", [
    lambda s: s[:-4],  # END 누락
    lambda s: s[:-8] + s[-4:],  # END_NODE 누락
    lambda s: s + struct.pack(">I", 4),  # END 뒤 잔여 토큰
    lambda s: struct.pack(">I", 2) + s,  # 짝 없는 END_NODE
    lambda s: s[:8] + struct.pack(">I", 0xDEADBEEF) + s[8:],
    lambda s: s[:-4] + s,  # 두 root
    lambda s: struct.pack(">I", 9),  # root 없는 END
])
def test_root_stack_and_end_contract(mutate):
    rejected(pack(mutate(structure(fdt()))))


@pytest.mark.parametrize("data", [
    fdt(root_name="not-root"),
    fdt(children=(("", (), ()),)),
    fdt((("", b"x"),)),
    fdt((("same", b"one"), ("same", b"two"))),
    fdt(children=(("same", (), ()), ("same", (), ()))),
])
def test_ambiguous_empty_and_duplicate_names(data):
    rejected(data)


def test_duplicate_and_property_order_legacy_contract_preserved():
    dup = fdt((("same", b"one"), ("same", b"two")))
    assert S.parse_fdt_tree(dup, 0, len(dup))["root"]["props"]["same"] == b"two"
    original = fdt((("k", b"v"),), (("child", (), ()),))
    s = structure(original)
    # root 시작8B, 속성16B 뒤 child16B를 앞으로 이동한다.
    late_prop = pack(s[:8] + s[24:40] + s[8:24] + s[40:], strings(original))
    assert S.parse_fdt_tree(late_prop, 0, len(late_prop))["root"]["props"]["k"] == b"v"
    rejected(late_prop)


@pytest.mark.parametrize("kind,maximum", [("node", 255), ("property", 128)])
def test_name_length_boundary(kind, maximum):
    make = (lambda n: fdt(children=(("n" * n, (), ()),))) if kind == "node" else (lambda n: fdt((("p" * n, b""),)))
    strict(make(maximum))
    rejected(make(maximum + 1))


def test_unterminated_names_and_property_span():
    data = fdt((("k", b"v"),))
    s = bytearray(structure(data))
    struct.pack_into(">I", s, 12, 0xFFFFFFFF)
    rejected(pack(bytes(s), strings(data)))
    s = bytearray(structure(data))
    struct.pack_into(">I", s, 16, len(strings(data)))
    rejected(pack(bytes(s), strings(data)))
    rejected(pack(structure(data), b"k"))
    rejected(pack(struct.pack(">I", 1) + b"x" * 256))


def test_exact_blob_and_strings_caps():
    data = fdt((("k", b"v"),))
    strict(data, shared=budget(max_blob_bytes=len(data), max_strings_bytes=len(strings(data))))
    rejected(data, "field_limit", shared=budget(max_blob_bytes=len(data) - 1))
    rejected(data, "field_limit", shared=budget(max_strings_bytes=len(strings(data)) - 1))


def test_node_property_and_depth_caps():
    data = fdt((("a", b""), ("b", b"")), (("child", (), ()),))
    strict(data, shared=budget(max_properties=2), max_nodes=2, max_depth=1)
    rejected(data, "node_limit", max_nodes=1)
    rejected(data, "property_limit", shared=budget(max_properties=1))
    deep = fdt(children=(("one", (), (("two", (), ()),)),))
    strict(deep, max_depth=2)
    rejected(deep, "depth_limit", max_depth=1)


def test_nops_count_and_shared_token_cap():
    data = pack(struct.pack(">I", 4) * 12 + structure(fdt()))
    b = budget(max_tokens=15)
    strict(data, shared=b)
    assert b.total_tokens == b.blob_tokens == 15
    rejected(data, "token_limit", shared=budget(max_tokens=14))
    b = budget(max_total_tokens=6)
    strict(fdt(), shared=b)
    strict(fdt(), shared=b)
    assert b.total_tokens == 6 and b.blob_tokens == 3
    rejected(fdt(), "token_limit", shared=b)
    assert b.total_tokens == 6 and b.blob_tokens == 0


def test_shared_owned_bytes_and_inventory_charge():
    data = fdt((("a", b"bc"),))
    b = budget(max_owned_bytes=6)
    strict(data, shared=b)
    assert b.owned_bytes == 3
    strict(data, shared=b)
    assert b.owned_bytes == 6
    rejected(data, "owned_bytes_limit", shared=b)
    assert b.owned_bytes == 6
    with pytest.raises(S.FdtStrictError, match="FDT") as exc:
        b.charge_owned(1)
    assert exc.value.reason == "owned_bytes_limit"
    b.charge_owned(0)


def test_malformed_candidate_does_not_refund_work():
    good = fdt((("a", b"bc"),))
    s = structure(good)
    malformed = pack(s[:-4] + struct.pack(">I", 0xDEADBEEF), strings(good))
    b = budget(max_total_tokens=7, max_owned_bytes=6)
    rejected(malformed, shared=b)
    assert (b.total_tokens, b.owned_bytes) == (4, 3)
    rejected(good, "token_limit", shared=b)
    assert b.total_tokens == 7 and b.owned_bytes == 6


class CheckedBuffer:
    """내용 복사와 범위 밖 읽기를 시험이 직접 감시하는 합성 입력."""

    def __init__(self, data, *, forbidden=(), hook=None):
        self.data = data
        self.forbidden = forbidden
        self.hook = hook
        self.reads = []

    def __len__(self):
        return len(self.data)

    def find(self, value, start, end):
        assert 0 <= start <= end <= len(self.data)
        return self.data.find(value, start, end)

    def __getitem__(self, item):
        start, end = item.start, item.stop
        assert 0 <= start <= end <= len(self.data)
        for lo, hi in self.forbidden:
            assert not (start < hi and lo < end), "금지한 payload 복사"
        self.reads.append((start, end))
        if self.hook:
            self.hook(start, end)
        return self.data[item]


@pytest.mark.parametrize("key,size", [
    ("data", 0), ("data", 1), ("value", 32), ("rsa,num-bits", 4),
    ("ecdsa,x-point", 64), ("data", 32768), ("unrelated", 1025),
])
def test_payload_value_and_keys_are_never_copied(key, size):
    data = fdt(((key, b"X" * size),))
    start = fields(data)[2] + 20
    buf = CheckedBuffer(data, forbidden=((start, start + size),))
    tree = strict(buf)
    assert tree["root"]["props"][key] == ("<blob>", start, size)


def test_small_value_and_name_are_precharged_before_slice():
    data = fdt((("algo", b"X" * 1024),))
    start = fields(data)[2] + 20
    strict(data, shared=budget(max_owned_bytes=1028))
    buf = CheckedBuffer(data, forbidden=((start, start + 1024),))
    rejected(buf, "owned_bytes_limit", shared=budget(max_owned_bytes=1027))
    name_start = fields(data)[3]
    buf = CheckedBuffer(data, forbidden=((name_start, name_start + 4),))
    rejected(buf, "owned_bytes_limit", shared=budget(max_owned_bytes=3))


@pytest.mark.parametrize("cap", list(CAPS))
@pytest.mark.parametrize("invalid", [True, 0, -1, 1.0, None])
def test_invalid_caps_fail_with_fixed_reason(cap, invalid):
    with pytest.raises(S.FdtStrictError) as exc:
        budget(**{cap: invalid})
    assert exc.value.reason == "field_limit"


@pytest.mark.parametrize("field", ["total_tokens", "owned_bytes", "blob_tokens", "blob_nodes", "blob_properties", "blob_reservations"])
def test_public_counters_read_only(field):
    b = budget()
    with pytest.raises(AttributeError):
        setattr(b, field, 0)


@pytest.mark.parametrize("step", [1, 3, 8, 12])
def test_cancellation_during_parse_uses_original_ctl(step):
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        return calls >= step

    b = budget(Ctl(cancelled=cancel))
    with pytest.raises(Cancelled):
        strict(fdt((("algo", b"sha256\0"),), (("child", (), ()),)), shared=b)


def test_cancel_and_time_checked_after_last_token(monkeypatch):
    b = None
    ctl = Ctl(cancelled=lambda: b is not None and b.blob_tokens == 3)
    b = budget(ctl)
    with pytest.raises(Cancelled):
        strict(fdt(), shared=b)
    assert b.blob_tokens == 3

    now = [0.0]
    monkeypatch.setattr(common.time, "monotonic", lambda: now[0])
    ctl = Ctl(max_seconds=1)
    b = budget(ctl)
    data = fdt()
    last = fields(data)[2] + fields(data)[9] - 4

    def expire(start, end):
        if start == last:
            now[0] = 2.0

    rejected(CheckedBuffer(data, hook=expire), "time_limit", shared=b)
    assert ctl.timed_out and b.total_tokens == 3
    rejected(data, "time_limit", shared=b)
    assert b.total_tokens == 3 and b.blob_tokens == 0


def test_reserve_loop_checks_cancel_without_tokens():
    b = None
    ctl = Ctl(cancelled=lambda: b is not None and b.blob_reservations == 2)
    b = budget(ctl)
    with pytest.raises(Cancelled):
        strict(fdt(reserves=((1, 1), (2, 1), (3, 1))), shared=b)
    assert b.blob_tokens == 0 and b.blob_reservations == 2


def test_fixed_error_never_contains_input_or_original_exception():
    sentinel = "PWEH-SECRET-SENTINEL"
    data = fdt(((sentinel, b"a"), (sentinel, b"b")))
    exc = rejected(data)
    assert sentinel not in str(exc) and sentinel not in repr(exc)

    class Broken(CheckedBuffer):
        def __getitem__(self, item):
            raise OSError(sentinel)

    exc = rejected(Broken(fdt()))
    assert sentinel not in str(exc) and exc.__suppress_context__


def test_unknown_token_no_legacy_retry(monkeypatch):
    data = pack(struct.pack(">I", 0xFEEDBABE))

    def legacy_read(*args):
        pytest.fail("strict 실패 뒤 legacy 읽기를 호출함")

    monkeypatch.setattr(S, "_rd", legacy_read)
    rejected(data)
