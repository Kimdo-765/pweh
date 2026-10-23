"""잔여 선택의 writer 산술·정확 타입·원자 게시를 독립 합성 manifest로 검증한다."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import stat
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from core.test_media_residual_extract_schema import KINDS, manifest
from forensics_mcp import dhav_record_output, dhav_record_tools, media_prefix_output, media_prefix_tools
from forensics_mcp import media_unit_output, media_unit_extract_tools
from pweh import evidence as E, safeio
from pweh.case import CaseStore
from pweh.errors import ValidationFailed

PARTS = {
    "bmff": (media_prefix_output, media_prefix_tools, "store_media_prefix", "validated_prefix_length"),
    "dhav": (dhav_record_output, dhav_record_tools, "store_dhav_record", "record_length"),
}


def parts(kind):
    return PARTS.get(kind, (media_unit_output, media_unit_extract_tools, "store_media_unit", "length"))


@pytest.fixture
def residual_case(workspace, auth):
    @contextlib.contextmanager
    def build(kind="xm", *, vdl=101):
        case = CaseStore(workspace["cases_dir"]).create(title="합성 residual writer", authorization=auth)
        log = E.CustodyLog(case, workspace["state_dir"] / "custody")
        value = manifest(kind)
        size = value["source"]["selected_size"]
        data = bytes((i + 37) % 256 for i in range(size))
        evidence = b"unselected-prefix" + data + b"unselected-suffix"
        ev = _commit_intake(case, log, evidence)
        with E.open_checked(case, ev, log.entries()) as opened:
            sha = opened.intake["hashes"]["sha256"]
            value.update(evidence_id=ev, evidence_sha256=sha)
            value["source"].update(evidence_id=ev, evidence_sha256=sha,
                selected_sha256=hashlib.sha256(data).hexdigest(), data_length=vdl + size, valid_data_length=vdl)
            value["files"][0]["sha256"] = hashlib.sha256(data[:value["bytes_total"]]).hexdigest()
            yield SimpleNamespace(case=case, log=log, opened=opened, manifest=value, data=data, kind=kind)
    return build


def store(ctx, **kwargs):
    module, _, method, _ = parts(ctx.kind)
    options = dict(manifest=ctx.manifest, custody_log=ctx.log, reference_roots=(),
                   deadline=time.monotonic() + 30, check=lambda: None, check_entries=lambda entries: None)
    options.update(kwargs)
    return getattr(module, method)(ctx.case, ctx.opened, ctx.data, **options)


def candidate_input(ctx):
    value = ctx.manifest
    origin = SimpleNamespace(**value["analysis"])
    origin.to_dict = lambda: copy.deepcopy(value["analysis"])
    return SimpleNamespace(source=value["source"], candidate=value["candidate"],
        coverage=value["source_coverage"], upstream_status=value["source_status"], origin=origin,
        params={"region": "residual", "partition": 1, "method": "auto", "max_seconds": 45,
                **({"format": ctx.kind} if ctx.kind not in PARTS else {})},
        format=ctx.kind, profile=value.get("source_profile"))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("vdl", [0, 101, (1 << 63) - (64 << 20)])
def test_writer_keeps_relative_slice_and_records_residual_region(residual_case, kind, vdl):
    with residual_case(kind, vdl=vdl) as ctx:
        module, tools, _, length_key = parts(kind)
        projected = tools._manifest(candidate_input(ctx), ctx.data, ctx.manifest["source"], 0, lambda: None)
        assert projected == ctx.manifest
        calls = []

        def check_entries(entries):
            assert [row["event"] for row in entries] == ["intake"]
            root = E.open_forensics(ctx.case)
            try:
                assert safeio.try_lock_at(root, E.CUSTODY_LOCK, create=False) is None
            finally:
                os.close(root)
            calls.append("verified")

        result = store(ctx, check_entries=check_entries)
        path = ctx.case.dir / result["output_dir"] / module.PAYLOAD_NAME
        size = ctx.manifest["candidate"][length_key]
        assert path.read_bytes() == ctx.data[:size]
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert result["bytes_total"] == size and calls == ["verified"]
        event = ctx.log.entries()[-1]
        assert event["data"]["region"] == "residual" and event["data"]["method"] == module.METHOD
        assert event["data"]["analysis"] == ctx.manifest["analysis"]
        assert event["data"]["manifest_sha256"] == result["manifest_sha256"]
        os.fstat(ctx.opened.fd)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("field,value", [
    ("data_length", 101), ("data_length", 100), ("data_length", float(101)),
    ("valid_data_length", 0), ("valid_data_length", 101.0), ("valid_data_length", True),
    ("selected_size", 16.0), ("partition", 1.0), ("region", "data"),
])
def test_writer_independent_lengths_and_exact_types_fail_before_output(residual_case, kind, field, value):
    with residual_case(kind) as ctx:
        ctx.manifest["source"][field] = value
        with pytest.raises(E.EvidenceError):
            store(ctx)
        assert [row["event"] for row in ctx.log.entries()] == ["intake"]
        assert list((ctx.case.dir / "forensics/recovered").glob("*")) == []


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("field,value", [
    ("confidence", "medium"), ("parent_deleted", None), ("deleted", 0), ("partition", 1.0),
    ("data_length", 0), ("valid_data_length", 0), ("offset", 0), ("selected_sha256", "0" * 64),
])
def test_manifest_rejects_any_fresh_residual_change(residual_case, kind, field, value):
    with residual_case(kind) as ctx:
        fresh = copy.deepcopy(ctx.manifest["source"])
        fresh[field] = value
        with pytest.raises(ValidationFailed):
            parts(kind)[1]._manifest(candidate_input(ctx), ctx.data, fresh, 0, lambda: None)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("field,value", [("region", "data"), ("partition", 2), ("partition", True),
                                      ("method", "stale-chain")])
def test_manifest_params_must_match_saved_selection(residual_case, kind, field, value):
    with residual_case(kind) as ctx:
        selected = candidate_input(ctx)
        selected.params[field] = value
        with pytest.raises(ValidationFailed):
            parts(kind)[1]._manifest(selected, ctx.data, ctx.manifest["source"], 0, lambda: None)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
def test_changed_selected_hash_never_publishes(residual_case, kind):
    with residual_case(kind) as ctx:
        ctx.manifest["source"]["selected_sha256"] = "0" * 64
        with pytest.raises(E.EvidenceError) as caught:
            store(ctx)
        assert caught.value.code.endswith("input_changed")
        assert [row["event"] for row in ctx.log.entries()] == ["intake"]


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
def test_late_callback_failure_preserves_residual_receipt(residual_case, kind):
    with residual_case(kind) as ctx:
        def fail(entry):
            raise RuntimeError("PRIVATE_RESIDUAL_CALLBACK")
        result = store(ctx, on_commit=fail)
        assert result["warnings"] == ["post_commit_callback_failed"]
        assert (ctx.case.dir / result["manifest"]).exists()
        assert ctx.log.entries()[-1]["data"]["region"] == "residual"
