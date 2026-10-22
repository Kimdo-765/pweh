"""합성 구간 bytes에서 상대 prefix를 쓰고 최종 EV·보고서 결속을 유지한다."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import time
from types import SimpleNamespace

import pytest

from core.test_media_candidate_input import load
from core.test_media_candidate_range_input import range_input  # noqa: F401
from forensics_mcp import media_candidate_selection as R
from forensics_mcp import media_prefix_output as W
from forensics_mcp import media_prefix_tools as T
from pweh import evidence as E, safeio
from pweh.errors import PwehError


def make_manifest(value):
    with load(value) as candidate:
        data, fresh = R.reselect_candidate_source(value.opened, candidate,
                                                  deadline=time.monotonic() + 20, cancel=lambda: False)
        return T._manifest(candidate, data, fresh, 0, lambda: None)


def store(value, manifest, **overrides):
    args = dict(manifest=manifest, custody_log=value.log, reference_roots=(),
                deadline=time.monotonic() + 20, check=lambda: None, check_entries=lambda entries: None)
    args.update(overrides)
    return W.store_media_prefix(value.case, value.opened, value.data, **args)


def assert_uncommitted(value):
    assert not any(e["event"] == "extract" for e in value.log.entries())
    assert list((value.case.dir / "forensics/recovered").glob("media-prefix-*")) == []


def test_range_prefix_writer_never_adds_ev_offset_twice(range_input):
    value = range_input(offset=4096)
    manifest = make_manifest(value)
    result = store(value, manifest)
    row = manifest["candidate"]
    expected = value.data[row["offset"]:row["offset"] + row["validated_prefix_length"]]
    output = value.case.dir / result["output_dir"]
    assert (output / W.PAYLOAD_NAME).read_bytes() == expected
    assert hashlib.sha256(expected).hexdigest() == manifest["files"][0]["sha256"]
    assert result["bytes_total"] == len(expected)
    saved = json.loads((output / W.MANIFEST_NAME).read_bytes())
    assert saved["source"] == value.report["source"]
    assert saved["source_coverage"] == value.report["coverage"]
    assert not saved["original_file_boundary_verified"] and not saved["complete_recording"]
    assert set(saved["source"]) == set(value.report["source"]) and "profile" not in saved


@pytest.mark.parametrize("change", [
    {"offset": 4096.0}, {"offset": True}, {"offset": -1}, {"offset": 1 << 63},
    {"offset": 10000}, {"evidence_size": 4096}, {"evidence_size": 1 << 63},
    {"evidence_size": True}, {"selected_size": 16.0}, {"selected_sha256": "0" * 64},
])
def test_range_writer_rejects_bad_source_before_output(range_input, change):
    value = range_input()
    manifest = make_manifest(value)
    manifest["source"].update(change)
    with pytest.raises(PwehError):
        store(value, manifest)
    assert_uncommitted(value)


@pytest.mark.parametrize("change", [
    {"offset": 4097}, {"offset": 4096.0}, {"evidence_size": 9000},
    {"selected_size": 16}, {"selected_sha256": "0" * 64}, {"method": "whole-file"},
])
def test_manifest_requires_exact_fresh_range_source(range_input, change):
    value = range_input()
    with load(value) as candidate:
        fresh = copy.deepcopy(candidate.source)
        fresh.update(change)
        with pytest.raises(PwehError):
            T._manifest(candidate, value.data, fresh, 0, lambda: None)
    assert_uncommitted(value)


@pytest.mark.parametrize("field", ["offset", "length"])
def test_manifest_range_params_reject_json_integer_float(range_input, field):
    value = range_input()
    with load(value) as candidate:
        candidate.params[field] = float(candidate.params[field])
        with pytest.raises(PwehError):
            T._manifest(candidate, value.data, candidate.source, 0, lambda: None)


def test_writer_rechecks_current_evidence_size_before_claim(range_input):
    value = range_input()
    manifest = make_manifest(value)
    path = value.case.dir / value.opened.intake["stored_path"]
    path.chmod(0o644)
    with path.open("ab") as output:
        output.write(b"X")
    path.chmod(0o444)
    with pytest.raises(PwehError):
        store(value, manifest)
    assert_uncommitted(value)


@pytest.mark.parametrize("change_at_commit", [False, True])
def test_adapter_range_check_occurs_inside_final_custody_lock(range_input, monkeypatch, change_at_commit):
    value = range_input()
    seen, committed = [], []
    original = R.check_candidate_range

    def checked(opened, source, **options):
        ffd = E.open_forensics(value.case)
        try:
            token = safeio.try_lock_at(ffd, E.CUSTODY_LOCK, create=False)
            if token is None:
                seen.append((source.copy(), options.get("time_limit", True)))
                if change_at_commit:
                    path = value.case.dir / value.opened.intake["stored_path"]
                    path.chmod(0o644)
                    with path.open("r+b") as output:
                        output.seek(source["offset"])
                        output.write(b"!")
                    path.chmod(0o444)
            else:
                os.close(token)
        finally:
            os.close(ffd)
        return original(opened, source, **options)

    monkeypatch.setattr(R, "check_candidate_range", checked)

    async def case_lookup(case_id):
        return value.case

    async def run_job(kind, case_id, title, work, **options):
        return work(SimpleNamespace(cancelled=False, progress=lambda *a: None,
                                    mark_committed=lambda: committed.append(True)))

    server = SimpleNamespace(_case=case_lookup, custody=lambda case: value.log,
                             _reference_roots=lambda: (), _run_job=run_job,
                             rt=lambda: SimpleNamespace(audit=lambda *args: None))
    operation = T._extract_run(server, case_id=value.case.id, evidence_id=value.opened.evidence_id,
                               analysis_path=value.path, candidate_index=0)
    if change_at_commit:
        with pytest.raises(PwehError) as error:
            asyncio.run(operation)
        assert error.value.code == "integrity_failed" and committed == []
        assert_uncommitted(value)
    else:
        result = asyncio.run(operation)
        assert result["ok"] and committed == [True]
    assert seen == [(value.report["source"], True)]


def test_range_commit_callback_failure_preserves_published_prefix(range_input):
    value = range_input()
    manifest = make_manifest(value)

    def audit_failed(entry):
        raise RuntimeError("PRIVATE_RANGE_AUDIT")

    result = store(value, manifest, on_commit=audit_failed)
    assert result["warnings"] == ["post_commit_callback_failed"]
    assert (value.case.dir / result["output_dir"] / W.PAYLOAD_NAME).is_file()
    assert value.log.entries()[-1]["event"] == "extract"
    assert "PRIVATE_RANGE_AUDIT" not in json.dumps(result)
