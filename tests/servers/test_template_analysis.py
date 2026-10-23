"""저장 PNG의 색인·같은 FD·단일 마감·checked commit 경계를 합성 파일로 검사한다."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import struct
import sys
import threading
import time
import traceback
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers/play-mcp"))
from play_mcp import template_analysis as A
from pweh import evidence, schemas
from pweh.errors import PwehError
from pweh.runtime import get_runtime

PRIVATE = "SYNTHETIC_TEMPLATE_PRIVATE"


def png(width=2, height=2, value=12):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress((b"\0" + bytes([value]) * width * 3) * height)) + chunk(b"IEND", b""))


@pytest.fixture
def case(workspace, auth):
    return get_runtime("test").cases.create(title="합성 PNG 비교", authorization=auth)


def attach(case, *, status="ok", value=12, crop=False):
    data = png(value=value)
    original = {"size": 23, "sha256": "a" * 64}
    report = {"schema": "pweh.image-hints/v1", "status": status, "input": original,
              "source": {"kind": "case-file", "path": PRIVATE, **original},
              "ocr": {"private": PRIVATE}, "extra_metadata": {"private": PRIVATE}}
    previews = [{"role": role, "data": data, "mime_type": "image/png", "sha256": hashlib.sha256(data).hexdigest(),
                 "width": 2, "height": 2, "crop": [0, 0, 2, 2] if role == "crop" else None}
                for role in (("overview", "crop") if crop else ("overview",))]
    result = evidence.store_image_hints(case, report, previews)
    row = next(row for row in case.artifacts() if row["path"] == result["analysis"]["path"])
    return row


def analyze(case, entry, candidate=None, **kwargs):
    return A.match_registered_previews(
        case, kwargs.pop("reference_artifact_id", entry["id"]), kwargs.pop("reference_preview_index", 0),
        kwargs.pop("reference_roi", (0, 0, 2, 2)),
        kwargs.pop("candidate_artifact_id", (candidate or entry)["id"]), kwargs.pop("candidate_preview_index", 0),
        kwargs.pop("candidate_roi", (0, 0, 2, 2)), kwargs.pop("max_mean_error", 0),
        deadline=kwargs.pop("deadline", time.monotonic() + 5), cancel_event=kwargs.pop("cancel_event", None), **kwargs)


def outputs(case):
    return list((case.dir / "analysis").glob("template-match-*.json"))


def failure(case, entry, *, code=None, **kwargs):
    with pytest.raises(PwehError) as caught:
        analyze(case, entry, **kwargs)
    if code is not None:
        assert caught.value.code == code
    assert PRIVATE not in str(caught.value) + json.dumps(caught.value.to_dict())
    assert "RuntimeError: " + PRIVATE not in "".join(traceback.format_exception(caught.value))
    return caught.value


def mutate_index(case, callback):
    case._update(lambda meta: callback(meta["artifacts"]))


def rewrite(case, entry, mutate=None, data=None):
    path = case.dir / entry["path"]
    if data is None:
        report = json.loads(path.read_bytes())
        mutate(report)
        data = json.dumps(report, ensure_ascii=True).encode()
    path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(0o444)
    updated = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    mutate_index(case, lambda rows: next(row for row in rows if row["id"] == entry["id"]).update(updated))


@pytest.fixture
def stub(monkeypatch):
    def compare(_a, _b, **kw):
        samples = kw["reference_roi"][2] * kw["reference_roi"][3] * 3
        return {"sum_abs": 0, "samples": samples, "mean_abs_error": 0.0, "matched": True}
    monkeypatch.setattr(A.imagehints, "match_png_rois", compare, raising=False)
    return compare


@pytest.mark.parametrize("status,threshold,second,matched", [("ok", 0, 12, True), ("partial", 0, 13, False),
                                                           ("ok", 1, 13, True), ("ok", 255, 255, True)])
def test_actual_rgb_worker_and_checked_report(case, status, threshold, second, matched):
    first, other = attach(case, status=status), attach(case, value=second)
    result = analyze(case, first, other, max_mean_error=threshold)
    assert set(result) == {"ok", "report", "artifact_id", "analysis_path", "sha256", "size", "warnings"}
    assert result["ok"] is True and result["warnings"] == []
    report = result["report"]
    schemas.validate("template-match", report)
    assert report["result"] == {"sum_abs": abs(second - 12) * 12, "samples": 12,
                                 "mean_abs_error": abs(second - 12), "matched": matched}
    assert all(report[key] is False for key in A._FLAGS)
    data = (case.dir / result["analysis_path"]).read_bytes()
    assert json.loads(data) == report and data.endswith(b"\n")
    assert result["size"] == len(data) <= 65536 and result["sha256"] == hashlib.sha256(data).hexdigest()
    assert PRIVATE not in data.decode() and "image-hints" not in data.decode()
    art = case.artifacts()[-1]
    assert art["id"] == result["artifact_id"] and art["kind"] == "other" and art["producer"] == "pweh-play"
    assert art["extra"] == {"type": "template-match"}
    assert stat.S_IMODE((case.dir / result["analysis_path"]).stat().st_mode) == 0o444


def test_same_selection_and_different_rois_share_no_original_coordinates(case):
    entry = attach(case, crop=True)
    result = analyze(case, entry, reference_preview_index=1, candidate_preview_index=1,
                     reference_roi=(0, 0, 1, 1), candidate_roi=(1, 1, 1, 1))
    assert result["report"]["sources"]["reference"] == result["report"]["sources"]["candidate"]
    assert result["report"]["result"]["samples"] == 3


@pytest.mark.parametrize("number", [1000, 99999])
def test_producer_larger_sequence_is_allowed(case, number, stub):
    entry = attach(case)
    old = "image-hints-001"
    new = f"image-hints-{number:03d}"
    for row in case.artifacts():
        src, dst = case.dir / row["path"], case.dir / row["path"].replace(old, new)
        src.rename(dst)
    mutate_index(case, lambda rows: [row.update(path=row["path"].replace(old, new)) for row in rows])
    entry = case.artifacts()[0]
    rewrite(case, entry, lambda value: value["artifacts"]["previews"][0].update(path=value["artifacts"]["previews"][0]["path"].replace(old, new)))
    assert analyze(case, entry)["ok"]


@pytest.mark.parametrize("kwargs", [
    {"reference_artifact_id": "A-0001\n"}, {"candidate_artifact_id": True},
    {"reference_preview_index": True}, {"candidate_preview_index": 1.0}, {"candidate_preview_index": 2},
    {"reference_roi": [0, 0, 2, 2]}, {"reference_roi": (0, 0, 2)}, {"reference_roi": (0, 0, True, 2)},
    {"reference_roi": (0, 0, 2.0, 2)}, {"reference_roi": (0, 0, 0, 2)}, {"reference_roi": (-1, 0, 2, 2)},
    {"reference_roi": (0, 0, 1601, 2)}, {"reference_roi": (0, 0, 1, 2)},
    {"max_mean_error": True}, {"max_mean_error": 1.0}, {"max_mean_error": -1}, {"max_mean_error": 256},
    {"deadline": True}, {"deadline": float("nan")}, {"deadline": float("inf")}, {"deadline": 10 ** 400},
    {"cancel_event": PRIVATE},
])
def test_exact_worker_arguments_reject_before_input_open(case, monkeypatch, kwargs):
    entry = attach(case)
    monkeypatch.setattr(A.safeio, "open_regular", lambda *a, **k: pytest.fail("입력 open 금지"))
    failure(case, entry, code="template_input_invalid", **kwargs)
    assert not outputs(case)


def test_future_deadline_rejected_before_input_open(case, monkeypatch):
    entry = attach(case)
    monkeypatch.setattr(A.safeio, "open_regular", lambda *a, **k: pytest.fail("입력 open 금지"))
    failure(case, entry, deadline=time.monotonic() + 500, code="template_input_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("field,value", [("producer", "pweh-forensics"), ("kind", "other"), ("size", True),
    ("size", 1.0), ("size", 0), ("sha256", "A" * 64), ("sha256", "a" * 64 + "\n"), ("is_dir", 0),
    ("is_dir", True), ("path", "analysis/image-hints-000.json"), ("path", "analysis/image-hints-0001.json"),
    ("path", "forensics/analysis/image-hints-001.json"), ("path", "analysis/../image-hints-001.json"),
    ("path", "analysis/image-hints-001.json\n"), ("path", "analysis/image-hints-100000.json")])
def test_report_index_admission(case, field, value, stub):
    entry = attach(case)
    mutate_index(case, lambda rows: rows[0].update({field: value}))
    failure(case, entry, code="template_input_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("kind", ["missing", "duplicate_id", "duplicate_path", "preview_duplicate_id", "preview_duplicate_path"])
def test_ambiguity_never_silently_selects_one_match(case, kind, stub):
    entry = attach(case)
    def mutate(rows):
        if kind == "missing": rows.pop(0)
        else:
            row = dict(rows[1 if kind.startswith("preview") else 0])
            row["path" if kind.endswith("id") else "id"] = PRIVATE
            rows.append(row)
    mutate_index(case, mutate)
    failure(case, entry, code="template_input_invalid")


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schema="pweh.image-hints-summary/v1"), lambda r: r.update(status="unsupported"),
    lambda r: r.update(source=None), lambda r: r["source"].update(kind="evidence"),
    lambda r: r["source"].update(size=True), lambda r: r["input"].update(size=24),
    lambda r: r["input"].update(sha256="b" * 64), lambda r: r["source"].update(path=1),
    lambda r: r.update(artifacts=[]), lambda r: r["artifacts"].update(previews=[]),
    lambda r: r["artifacts"]["previews"].append(dict(r["artifacts"]["previews"][0])),
    lambda r: r["artifacts"]["previews"][0].update(role="thumbnail"),
    lambda r: r["artifacts"]["previews"][0].update(path="analysis/image-hints-002-01-overview.png"),
    lambda r: r["artifacts"]["previews"][0].update(width=True),
    lambda r: r["artifacts"]["previews"][0].update(width=1601),
    lambda r: r["artifacts"]["previews"][0].update(width=1),
    lambda r: r["artifacts"]["previews"][0].update(size=0),
])
def test_stored_report_required_fields_are_not_summary_schema(case, mutate, stub):
    entry = attach(case)
    rewrite(case, entry, mutate)
    failure(case, entry, code="template_input_invalid")


@pytest.mark.parametrize("data", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\\ud800"}',
                                  b'\xff', b'[' * 1500 + b']' * 1500])
def test_json_duplicate_nonfinite_unicode_recursion_are_fixed(case, data, stub):
    entry = attach(case)
    rewrite(case, entry, data=data)
    failure(case, entry, code="template_input_invalid")


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize("change", ["content", "writable", "hardlink", "symlink", "size", "hash"])
def test_input_fd_integrity_before_worker(case, which, change, stub):
    entry = attach(case)
    row = case.artifacts()[which]
    path = case.dir / row["path"]
    if change == "content":
        original = path.read_bytes()
        path.chmod(0o600); path.write_bytes(b"X" + original[1:]); path.chmod(0o444)
    elif change == "writable": path.chmod(0o644)
    elif change == "hardlink": os.link(path, path.with_suffix(".other"))
    elif change == "symlink":
        other = path.with_suffix(".other"); path.rename(other); path.symlink_to(other.name)
    else: mutate_index(case, lambda rows: rows[which].update({change if change == "size" else "sha256": 1 if change == "size" else "b" * 64}))
    failure(case, entry)
    assert not outputs(case)


@pytest.mark.parametrize("kind", ["name", "content", "index", "parent", "root"])
def test_mutation_during_worker_prevents_commit(case, monkeypatch, stub, kind):
    entry = attach(case)
    def changed(*args, **kwargs):
        result = stub(*args, **kwargs)
        path = case.dir / entry["path"]
        if kind == "name":
            data = path.read_bytes(); path.rename(path.with_suffix(".old")); path.write_bytes(data); path.chmod(0o444)
        elif kind == "content":
            path.chmod(0o600); path.write_bytes(path.read_bytes().replace(b'"ok"', b'"xx"')); path.chmod(0o444)
        elif kind == "index": mutate_index(case, lambda rows: rows[1].update(producer=PRIVATE))
        else:
            path = case.dir / "analysis" if kind == "parent" else case.dir
            path.rename(path.with_name(path.name + "-old")); path.mkdir()
        return result
    monkeypatch.setattr(A.imagehints, "match_png_rois", changed)
    failure(case, entry)
    rows = (json.loads((case.dir.with_name(case.dir.name + "-old") / "case.json").read_bytes())["artifacts"]
            if kind == "root" else case.artifacts())
    assert not any(row.get("extra", {}).get("type") == "template-match" for row in rows)


@pytest.mark.parametrize("field,value", [("sum_abs", True), ("samples", 12.0), ("samples", 11),
    ("sum_abs", -1), ("sum_abs", 4000), ("mean_abs_error", True), ("mean_abs_error", float("nan")),
    ("mean_abs_error", float("inf")), ("mean_abs_error", 1), ("matched", 1), ("matched", False)])
def test_worker_response_relation_failure_is_closed(case, monkeypatch, stub, field, value):
    entry = attach(case)
    def changed(*args, **kwargs):
        result = stub(*args, **kwargs); result[field] = value; return result
    monkeypatch.setattr(A.imagehints, "match_png_rois", changed)
    failure(case, entry, code="template_output_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("code", ["template_input_invalid", "template_failed", "time_limit", "cancelled", "private_error"])
def test_child_error_fixed_projection(case, monkeypatch, code):
    entry = attach(case)
    def bad(*args, **kwargs): raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE})
    monkeypatch.setattr(A.imagehints, "match_png_rois", bad, raising=False)
    failure(case, entry, code=code if code in A._CODES else "template_failed")


@pytest.mark.parametrize("phase", ["input", "child", "final_hash", "last_seal"])
def test_cancel_before_commit_cleans_owned_output(case, monkeypatch, stub, phase):
    entry = attach(case); event = threading.Event()
    if phase == "input": event.set()
    elif phase == "child":
        def compare(*a, **k): event.set(); return stub(*a, **k)
        monkeypatch.setattr(A.imagehints, "match_png_rois", compare)
    elif phase == "final_hash":
        original = A._read_fd
        def read(*a, **k):
            result = original(*a, **k)
            if not k.get("collect", False): event.set()
            return result
        monkeypatch.setattr(A, "_read_fd", read)
    else:
        original = A._check_file
        def check(fd, parent, name, seal, **kw):
            original(fd, parent, name, seal, **kw)
            if name.startswith("template-match"):
                check.n += 1
                if check.n == 2: event.set()
        check.n = 0
        monkeypatch.setattr(A, "_check_file", check)
    failure(case, entry, code="cancelled", cancel_event=event)
    assert not outputs(case)


def test_same_end_and_event_no_final_extension(case, monkeypatch, stub):
    entry = attach(case); event = threading.Event(); now = [time.monotonic()]; end = now[0] + 5
    monkeypatch.setattr(A, "time", SimpleNamespace(monotonic=lambda: now[0]))
    def compare(*args, **kw):
        assert kw["deadline"] == end and kw["cancel_event"] is event
        now[0] = end
        return stub(*args, **kw)
    monkeypatch.setattr(A.imagehints, "match_png_rois", compare)
    failure(case, entry, deadline=end, cancel_event=event, code="time_limit")
    assert not outputs(case)


@pytest.mark.parametrize("field,value", [("size", 1), ("size", True), ("sha256", "b" * 64),
                                        ("path", "analysis/other.json"), ("is_dir", 0)])
def test_check_entry_uses_fd_facts(case, monkeypatch, stub, field, value):
    entry = attach(case); original = case.register_artifact
    def register(*args, **kw):
        real = kw["check"]
        kw["check"] = lambda row: real({**row, field: value})
        return original(*args, **kw)
    monkeypatch.setattr(case, "register_artifact", register)
    failure(case, entry, code="template_output_invalid")
    assert not outputs(case)


def test_input_changed_during_output_hash_is_rechecked(case, monkeypatch, stub):
    entry = attach(case); original = A._read_fd
    def read(fd, *args, **kw):
        result = original(fd, *args, **kw)
        if "template-match" in os.readlink(f"/proc/self/fd/{fd}"):
            path = case.dir / entry["path"]
            path.chmod(0o644)
        return result
    monkeypatch.setattr(A, "_read_fd", read)
    failure(case, entry, code="template_input_changed")
    assert not outputs(case)


@pytest.mark.parametrize("kind", ["audit", "late_cancel", "close", "audit_close"])
def test_committed_receipt_survives_late_failures(case, monkeypatch, stub, kind):
    entry = attach(case); event = threading.Event()
    if "audit" in kind or kind == "late_cancel":
        original = case.audit
        def audit(value):
            if value.get("event") == "artifact_registered":
                if kind == "late_cancel": event.set()
                else: raise RuntimeError(PRIVATE)
            return original(value)
        monkeypatch.setattr(case, "audit", audit)
    if "close" in kind:
        original_close = os.close
        def close(fd):
            name = os.readlink(f"/proc/self/fd/{fd}")
            original_close(fd)
            if "template-match" in name: raise OSError(PRIVATE)
        monkeypatch.setattr(A.os, "close", close)
    result = analyze(case, entry, cancel_event=event)
    expected = (["post_commit_callback_failed"] if "audit" in kind else []) + (["output_close_unconfirmed"] if "close" in kind else [])
    assert result["warnings"] == expected and result["ok"]
    assert outputs(case) and case.artifacts()[-1]["id"] == result["artifact_id"]


def test_replaced_output_is_not_unlinked(case, monkeypatch, stub):
    entry = attach(case)
    def register(relative, **kwargs):
        path = case.dir / relative
        path.rename(path.with_suffix(".owned")); path.write_bytes(PRIVATE.encode())
        raise RuntimeError(PRIVATE)
    monkeypatch.setattr(case, "register_artifact", register)
    failure(case, entry, code="template_cleanup_incomplete")
    assert outputs(case)[0].read_bytes() == PRIVATE.encode()


def test_all_input_and_output_fds_close_after_precommit_failure(case, monkeypatch, stub):
    entry = attach(case); seen = []; original = A.safeio.open_regular
    def open_regular(*args, **kw):
        result = original(*args, **kw); seen.append(result[0]); return result
    monkeypatch.setattr(A.safeio, "open_regular", open_regular)
    monkeypatch.setattr(case, "register_artifact", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(PRIVATE)))
    failure(case, entry, code="template_failed")
    assert len(seen) == 4 and not outputs(case)
    for fd in seen:
        with pytest.raises(OSError): os.fstat(fd)
