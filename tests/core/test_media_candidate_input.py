"""합성 보관 보고서의 선택·범위·held fd·최종 사건 결속 시험."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import struct
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from pweh import evidence as E, media_candidate_input as I
from pweh.case import CaseStore
from pweh.errors import PwehError
from pweh.media_candidates import scan_bmff_candidates

PRIVATE = "SYNTHETIC_PRIVATE_PREFIX_7d8c"


def box(kind, payload=b""):
    return struct.pack(">I4s", len(payload) + 8, kind) + payload


CONTENT = b"prefix" + box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", b"synthetic")


def report_for(data, ev, intake):
    report = scan_bmff_candidates(data, deadline=time.monotonic() + 20)
    report["source"] = {
        "kind": "evidence", "evidence_id": ev, "evidence_sha256": intake["hashes"]["sha256"],
        "container": "file", "member_selected": False,
        "selected_sha256": hashlib.sha256(data).hexdigest(), "selected_size": len(data),
        "complete": True, "method": "whole-file", "confidence": "high", "partition": None, "ref": None,
        "deleted": None, "parent_deleted": None, "container_truncated": None, "container_truncated_reasons": [],
    }
    report["params"] = {"partition": None, "method": "auto", "max_seconds": 45.0}
    return report


@pytest.fixture
def prepared(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 prefix 입력", authorization=auth, case_id="prefix-input")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(data=CONTENT, mutate=None, raw=None):
            ev = _commit_intake(case, log, data)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            report = report_for(data, ev, opened.intake)
            stored = E.store_analysis(case, opened, report, event="media-candidates", custody_log=log)
            path = stored["analysis"]["path"]
            if mutate:
                mutate(report)
                raw = (json.dumps(report) + "\n").encode()
            if raw is not None:
                # 잘못된 JSON도 hash를 결속한 합성 사건으로만 만든다.
                target = case.dir / path
                target.chmod(0o644)
                target.write_bytes(raw)
                target.chmod(0o444)
                entries = log.entries()
                entries[-1]["data"]["analysis"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                if mutate:
                    entries[-1]["data"].update(source=copy.deepcopy(report["source"]),
                                                params=copy.deepcopy(report["params"]), status=report["status"])
            else:
                entries = None
            return SimpleNamespace(case=case, log=log, opened=opened, report=report, path=path, entries=entries)
        yield make


def load(value, **updates):
    args = dict(analysis_path=value.path, candidate_index=0,
                entries=value.entries if value.entries is not None else value.log.entries(),
                deadline=time.monotonic() + 20, cancel=lambda: False)
    args.update(updates)
    return I.open_media_candidate(value.case, value.opened, **args)


def test_real_stored_report_origin_and_fd_lifetime(prepared, monkeypatch):
    value = prepared()
    calls = []
    original = I.safeio.open_regular
    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(I.safeio, "open_regular", counted)
    with load(value) as candidate:
        assert candidate.source == value.report["source"]
        assert candidate.candidate == value.report["candidates"][0]
        assert candidate.coverage == value.report["coverage"]
        assert candidate.origin.to_dict() == {
            **value.log.entries()[-1]["data"]["analysis"],
            "custody_seq": value.log.entries()[-1]["seq"],
            "custody_hash": E.entry_hash(value.log.entries()[-1]),
        }
        fds = [candidate._fd, *candidate._dirs]
        candidate.check()
        candidate.check_entries(value.log.entries())
        assert calls.count(value.path.rsplit("/", 1)[1]) == 1  # 같은 열린 fd를 재해시한다.
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("index", [True, False, "0", 0.0, -1, 128, 1])
def test_index_exact_and_in_range(prepared, index):
    with pytest.raises(PwehError) as error:
        with load(prepared(), candidate_index=index):
            pass
    assert error.value.code == "media_prefix_input_invalid"


@pytest.mark.parametrize("path", ["/forensics/analysis/x.json", "../" + PRIVATE, PRIVATE,
                                 "forensics/analysis/media-candidates-EV-9999-001.json",
                                 "forensics/analysis/media-inventory-EV-0001-001.json"])
def test_generated_same_ev_path_only(prepared, path, monkeypatch):
    value = prepared()
    value.entries = value.log.entries()
    monkeypatch.setattr(I.safeio, "open_dir_chain", lambda *a, **k: pytest.fail("입력 거부 전 파일 열기"))
    with pytest.raises(PwehError) as error:
        with load(value, analysis_path=path):
            pass
    assert PRIVATE not in str(error.value) and not error.value.data


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(profile=PRIVATE),
    lambda r: r.update(status="unsupported"),
    lambda r: r["source"].update(selected_size=0, method="empty"),
    lambda r: r["source"].update(evidence_sha256="0" * 64),
    lambda r: r["source"].update(evidence_id="EV-9999"),
    lambda r: r["source"].update(selected_size=(64 << 20) + 1),
    lambda r: r["coverage"].update(input_bytes=1),
    lambda r: r["summary"].update(candidates_reported=2),
    lambda r: r["candidates"][0].update(index=1),
    lambda r: r["candidates"][0].update(index=0.0),
    lambda r: r["candidates"][0].update(offset=True),
    lambda r: r["candidates"][0].update(offset=len(CONTENT)),
    lambda r: r["candidates"][0].update(validated_prefix_length=16.0),
    lambda r: r["candidates"][0].update(boxes_validated=5),
    lambda r: r["candidates"][0].update(overlap_with_reported=[1]),
    lambda r: r["candidates"][0].update(contained_by_reported=[0]),
    lambda r: r["coverage"].update(reasons=["time_limit"]),
    lambda r: r["candidates"][0].update(framing_status="partial", end_reason="truncated_header"),
])
def test_semantic_or_schema_invalid_stored_rows(prepared, mutate):
    value = prepared(mutate=mutate)
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == "media_prefix_input_invalid"
    assert PRIVATE not in str(error.value) and not error.value.data


def test_partial_report_keeps_original_candidate_and_coverage(prepared):
    value = prepared(data=CONTENT + b"\0")
    assert value.report["status"] == "partial"
    with load(value) as candidate:
        assert candidate.upstream_status == "partial"
        assert candidate.candidate["validated_prefix_length"] == len(CONTENT) - 6
        assert candidate.coverage == value.report["coverage"]


@pytest.mark.parametrize("raw", [b'{"private":NaN}', b'{"private":1,"private":2}', b'{"a":"\xff"}',
                                  b'{"a":"\\ud800"}', b'{"a":' + b'[' * 40 + b'0' + b']' * 40 + b'}'])
def test_bounded_strict_json_fixed_error(prepared, raw):
    with pytest.raises(PwehError) as error:
        with load(prepared(raw=raw)):
            pass
    assert error.value.code in {"media_prefix_input_invalid", "media_prefix_input_limit"}
    assert "private" not in str(error.value)


@pytest.mark.parametrize("kind", ["none", "duplicate", "wrong-case", "source", "params", "status", "sha", "size", "seq"])
def test_upstream_event_unique_and_exact(prepared, kind):
    value = prepared()
    entries = value.log.entries()
    event = entries[-1]
    if kind == "none":
        entries.pop()
    elif kind == "duplicate":
        entries.append(copy.deepcopy(event))
    elif kind == "wrong-case":
        event["case_id"] = "other"
    elif kind in {"source", "params", "status"}:
        event["data"][kind] = PRIVATE
    elif kind in {"sha", "size"}:
        event["data"]["analysis"]["sha256" if kind == "sha" else "size"] = "0" * 64 if kind == "sha" else 10
    else:
        event["seq"] = True
    with pytest.raises(PwehError):
        with load(value, entries=entries):
            pass


@pytest.mark.parametrize("kind", ["writable", "hardlink", "symlink", "over-limit"])
def test_report_file_boundaries(prepared, kind):
    value = prepared()
    path = value.case.dir / value.path
    if kind == "writable":
        path.chmod(0o644)
    elif kind == "hardlink":
        os.link(path, path.with_suffix(".alias"))
    elif kind == "symlink":
        other = path.with_suffix(".held")
        path.rename(other)
        path.symlink_to(other.name)
    else:
        path.chmod(0o644)
        with path.open("wb") as f:
            f.truncate(I.MAX_REPORT_BYTES + 1)
        path.chmod(0o444)
    with pytest.raises(PwehError):
        with load(value):
            pass


@pytest.mark.parametrize("kind", ["file", "parent", "ancestor", "root", "same-inode"])
def test_final_identity_change_is_rejected(prepared, kind):
    value = prepared()
    path = value.case.dir / value.path
    with load(value) as candidate:
        if kind == "same-inode":
            path.chmod(0o644)
            raw = bytearray(path.read_bytes())
            raw[0] ^= 1
            path.write_bytes(raw)
            path.chmod(0o444)
        elif kind == "file":
            raw = path.read_bytes()
            path.rename(path.with_suffix(".old"))
            path.write_bytes(raw)
            path.chmod(0o444)
        else:
            directory = path.parent if kind == "parent" else path.parent.parent if kind == "ancestor" else value.case.dir
            directory.rename(directory.with_name(directory.name + "-held"))
            directory.mkdir()
        with pytest.raises(PwehError) as error:
            candidate.check()
        assert error.value.code == "media_prefix_input_changed"


def test_final_check_rehashes_even_if_metadata_comparison_is_stubbed(prepared, monkeypatch):
    value = prepared()
    path = value.case.dir / value.path
    with load(value) as candidate:
        path.chmod(0o644)
        raw = bytearray(path.read_bytes())
        raw[0] ^= 1
        path.write_bytes(raw)
        monkeypatch.setattr(candidate, "_names", lambda: None)
        with pytest.raises(PwehError) as error:
            candidate.check()
        assert error.value.code == "media_prefix_input_changed"


@pytest.mark.parametrize("kind", ["missing", "duplicate", "params", "status", "source", "hash"])
def test_final_custody_check_uses_private_initial_hash(prepared, kind):
    value = prepared()
    with load(value) as candidate:
        entries = value.log.entries()
        if kind == "missing":
            entries.pop()
        elif kind == "duplicate":
            entries.append(copy.deepcopy(entries[-1]))
        elif kind == "hash":
            entries[-1]["hash"] = "0" * 64
        else:
            entries[-1]["data"][kind] = PRIVATE
        candidate.source.clear()
        candidate.params.clear()
        with pytest.raises(PwehError) as error:
            candidate.check_entries(entries)
        assert error.value.code == "media_prefix_input_changed"


@pytest.mark.parametrize("args,code", [({"cancel": lambda: True}, "cancelled"),
                                      ({"deadline": 0}, "timeout"),
                                      ({"deadline": 10 ** 400}, "media_prefix_input_invalid")])
def test_budget_fixed_errors(prepared, args, code):
    with pytest.raises(PwehError) as error:
        with load(prepared(), **args):
            pass
    assert error.value.code == code


def test_late_cancel_applies_to_both_final_checks(prepared):
    value, cancelled = prepared(), False
    with load(value, cancel=lambda: cancelled) as candidate:
        cancelled = True
        for check in (candidate.check, lambda: candidate.check_entries(value.log.entries())):
            with pytest.raises(PwehError) as error:
                check()
            assert error.value.code == "cancelled"
