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
from pweh import evidence as E, dhav_candidate_input as I
from pweh.case import CaseStore
from pweh.errors import PwehError
from pweh import dhav

PRIVATE = "SYNTHETIC_PRIVATE_RECORD_7d8c"


def record(kind=0xF0, payload=b"synthetic", extension=b""):
    header = bytearray(24)
    header[:4], header[4], header[22] = b"DHAV", kind, len(extension)
    length = 32 + len(extension) + len(payload)
    struct.pack_into("<I", header, 12, length)
    return bytes(header) + extension + payload + b"dhav" + struct.pack("<I", length)


CONTENT = b"prefix" + record()


def report_for(data, ev, intake, *, offset=None):
    report = dhav.scan_dhav_candidates(data, deadline=time.monotonic() + 20)
    report["source"] = {
        "kind": "evidence", "evidence_id": ev, "evidence_sha256": intake["hashes"]["sha256"],
        "container": "file", "member_selected": False,
        "selected_sha256": hashlib.sha256(data).hexdigest(), "selected_size": len(data),
        "complete": True, "method": "whole-file", "confidence": "high", "partition": None, "ref": None,
        "deleted": None, "parent_deleted": None, "container_truncated": None, "container_truncated_reasons": [],
    }
    report["params"] = {"partition": None, "method": "auto", "max_seconds": 45.0}
    if offset is not None:
        report["profile"] = dhav.RANGE_PROFILE
        report["source"].update(method="byte-range", offset=offset, evidence_size=intake["size"])
        report["params"].update(offset=offset, length=len(data))
        report["limitations"] += list(dhav.RANGE_LIMITATIONS)
    return report


@pytest.fixture
def prepared(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 record 입력", authorization=auth, case_id="dhav-input")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(data=CONTENT, mutate=None, raw=None, selected=None, offset=None):
            ev = _commit_intake(case, log, data)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            report = report_for(data if selected is None else selected, ev, opened.intake, offset=offset)
            stored = E.store_analysis(case, opened, report, event="dhav-candidates", custody_log=log)
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
    return I.open_dhav_candidate(value.case, value.opened, **args)


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
    assert error.value.code == "dhav_record_input_invalid"


@pytest.mark.parametrize("path", ["/forensics/analysis/x.json", "../" + PRIVATE, PRIVATE,
                                 "forensics/analysis/dhav-candidates-EV-9999-001.json",
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
    lambda r: r["candidates"][0].update(record_length=41.0),
    lambda r: r["candidates"][0].update(header_length=25),
    lambda r: r["candidates"][0].update(payload_length=999),
    lambda r: r["candidates"][0].update(footer_length_matches=False),
    lambda r: r["coverage"].update(reasons=["time_limit"]),
    lambda r: r["summary"]["anchor_rejections"].update(empty_payload=1),
])
def test_semantic_or_schema_invalid_stored_rows(prepared, mutate):
    value = prepared(mutate=mutate)
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == "dhav_record_input_invalid"
    assert PRIVATE not in str(error.value) and not error.value.data


def test_partial_report_keeps_original_candidate_and_coverage(prepared):
    value = prepared(data=CONTENT + b"DHAV")
    assert value.report["status"] == "partial"
    with load(value) as candidate:
        assert candidate.upstream_status == "partial"
        assert candidate.candidate["record_length"] == len(CONTENT) - 6
        assert candidate.coverage == value.report["coverage"]


@pytest.mark.parametrize("raw", [b'{"private":NaN}', b'{"private":1,"private":2}', b'{"a":"\xff"}',
                                  b'{"a":"\\ud800"}', b'{"a":' + b'[' * 40 + b'0' + b']' * 40 + b'}'])
def test_bounded_strict_json_fixed_error(prepared, raw):
    with pytest.raises(PwehError) as error:
        with load(prepared(raw=raw)):
            pass
    assert error.value.code in {"dhav_record_input_invalid", "dhav_record_input_limit"}
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
        assert error.value.code == "dhav_record_input_changed"


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
        assert error.value.code == "dhav_record_input_changed"


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
        assert error.value.code == "dhav_record_input_changed"


@pytest.mark.parametrize("args,code", [({"cancel": lambda: True}, "cancelled"),
                                      ({"deadline": 0}, "timeout"),
                                      ({"deadline": 10 ** 400}, "dhav_record_input_invalid")])
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


@pytest.mark.parametrize("kind", [0xF0, 0xFC, 0xFD])
def test_minimum_and_extension_record_selection_reuses_no_scanner(prepared, monkeypatch, kind):
    data = record(kind, b"x") + record(kind, b"x", b"E" * 255)
    value = prepared(data=data)
    monkeypatch.setattr(dhav, "scan_dhav_candidates", lambda *a, **k: pytest.fail("후보 재검색"))
    with load(value, candidate_index=1) as candidate:
        assert candidate.candidate["index"] == 1
        assert candidate.candidate["offset"] == 33
        assert candidate.candidate["extension_length"] == 255
        assert candidate.source["selected_sha256"] == hashlib.sha256(data).hexdigest()


def test_nested_record_selects_exact_stored_row_without_reconstruction(prepared):
    inner = record(0xFC)
    value = prepared(data=record(payload=b"xx" + inner))
    with load(value, candidate_index=1) as candidate:
        assert candidate.candidate == value.report["candidates"][1]
        assert candidate.candidate["offset"] == 26
        assert candidate.candidate["record_length"] == len(inner)


def test_core_accounting_checks_all_rows_not_only_selected_row(prepared, monkeypatch):
    value = prepared(data=record() * 2)
    calls = []
    original = dhav.validate_dhav_accounting

    def counted(report):
        calls.append(len(report["candidates"]))
        return original(report)

    monkeypatch.setattr(dhav, "validate_dhav_accounting", counted)
    with load(value):
        pass
    assert calls == [2]
    value = prepared(data=record() * 2, mutate=lambda r: r["candidates"][1].update(payload_length=5))
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == "dhav_record_input_invalid"


@pytest.mark.parametrize("mutation", [
    lambda r: r["source"].update(selected_size=47.0),
    lambda r: r["coverage"].update(anchor_probes=1.0),
    lambda r: r["summary"].update(anchors_observed=True),
    lambda r: r["coverage"].update(search_complete=False),
    lambda r: r["coverage"].update(candidate_checks_complete=False),
    lambda r: r["coverage"].update(candidate_list_complete=False),
    lambda r: r["candidates"][0].update(record_type="type_f1"),
    lambda r: r["candidates"][0].update(confidence="confirmed"),
    lambda r: r["candidates"][0].update(extension_length=256),
    lambda r: r["candidates"][0].update(validated_prefix_length=16),
    lambda r: r.update(schema="pweh.media-candidates/v1"),
    lambda r: r.update(profile="ftyp-contiguous-prefix-v1"),
])
def test_dhav_full_schema_accounting_and_type_boundary(prepared, mutation):
    with pytest.raises(PwehError) as error:
        with load(prepared(mutate=mutation)):
            pass
    assert error.value.code == "dhav_record_input_invalid"


@pytest.mark.parametrize("data", [b"", b"x" * 32, b"DHAV", record(0xF1), record(payload=b"")])
def test_no_stored_candidate_cannot_be_extracted(prepared, data):
    with pytest.raises(PwehError):
        with load(prepared(data=data)):
            pass


def test_range_origin_keeps_both_offsets_without_adding_them(prepared):
    selected = b"abcde" + record()
    offset = 100
    value = prepared(data=b"A" * offset + selected + b"Z" * 100, selected=selected, offset=offset)
    with load(value) as candidate:
        assert candidate.source["offset"] == candidate.params["offset"] == 100
        assert candidate.candidate["offset"] == 5
        assert candidate.params["length"] == len(selected)
        assert candidate.source["evidence_size"] == 200 + len(selected)
        candidate.check()
        candidate.check_entries(value.log.entries())


@pytest.mark.parametrize("section,key,value", [
    ("source", "offset", -1), ("source", "offset", 100.0), ("source", "offset", True),
    ("source", "offset", (1 << 63) - 1), ("source", "selected_size", 33),
    ("source", "evidence_size", 0), ("source", "evidence_size", 999),
    ("source", "evidence_size", 247.0), ("params", "offset", 101),
    ("params", "offset", 100.0), ("params", "offset", True),
    ("params", "length", 0), ("params", "length", 47.0), ("params", "length", True),
])
def test_range_source_params_and_evidence_size_exact(prepared, section, key, value):
    selected = CONTENT
    mutate = lambda r: r[section].update({key: value})
    item = prepared(data=b"A" * 100 + selected + b"Z" * 100, selected=selected, offset=100, mutate=mutate)
    with pytest.raises(PwehError) as error:
        with load(item):
            pass
    assert error.value.code == "dhav_record_input_invalid"


def test_range_live_fd_size_is_compared_independently(prepared, monkeypatch):
    value = prepared(data=b"A" * 100 + CONTENT, selected=CONTENT, offset=100)
    original = os.fstat

    def changed(fd):
        st = original(fd)
        if fd == value.opened.fd:
            return SimpleNamespace(st_size=st.st_size + 1)
        return st

    monkeypatch.setattr(I.os, "fstat", changed)
    with pytest.raises(PwehError):
        with load(value):
            pass


@pytest.mark.parametrize("value", [0, 1, None, "PRIVATE", object()])
def test_callback_requires_exact_boolean(prepared, value):
    with pytest.raises(PwehError) as error:
        with load(prepared(), cancel=lambda: value):
            pass
    assert error.value.code == "dhav_record_input_invalid"
    assert PRIVATE not in str(error.value) and not error.value.data


def test_callback_failure_is_fixed_and_no_raw_exception_chain(prepared):
    def cancel():
        raise RuntimeError(PRIVATE)

    with pytest.raises(PwehError) as error:
        with load(prepared(), cancel=cancel):
            pass
    assert error.value.code == "dhav_record_input_invalid" and error.value.__cause__ is None
    assert PRIVATE not in str(error.value) and not error.value.data


def test_report_reads_use_same_fd_and_at_most_64k_chunks(prepared, monkeypatch):
    value = prepared()
    path = value.case.dir / value.path
    raw = path.read_bytes() + b" " * (150 << 10)
    path.chmod(0o644)
    path.write_bytes(raw)
    path.chmod(0o444)
    value.entries = value.log.entries()
    value.entries[-1]["data"]["analysis"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    original, reads = I.os.pread, []

    def read(fd, size, offset):
        reads.append((fd, size, offset))
        return original(fd, size, offset)

    monkeypatch.setattr(I.os, "pread", read)
    with load(value) as candidate:
        assert {fd for fd, _, _ in reads} == {candidate._fd}
        assert max(size for _, size, _ in reads) == 64 << 10
        reads.clear()
        candidate.check()
        assert {fd for fd, _, _ in reads} == {candidate._fd}
        assert sum(size for _, size, _ in reads) == len(raw)


def test_admission_failure_closes_owned_report_fd(prepared, monkeypatch):
    value = prepared(raw=b'{"bad":NaN}')
    opened, original = [], I.safeio.open_regular

    def track(*args, **kwargs):
        result = original(*args, **kwargs)
        opened.append(result[0])
        return result

    monkeypatch.setattr(I.safeio, "open_regular", track)
    with pytest.raises(PwehError):
        with load(value):
            pass
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_unrelated_analysis_creation_does_not_invalidate_parent_seal(prepared):
    value = prepared()
    with load(value) as candidate:
        (value.case.dir / "forensics" / "analysis" / "unrelated.json").write_bytes(b"{}")
        candidate.check()


def test_final_event_check_does_not_reopen_custody(prepared, monkeypatch):
    value = prepared()
    entries = value.log.entries()
    with load(value) as candidate:
        monkeypatch.setattr(E.CustodyLog, "entries", lambda *a, **k: pytest.fail("중첩 custody 읽기"))
        candidate.check_entries(entries)
