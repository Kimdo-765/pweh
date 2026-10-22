"""합성 JSON만 사용하는 SD 대조 입력 제한·권위 결속·파일 경합 회귀."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time

import pytest

from core.test_evidence import _commit_intake
from pweh import evidence as E, sdioc_input as I
from pweh.case import CaseStore
from pweh.errors import PwehError


def parse(raw):
    return I.load_json(raw, deadline=time.monotonic() + 20, cancel=lambda: False)


def test_preflight_quotes_escapes_unicode_and_structural_text():
    value = {"k": 'brace {[,] and quote " and slash \\ 끝', "a": [True, False, None, -1.23e4]}
    for ascii_only in (True, False):
        assert parse(json.dumps(value, ensure_ascii=ascii_only).encode()) == value


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'{"a":NaN}', b'{"a":Infinity}',
                                  b'{"a":1e999}', b'{"a":-Infinity}', b'{"a":"\\ud800"}', b'{"a":"\xff"}',
                                  b'\xef\xbb\xbf{}', b'{"a":"\\x20"}', b'{"a":"\\u00Q0"}', b'{"a":"x\n"}',
                                  b'{"a":"unfinished', b'{"a": [}', b'{"a":+1}', b'{"a":01}', b'{"a":true false}',
                                  b'[]', b'{"secret-marker": }'])
def test_invalid_json_never_echoes_input(raw):
    with pytest.raises(PwehError) as error:
        parse(raw)
    assert error.value.code == "sdioc_input_invalid"
    assert "secret-marker" not in str(error.value)


@pytest.mark.parametrize("kind", ["nodes", "containers", "depth", "structure", "string", "strings", "number", "size"])
def test_limits_precede_json_parser(monkeypatch, kind):
    if kind == "nodes":
        monkeypatch.setattr(I, "MAX_NODES", 5)
        raw = b'{"a":[0,0,0,0]}'
    elif kind == "containers":
        raw = b'{"a":[' + b'{},' * I.MAX_CONTAINERS + b'{}]}'
    elif kind == "depth":
        raw = b'{"a":' + b'[' * I.MAX_DEPTH + b'0' + b']' * I.MAX_DEPTH + b'}'
    elif kind == "structure":
        monkeypatch.setattr(I, "MAX_STRUCTURAL", 3)
        raw = b'{"a":[]}'
    elif kind == "string":
        raw = b'{"a":"' + b'x' * (I.MAX_STRING_BYTES + 1) + b'"}'
    elif kind == "strings":
        monkeypatch.setattr(I, "MAX_STRINGS_BYTES", 7)
        raw = b'{"a":"1234","b":"5678"}'
    elif kind == "number":
        raw = b'{"a":' + b'1' * (I.MAX_NUMBER_BYTES + 1) + b'}'
    else:
        monkeypatch.setattr(I, "MAX_REPORT_BYTES", 4)
        raw = b'{"a":0}'

    def forbidden(*args, **kwargs):
        pytest.fail("상한 초과 입력에서 json.loads를 호출했다")

    monkeypatch.setattr(I.json, "loads", forbidden)
    with pytest.raises(PwehError) as error:
        parse(raw)
    assert error.value.code == "sdioc_input_limit"


def test_depth_boundary_and_string_structure_not_counted(monkeypatch):
    raw = b'{"a":' + b'[' * (I.MAX_DEPTH - 1) + b'0' + b']' * (I.MAX_DEPTH - 1) + b'}'
    assert isinstance(parse(raw), dict)
    monkeypatch.setattr(I, "MAX_STRUCTURAL", 3)
    assert parse(b'{"a":"{}[],:"}') == {"a": "{}[],:"}


@pytest.mark.parametrize("body", [b" " * 10000 + b"{}", b'{"a":"' + b"x" * 10000 + b'"}'])
def test_preflight_checks_cancel_inside_long_regions(monkeypatch, body):
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        return calls >= 2

    monkeypatch.setattr(I.json, "loads", lambda *a, **kw: pytest.fail("취소 후 JSON 파싱"))
    with pytest.raises(PwehError) as error:
        I.load_json(body, deadline=time.monotonic() + 30, cancel=cancel)
    assert error.value.code == "cancelled" and calls == 2


def test_input_deadline_before_json():
    with pytest.raises(PwehError) as error:
        I.load_json(b"{}", deadline=time.monotonic() - 1, cancel=lambda: False)
    assert error.value.code == "timeout"


@pytest.fixture
def inputs_case(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(title="합성 SD 입력", authorization=auth, case_id="ioc-input")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    ev = _commit_intake(case, log, b"synthetic image bytes\n")
    fw = "analysis/sd-surface-001.json"
    li = f"forensics/analysis/fs-list-{ev}-001.json"
    firmware = {"schema": "pweh.fwtriage.sd-surface/v1", "tool": "fw_sd_surface", "producer": "fwtriage-mcp 0.1.0",
                "case_id": case.id, "sd_paths_referenced": [], "mount_points": [], "sd_paths_total": 0,
                "sd_paths_truncated": False, "timed_out": False, "private-extra": "synthetic private marker"}
    listing = {"schema": "pweh.forensics.fs-list/v1", "evidence_id": ev, "params": {"include_deleted": True},
               "volumes": [], "call": {}, "private-extra": "synthetic private marker"}
    (case.dir / fw).write_text(json.dumps(firmware), encoding="utf-8")
    case.register_artifact(fw, kind="triage-report", producer="fwtriage-mcp")
    (case.dir / li).parent.mkdir(exist_ok=True)
    (case.dir / li).write_text(json.dumps(listing), encoding="utf-8")
    (case.dir / li).chmod(0o444)
    log.append("list", evidence_id=ev, data={"result_path": li, "result_sha256": hashlib.sha256((case.dir / li).read_bytes()).hexdigest()})
    with E.open_checked(case, ev, log.entries()) as opened:
        yield case, log, opened, fw, li


def load(context, **kwargs):
    case, log, opened, fw, li = context
    entries = kwargs.pop("entries") if "entries" in kwargs else log.entries()
    args = {"firmware_result_path": fw, "fs_list_path": li, "entries": entries,
            "deadline": time.monotonic() + 20, "cancel": lambda: False, **kwargs}
    return I.open_inputs(case, opened, **args)


def test_input_sources_projection_fd_lifetime_and_single_open(inputs_case, monkeypatch):
    case, log, opened, fw, li = inputs_case
    calls = []
    original = I.safeio.open_regular

    def capture(path, **kwargs):
        calls.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(I.safeio, "open_regular", capture)
    with load(inputs_case) as inputs:
        assert "private-extra" not in inputs.firmware and "private-extra" not in inputs.listing
        assert "synthetic private marker" not in json.dumps(inputs.source)
        assert inputs.source["firmware"]["origin_basis"] == "case-artifact-index"
        assert inputs.source["listing"]["custody_hash"] == E.entry_hash(log.entries()[-1])
        assert inputs.source["evidence_sha256"] == opened.intake["hashes"]["sha256"]
        assert (case.dir / fw).stat().st_mode & 0o200  # 펌웨어 결과의 쓰기 권한을 바꾸지 않는다.
        fds = [r.fd for r in inputs.reports]
        inputs.check()
        inputs.check_entries(log.entries())
    assert calls.count(fw.split("/")[-1]) == 1 and calls.count(li.split("/")[-1]) == 1
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("path", ["/analysis/sd-surface-001.json", "analysis/../analysis/sd-surface-001.json",
                                   "analysis/sd-surface-secret-marker.json", "analysis//sd-surface-001.json", "analysis/sd-surface-001.json\x00"])
def test_input_path_whitelist_before_open(inputs_case, monkeypatch, path):
    monkeypatch.setattr(I.safeio, "open_dir_chain", lambda *a, **kw: pytest.fail("잘못된 경로를 열었다"))
    with pytest.raises(PwehError) as error:
        with load(inputs_case, firmware_result_path=path, entries=[]):
            pass
    assert error.value.code == "sdioc_input_invalid" and "secret-marker" not in str(error.value)


@pytest.mark.parametrize("field,value", [("producer", "other"), ("id", "secret-marker"), ("kind", "other"),
                                         ("is_dir", True), ("size", True), ("size", 1), ("sha256", "0" * 64)])
def test_artifact_authority_fields(inputs_case, field, value):
    case, log, opened, fw, li = inputs_case
    metadata = case.load()
    next(a for a in metadata["artifacts"] if a["path"] == fw)[field] = value
    case.meta_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(PwehError) as error:
        with load(inputs_case):
            pass
    assert error.value.code == "sdioc_input_invalid"


@pytest.mark.parametrize("kind", ["missing", "duplicate", "sha", "ev", "path", "seq"])
def test_listing_custody_authority(inputs_case, kind):
    case, log, opened, fw, li = inputs_case
    entries = log.entries()
    if kind == "missing":
        entries.pop()
    elif kind == "duplicate":
        entries.append(copy.deepcopy(entries[-1]))
    elif kind == "sha":
        entries[-1]["data"]["result_sha256"] = "0" * 64
    elif kind == "ev":
        entries[-1]["evidence_id"] = "EV-9999"
    elif kind == "path":
        entries[-1]["data"]["result_path"] = "forensics/analysis/other.json"
    else:
        entries[-1]["seq"] = True
    with pytest.raises(PwehError):
        with load(inputs_case, entries=entries):
            pass


@pytest.mark.parametrize("kind", ["firmware-schema", "firmware-case", "firmware-tool", "firmware-producer", "listing-schema", "listing-ev", "archive"])
def test_hash_matching_report_with_false_envelope(inputs_case, kind):
    case, log, opened, fw, li = inputs_case
    is_fw = kind.startswith("firmware")
    path = case.dir / (fw if is_fw else li)
    doc = json.loads(path.read_bytes())
    if kind == "archive":
        doc["archive"] = {}
    else:
        field = {"case": "case_id", "ev": "evidence_id"}.get(kind.split("-")[1], kind.split("-")[1])
        doc[field] = "secret-marker"
    path.chmod(0o644)
    path.write_text(json.dumps(doc), encoding="utf-8")
    entries = log.entries()
    if is_fw:
        case.register_artifact(fw, kind="triage-report", producer="fwtriage-mcp")
    else:
        path.chmod(0o444)
        entries[-1]["data"]["result_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(PwehError) as error:
        with load(inputs_case, entries=entries):
            pass
    assert "secret-marker" not in str(error.value)


@pytest.mark.parametrize("which", ["firmware", "listing"])
@pytest.mark.parametrize("mutation", ["replacement", "symlink", "hardlink", "write", "parent", "parent-symlink", "missing"])
def test_final_report_seal_rejects_changes_and_preserves_foreign(inputs_case, tmp_path, which, mutation):
    case, log, opened, fw, li = inputs_case
    path = case.dir / (fw if which == "firmware" else li)
    foreign = tmp_path / "foreign.json"
    foreign.write_bytes(b"synthetic foreign file")
    with load(inputs_case) as inputs:
        st = path.stat()
        if mutation in ("replacement", "symlink", "missing"):
            path.rename(tmp_path / "original.json")
            if mutation == "replacement":
                path.write_bytes(b"synthetic replacement")
            elif mutation == "symlink":
                path.symlink_to(foreign)
        elif mutation == "hardlink":
            os.link(path, tmp_path / "alias.json")
        elif mutation == "write":
            path.chmod(0o644)
            original = path.read_bytes()
            path.write_bytes(b" " + original[1:])
            path.chmod(st.st_mode & 0o777)
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        else:
            directory = path.parent
            directory.rename(directory.with_name(directory.name + "-old"))
            if mutation == "parent":
                directory.mkdir()
            else:
                directory.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(PwehError) as error:
            inputs.check()
        assert error.value.code == "sdioc_input_changed"
    assert foreign.read_bytes() == b"synthetic foreign file"


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "writable", "parent-symlink"])
def test_listing_bad_initial_identity(inputs_case, tmp_path, mutation):
    case, log, opened, fw, li = inputs_case
    path = case.dir / li
    if mutation == "symlink":
        target = tmp_path / "secret-marker.json"
        path.rename(target)
        path.symlink_to(target)
    elif mutation == "hardlink":
        os.link(path, tmp_path / "alias.json")
    elif mutation == "writable":
        path.chmod(0o644)
    else:
        path.parent.rename(tmp_path / "analysis")
        path.parent.symlink_to(tmp_path / "analysis", target_is_directory=True)
    with pytest.raises(PwehError) as error:
        with load(inputs_case):
            pass
    assert "secret-marker" not in str(error.value)


def test_final_entries_recheck_uses_original_seal_and_allows_time_partial(inputs_case):
    case, log, opened, fw, li = inputs_case
    with load(inputs_case) as inputs:
        inputs.deadline = time.monotonic() - 1
        inputs.check()
        inputs.check_entries(log.entries())
        changed = log.entries()
        changed[-1]["data"]["result_sha256"] = "0" * 64
        inputs.source["listing"]["sha256"] = "0" * 64
        inputs.source["listing"]["custody_hash"] = E.entry_hash(changed[-1])
        with pytest.raises(PwehError):
            inputs.check_entries(changed)


def test_commit_uses_entries_seam_and_preserves_partial(inputs_case):
    case, log, opened, fw, li = inputs_case
    with load(inputs_case) as inputs:
        inputs.deadline = time.monotonic() - 1
        report = {"source": inputs.source, "status": "partial", "params": {}}
        result = E.store_analysis(case, opened, report, event="sd-ioc-scan", custody_log=log,
                                  check=inputs.check, check_entries=inputs.check_entries)
    assert result["ok"] and log.entries()[-1]["event"] == "sd-ioc-scan"
    assert json.loads((case.dir / result["analysis"]["path"]).read_bytes())["source"] == report["source"]


def test_total_report_limit_has_fixed_narrowing_hint(inputs_case, monkeypatch):
    monkeypatch.setattr(I, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(PwehError) as error:
        with load(inputs_case):
            pass
    assert error.value.code == "sdioc_input_limit"
    assert "partition" in error.value.hint and "max_entries" in error.value.hint


def test_duplicate_artifact_rejected(inputs_case):
    case, log, opened, fw, li = inputs_case
    metadata = case.load()
    metadata["artifacts"].append(copy.deepcopy(next(a for a in metadata["artifacts"] if a["path"] == fw)))
    case.meta_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(PwehError):
        with load(inputs_case):
            pass


@pytest.mark.parametrize("mutation", ["case-id", "duplicate-id"])
def test_artifact_index_contradictions_rejected(inputs_case, mutation):
    case, log, opened, fw, li = inputs_case
    metadata = case.load()
    if mutation == "case-id":
        metadata["id"] = "different-case"
    else:
        artifact = copy.deepcopy(next(a for a in metadata["artifacts"] if a["path"] == fw))
        artifact["path"] = "analysis/sd-surface-002.json"
        metadata["artifacts"].append(artifact)
    case.meta_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(PwehError):
        with load(inputs_case):
            pass


@pytest.mark.parametrize("source", ["opened", "list-event"])
def test_other_case_inputs_rejected(inputs_case, source):
    case, log, opened, fw, li = inputs_case
    entries = log.entries()
    if source == "opened":
        opened.record["case_id"] = "different-case"
    else:
        entries[-1]["case_id"] = "different-case"
    with pytest.raises(PwehError):
        with load(inputs_case, entries=entries):
            pass


def test_hash_mismatch_stops_before_report_parsing_and_closes_fds(inputs_case, monkeypatch):
    case, log, opened, fw, li = inputs_case
    path = case.dir / fw
    data = path.read_bytes()
    path.write_bytes(b" " + data[1:])
    opened_reports = []
    open_report = I._open_report
    parse_json = I.load_json
    parsed = []

    def capture(*args, **kwargs):
        result = open_report(*args, **kwargs)
        opened_reports.append((result.fd, result.parent))
        return result

    def parse_capture(raw, **kwargs):
        parsed.append(raw)
        return parse_json(raw, **kwargs)

    monkeypatch.setattr(I, "_open_report", capture)
    monkeypatch.setattr(I, "load_json", parse_capture)
    with pytest.raises(PwehError):
        with load(inputs_case):
            pass
    assert len(parsed) == 1 and json.loads(parsed[0])["id"] == case.id  # 일반 색인만 파싱했다.
    for pair in opened_reports:
        for fd in pair:
            with pytest.raises(OSError):
                os.fstat(fd)


def test_short_read_changed_input_is_rejected(inputs_case, monkeypatch):
    original = os.pread
    reads = []

    def pread(fd, length, offset):
        data = original(fd, length, offset)
        if b'"tool": "fw_sd_surface"' in data:
            reads.append(fd)
            return b""
        return data

    monkeypatch.setattr(I.os, "pread", pread)
    with pytest.raises(PwehError) as error:
        with load(inputs_case):
            pass
    assert reads and error.value.code == "sdioc_input_changed"


def test_final_cancel_does_not_commit_report(inputs_case):
    case, log, opened, fw, li = inputs_case
    cancelled = False
    with load(inputs_case, cancel=lambda: cancelled) as inputs:
        cancelled = True
        with pytest.raises(PwehError) as error:
            E.store_analysis(case, opened, {"source": inputs.source}, event="sd-ioc-scan", custody_log=log,
                             check=inputs.check, check_entries=inputs.check_entries)
        assert error.value.code == "cancelled"
    assert all(e["event"] != "sd-ioc-scan" for e in log.entries())
    assert not list((case.dir / "forensics/analysis").glob("sd-ioc-scan-*"))


@pytest.mark.parametrize("ev", ["EV-001", "EV-1234567", "EV-0001\n", "secret-marker"])
def test_evidence_identifier_is_closed_even_before_path_match(inputs_case, ev):
    case, log, opened, fw, li = inputs_case
    opened.evidence_id = ev
    with pytest.raises(PwehError) as error:
        with load(inputs_case):
            pass
    assert error.value.code == "sdioc_input_invalid" and "secret-marker" not in str(error.value)


def test_nine_digit_generated_sequence_accepted(inputs_case):
    case, log, opened, fw, li = inputs_case
    new_fw = "analysis/sd-surface-123456789.json"
    new_li = f"forensics/analysis/fs-list-{opened.evidence_id}-123456789.json"
    (case.dir / fw).rename(case.dir / new_fw)
    (case.dir / li).rename(case.dir / new_li)
    case.register_artifact(new_fw, kind="triage-report", producer="fwtriage-mcp")
    entries = log.entries()
    entries[-1]["data"]["result_path"] = new_li
    with load(inputs_case, firmware_result_path=new_fw, fs_list_path=new_li, entries=entries) as inputs:
        assert inputs.source["firmware"]["path"] == new_fw
        assert inputs.source["listing"]["path"] == new_li
