"""합성 EV 구간 보고서의 exact 정수·출처·범위 재생 경계."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from core.test_media_candidate_input import CONTENT, load, report_for
from pweh import evidence as E, media_candidate_input as I
from pweh.case import CaseStore
from pweh.errors import PwehError

PRIVATE = "PRIVATE_RANGE_INPUT_d34e"
RANGE_PROFILE = "ftyp-contiguous-ev-range-v1"


def range_report(selected, opened, offset):
    """scanner는 그대로 두고 합성 전체 EV와 선택 구간을 독립 결속한다."""
    report = report_for(selected, opened.evidence_id, opened.intake)
    report["profile"] = RANGE_PROFILE
    report["limitations"] += ["explicit_evidence_range_only", "outside_range_unexamined"]
    report["source"].update(method="byte-range", offset=offset, evidence_size=opened.intake["size"])
    report["params"].update(offset=offset, length=len(selected), max_seconds=12.5)
    return report


@pytest.fixture
def range_input(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(title="합성 EV 구간 입력", authorization=auth)
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(*, offset=4096, selected=CONTENT, tail=32, mutate=None):
            data = b"X" * offset + selected + b"Y" * tail
            ev = _commit_intake(case, log, data)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            report = range_report(selected, opened, offset)
            if mutate:
                mutate(report)
            stored = E.store_analysis(case, opened, report, event="media-candidates", custody_log=log)
            return SimpleNamespace(case=case, log=log, opened=opened, report=report,
                                   path=stored["analysis"]["path"], stored=stored, entries=None,
                                   data=selected, evidence=data)
        yield make


@pytest.mark.parametrize("offset,tail", [(0, 0), (7, 0), (4096, 32)])
def test_range_loader_keeps_relative_candidate_and_finite_float_parameter(range_input, offset, tail):
    value = range_input(offset=offset, tail=tail)
    with load(value) as candidate:
        assert candidate.source == value.report["source"]
        assert candidate.params["max_seconds"] == 12.5
        assert len(candidate.source) == 18 and len(candidate.params) == 5
        assert candidate.source["selected_size"] == len(CONTENT)
        assert candidate.source["evidence_size"] == len(value.evidence)
        assert candidate.candidate["offset"] == 6
        assert candidate.source["selected_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        candidate.check()
        candidate.check_entries(value.log.entries())
        fd = candidate._fd
    with pytest.raises(OSError):
        os.fstat(fd)
    os.fstat(value.opened.fd)


@pytest.mark.parametrize("mutate", [
    lambda r: r["params"].update(offset=4096.0),
    lambda r: r["params"].update(offset=True),
    lambda r: r["params"].update(length=float(len(CONTENT))),
    lambda r: r["params"].update(length=True),
    lambda r: r["params"].update(offset=4097),
    lambda r: r["params"].update(length=len(CONTENT) - 1),
    lambda r: r["params"].update(partition=1),
    lambda r: r["params"].update(method="chain"),
    lambda r: r["source"].update(offset=4096.0),
    lambda r: r["source"].update(offset=True),
    lambda r: r["source"].update(offset=-1),
    lambda r: r["source"].update(offset=1 << 63),
    lambda r: r["source"].update(evidence_size=float(4096 + len(CONTENT) + 32)),
    lambda r: r["source"].update(evidence_size=True),
    lambda r: r["source"].update(evidence_size=1 << 63),
    lambda r: r["source"].update(evidence_size=4096 + len(CONTENT) + 31),
    lambda r: r["source"].update(evidence_size=4096 + len(CONTENT) - 1),
    lambda r: r["source"].update(offset=5000),
    lambda r: r["source"].update(size=len(CONTENT)),
    lambda r: r["source"].update(length=len(CONTENT)),
    lambda r: r["source"].update(selected_size=len(CONTENT) + 1),
    lambda r: r["source"].update(method="whole-file"),
    lambda r: r["source"].update(member_selected=True),
    lambda r: r["source"].update(ref="root/0"),
    lambda r: r.update(profile="ftyp-contiguous-top-level-v1"),
    lambda r: r["params"].pop("length"),
    lambda r: r["source"].pop("offset"),
])
def test_range_semantic_rejects_hash_bound_invalid_report(range_input, mutate):
    value = range_input(mutate=mutate)
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == "media_prefix_input_invalid"
    assert PRIVATE not in str(error.value) and not error.value.data


@pytest.mark.parametrize("which", ["intake", "initial-stat", "current-stat"])
def test_range_evidence_size_must_match_all_open_observations(range_input, which):
    value = range_input()
    if which == "intake":
        value.opened.intake = {**value.opened.intake, "size": len(value.evidence) + 1}
    elif which == "initial-stat":
        value.opened.st = SimpleNamespace(st_size=len(value.evidence) + 1)
    else:
        path = value.case.dir / value.opened.intake["stored_path"]
        path.chmod(0o644)
        with path.open("ab") as output:
            output.write(b"Z")
        path.chmod(0o444)
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == "media_prefix_input_invalid"


def test_range_params_remain_bound_to_original_event(range_input):
    value = range_input()
    entries = value.log.entries()
    entries[-1]["data"]["params"]["offset"] += 1
    with pytest.raises(PwehError):
        with load(value, entries=entries):
            pass


def test_partial_range_preserves_original_coverage_and_report_checks(range_input):
    value = range_input(selected=CONTENT + b"\0")
    with load(value) as candidate:
        assert candidate.upstream_status == "partial"
        assert candidate.coverage == value.report["coverage"]
        assert candidate.candidate["validated_prefix_length"] == len(CONTENT) - 6
        entries = copy.deepcopy(value.log.entries())
        entries[-1]["data"]["source"]["offset"] += 1
        with pytest.raises(PwehError) as error:
            candidate.check_entries(entries)
        assert error.value.code == "media_prefix_input_changed"


def test_range_report_rehash_does_not_trust_valid_source_after_content_change(range_input):
    value = range_input()
    with load(value) as candidate:
        path = value.case.dir / value.path
        path.chmod(0o644)
        with path.open("r+b") as output:
            output.write(b"!")
        path.chmod(0o444)
        with pytest.raises(PwehError) as error:
            candidate.check()
        assert error.value.code == "media_prefix_input_changed"


def test_range_loader_does_not_restart_expired_deadline(range_input):
    with pytest.raises(PwehError) as error:
        with load(range_input(), deadline=time.monotonic() - 1):
            pass
    assert error.value.code == "timeout"
