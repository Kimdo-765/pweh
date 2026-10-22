"""실제 합성 FAT/exFAT·TAR/ZIP·whole 선택기의 concrete method와 hash 결속."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from core.test_media_candidate_input import CONTENT, box
from fs.builders import exfat_small, fat32_small
from forensics_mcp import fsops, media_candidate_selection as S
from forensics_mcp.media_tools import _source
from forensics_mcp.media_candidate_tools import _selection_coverage
from pweh import evidence as E
from pweh.case import CaseStore
from pweh.errors import PwehError
from pweh.media_candidate_input import open_media_candidate
from pweh.media_candidates import scan_bmff_candidates

PRIVATE = "SYNTHETIC_PRIVATE_SELECTION_992a"


def packed(kind, content):
    import tarfile
    import zipfile
    if kind == "file":
        return content, None
    path = "/" + PRIVATE + ".bin"
    if kind.startswith(("fat", "exfat")):
        disk = fat32_small() if kind.startswith("fat") else exfat_small()
        if kind.endswith("parent"):
            disk.mkdir("/parent")
            path = "/parent" + path
        kwargs = {}
        if kind.endswith("fragmented"):
            kwargs["clusters"] = [100 + 2 * i for i in range((len(content) + disk.cs - 1) // disk.cs)]
            if kind.startswith("exfat"):
                kwargs["contiguous"] = False
        disk.add_file(path, content, **kwargs)
        if kind.endswith("deleted"):
            disk.delete(path)
        if kind.endswith("parent"):
            disk.delete("/parent")
        return disk.image(), path
    stream = io.BytesIO()
    path = PRIVATE + ".bin"
    if kind == "tar":
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo(path)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    else:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(path, content)
    return stream.getvalue(), path


@pytest.fixture
def selected(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 후보 재선택", authorization=auth, case_id="prefix-selection")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(kind="file"):
            content = CONTENT if not kind.endswith("fragmented") else box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", b"x" * 2000)
            blob, path = packed(kind, content)
            ev = _commit_intake(case, log, blob)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            deadline = time.monotonic() + 30
            ref = None
            if kind.endswith(("deleted", "parent")):
                with fsops.image_reader(opened.fd) as image:
                    _, volume = fsops.open_partition_volume(image, None)
                    entry = next(e for e in volume.walk()["entries"] if not e["is_dir"])
                    ref, path = entry["ref"], None
            data, member = fsops.read_selected_file(opened.fd, path=path, ref=ref, max_bytes=64 << 20,
                                                    deadline=deadline, cancel=lambda: False)
            source = _source(opened, ev, member, data)
            report = scan_bmff_candidates(data, deadline=deadline)
            report.update(source=source, params={"partition": None, "method": "auto", "max_seconds": 45})
            _selection_coverage(report, source)
            result = E.store_analysis(case, opened, report, event="media-candidates", custody_log=log)
            candidate = stack.enter_context(open_media_candidate(
                case, opened, analysis_path=result["analysis"]["path"], candidate_index=0,
                entries=log.entries(), deadline=deadline, cancel=lambda: False))
            return SimpleNamespace(opened=opened, candidate=candidate, data=data, member=member, deadline=deadline)
        yield make


def reselect(value, **kwargs):
    return S.reselect_candidate_source(value.opened, value.candidate,
                                       **{"deadline": value.deadline, "cancel": lambda: False, **kwargs})


@pytest.mark.parametrize("kind", ["file", "tar", "zip", "fat", "fat-deleted", "exfat", "exfat-deleted",
                                 "fat-fragmented", "exfat-fragmented", "fat-parent", "exfat-parent"])
def test_actual_selection_repeats_concrete_source_not_original_arguments(selected, monkeypatch, kind):
    value = selected(kind)
    original = S.fsops.read_selected_file
    calls = []
    def read(fd, **kwargs):
        calls.append(kwargs)
        return original(fd, **kwargs)
    monkeypatch.setattr(S.fsops, "read_selected_file", read)
    # 재선택 중 scanner를 호출하는 구현은 허용하지 않는다.
    import pweh.media_candidates as C
    monkeypatch.setattr(C, "scan_bmff_candidates", lambda *a, **k: pytest.fail("재탐색 금지"))
    data, fresh = reselect(value)
    assert data == value.data and fresh == value.candidate.source
    source = value.candidate.source
    assert calls[0]["path"] is None and calls[0]["allow_empty"] is False
    assert calls[0]["max_bytes"] == 64 << 20
    assert calls[0]["ref"] == source["ref"]
    if source["container"] == "filesystem":
        assert value.candidate.params["partition"] is None
        assert calls[0]["partition"] == source["partition"] == 1
        assert calls[0]["method"] == source["method"] != "auto"
    else:
        assert calls[0]["method"] == "auto" and calls[0]["partition"] is None
    assert PRIVATE not in json.dumps(fresh)


@pytest.mark.parametrize("field,value", [("method", "fat-chain"), ("ref", "root/999"), ("partition", 2),
                                         ("deleted", True), ("parent_deleted", True)])
def test_fresh_selection_identity_must_match(selected, monkeypatch, field, value):
    original = selected("fat")
    member = {**original.member, field: value}
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: (original.data, member))
    with pytest.raises(PwehError) as error:
        reselect(original)
    assert error.value.code == "media_prefix_input_changed"


def test_same_size_different_selected_hash_rejected(selected, monkeypatch):
    value = selected()
    data = b"X" + value.data[1:]
    member = {**value.member, "sha256": hashlib.sha256(data).hexdigest()}
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: (data, member))
    with pytest.raises(PwehError) as error:
        reselect(value)
    assert error.value.code == "media_prefix_input_changed"


def test_fresh_uncertainty_does_not_replace_stored_source(selected, monkeypatch):
    value = selected("fat")
    old = copy.deepcopy(value.candidate.source)
    member = {**value.member, "parent_deleted": None, "confidence": "low", "container_truncated": True,
              "container_truncated_reasons": ["max_entries"]}
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: (value.data, member))
    _, fresh = reselect(value)
    assert fresh["parent_deleted"] is None and fresh["confidence"] == "low"
    assert fresh["container_truncated"] is True
    assert value.candidate.source == old


@pytest.mark.parametrize("kind", ["incomplete", "bad-size", "empty", "bytearray"])
def test_incomplete_or_nonexact_bytes_never_return_success(selected, monkeypatch, kind):
    value = selected()
    data, member = value.data, dict(value.member)
    if kind == "incomplete":
        member["complete"] = False
    elif kind == "bad-size":
        member["size"] += 1
    elif kind == "empty":
        data = b""
        member.update(size=0, sha256=hashlib.sha256(data).hexdigest())
    else:
        data = bytearray(data)
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: (data, member))
    with pytest.raises(PwehError):
        reselect(value)


@pytest.mark.parametrize("code", ["cancelled", "timeout", "unknown-secret-code"])
def test_fixed_errors_and_cancel_time_preserved(selected, monkeypatch, code):
    value = selected()
    def failed(*a, **k):
        raise PwehError(PRIVATE, code=code, data={"path": PRIVATE})
    monkeypatch.setattr(S.fsops, "read_selected_file", failed)
    with pytest.raises(PwehError) as error:
        reselect(value)
    assert error.value.code == (code if code in {"cancelled", "timeout"} else "media_prefix_input_invalid")
    assert PRIVATE not in str(error.value) and not error.value.data


def test_cancel_before_read_opens_no_selection(selected, monkeypatch):
    value = selected()
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: pytest.fail("취소 뒤 선택 읽기"))
    with pytest.raises(PwehError) as error:
        reselect(value, cancel=lambda: True)
    assert error.value.code == "cancelled"
