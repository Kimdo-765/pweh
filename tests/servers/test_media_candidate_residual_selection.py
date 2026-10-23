"""합성 exFAT 잔여의 선택·계획 결속·동일 fd 재선택만 검증한다."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import os
import tarfile
import time
from types import SimpleNamespace

import pytest

from fs.builders import exfat_small, fat16_small
from forensics_mcp import fsops, media_candidate_selection as S
from forensics_mcp.media_tools import _residual_source
from pweh import evidence as E
from pweh.errors import PwehError
from pweh.fs import BytesReader, ExfatVolume, FsError, open_volume

PRIVATE = "SYNTHETIC_RESIDUAL_PRIVATE_84d1"
MEMBER_KEYS = {"container", "member_selected", "partition", "ref", "path", "requested_path", "deleted",
               "parent_deleted", "method", "confidence", "complete", "note", "size", "sha256",
               "region", "data_length", "valid_data_length"}


def make_image(*, mode="live", head=b"valid-data", tail=b"RESIDUAL" * 20, **kwargs):
    b = exfat_small()
    parent = "/parent" if mode == "parent" else ""
    if parent:
        b.mkdir(parent)
    path = parent + "/" + PRIVATE + ".bin"
    fragmented = mode in {"fragmented", "deleted-chain", "deleted-skip"}
    n = (len(head) + len(tail) + b.cs - 1) // b.cs
    rec = b.add_file(path, head, residual=tail, contiguous=not fragmented,
                     clusters=[100 + i * 3 for i in range(n)] if fragmented else None, **kwargs)
    if mode.startswith("deleted"):
        b.delete(path)
    if mode == "parent":
        b.delete(parent)
    blob = b.image()
    vol = open_volume(BytesReader(blob))
    entry = next(e for e in vol.walk()["entries"] if not e["is_dir"])
    return SimpleNamespace(builder=b, blob=blob, ref=entry["ref"], path=path, entry=entry, rec=rec,
                           head=head, tail=tail)


def read(image, **kwargs):
    return fsops.read_selected_residual(BytesReader(image.blob), **{
        "partition": 1, "ref": image.ref, "method": "auto", "max_bytes": 64 << 20,
        "deadline": time.monotonic() + 30, "cancel": lambda: False, **kwargs})


@pytest.mark.parametrize("mode,method,actual", [
    ("live", "auto", "nofatchain"), ("live", "nofatchain", "nofatchain"),
    ("fragmented", "chain", "chain"), ("deleted", "auto", "contiguous"),
    ("deleted-chain", "stale-chain", "stale-chain"), ("deleted-chain", "contiguous", "contiguous"),
    ("deleted-skip", "skip-allocated", "skip-allocated"), ("parent", "auto", "nofatchain"),
])
def test_real_selection_method_and_complete_member(mode, method, actual):
    # 손상 복구 가정의 실제 선택 내용도 같은 엔진 계획으로 독립 확인한다.
    image = make_image(mode=mode, head=b"D" * 5000, tail=b"R" * 7000)
    data, member = read(image, method=method)
    vol = open_volume(BytesReader(image.blob))
    expected = b"".join(vol.iter_content(image.ref, method, "residual"))
    assert data == expected and len(data) == 7000
    if method not in {"contiguous", "skip-allocated"}:
        assert data == image.tail
    assert set(member) == MEMBER_KEYS and len(member) == 17
    assert member["container"] == "filesystem" and member["member_selected"] is True
    assert member["partition"] == 1 and member["ref"] == image.ref
    assert member["method"] == actual and member["complete"] is True
    assert member["deleted"] is mode.startswith("deleted")
    assert member["parent_deleted"] is (mode == "parent")
    assert member["size"] == 7000 and member["sha256"] == hashlib.sha256(data).hexdigest()
    assert member["data_length"] == 12000 and member["valid_data_length"] == 5000


def test_vdl_zero_and_body_excludes_data_and_cluster_slack(monkeypatch):
    image = make_image(head=b"", tail=b"R" * 150000)
    observed = []
    original = ExfatVolume.iter_plan
    def chunks(self, plan, **kw):
        observed.append(kw)
        for blob in original(self, plan, **kw):
            assert len(blob) <= 65536
            yield blob
    monkeypatch.setattr(ExfatVolume, "iter_plan", chunks)
    data, member = read(image)
    assert data == image.tail and member["valid_data_length"] == 0
    assert observed == [{"max_bytes": 64 << 20, "chunk_size": 65536}]
    image = make_image(head=b"D" * 4097, tail=b"R" * 4201)
    data, member = read(image)
    assert data == image.tail and member["size"] == 4201
    assert member["valid_data_length"] == 4097


@pytest.mark.parametrize("vdl", [30, 31])
def test_raw_vdl_equal_or_above_length_is_not_clamped(vdl):
    image = make_image(head=b"D" * 10, tail=b"R" * 20, valid_data_length=vdl)
    assert image.entry["valid_data_length_raw"] == vdl
    with pytest.raises(FsError) as err:
        read(image)
    assert err.value.reason == "incomplete_file" and PRIVATE not in str(err.value)


@pytest.mark.parametrize("key,value", [
    ("partition", None), ("partition", True), ("partition", 1.0), ("partition", 0), ("partition", 4097),
    ("ref", None), ("ref", "arc:1"), ("ref", "root/1\n"), ("ref", "/private"),
    ("method", "empty"), ("method", "fat-chain"), ("method", "skip-claimed"),
    ("max_bytes", True), ("max_bytes", 1.0), ("max_bytes", 0), ("max_bytes", (64 << 20) + 1),
])
def test_bad_helper_arguments_stop_before_open(monkeypatch, key, value):
    image = SimpleNamespace(blob=b"", ref="root/1")
    monkeypatch.setattr(fsops, "open_partition_volume", lambda *a, **k: pytest.fail("인자 거부 뒤 열기"))
    with pytest.raises(FsError) as err:
        read(image, **{key: value})
    assert err.value.reason == "bad_argument"


def test_residual_size_limit_is_separate_from_metadata_reads():
    image = make_image(tail=b"R" * 20)
    assert read(image, max_bytes=20)[0] == b"R" * 20
    with pytest.raises(FsError) as err:
        read(image, max_bytes=19)
    assert err.value.reason == "max_bytes"


@pytest.mark.parametrize("choice", ["fat", "archive", "directory", "partition", "ref", "method"])
def test_wrong_filesystem_or_selector_or_method(choice):
    image = make_image()
    if choice == "fat":
        b = fat16_small()
        rec = b.add_file("/F.BIN", b"R")
        image.blob, image.ref = b.image(), f"root/{rec.slots[-1]}"
    elif choice == "archive":
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as arc:
            item = tarfile.TarInfo("private")
            item.size = 1
            arc.addfile(item, io.BytesIO(b"R"))
        image.blob = stream.getvalue()
    elif choice == "directory":
        b = exfat_small()
        rec = b.mkdir("/D")
        image.blob, image.ref = b.image(), f"root/{rec.slots[0]}"
    kwargs = {"partition": 2} if choice == "partition" else {"ref": "root/999999"} if choice == "ref" else (
        {"method": "stale-chain"} if choice == "method" else {})
    with pytest.raises(FsError):
        read(image, **kwargs)


@pytest.mark.parametrize("field,value", [
    ("size", True), ("size", 1.0), ("valid_data_length_raw", False),
    ("valid_data_length_raw", 1.0), ("valid_data_length_raw", -1),
    ("valid_data_length", 0), ("ref", "root/999"), ("fs", "fat32"),
    ("is_dir", None), ("deleted", 1), ("parent_deleted", 1),
])
def test_entry_metadata_must_be_exact(monkeypatch, field, value):
    image = make_image()
    original = fsops.resolve_targets
    def resolve(*a, **kw):
        entries, unresolved = original(*a, **kw)
        entries[0][field] = value
        return entries, unresolved
    monkeypatch.setattr(fsops, "resolve_targets", resolve)
    with pytest.raises(FsError) as err:
        read(image)
    assert err.value.reason == "incomplete_file"


@pytest.mark.parametrize("field,value", [
    ("skip", 0), ("skip", True), ("size", 1), ("expected_size", 1),
    ("region", "data"), ("ref", "root/999"), ("method", "empty"),
    ("data_length", 0), ("valid_data_length", 0),
    ("data_length", 170.0), ("limit_reason", "steps"),
    ("bytes_beyond_image", 1), ("status", "limit"),
])
def test_plan_and_entry_must_describe_same_residual(monkeypatch, field, value):
    image = make_image()
    original = ExfatVolume.content_plan
    def plan(*a, **kw):
        result = original(*a, **kw)
        if field in {"data_length", "valid_data_length", "limit_reason", "bytes_beyond_image"}:
            result.extra[field] = value
        else:
            setattr(result, field, value)
        return result
    monkeypatch.setattr(ExfatVolume, "content_plan", plan)
    with pytest.raises(FsError) as err:
        read(image)
    assert err.value.reason == "incomplete_file"


@pytest.mark.parametrize("fault", ["incomplete", "short", "wrongtype", "longchunk", "oversized", "beyond"])
def test_incomplete_plan_or_iterator_never_succeeds(monkeypatch, fault):
    image = make_image()
    if fault == "incomplete":
        original = ExfatVolume.content_plan
        def plan(*a, **kw):
            result = original(*a, **kw)
            result.clusters = 0
            return result
        monkeypatch.setattr(ExfatVolume, "content_plan", plan)
    elif fault == "beyond":
        image.blob = image.blob[:image.builder.coff(image.rec.clusters[0]) + 12]
    else:
        payload = {"short": b"R", "wrongtype": bytearray(b"R"),
                   "longchunk": b"R" * 65537, "oversized": b"R" * 161}[fault]
        monkeypatch.setattr(ExfatVolume, "iter_plan", lambda *a, **kw: iter([payload]))
    with pytest.raises(FsError):
        read(image)


def test_large_datalength_small_residual_uses_only_planned_tail(monkeypatch):
    image = make_image()
    dl, tail = (64 << 20) + 100, b"tail"
    vol = open_volume(BytesReader(image.blob))
    plan = vol.content_plan(image.ref, "auto", "residual")
    plan.skip, plan.size, plan.expected_size = dl - 4, 4, 4
    plan.clusters = (dl + vol.cluster_size - 1) // vol.cluster_size
    plan.extra.update(data_length=dl, valid_data_length=dl - 4)
    entry = dict(image.entry, size=dl, valid_data_length_raw=dl - 4, valid_data_length=dl - 4,
                 parent_deleted=False)
    monkeypatch.setattr(fsops, "resolve_targets", lambda *a, **kw: ([entry], []))
    monkeypatch.setattr(ExfatVolume, "content_plan", lambda *a, **kw: plan)
    monkeypatch.setattr(ExfatVolume, "iter_plan", lambda *a, **kw: iter([tail]))
    data, member = read(image, max_bytes=4)
    assert data == tail and member["data_length"] == dl and member["size"] == 4


@pytest.mark.parametrize("stage", ["start", "resolve", "plan", "chunk"])
@pytest.mark.parametrize("stop", ["cancel", "time"])
def test_same_deadline_and_cancel_at_each_stage(monkeypatch, stage, stop):
    image = make_image()
    state = {"stop": stage == "start"}
    end = time.monotonic() + 30
    if stop == "time":
        original_clock = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: end + 1 if state["stop"] else original_clock())
    if stage in {"resolve", "plan"}:
        target, name = (fsops, "resolve_targets") if stage == "resolve" else (ExfatVolume, "content_plan")
        original = getattr(target, name)
        def invoke(*a, **kw):
            value = original(*a, **kw)
            state["stop"] = True
            return value
        monkeypatch.setattr(target, name, invoke)
    elif stage == "chunk":
        original = ExfatVolume.iter_plan
        def iterator(*a, **kw):
            for chunk in original(*a, **kw):
                state["stop"] = True
                yield chunk
        monkeypatch.setattr(ExfatVolume, "iter_plan", iterator)
    with pytest.raises(PwehError) as err:
        read(image, deadline=end, cancel=lambda: stop == "cancel" and state["stop"])
    assert err.value.code == ("cancelled" if stop == "cancel" else "time_limit")


@pytest.fixture
def selected(tmp_path):
    with contextlib.ExitStack() as stack:
        def make(mode="live"):
            image = make_image(mode=mode)
            path = tmp_path / (PRIVATE + str(len(stack._exit_callbacks)))
            path.write_bytes(image.blob)
            path.chmod(0o444)
            fd = os.open(path, os.O_RDONLY)
            st = os.fstat(fd)
            opened = E.OpenedEvidence(evidence_id="EV-0001", record={}, intake={"size": st.st_size,
                "hashes": {"sha256": hashlib.sha256(image.blob).hexdigest()}}, intake_ts=None, fd=fd, st=st)
            stack.enter_context(opened)
            with fsops.image_reader(opened.fd) as img:
                data, member = fsops.read_selected_residual(img, partition=1, ref=image.ref, method="auto",
                    max_bytes=64 << 20, deadline=time.monotonic() + 30, cancel=lambda: False)
                assert not img.closed
            source = _residual_source(opened, opened.evidence_id, member, data)
            return SimpleNamespace(opened=opened, candidate=SimpleNamespace(source=source), member=member,
                                   data=data, path=path, image=image)
        yield make


def reselect(value, **kwargs):
    return S.reselect_candidate_source(value.opened, value.candidate, **{
        "deadline": time.monotonic() + 30, "cancel": lambda: False, **kwargs})


@pytest.mark.parametrize("mode", ["live", "fragmented", "deleted", "deleted-chain", "parent"])
def test_reselect_same_bytes_and_all_19_fields(selected, monkeypatch, mode):
    value = selected(mode)
    calls = []
    original = fsops.read_selected_residual
    def record(img, **kw):
        calls.append(kw)
        return original(img, **kw)
    monkeypatch.setattr(fsops, "read_selected_residual", record)
    monkeypatch.setattr(fsops, "read_selected_file", lambda *a, **k: pytest.fail("residual을 data로 재선택"))
    data, fresh = reselect(value)
    assert len(fresh) == 19 and fresh == value.candidate.source and data == value.data
    assert PRIVATE not in repr(fresh)
    assert calls[0]["method"] == value.member["method"] and calls[0]["partition"] == 1
    assert os.fstat(value.opened.fd).st_ino == value.opened.st.st_ino


@pytest.mark.parametrize("field,change", [
    ("kind", "file"), ("evidence_id", "EV-9999"), ("evidence_sha256", "0" * 64),
    ("container", "tar"), ("member_selected", False), ("selected_sha256", "0" * 64),
    ("selected_size", 161), ("complete", False), ("method", "fat-chain"),
    ("confidence", "low"), ("partition", 2), ("ref", "root/999"), ("deleted", True),
    ("parent_deleted", None), ("container_truncated", False),
    ("container_truncated_reasons", ["time"]), ("region", "data"),
    ("data_length", 171), ("valid_data_length", 9),
])
def test_all_source_fields_are_bound(selected, field, change):
    value = selected()
    value.candidate.source[field] = change
    with pytest.raises(PwehError):
        reselect(value)


@pytest.mark.parametrize("field", ["partition", "selected_size", "data_length", "valid_data_length", "deleted",
                                   "member_selected", "complete"])
def test_bool_int_or_float_source_impersonation_rejected(selected, field):
    value = selected()
    before = value.candidate.source[field]
    value.candidate.source[field] = int(before) if type(before) is bool else float(before)
    with pytest.raises(PwehError):
        reselect(value)


@pytest.mark.parametrize("field,value", [("offset", 0), ("evidence_size", 100), ("private_name", PRIVATE)])
def test_range_or_unknown_source_keys_rejected(selected, field, value):
    item = selected()
    item.candidate.source[field] = value
    with pytest.raises(PwehError) as err:
        reselect(item)
    assert err.value.code == "media_prefix_input_invalid" and PRIVATE not in str(err.value)


@pytest.mark.parametrize("field,value", [("confidence", "low"), ("parent_deleted", None), ("deleted", True)])
def test_fresh_uncertainty_cannot_replace_recorded_value(selected, monkeypatch, field, value):
    item = selected()
    before = copy.deepcopy(item.candidate.source)
    member = {**item.member, field: value}
    monkeypatch.setattr(fsops, "read_selected_residual", lambda *a, **k: (item.data, member))
    with pytest.raises(PwehError) as err:
        reselect(item)
    assert err.value.code == "media_prefix_input_changed" and item.candidate.source == before


def test_reselection_owns_only_dup_and_never_reopens_replaced_path(selected, monkeypatch):
    item = selected()
    original = fsops.image_reader
    readers = []
    def reader(fd, *a, **kw):
        assert fd == item.opened.fd
        result = original(fd, *a, **kw)
        readers.append(result)
        return result
    monkeypatch.setattr(fsops, "image_reader", reader)
    moved = item.path.with_suffix(".old")
    item.path.rename(moved)
    item.path.write_bytes(b"replacement")
    monkeypatch.setattr(os, "open", lambda *a, **kw: pytest.fail("증거 경로 재열기"))
    assert reselect(item)[0] == item.data
    assert readers[0].closed and os.fstat(item.opened.fd).st_ino == item.opened.st.st_ino
    # 경로 seal은 caller의 E.recheck_opened가 거부한다. 여기서는 같은 열린 bytes만 읽는다.


@pytest.mark.parametrize("reason,code", [("cancelled", "cancelled"), ("time", "timeout"),
                                        ("max_bytes", "media_prefix_input_limit"),
                                        ("incomplete_file", "media_prefix_input_invalid")])
def test_reselection_failure_closes_dup_and_keeps_fixed_alias(selected, monkeypatch, reason, code):
    item = selected()
    readers = []
    original = fsops.image_reader
    def reader(*a, **kw):
        result = original(*a, **kw)
        readers.append(result)
        return result
    def failed(*a, **kw):
        raise FsError(PRIVATE, reason=reason)
    monkeypatch.setattr(fsops, "image_reader", reader)
    monkeypatch.setattr(fsops, "read_selected_residual", failed)
    with pytest.raises(PwehError) as err:
        reselect(item)
    assert err.value.code == code and PRIVATE not in str(err.value)
    assert readers[0].closed and os.fstat(item.opened.fd)


def test_integrity_problem_is_not_hidden(selected, monkeypatch):
    item = selected()
    def failed(*a, **kw):
        raise E.IntegrityProblem("합성 변경", reason="source-changed")
    monkeypatch.setattr(fsops, "read_selected_residual", failed)
    with pytest.raises(E.IntegrityProblem):
        reselect(item)


def test_actual_helper_deadline_keeps_reselection_timeout_alias(selected, monkeypatch):
    item = selected()
    end = time.monotonic() + 30
    state = {"expired": False}
    original_clock = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: end + 1 if state["expired"] else original_clock())
    original_plan = ExfatVolume.content_plan
    def plan(*a, **kw):
        value = original_plan(*a, **kw)
        state["expired"] = True
        return value
    monkeypatch.setattr(ExfatVolume, "content_plan", plan)
    with pytest.raises(PwehError) as err:
        reselect(item, deadline=end)
    assert err.value.code == "timeout"
    assert os.fstat(item.opened.fd).st_ino == item.opened.st.st_ino
