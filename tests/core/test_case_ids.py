"""실제 상태를 사용하지 않는 케이스 ID 잔존·별칭·동시 생성 회귀."""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pweh import caseids, safeio
from pweh.case import CaseStore
from pweh.errors import CaseError, ValidationFailed
from pweh.runtime import get_runtime


def _store(tmp_path):
    return CaseStore(tmp_path / "cases", state_dir=tmp_path / "state")


def _record(state: Path, folder: str, case_id, *, binding=None, status="expired"):
    prefix, schema = ("ap", "approval") if folder == "approvals" else ("att", "attestation")
    record_id = prefix + "-0000000001"
    rec = {"schema": f"pweh.{schema}/v1", "id": record_id, "case_id": case_id, "status": status}
    if binding is not None:
        rec["binding"] = binding
    path = state / folder / (record_id + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec), encoding="utf-8")
    return path


def _create_process(cases, state, case_id, queue):
    try:
        case = CaseStore(Path(cases), state_dir=Path(state)).create(title="parallel", case_id=case_id)
        queue.put(("ok", case.id))
    except CaseError as exc:
        queue.put((exc.code, None))


def test_runtime_lazy_and_reservation_survives_case_deletion(workspace):
    rt = get_runtime("case-id-test")
    state = workspace["state_dir"]
    assert not state.exists()
    case = rt.cases.create(title="first", case_id="Lab-Unit")
    marker = state / caseids.REGISTRY / caseids.reservation_name(case.id)
    before = marker.read_bytes()
    assert json.loads(before)["case_id"] == case.id
    assert marker.stat().st_mode & 0o777 == 0o600
    shutil.rmtree(case.dir)
    for value in ("Lab-Unit", "lab-unit", "LAB-UNIT"):
        with pytest.raises(CaseError, match="case_id_used"):
            rt.cases.create(title="second", case_id=value)
    assert marker.read_bytes() == before
    assert not case.dir.exists()


@pytest.mark.parametrize("folder,name", [
    ("provenance", "Lab.Unit.jsonl"), ("salts", "Lab.Unit.key"), ("custody", "Lab.Unit.jsonl"),
    ("provenance", ".Lab.Unit.lock"), ("salts", ".Lab.Unit.random.tmp"),
    ("custody", ".Lab.Unit.jsonl.random.tmp"),
])
@pytest.mark.parametrize("kind", ["empty", "symlink", "directory", "fifo"])
def test_legacy_named_state_is_not_opened(tmp_path, monkeypatch, folder, name, kind):
    store = _store(tmp_path)
    path = store.state_dir / folder / name
    path.parent.mkdir(parents=True)
    if kind == "empty":
        path.touch()
    elif kind == "symlink":
        path.symlink_to(tmp_path / "missing")
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)

    def forbidden(*args, **kwargs):
        raise AssertionError("원장/솔트/custody 본문을 열면 안 됨")

    monkeypatch.setattr(safeio, "read_regular", forbidden)
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="reuse", case_id="lab.unit")
    assert not (store.dir / "lab.unit").exists()


@pytest.mark.parametrize("folder", ["approvals", "attestations"])
@pytest.mark.parametrize("status", ["pending", "approved", "denied", "expired", "revoked", "consumed"])
def test_all_record_statuses_remain_used(tmp_path, folder, status):
    store = _store(tmp_path)
    record = _record(store.state_dir, folder, "Past-ID", status=status)
    before = record.read_bytes()
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="reuse", case_id="past-id")
    assert record.read_bytes() == before
    assert store.create(title="fresh", case_id="fresh-id").id == "fresh-id"


def test_attestation_binding_and_global_records(tmp_path):
    store = _store(tmp_path)
    _record(store.state_dir, "attestations", None, binding={"scope": "session", "case_id": "Past"})
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="reuse", case_id="past")
    _record(store.state_dir, "attestations", None, binding={"scope": "global"})
    assert store.create(title="unused", case_id="unused").id == "unused"


def test_salt_temp_keeps_id_ending_in_key(tmp_path):
    store = _store(tmp_path)
    directory = store.state_dir / "salts"
    directory.mkdir(parents=True)
    (directory / ".Past.key.random.tmp").touch()
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="reuse", case_id="past.key")


@pytest.mark.parametrize("damage", ["truncated", "duplicate", "missing_case_id", "bad_schema", "bad_id", "bad_binding", "bad_case_id", "symlink", "fifo", "directory", "oversized"])
def test_unreadable_reference_state_refuses_even_auto_creation(tmp_path, damage):
    store = _store(tmp_path)
    path = _record(store.state_dir, "attestations", "past")
    doc = json.loads(path.read_text())
    if damage == "truncated":
        path.write_bytes(b"{")
    elif damage == "duplicate":
        path.write_text(path.read_text()[:-1] + ', "case_id": null}')
    elif damage == "missing_case_id":
        del doc["case_id"]
        path.write_text(json.dumps(doc))
    elif damage in {"bad_schema", "bad_id", "bad_binding", "bad_case_id"}:
        doc[damage[4:]] = []
        path.write_text(json.dumps(doc))
    elif damage == "oversized":
        path.write_bytes(b" " * (caseids.MAX_RECORD_BYTES + 1))
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(tmp_path / "missing")
        elif damage == "fifo":
            os.mkfifo(path)
        else:
            path.mkdir()
    with pytest.raises(CaseError, match="case_id_state_unverified"):
        store.create(title="auto")
    assert not list(store.dir.glob("*/case.json"))


@pytest.mark.parametrize("folder", ["provenance", "salts", "custody", "approvals", "attestations", caseids.REGISTRY])
def test_state_subdir_symlink_is_not_followed(tmp_path, folder):
    store = _store(tmp_path)
    store.state_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.state_dir / folder).symlink_to(outside, target_is_directory=True)
    with pytest.raises(CaseError, match="case_id_state_unverified"):
        store.create(title="new", case_id="new")
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("kind", ["empty", "corrupt", "symlink", "directory"])
def test_reservation_collision_never_overwrites(tmp_path, monkeypatch, kind):
    store = _store(tmp_path)
    # 다른 ID의 해시 충돌도 같은 원칙으로 차단한다.
    monkeypatch.setattr(caseids, "reservation_name", lambda value: "a" * 64 + ".json")
    marker = store.state_dir / caseids.REGISTRY / caseids.reservation_name("new")
    marker.parent.mkdir(parents=True)
    if kind == "empty":
        marker.touch()
    elif kind == "corrupt":
        marker.write_bytes(b"{")
    elif kind == "symlink":
        marker.symlink_to(tmp_path / "missing")
    else:
        marker.mkdir()
    before = marker.lstat()
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="new", case_id="new")
    assert marker.lstat().st_ino == before.st_ino


@pytest.mark.parametrize("kind", ["empty", "file", "symlink", "dangling"])
def test_incomplete_case_and_path_aliases_are_occupied(tmp_path, kind):
    store = _store(tmp_path)
    store.dir.mkdir()
    occupied = store.dir / "Old-ID"
    if kind == "empty":
        occupied.mkdir()
    elif kind == "file":
        occupied.write_bytes(b"data")
    elif kind == "symlink":
        target = tmp_path / "outside"
        target.mkdir()
        occupied.symlink_to(target, target_is_directory=True)
    else:
        occupied.symlink_to(tmp_path / "missing")
    for name in ("Old-ID", "old-id"):
        with pytest.raises(CaseError, match="case_id_used"):
            store.create(title="reuse", case_id=name)


def test_automatic_ids_skip_paths_legacy_and_reservation(tmp_path):
    store = _store(tmp_path)
    first = store.create(title="automatic")
    base = first.id
    shutil.rmtree(first.dir)
    (store.dir / (base + "-2").upper()).mkdir()
    _record(store.state_dir, "approvals", (base + "-3").upper())
    assert store.create(title="automatic").id == base + "-4"


@pytest.mark.parametrize("limit", ["entries", "bytes", "time", "candidates"])
def test_bounded_inspection_does_not_report_absence(tmp_path, monkeypatch, limit):
    store = _store(tmp_path)
    _record(store.state_dir, "approvals", "old")
    name, value = {"entries": ("MAX_ENTRIES", 0), "bytes": ("MAX_TOTAL_BYTES", 1),
                   "time": ("MAX_SECONDS", -1), "candidates": ("MAX_CANDIDATES", 0)}[limit]
    monkeypatch.setattr(caseids, name, value)
    with pytest.raises(CaseError, match="case_id_state_unverified"):
        store.create(title="new")
    assert not list(store.dir.glob("*/case.json"))


def test_shared_state_and_configured_root_aliases(tmp_path):
    store = _store(tmp_path)
    case = store.create(title="first", case_id="shared")
    alternate = CaseStore(tmp_path / "other-cases", state_dir=store.state_dir)
    with pytest.raises(CaseError, match="case_id_used"):
        alternate.create(title="second", case_id="shared")
    alias = tmp_path / "case-alias"
    state_alias = tmp_path / "state-alias"
    alias.symlink_to(store.dir, target_is_directory=True)
    state_alias.symlink_to(store.state_dir, target_is_directory=True)
    via_alias = CaseStore(alias, state_dir=state_alias)
    assert via_alias.get(case.id).load() == case.load()
    with pytest.raises(CaseError, match="case_id_used"):
        via_alias.create(title="alias", case_id="shared")
    assert via_alias.create(title="new", case_id="new").dir == store.dir / "new"


def test_get_existing_case_does_not_scan_or_reserve(tmp_path):
    legacy = CaseStore(tmp_path / "cases")
    case = legacy.create(title="legacy", case_id="legacy")
    store = CaseStore(legacy.dir, state_dir=tmp_path / "missing-state")
    assert store.get(case.id).load()["title"] == "legacy"
    assert store.list()[0]["id"] == case.id
    assert not store.state_dir.exists()


def test_failed_creation_keeps_reservation(tmp_path, monkeypatch):
    store = _store(tmp_path)
    real = safeio.write_new

    def fail(fd, name, *args, **kwargs):
        if name == "case.json":
            raise OSError("합성 쓰기 실패")
        return real(fd, name, *args, **kwargs)

    monkeypatch.setattr(safeio, "write_new", fail)
    with pytest.raises(OSError, match="합성"):
        store.create(title="first", case_id="failed")
    shutil.rmtree(store.dir / "failed")
    monkeypatch.setattr(safeio, "write_new", real)
    with pytest.raises(CaseError, match="case_id_used"):
        store.create(title="second", case_id="failed")


def test_validation_failure_has_no_creation_side_effect(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValidationFailed):
        store.create(title="invalid", case_id="valid", authorization={"basis": "invalid"})
    with pytest.raises(ValidationFailed):
        store.create(title="invalid", case_id="../escape")
    assert not store.dir.exists() and not store.state_dir.exists()


def test_case_path_replacement_does_not_redirect_writes(tmp_path, monkeypatch):
    store = _store(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    real = safeio.write_new

    def swap(fd, name, *args, **kwargs):
        if name == "case.json":
            (store.dir / "fresh").rename(tmp_path / "held-case")
            (store.dir / "fresh").symlink_to(outside, target_is_directory=True)
        return real(fd, name, *args, **kwargs)

    monkeypatch.setattr(safeio, "write_new", swap)
    with pytest.raises(CaseError, match="case_id_state_unverified"):
        store.create(title="new", case_id="fresh")
    assert list(outside.iterdir()) == []
    assert (store.state_dir / caseids.REGISTRY / caseids.reservation_name("fresh")).exists()


def test_overlapping_lock_paths_do_not_deadlock(tmp_path):
    store = CaseStore(tmp_path / "state" / caseids.REGISTRY, state_dir=tmp_path / "state")
    assert store.create(title="new", case_id="fresh").id == "fresh"


@pytest.mark.parametrize("case_id", ["same", None])
def test_processes_serialize_explicit_and_automatic_creation(tmp_path, case_id):
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    processes = [ctx.Process(target=_create_process, args=(str(tmp_path / "cases"), str(tmp_path / "state"), case_id, queue)) for _ in range(4)]
    try:
        for process in processes:
            process.start()
        rows = [queue.get(timeout=10) for _ in processes]
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        if case_id:
            assert [row[0] for row in rows].count("ok") == 1
            assert [row[0] for row in rows].count("case_id_used") == 3
        else:
            assert len({row[1] for row in rows}) == 4
            assert all(row[0] == "ok" for row in rows)
        assert len(list((tmp_path / "cases").glob("*/case.json"))) == (1 if case_id else 4)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
        queue.close()


def test_two_case_roots_concurrently_share_state_reservation(tmp_path):
    def create(index):
        store = CaseStore(tmp_path / f"cases-{index}", state_dir=tmp_path / "state")
        try:
            return store.create(title="same", case_id="same").id
        except CaseError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(create, range(4)))
    assert results.count("same") == 1
    assert results.count("case_id_used") == 3
