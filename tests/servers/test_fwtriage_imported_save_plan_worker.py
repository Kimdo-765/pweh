"""합성 import의 로컬 계획·같은 FD·출처·최종 커밋 수명을 검증한다."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import struct
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from fwtriage_mcp import imported_save_plan as A, saves, server as S
from pweh import espfmt, safeio, schemas
from pweh.errors import PwehError
from pweh.runtime import get_runtime
from pweh.safety.attestations import canonical_json

PRIVATE = "SYNTHETIC_IMPORTED_SAVE_PRIVATE"


def make_imported(case, runtime, data, *, relative="dumps/synthetic-save.bin"):
    """실제 합성 artifact와 import 원장을 기록한다. 운영 상태는 workspace fixture 밖에 없다."""
    path = case.dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    artifact = case.register_artifact(relative, kind="other", producer="synthetic")
    entry = runtime.provenance.record_import(case, relative, {"server": "case-mcp", "tool": "case_import_file"})
    return artifact, path, entry


def make_save():
    data = bytearray(64)
    data[:4] = b"SAVE"
    struct.pack_into("<I", data, 16, 123456)
    struct.pack_into("<I", data, 60, sum(data[:60]))
    return bytes(data)


@pytest.fixture
def env(workspace, auth):
    runtime = get_runtime("test")
    case = runtime.cases.create(title="합성 세이브", authorization=auth)
    namespace = SimpleNamespace(rt=lambda: runtime, _looks_like_nvs=S._looks_like_nvs)
    return case, runtime, namespace


def plan(env, artifact, **kwargs):
    case, _, namespace = env
    values = dict(offset=0, length=64, edits=[{"offset": 16, "encoding": "u32le", "value": 999999}],
                  purpose="score", unlock_source="in-device", online_capable="no",
                  checksum={"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 60]},
                  max_seconds=30, deadline=time.monotonic() + 30, cancel=None)
    values.update(kwargs)
    return A.plan_imported_save(namespace, case, artifact["id"], **values)


def attached(env, data=None, relative="dumps/synthetic-save.bin"):
    return make_imported(env[0], env[1], make_save() if data is None else data, relative=relative)


def fail(env, artifact, *, code=None, **kwargs):
    with pytest.raises(PwehError) as caught:
        plan(env, artifact, **kwargs)
    assert PRIVATE not in str(caught.value) and PRIVATE not in json.dumps(caught.value.to_dict())
    assert caught.value.__suppress_context__
    if code:
        assert caught.value.code == code
    return caught.value.code


def output_dirs(env):
    return list((env[0].dir / "patches").glob("imported-save-plan-*"))


def mutate_artifact(case, fn):
    case._update(lambda meta: fn(meta["artifacts"]))


def test_full_plan_single_artifact_source_ledger_and_no_operational_authority(env):
    artifact, path, ledger = attached(env, relative=f"dumps/{PRIVATE}.bin")
    original = path.read_bytes()
    result = plan(env, artifact)
    assert set(result) == {"ok", "stage", "report", "analysis", "patch", "warnings"}
    assert result["stage"] == "planned" and result["warnings"] == []
    report = result["report"]
    schemas.validate("imported-save-plan", report)
    assert report["source"] == {"kind": "case-artifact", "artifact_id": artifact["id"],
                                "size": 64, "sha256": artifact["sha256"],
                                "import_provenance": {"kind": "imported-unattested", "seq": 1,
                                "record_sha256": hashlib.sha256(canonical_json(ledger).encode()).hexdigest()}}
    assert report["edits"] == [{"offset": 16, "encoding": "u32le", "before_value": 123456,
                                 "after_value": 999999, "in_checksum_range": True}]
    for key in A.FLAGS:
        assert report[key] is False
    patch = (env[0].dir / result["patch"]["path"]).read_bytes()
    manifest = (env[0].dir / result["analysis"]["path"]).read_bytes()
    assert len(patch) == 64 and patch[16:20] == (999999).to_bytes(4, "little")
    assert int.from_bytes(patch[60:], "little") == sum(patch[:60])
    assert path.read_bytes() == original and json.loads(manifest) == report and manifest.endswith(b"\n")
    assert result["analysis"]["sha256"] == hashlib.sha256(manifest).hexdigest()
    assert result["patch"]["sha256"] == hashlib.sha256(patch).hexdigest()
    assert PRIVATE.encode() not in manifest and b"before_hex" not in manifest and b"after_hex" not in manifest
    assert len(env[0].artifacts()) == 2 and len(env[1].provenance.entries(env[0])) == 1
    entry = env[0].artifacts()[-1]
    assert entry["producer"] == "fwtriage-mcp" and entry["extra"] == {"type": "imported-save-plan"}
    for name in ("planned.bin", "manifest.json"):
        assert stat.S_IMODE((output_dirs(env)[0] / name).stat().st_mode) == 0o444


@pytest.mark.parametrize("encoding", saves.ENCODINGS)
def test_all_existing_encodings_nonzero_selection_and_no_checksum(env, encoding):
    data = b"HEAD" + bytes(32) + b"TAIL"
    artifact, path, _ = attached(env, data)
    result = plan(env, artifact, offset=4, length=32, checksum=None,
                  edits=[{"offset": 8, "encoding": encoding, "value": 12}])
    blob = (env[0].dir / result["patch"]["path"]).read_bytes()
    assert blob[:4] == b"HEAD" and blob[36:] == b"TAIL" and path.read_bytes() == data
    assert saves.decode_value(blob, 8, encoding) == 12
    assert result["report"]["edits"][0]["in_checksum_range"] is None
    assert result["report"]["checksum"] is None


@pytest.mark.parametrize("algorithm,endian", [(a, e) for a, p in saves.CHECKSUM_ALGORITHMS.items()
                                             for e in ([None] if p["width"] == 1 else ["le", "be"])])
def test_existing_checksum_rules_file_coordinates_and_outside_range(env, algorithm, endian):
    selected = bytearray(64)
    selected[:48] = bytes(range(48))
    width = saves.CHECKSUM_ALGORITHMS[algorithm]["width"]
    value = saves.checksum_compute(algorithm, selected[:48])
    selected[60:60 + width] = value.to_bytes(width, "big" if endian == "be" else "little")
    artifact, _, _ = attached(env, b"HEAD" + selected + b"TAIL")
    result = plan(env, artifact, offset=4, length=64,
                  edits=[{"offset": 12, "encoding": "u8", "value": 55},
                         {"offset": 54, "encoding": "u8", "value": 3}],
                  checksum={"algorithm": algorithm, "endian": endian, "location": 64, "range": [4, 52]})
    report = result["report"]
    assert [row["in_checksum_range"] for row in report["edits"]] == [True, False]
    assert report["checksum"]["location"] == 64 and report["checksum"]["range"] == [4, 52]
    assert report["checksum"]["original_rule_reproduced"] is True


def test_invalid_bcd_before_value_is_null(env):
    artifact, _, _ = attached(env, bytes([255]) * 64)
    result = plan(env, artifact, checksum=None, edits=[{"offset": 4, "encoding": "bcd2be", "value": 123}])
    assert result["report"]["edits"][0]["before_value"] is None


@pytest.mark.parametrize("change", [
    {"offset": True}, {"offset": 0.0}, {"length": 0}, {"length": 65}, {"length": "64"},
    {"edits": []}, {"edits": tuple()}, {"edits": [{"offset": 16, "encoding": "u8", "value": True}]},
    {"edits": [{"offset": 16, "encoding": "u8", "value": 256}]},
    {"edits": [{"offset": 16, "encoding": "u8", "value": 1, PRIVATE: 0}]},
    {"edits": [{"offset": 16, "encoding": "u32le", "value": 1}, {"offset": 18, "encoding": "u8", "value": 2}]},
    {"edits": [{"offset": 60, "encoding": "u8", "value": 1}]},
    {"edits": [{"offset": 63, "encoding": "u32le", "value": 1}]},
    {"edits": [{"offset": 1, "encoding": PRIVATE, "value": 1}]},
    {"purpose": "online"}, {"unlock_source": "sold-token"}, {"online_capable": "yes"},
    {"max_seconds": True}, {"max_seconds": float("nan")}, {"max_seconds": float("inf")},
    {"max_seconds": 31}, {"max_seconds": 10 ** 1000}, {"deadline": True}, {"deadline": float("inf")},
    {"checksum": {"algorithm": "sum8", "endian": "le", "location": 60, "range": [0, 60]}},
    {"checksum": {"algorithm": "sum32", "endian": None, "location": 60, "range": [0, 60]}},
    {"checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 64]}},
    {"checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": (0, 60)}},
    {"checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": [False, 60]}},
    {"checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 60], "width": 4}},
])
def test_strict_arguments_fail_before_output(env, change):
    artifact, _, _ = attached(env)
    fail(env, artifact, code="imported_save_input_invalid", **change)
    assert not output_dirs(env)


@pytest.mark.parametrize("kind", ["noop", "bad_checksum"])
def test_no_change_and_original_checksum_mismatch(env, kind):
    artifact, _, _ = attached(env, make_save() if kind == "noop" else bytes(64))
    if kind == "noop":
        fail(env, artifact, code="imported_save_no_changes", edits=[{"offset": 16, "encoding": "u32le", "value": 123456}])
    else:
        fail(env, artifact, code="imported_save_input_invalid",
             checksum={"algorithm": "crc32", "endian": "le", "location": 60, "range": [0, 60]})


@pytest.mark.parametrize("field,value", [("size", True), ("size", 0), ("size", (8 << 20) + 1),
    ("sha256", "A" * 64), ("is_dir", 0), ("path", "../outside"), ("path", "forensics/hidden"),
    ("path", "emu/hidden"), ("path", "dumps//x"), ("path", PRIVATE + "\x00")])
def test_index_projection_errors(env, field, value):
    artifact, _, _ = attached(env)
    mutate_artifact(env[0], lambda rows: rows[0].update({field: value}))
    fail(env, artifact, code="imported_save_input_limit" if field == "size" and value > A.MAX_INPUT_BYTES else "imported_save_input_invalid")


@pytest.mark.parametrize("kind", ["duplicate_id", "duplicate_path", "missing", "list_bad"])
def test_index_identity_is_unique(env, kind):
    artifact, _, _ = attached(env)
    def change(meta):
        rows = meta["artifacts"]
        if kind == "missing":
            rows.clear()
        elif kind == "list_bad":
            meta["artifacts"] = {}
        else:
            rows.append({**rows[0], "id": "A-9999" if kind == "duplicate_path" else rows[0]["id"]})
    env[0]._update(change)
    fail(env, artifact, code="imported_save_input_invalid")


@pytest.mark.parametrize("kind", ["missing", "device-read", "patch-plan", "same-path", "other-path"])
def test_latest_same_path_entry_not_import_prefilter(env, monkeypatch, kind):
    artifact, path, _ = attached(env)
    ledger = env[1].provenance
    if kind == "missing":
        monkeypatch.setattr(ledger, "entries", lambda *a, **k: [])
    elif kind == "device-read":
        ledger.record_device_read(env[0], path, {"server": "synthetic", "tool": "test"})
    elif kind == "patch-plan":
        ledger.record_patch_plan(env[0], path, {"server": "synthetic", "tool": "test"}, sha256=artifact["sha256"])
    else:
        original = A._Output.write
        added = False
        def write(self, *a, **k):
            nonlocal added
            result = original(self, *a, **k)
            if not added:
                added = True
                if kind == "same-path":
                    ledger.record_import(env[0], path, {"server": "synthetic", "tool": "test"})
                else:
                    other = env[0].dir / "dumps/other.bin"
                    other.write_bytes(b"other")
                    ledger.record_import(env[0], other, {"server": "synthetic", "tool": "test"})
            return result
        monkeypatch.setattr(A._Output, "write", write)
    if kind == "other-path":
        assert plan(env, artifact)["ok"]
    else:
        fail(env, artifact, code="imported_save_input_changed" if kind == "same-path" else "imported_save_input_invalid")
        assert not output_dirs(env)


def test_bounded_entries_twice_single_input_open_and_pread_chunks(env, monkeypatch):
    artifact, path, _ = attached(env, make_save() + bytes(200000))
    counts = {"entries": 0, "opens": 0}
    entries, op, pread = env[1].provenance.entries, A.safeio.open_regular, os.pread
    def snapshot(*a, **k):
        assert k["max_bytes"] == 16 << 20 and k["max_entries"] == 10000 and callable(k["check"])
        counts["entries"] += 1
        return entries(*a, **k)
    def open_file(name, **kwargs):
        if name == path.name:
            counts["opens"] += 1
        return op(name, **kwargs)
    def read(fd, size, offset):
        assert size <= 65536
        return pread(fd, size, offset)
    monkeypatch.setattr(env[1].provenance, "entries", snapshot)
    monkeypatch.setattr(A.safeio, "open_regular", open_file)
    monkeypatch.setattr(os, "pread", read)
    monkeypatch.setattr(env[1].provenance, "verify", lambda *a, **k: pytest.fail("증명 조회가 필요 없음"))
    plan(env, artifact)
    assert counts == {"entries": 2, "opens": 1}


@pytest.mark.parametrize("kind", ["nvs-whole", "nvs-selected", "esp"])
def test_existing_format_filters_use_bytes(env, kind):
    if kind.startswith("nvs"):
        page = bytearray(b"\xff" * 4096)
        struct.pack_into("<I", page, 0, 0xFFFFFFFE)
        struct.pack_into("<I", page, 28, espfmt.nvs_crc32(page[4:28]))
        data = bytes(page) if kind == "nvs-whole" else b"HEAD" + page + b"TAIL"
        offset, length = (0, 64) if kind == "nvs-whole" else (4, 4096)
    else:
        data = struct.pack("<HBBII16sI", 0x50AA, 1, 2, 0x9000, 0x1000, b"nvs", 0) + b"\xff" * 96
        offset, length = 0, 64
    artifact, _, _ = attached(env, data)
    fail(env, artifact, code="imported_save_input_invalid", offset=offset, length=length, checksum=None)


@pytest.mark.parametrize("kind", ["hardlink", "symlink", "parent-link", "same-inode", "replace", "atime"])
def test_input_file_and_parent_identity(env, monkeypatch, kind):
    artifact, path, _ = attached(env, relative="dumps/nested/save.bin")
    if kind == "hardlink":
        os.link(path, path.with_name("alias"))
    elif kind == "symlink":
        path.rename(path.with_name("old"))
        path.symlink_to(path.with_name("old"))
    elif kind == "parent-link":
        path.parent.rename(path.parent.with_name("old"))
        path.parent.symlink_to(path.parent.with_name("old"))
    else:
        original = A._plan_bytes
        def changed(*a, **k):
            result = original(*a, **k)
            if kind == "same-inode":
                with path.open("r+b") as f:
                    f.write(b"FAIL")
            elif kind == "replace":
                raw = path.read_bytes()
                path.unlink()
                path.write_bytes(raw)
            else:
                st = path.stat()
                # 읽기에 따른 atime 갱신은 ctime을 바꾸는 명시 utime 대신 실제 읽기로 검증한다.
                path.read_bytes()
                assert path.stat().st_mtime_ns == st.st_mtime_ns
            return result
        monkeypatch.setattr(A, "_plan_bytes", changed)
    if kind == "atime":
        assert plan(env, artifact)["ok"]
    else:
        fail(env, artifact)
        assert len(env[0].artifacts()) == 1


@pytest.mark.parametrize("kind", ["binary", "manifest", "unknown", "replacement", "source-during-output-hash", "index"])
def test_final_check_detects_source_and_output_changes(env, monkeypatch, kind):
    artifact, path, _ = attached(env)
    register = env[0].register_artifact
    def wrapped(name, **kwargs):
        out = env[0].dir / name
        if kind in ("binary", "manifest"):
            target = out if kind == "manifest" else out.with_name("planned.bin")
            target.chmod(0o600)
            with target.open("r+b") as f:
                f.write(b"!")
        elif kind == "unknown":
            out.with_name(PRIVATE).write_bytes(b"retain")
        elif kind == "replacement":
            out.rename(out.with_name("moved"))
            out.write_bytes(b"retain")
        elif kind == "index":
            mutate_artifact(env[0], lambda rows: rows[0].update(sha256="0" * 64))
        else:
            original = A._read_fd
            changed = False
            def read(fd, size, end, cancel, **kw):
                nonlocal changed
                result = original(fd, size, end, cancel, **kw)
                if not changed and os.fstat(fd).st_ino == out.stat().st_ino:
                    changed = True
                    with path.open("r+b") as f:
                        f.write(b"FAIL")
                return result
            monkeypatch.setattr(A, "_read_fd", read)
        return register(name, **kwargs)
    monkeypatch.setattr(env[0], "register_artifact", wrapped)
    code = fail(env, artifact)
    assert len(env[0].artifacts()) == 1
    if kind in ("unknown", "replacement"):
        assert code == "imported_save_cleanup_incomplete" and output_dirs(env)
    else:
        assert not output_dirs(env)


@pytest.mark.parametrize("stage", ["start", "helper", "final", "late"])
def test_cancellation_before_commit_or_after_receipt(env, monkeypatch, stage):
    artifact, _, _ = attached(env)
    cancelled = threading.Event()
    if stage == "start":
        cancelled.set()
    elif stage == "helper":
        original = saves.apply_raw_edits
        def compute(*a, **k):
            result = original(*a, **k)
            cancelled.set()
            return result
        monkeypatch.setattr(saves, "apply_raw_edits", compute)
    else:
        original = env[0].register_artifact
        def register(name, **kwargs):
            callback_name = "check" if stage == "final" else "on_commit"
            callback = kwargs[callback_name]
            def cb(entry):
                if stage == "late":
                    callback(entry)
                cancelled.set()
                if stage == "final":
                    callback(entry)
            kwargs[callback_name] = cb
            return original(name, **kwargs)
        monkeypatch.setattr(env[0], "register_artifact", register)
    if stage == "late":
        assert plan(env, artifact, cancel=cancelled.is_set)["ok"] and len(env[0].artifacts()) == 2
    else:
        fail(env, artifact, code="cancelled", cancel=cancelled.is_set)
        assert not output_dirs(env)


@pytest.mark.parametrize("stage", ["write", "fsync", "schema", "register", "postcommit", "close"])
def test_failure_cleanup_and_postcommit_warning(env, monkeypatch, stage):
    artifact, _, _ = attached(env)
    def broken(*a, **k):
        raise RuntimeError(PRIVATE)
    if stage == "write":
        monkeypatch.setattr(os, "write", broken)
    elif stage == "fsync":
        monkeypatch.setattr(os, "fsync", broken)
    elif stage == "schema":
        monkeypatch.setattr(A.schemas, "validate", broken)
    elif stage == "register":
        monkeypatch.setattr(env[0], "register_artifact", broken)
    elif stage == "postcommit":
        monkeypatch.setattr(env[0], "audit", broken)
    else:
        original = A._Output.close
        def close(self):
            assert original(self)
            return False
        monkeypatch.setattr(A._Output, "close", close)
    if stage in ("postcommit", "close"):
        result = plan(env, artifact)
        assert result["warnings"] == ["post_commit_callback_failed" if stage == "postcommit" else "output_close_unconfirmed"]
        assert len(env[0].artifacts()) == 2 and output_dirs(env)
    else:
        fail(env, artifact)
        assert not output_dirs(env)


@pytest.mark.parametrize("kind", ["bad_encoding_value", "changed_unedited", "numeric_bool", "length"])
def test_helper_projection_cannot_publish_forged_output(env, monkeypatch, kind):
    artifact, _, _ = attached(env)
    original = saves.apply_raw_edits
    def compute(*a, **k):
        data, rows = original(*a, **k)
        if kind == "bad_encoding_value":
            data = data[:16] + b"\x00" * 4 + data[20:]
        elif kind == "changed_unedited":
            data = b"FAIL" + data[4:]
        elif kind == "numeric_bool":
            rows[0]["offset"] = True
        else:
            data += b"x"
        return data, rows
    monkeypatch.setattr(saves, "apply_raw_edits", compute)
    fail(env, artifact, code="imported_save_failed")
    assert not output_dirs(env)


@pytest.mark.parametrize("code,expected", [
    ("provenance_bounded_limit", "imported_save_input_limit"),
    ("provenance_ledger_broken", "imported_save_input_invalid"),
    ("provenance_bounded_changed", "imported_save_input_changed"),
    ("lock_timeout", "time_limit"), ("artifact_timeout", "time_limit"),
])
def test_existing_ledger_and_lock_errors_have_fixed_projection(env, monkeypatch, code, expected):
    artifact, _, _ = attached(env)
    def broken(*a, **k):
        raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE})
    monkeypatch.setattr(env[1].provenance, "entries", broken)
    fail(env, artifact, code=expected)
    assert not output_dirs(env)


@pytest.mark.parametrize("field,value", [("seq", True), ("size", True), ("size", 65), ("sha256", "0" * 64),
                                        ("kind", "imported-attested"), ("case_id", "different-case")])
def test_ledger_exact_projection_cannot_be_forged(env, monkeypatch, field, value):
    artifact, _, entry = attached(env)
    monkeypatch.setattr(env[1].provenance, "entries", lambda *a, **k: [{**entry, field: value}])
    fail(env, artifact)
    assert not output_dirs(env)


@pytest.mark.parametrize("point", ["helper", "first-output-hash", "final-hash"])
def test_one_main_deadline_and_one_final_deadline(env, monkeypatch, point):
    artifact, _, _ = attached(env)
    clock = [time.monotonic()]
    monkeypatch.setattr(A, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    if point == "helper":
        original = saves.apply_raw_edits
        def compute(*a, **k):
            result = original(*a, **k)
            clock[0] += 31
            return result
        monkeypatch.setattr(saves, "apply_raw_edits", compute)
    else:
        original_read, original_register = A._read_fd, env[0].register_artifact
        final = False
        def register(name, **kwargs):
            nonlocal final
            final = True
            assert kwargs["deadline"] == clock[0] + 5
            return original_register(name, **kwargs)
        def read(fd, size, deadline, cancel, **kw):
            result = original_read(fd, size, deadline, cancel, **kw)
            output_file = safeio.fd_real_path(fd) or ""
            if (point == "first-output-hash" and str(output_file).endswith("planned.bin") and not final
                    or point == "final-hash" and final):
                clock[0] = deadline + 1
            return result
        monkeypatch.setattr(env[0], "register_artifact", register)
        monkeypatch.setattr(A, "_read_fd", read)
    fail(env, artifact, code="time_limit", deadline=clock[0] + 30)
    assert not output_dirs(env)


def test_final_budget_does_not_reuse_expired_processing_deadline(env, monkeypatch):
    artifact, _, _ = attached(env)
    clock = [time.monotonic()]
    start = clock[0]
    monkeypatch.setattr(A, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    original = env[0].register_artifact
    def register(name, **kwargs):
        assert kwargs["deadline"] == start + 5
        clock[0] += 2
        return original(name, **kwargs)
    monkeypatch.setattr(env[0], "register_artifact", register)
    assert plan(env, artifact, max_seconds=1, deadline=start + 1)["ok"]


@pytest.mark.parametrize("point", ["mkdir", "second-create", "second-write", "dir-replace"])
def test_partial_output_failure_tracks_created_inodes(env, monkeypatch, point):
    artifact, _, _ = attached(env)
    if point == "mkdir":
        original = os.open
        def open_file(name, flags, *args, **kwargs):
            if str(name).startswith("imported-save-plan-"):
                raise OSError(PRIVATE)
            return original(name, flags, *args, **kwargs)
        monkeypatch.setattr(os, "open", open_file)
    elif point == "second-create":
        original = os.open
        def open_file(name, flags, *args, **kwargs):
            if name == "manifest.json":
                raise OSError(PRIVATE)
            return original(name, flags, *args, **kwargs)
        monkeypatch.setattr(os, "open", open_file)
    else:
        original = A._Output.write
        def write(self, name, data, deadline, cancel):
            if name == "manifest.json" and point == "second-write":
                old_write = os.write
                def broken(fd, data):
                    if str(safeio.fd_real_path(fd)).endswith("manifest.json"):
                        raise OSError(PRIVATE)
                    return old_write(fd, data)
                monkeypatch.setattr(os, "write", broken)
            result = original(self, name, data, deadline, cancel)
            if name == "manifest.json" and point == "dir-replace":
                directory = env[0].dir / "patches" / self.name
                directory.rename(directory.with_name("preserved-original"))
                directory.mkdir()
                (directory / PRIVATE).write_bytes(b"retain")
            return result
        monkeypatch.setattr(A._Output, "write", write)
    code = fail(env, artifact)
    assert len(env[0].artifacts()) == 1
    if point == "dir-replace":
        assert code == "imported_save_cleanup_incomplete"
        assert (output_dirs(env)[0] / PRIVATE).read_bytes() == b"retain"
    else:
        assert not output_dirs(env)


def test_output_reservation_is_bounded_and_does_not_touch_existing_dirs(env):
    artifact, _, _ = attached(env)
    for index in range(1, 65):
        p = env[0].dir / "patches" / f"imported-save-plan-{index:03d}"
        p.mkdir()
        (p / "keep").write_bytes(b"preserve")
    fail(env, artifact, code="imported_save_failed")
    assert len(output_dirs(env)) == 64
    assert all((path / "keep").read_bytes() == b"preserve" for path in output_dirs(env))


@pytest.mark.parametrize("field,value", [("size", True), ("path", "patches/other"),
                                        ("sha256", "0" * 64), ("is_dir", True)])
def test_checked_registration_entry_is_exact(env, monkeypatch, field, value):
    artifact, _, _ = attached(env)
    original = env[0].register_artifact
    def register(name, **kwargs):
        check = kwargs["check"]
        kwargs["check"] = lambda entry: check({**entry, field: value})
        return original(name, **kwargs)
    monkeypatch.setattr(env[0], "register_artifact", register)
    fail(env, artifact, code="imported_save_input_changed")
    assert len(env[0].artifacts()) == 1 and not output_dirs(env)


def test_callback_exception_is_fixed_and_close_attempts_are_independent(env, monkeypatch):
    artifact, _, _ = attached(env)
    def cancel():
        raise RuntimeError(PRIVATE)
    fail(env, artifact, code="imported_save_failed", cancel=cancel)
    original = os.close
    closed = []
    def close(fd):
        path = str(safeio.fd_real_path(fd))
        original(fd)
        closed.append(path)
        if path.endswith("planned.bin"):
            raise OSError(PRIVATE)
    monkeypatch.setattr(os, "close", close)
    result = plan(env, artifact)
    assert result["warnings"] == ["output_close_unconfirmed"]
    assert any(path.endswith("manifest.json") for path in closed)
    assert any(path.endswith("synthetic-save.bin") for path in closed)
