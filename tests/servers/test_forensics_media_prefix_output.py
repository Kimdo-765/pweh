"""합성 prefix 출력의 같은 fd 검증·원자 커밋·자기 inode 정리 회귀."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import stat
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from core.test_media_candidates import box, envelope, ftyp
from forensics_mcp import media_prefix_output as W
from forensics_mcp.media_prefix_tools import _manifest
from pweh import evidence as E, safeio, schemas
from pweh.case import CaseStore
from pweh.jobs import JobCancelled
from pweh.media_candidates import scan_bmff_candidates

PRIVATE = b"SYNTHETIC_PRIVATE_PREFIX_91"


@pytest.fixture
def prefix_case(workspace, auth):
    @contextlib.contextmanager
    def build(*, content=None, partial=False):
        case = CaseStore(workspace["cases_dir"]).create(
            title="합성 prefix writer", authorization=auth)
        log = E.CustodyLog(case, workspace["state_dir"] / "custody")
        data = content if content is not None else PRIVATE + ftyp() + box(b"mdat", PRIVATE * 4)
        if partial:
            data += b"truncated"
        ev = _commit_intake(case, log, data)
        with E.open_checked(case, ev, log.entries()) as opened:
            report = envelope(scan_bmff_candidates(data, deadline=time.monotonic() + 30))
            report["source"].update(evidence_id=ev, evidence_sha256=hashlib.sha256(data).hexdigest(),
                                    selected_sha256=hashlib.sha256(data).hexdigest())
            schemas.validate("media-candidates", report)
            stored = E.store_analysis(case, opened, report, event="media-candidates", custody_log=log)
            source = SimpleNamespace(source=report["source"], candidate=report["candidates"][0],
                                     coverage=report["coverage"], upstream_status=report["status"],
                                     origin=SimpleNamespace(**stored["analysis"]))
            manifest = _manifest(source, data, report["source"], 0, lambda: None)
            yield SimpleNamespace(case=case, log=log, opened=opened, data=data, manifest=manifest,
                                  report=report, stored=stored)
    return build


def store(context, **kwargs):
    defaults = dict(manifest=context.manifest, custody_log=context.log, reference_roots=(),
                    deadline=time.monotonic() + 30, check=lambda: None, check_entries=lambda entries: None)
    defaults.update(kwargs)
    return W.store_media_prefix(context.case, context.opened, context.data, **defaults)


def directories(context):
    return list((context.case.dir / "forensics/recovered").glob("media-prefix-*"))


def no_commit(context):
    assert [item["event"] for item in context.log.entries()] == ["intake", "media-candidates"]


def test_prefix_same_fd_lock_hash_permissions_and_closed_receipt(prefix_case, monkeypatch):
    with prefix_case() as ctx:
        made, calls = [], []
        create = W._Output.create

        def capture(self, name):
            fd = create(self, name)
            made.append(fd)
            return fd

        def check_entries(entries):
            assert [item["event"] for item in entries] == ["intake", "media-candidates"]
            assert len(made) == 2
            assert all(stat.S_IMODE(os.fstat(fd).st_mode) == 0o444 for fd in made)
            ffd = E.open_forensics(ctx.case)
            try:
                assert safeio.try_lock_at(ffd, E.CUSTODY_LOCK, create=False) is None
            finally:
                os.close(ffd)
            calls.append("same-lock")

        monkeypatch.setattr(W._Output, "create", capture)
        result = store(ctx, check_entries=check_entries, on_commit=lambda entry: calls.append("committed"))
        root = ctx.case.dir / result["output_dir"]
        candidate = ctx.manifest["candidate"]
        expected = ctx.data[candidate["offset"]:candidate["offset"] + candidate["validated_prefix_length"]]
        assert result["ok"] and result["warnings"] == [] and calls == ["same-lock", "committed"]
        assert (root / W.PAYLOAD_NAME).read_bytes() == expected
        assert stat.S_IMODE(root.stat().st_mode) == 0o555
        assert {item.name for item in root.iterdir()} == {W.PAYLOAD_NAME, W.MANIFEST_NAME}
        for item in root.iterdir():
            assert stat.S_IMODE(item.stat().st_mode) == 0o444 and item.stat().st_nlink == 1
        raw = (root / W.MANIFEST_NAME).read_bytes()
        assert len(raw) <= W.MAX_MANIFEST_BYTES and hashlib.sha256(raw).hexdigest() == result["manifest_sha256"]
        assert json.loads(raw) == ctx.manifest
        assert PRIVATE not in raw and PRIVATE.decode() not in json.dumps(result)
        event = ctx.log.entries()[-1]
        assert event["event"] == "extract" and event["data"]["method"] == W.METHOD
        assert event["data"]["analysis"] == ctx.manifest["analysis"]
        assert event["data"]["bytes"] == len(expected) == result["bytes_total"]
        assert E.replay_status(ctx.log.entries(), ctx.opened.evidence_id)["extracts"] == 1
        for fd in made:
            with pytest.raises(OSError):
                os.fstat(fd)
        os.fstat(ctx.opened.fd)  # 호출자의 증거 fd는 닫지 않는다.


def test_partial_observations_preserved_but_prefix_complete(prefix_case):
    with prefix_case(partial=True) as ctx:
        assert ctx.manifest["status"] == "partial"
        result = store(ctx)
        saved = json.loads((ctx.case.dir / result["manifest"]).read_bytes())
        assert result["status"] == saved["source_status"] == "partial"
        assert saved["source_coverage"] == ctx.report["coverage"]
        assert saved["files"][0]["complete"] is True
        assert saved["complete_recording"] is saved["media_decoded"] is saved["playback_verified"] is False


@pytest.mark.parametrize("field", ["evidence_id", "evidence_sha256", "source.evidence_id", "source.evidence_sha256",
                                    "source.selected_size", "source.selected_sha256", "source_coverage.input_bytes",
                                    "candidate.offset", "candidate.validated_prefix_length", "candidate.index",
                                    "files.sha256", "files.size", "bytes_total"])
def test_manifest_input_and_expected_hash_mismatch_never_commit(prefix_case, field):
    with prefix_case() as ctx:
        manifest = copy.deepcopy(ctx.manifest)
        parts = field.split(".")
        target = manifest if len(parts) == 1 else manifest[parts[0]]
        if parts[0] == "files":
            target = target[0]
        key = parts[-1]
        if key == "evidence_id":
            target[key] = "EV-0099"
        elif "sha256" in key:
            target[key] = "0" * 64
        elif key == "index":
            target[key] = True
        elif key == "offset":
            target[key] = len(ctx.data)
        else:
            target[key] += 1
        with pytest.raises(E.EvidenceError):
            store(ctx, manifest=manifest)
        no_commit(ctx)
        assert directories(ctx) == []


@pytest.mark.parametrize("invalid", [None, [], "private", {"private": PRIVATE.decode()}, {"x": [0] * 1025},
                                     {"x": "x" * (W.MAX_MANIFEST_BYTES + 1)}, {"x": 1.0}, {"x": 10**100}])
def test_invalid_manifest_closed_error(prefix_case, invalid):
    with prefix_case() as ctx:
        with pytest.raises(E.EvidenceError) as error:
            store(ctx, manifest=invalid)
        assert PRIVATE.decode() not in str(error.value)
        assert error.value.__suppress_context__
        assert directories(ctx) == []
        no_commit(ctx)


def test_cyclic_manifest_is_bounded(prefix_case):
    with prefix_case() as ctx:
        bad = {}
        bad["loop"] = bad
        with pytest.raises(E.EvidenceError) as error:
            store(ctx, manifest=bad)
        assert error.value.code == "output_limit"


@pytest.mark.parametrize("deadline,code", [(float("nan"), "media_prefix_input_invalid"),
    (float("inf"), "media_prefix_input_invalid"), (10**400, "media_prefix_input_invalid"),
    (True, "media_prefix_input_invalid"), ("30", "media_prefix_input_invalid"), (0, "time_limit")])
def test_deadline_is_finite_shared_and_bounded(prefix_case, deadline, code):
    with prefix_case() as ctx:
        with pytest.raises(E.EvidenceError) as error:
            store(ctx, deadline=deadline)
        assert error.value.code == code
        no_commit(ctx)


def test_deadline_not_extended_by_successful_callback(prefix_case, monkeypatch):
    with prefix_case() as ctx:
        clock = [100.0]
        monkeypatch.setattr(W, "time", SimpleNamespace(monotonic=lambda: clock[0]))
        def check():
            clock[0] = 102.0
        with pytest.raises(E.EvidenceError) as error:
            store(ctx, deadline=101.0, check=check)
        assert error.value.code == "time_limit" and directories(ctx) == []


def test_manifest_frozen_before_external_final_callback(prefix_case):
    with prefix_case() as ctx:
        original = copy.deepcopy(ctx.manifest)
        def change(entries):
            ctx.manifest["analysis"]["path"] = PRIVATE.decode()
            ctx.manifest["files"][0]["sha256"] = "0" * 64
        result = store(ctx, check_entries=change)
        assert json.loads((ctx.case.dir / result["manifest"]).read_bytes()) == original
        assert ctx.log.entries()[-1]["data"]["analysis"] == original["analysis"]


@pytest.mark.parametrize("name", [W.PAYLOAD_NAME, W.MANIFEST_NAME])
@pytest.mark.parametrize("mutation", ["regular", "symlink", "foreign-hardlink", "own-hardlink", "content", "writable", "missing"])
def test_output_mutation_refused_and_only_owned_inode_removed(prefix_case, tmp_path, name, mutation):
    with prefix_case() as ctx:
        foreign = tmp_path / "unrelated"
        foreign.write_bytes(PRIVATE)
        foreign.chmod(0o444)
        moved = tmp_path / "original"
        output = None

        def change(entries):
            nonlocal output
            directory, = directories(ctx)
            directory.chmod(0o755)
            output = directory / name
            old = output.stat()
            if mutation in {"regular", "symlink", "foreign-hardlink", "missing"}:
                output.rename(moved)
                if mutation == "regular":
                    output.write_bytes(PRIVATE)
                    output.chmod(0o444)
                elif mutation == "symlink":
                    output.symlink_to(foreign)
                elif mutation == "foreign-hardlink":
                    os.link(foreign, output)
            elif mutation == "own-hardlink":
                os.link(output, moved)
            elif mutation == "content":
                output.chmod(0o644)
                output.write_bytes(b"x" * old.st_size)
                os.utime(output, ns=(old.st_atime_ns, old.st_mtime_ns))
                output.chmod(0o444)
            else:
                output.chmod(0o644)
            directory.chmod(0o555)

        with pytest.raises(E.EvidenceError) as error:
            store(ctx, check_entries=change)
        no_commit(ctx)
        assert foreign.read_bytes() == PRIVATE
        if mutation in {"regular", "symlink", "foreign-hardlink"}:
            assert error.value.code == "cleanup_incomplete"
            assert output.read_bytes() == PRIVATE
        else:
            assert directories(ctx) == []
        if mutation in {"regular", "symlink", "foreign-hardlink", "missing", "own-hardlink"}:
            assert moved.exists()


@pytest.mark.parametrize("mutation", ["directory", "parent", "unknown"])
def test_directory_swap_and_unknown_entries_are_preserved(prefix_case, tmp_path, mutation):
    with prefix_case() as ctx:
        moved = tmp_path / "moved"
        foreign = None
        def change(entries):
            nonlocal foreign
            directory, = directories(ctx)
            if mutation == "unknown":
                directory.chmod(0o755)
                foreign = directory / "unknown.bin"
            elif mutation == "directory":
                directory.chmod(0o755)  # 다른 부모로 옮길 때 합성 디렉터리의 .. 갱신도 허용한다.
                directory.rename(moved)
                moved.chmod(0o555)
                directory.mkdir()
                foreign = directory / "foreign.bin"
            else:
                parent = directory.parent
                parent.rename(moved)
                parent.mkdir()
                foreign = parent / "foreign.bin"
            foreign.write_bytes(PRIVATE)
        with pytest.raises(E.EvidenceError) as error:
            store(ctx, check_entries=change)
        assert foreign.read_bytes() == PRIVATE
        if mutation != "parent":
            assert error.value.code == "cleanup_incomplete"
        no_commit(ctx)


@pytest.mark.parametrize("stage", ["payload-created", "manifest-created", "payload-sealed", "manifest-sealed"])
def test_partial_creation_and_sealing_failure_cleanup(prefix_case, monkeypatch, stage):
    with prefix_case() as ctx:
        name = W.PAYLOAD_NAME if stage.startswith("payload") else W.MANIFEST_NAME
        method = "create" if stage.endswith("created") else "seal"
        original = getattr(W._Output, method)
        captured = []
        def fail(self, selected):
            value = original(self, selected)
            captured[:] = self.files.values()
            if selected == name:
                raise OSError(PRIVATE.decode())
            return value
        monkeypatch.setattr(W._Output, method, fail)
        with pytest.raises(E.EvidenceError) as error:
            store(ctx)
        assert PRIVATE.decode() not in str(error.value)
        assert directories(ctx) == []
        no_commit(ctx)
        for fd in captured:
            with pytest.raises(OSError):
                os.fstat(fd)


@pytest.mark.parametrize("behavior", ["short", "zero", "cancel", "timeout"])
def test_bounded_chunks_partial_writes_and_cancel_cleanup(prefix_case, monkeypatch, behavior):
    content = ftyp() + box(b"mdat", b"S" * (W.CHUNK_BYTES * 2))
    with prefix_case(content=content) as ctx:
        writes, fds = [], set()
        create, write = W._Output.create, os.write
        cancelled = [False]
        def capture(self, name):
            fd = create(self, name)
            fds.add(fd)
            return fd
        def bounded(fd, data):
            if fd in fds:
                assert len(data) <= W.CHUNK_BYTES
                writes.append(len(data))
                if behavior == "zero":
                    return 0
                if behavior in {"cancel", "timeout"}:
                    cancelled[0] = True
                if behavior == "short":
                    return write(fd, data[:4096])
            return write(fd, data)
        def check():
            if cancelled[0]:
                if behavior == "cancel":
                    raise JobCancelled()
                raise E.EvidenceError("합성 마감", code="time_limit")
        monkeypatch.setattr(W._Output, "create", capture)
        monkeypatch.setattr(os, "write", bounded)
        if behavior == "short":
            assert store(ctx, check=check)["ok"]
            assert len(writes) > 3
        else:
            with pytest.raises(E.EvidenceError) as error:
                store(ctx, check=check)
            assert error.value.code == {"cancel": "cancelled", "timeout": "time_limit", "zero": "media_prefix_failed"}[behavior]
            no_commit(ctx)
            assert directories(ctx) == []
        assert writes


def test_same_fd_payload_hash_rechecked_at_commit(prefix_case, monkeypatch):
    with prefix_case() as ctx:
        real = os.pread
        def corrupt(fd, length, offset):
            st = os.fstat(fd)
            # 증거 fd와 보고서는 그대로이며, 작성한 prefix의 같은 fd 재해시만 변조한다.
            if st.st_size == ctx.manifest["bytes_total"] and offset == 0:
                return b"x" * length
            return real(fd, length, offset)
        monkeypatch.setattr(os, "pread", corrupt)
        with pytest.raises(E.EvidenceError):
            store(ctx)
        assert directories(ctx) == []
        no_commit(ctx)


@pytest.mark.parametrize("error", [JobCancelled(), RuntimeError(PRIVATE.decode())])
def test_final_entries_callback_failure_does_not_commit(prefix_case, error):
    with prefix_case() as ctx:
        def fail(entries):
            raise error
        with pytest.raises(E.EvidenceError) as caught:
            store(ctx, check_entries=fail)
        assert PRIVATE.decode() not in str(caught.value) and caught.value.__suppress_context__
        no_commit(ctx)
        assert directories(ctx) == []


def test_ev_integrity_failure_survives_fixed_error_boundary(prefix_case):
    with prefix_case() as ctx:
        def change():
            if directories(ctx):
                path = ctx.case.dir / ctx.opened.record["stored"]["path"]
                path.chmod(0o644)
                path.write_bytes(b"x" * len(ctx.data))
                path.chmod(0o444)
        with pytest.raises(E.IntegrityProblem) as error:
            store(ctx, check=change)
        assert error.value.record and error.value.reason == "media-prefix-integrity-check"
        no_commit(ctx)
        assert directories(ctx) == []


def test_postcommit_cancel_and_audit_failure_preserve_receipt(prefix_case):
    with prefix_case() as ctx:
        late = [False]
        def check():
            if late[0]:
                raise JobCancelled()
        def commit(entry):
            assert entry["event"] == "extract"
            late[0] = True
            raise RuntimeError(PRIVATE.decode())
        result = store(ctx, check=check, on_commit=commit)
        assert result["ok"] and result["warnings"] == ["post_commit_callback_failed"]
        assert (ctx.case.dir / result["manifest"]).exists()
        assert ctx.log.entries()[-1]["event"] == "extract"
        assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize("mutation,expected", [("none", "recorded"), ("manifest", "mismatch"),
    ("missing", "missing"), ("unrecorded", "unrecorded"), ("unknown", "unknown"), ("payload", "recorded")])
def test_derived_manifest_binding_uses_existing_semantics(prefix_case, mutation, expected):
    from forensics_mcp import server as S
    with prefix_case() as ctx:
        result = store(ctx)
        directory = ctx.case.dir / result["output_dir"]
        entries = ctx.log.entries()
        if mutation == "manifest":
            path = directory / W.MANIFEST_NAME
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b" ")
            path.chmod(0o444)
        elif mutation == "missing":
            directory.rename(directory.with_name("unrelated"))
        elif mutation == "unrecorded":
            entries = entries[:-1]
        elif mutation == "unknown":
            entries = None
        elif mutation == "payload":
            path = directory / W.PAYLOAD_NAME
            path.chmod(0o644)
            path.write_bytes(b"x" * result["bytes_total"])
            path.chmod(0o444)
        item, = [item for item in S._derived_outputs(ctx.case, entries) if item["path"] == result["output_dir"]]
        assert item["custody"] == expected
        # recorded는 manifest 결속이며, 목록 조회가 payload를 다시 해시했다는 뜻이 아니다.
        if mutation in {"none", "payload"}:
            assert item["files"] == 1 and item["bytes"] == result["bytes_total"]
