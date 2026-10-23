"""실제 Linux pipe owner와 합성 writer의 같은 FD/게시 경계 시험."""
from dataclasses import replace
import hashlib
import json
import os
import stat
import time
from types import SimpleNamespace

import pytest

from openocd_mcp import windows_output as O
from pweh.runtime import get_runtime
from .test_openocd_windows_process import setup as owner_setup, end


@pytest.fixture
def lab(owner_setup, workspace, auth):
    case = get_runtime("openocd").cases.create(title="합성 내부 출력", authorization=auth)
    owners = owner_setup.owners
    def start(**changes):
        owner = owner_setup.spawn()
        assert owner.wait_ready(timeout=2).ready
        spec = O.PipeFileSpec(case, "memory", "sample", 512, 256, address=0x1000)
        spec = replace(spec, **changes)
        output = O.prepare_output(owner, spec, deadline=end(), cancel=None)
        return owner, output
    yield SimpleNamespace(case=case, start=start, fixture=owner_setup)
    for owner in owners:
        assert owner.close(timeout=3).confirmed
        assert O.release_outputs(owner, deadline=end())


def fill(output, data=None):
    n = min(output.spec.chunk_size, output.spec.length-output.done)
    data = bytes((output.done + i) % 251 for i in range(n)) if data is None else data
    chunk = output.create_chunk(output.chunks, "primary", n, deadline=end())
    offset = (output.spec.address if output.spec.kind == "memory" else output.spec.offset) + output.done
    operation = "dump_image" if output.spec.kind == "memory" else "read_bank"
    output.command(operation, chunk, address_or_offset=offset)
    chunk.local_path.write_bytes(data)
    second = None
    if output.spec.verify:
        if output.spec.kind == "memory":
            second = output.create_chunk(output.chunks, "second", n, deadline=end())
            output.command(operation, second, address_or_offset=offset)
            second.local_path.write_bytes(data)
        else:
            output.command("verify_bank", chunk, address_or_offset=offset)
    output.accept_chunk(chunk, second, deadline=end(), cancel=None)
    return data


@pytest.mark.parametrize("kind,verify", [("memory", False), ("memory", True), ("flash", False), ("flash", True)])
def test_multichunk_publish_actual_owner_receipt(lab, kind, verify):
    changes = dict(kind=kind, verify=verify, length=600)
    if kind == "flash":
        changes.update(address=None, bank=0, offset=128, bank_size=1024)
    owner, output = lab.start(**changes)
    data = b""
    while output.done < output.spec.length:
        data += fill(output)
    assert output.chunks == 3 and output.done == 600
    assert owner.close(timeout=3).confirmed
    result = output.publish(owner_confirmed=True, deadline=end(), cancel=None)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert lab.case.path(result["path"]).read_bytes() == data
    assert result["artifact"]["sha256"] == result["sha256"]
    assert result["warnings"] == []
    assert stat.S_IMODE(lab.case.path(result["path"]).stat().st_mode) == 0o444
    assert O.release_outputs(owner, deadline=end())
    assert not lab.case.path("jtag" if kind == "memory" else "dumps", "sample.part").exists()
    assert lab.case.path(result["path"]).exists()


@pytest.mark.parametrize("changes", [
    {"length": True}, {"length": 0}, {"length": (1 << 32)+1}, {"chunk_size": 255},
    {"chunk_size": (16 << 20)+1}, {"verify": 1}, {"resume": 0}, {"address": True},
    {"address": 1 << 64}, {"address": (1 << 64)-1}, {"offset": True}, {"offset": 1},
    {"output_name": "../private"}, {"output_name": "sample.bin"}, {"output_name": " x"},
    {"kind": "auto"}, {"bank": 0}, {"bank_size": 1},
])
def test_invalid_memory_specs_before_io(lab, changes):
    spec = O.PipeFileSpec(lab.case, "memory", "valid", 512, 256, address=0)
    with pytest.raises(O.PipeOutputError, match="내부 pipe"):
        O._spec(replace(spec, **changes))


@pytest.mark.parametrize("changes", [
    {"length": 1 << 32}, {"offset": 1 << 32}, {"bank_size": 1 << 32},
    {"offset": (1 << 32)-1}, {"bank": 1 << 31}, {"bank": True}, {"address": 0},
])
def test_flash_u32_is_distinct_from_memory(lab, changes):
    spec = O.PipeFileSpec(lab.case, "flash", "valid", 256, 256, bank=0, bank_size=(1 << 32)-1)
    with pytest.raises(O.PipeOutputError):
        O._spec(replace(spec, **changes))


def test_flash_upper_boundary_commands(lab):
    owner, output = lab.start(kind="flash", address=None, bank=1, bank_size=(1 << 32)-1,
                             offset=(1 << 32)-257, length=256, verify=True)
    fill(output)
    assert output.done == 256


@pytest.mark.parametrize("path", ["C:/단어 $x; 이름/chunk.bin", "//wsl.localhost/Ubuntu/home/a/b.bin"])
def test_exact_path_pair_and_braced_word(lab, path):
    owner, output = lab.start(length=256)
    owner._path_converter = lambda *a, **kw: path
    chunk = output.create_chunk(0, "primary", 256, deadline=end())
    command = output.command("dump_image", chunk, address_or_offset=0x1000)
    assert O.split_list(command) == ["dump_image", path, "0x1000", "0x100"]


@pytest.mark.parametrize("path", ["relative.bin", "C:/a:stream", "//server/share/x", "C:/a{b}", "C:/a\nx"])
def test_bad_windows_pair_is_fixed(lab, path):
    owner, output = lab.start()
    owner._path_converter = lambda *a, **kw: path
    with pytest.raises(O.PipeOutputError) as caught:
        output.create_chunk(0, "primary", 256, deadline=end())
    assert path not in str(caught.value) and caught.value.__cause__ is None


def test_cloned_chunk_rejected(lab):
    _, output = lab.start()
    chunk = output.create_chunk(0, "primary", 256, deadline=end())
    with pytest.raises(O.PipeOutputError):
        output.command("dump_image", replace(chunk), address_or_offset=0x1000)


@pytest.mark.parametrize("size", [0, 255, 257])
def test_short_or_long_writer_output(lab, size):
    _, output = lab.start()
    with pytest.raises(O.PipeOutputError):
        fill(output, b"x"*size)
    assert output.done == 0


def test_bool_confirmation_is_not_owner_receipt(lab):
    owner, output = lab.start(length=256)
    fill(output)
    with pytest.raises(O.PipeOutputError) as caught:
        output.publish(owner_confirmed=True, deadline=end(), cancel=None)
    assert caught.value.code == "openocd_output_cleanup_unknown"
    assert not lab.case.path("jtag/sample.bin").exists()


def test_unknown_actual_owner_preserves_output(lab):
    owner, output = lab.start()
    fill(output)
    lab.fixture.life.confirm = False
    assert not owner.close(timeout=2).confirmed
    assert not O.release_outputs(owner, deadline=end())
    assert owner.token in O._OUTPUTS and output.part.fd is not None
    lab.fixture.life.confirm = True


def test_resume_checkpoint_and_uncheckpointed_tail(lab):
    owner, output = lab.start()
    first = fill(output)
    assert owner.close(timeout=3).confirmed
    assert O.release_outputs(owner, deadline=end())
    part = lab.case.path("jtag/sample.part")
    with part.open("ab") as stream:
        stream.write(b"TAIL")
    owner2, resumed = lab.start()
    assert resumed.done == resumed.resumed_from == 256 and part.stat().st_size == 256
    data = first + fill(resumed)
    assert owner2.close(timeout=3).confirmed
    result = resumed.publish(owner_confirmed=True, deadline=end(), cancel=None)
    assert result["resumed_from"] == 256 and result["chunks"] == 1
    assert lab.case.path(result["path"]).read_bytes() == data


@pytest.mark.parametrize("mode", ["v1", "sha", "bool", "spec", "extra", "short", "tail", "no-resume"])
def test_resume_invalid_does_not_delete_files(lab, mode):
    owner, output = lab.start()
    fill(output)
    assert owner.close(timeout=3).confirmed and O.release_outputs(owner, deadline=end())
    state_path = lab.case.path("jtag/sample.state.json")
    part_path = lab.case.path("jtag/sample.part")
    value = json.loads(state_path.read_bytes())
    if mode == "v1": value["schema"] = "pweh.openocd-pipe-state/v1"
    if mode == "sha": value["prefix_sha256"] = "0"*64
    if mode == "bool": value["done"] = True
    if mode == "spec": value["spec"]["address"] += 1
    if mode == "extra": value["private"] = "SYNTHETIC_PRIVATE"
    if mode == "short": part_path.write_bytes(b"x")
    if mode == "tail": part_path.write_bytes(b"x"*513)
    state_path.write_text(json.dumps(value))
    with pytest.raises(O.PipeOutputError) as caught:
        lab.start(resume=mode != "no-resume")
    assert caught.value.code == "openocd_output_resume_invalid"
    assert state_path.exists() and part_path.exists()


@pytest.mark.parametrize("late", [False, True])
def test_cancel_before_or_after_commit(lab, late):
    owner, output = lab.start(length=256)
    fill(output)
    assert owner.close(timeout=3).confirmed
    cancelled = [not late]
    if late:
        result = output.publish(owner_confirmed=True, deadline=end(), cancel=lambda: cancelled[0],
                                on_commit=lambda entry: cancelled.__setitem__(0, True))
        assert result["artifact"]["id"] and result["warnings"] == []
    else:
        with pytest.raises(O.PipeOutputError) as caught:
            output.publish(owner_confirmed=True, deadline=end(), cancel=lambda: cancelled[0])
        assert caught.value.code == "cancelled"
        assert not lab.case.path("jtag/sample.bin").exists()


@pytest.mark.parametrize("which", ["callback", "audit"])
def test_postcommit_error_preserves_receipt(lab, monkeypatch, which):
    owner, output = lab.start(length=256)
    fill(output)
    assert owner.close(timeout=3).confirmed
    def fail(*a, **kw):
        raise ValueError("SYNTHETIC_PRIVATE")
    if which == "audit": monkeypatch.setattr(lab.case, "audit", fail)
    result = output.publish(owner_confirmed=True, deadline=end(), cancel=None,
                            on_commit=fail if which == "callback" else None)
    assert result["warnings"] == ["post_commit_callback_failed"]
    assert result["artifact"]["id"] and "SYNTHETIC_PRIVATE" not in str(result)


def test_unknown_output_entry_is_preserved(lab):
    owner, output = lab.start()
    extra = output.output.path / "unknown"
    extra.write_bytes(b"unowned")
    assert owner.close(timeout=3).confirmed
    assert not O.release_outputs(owner, deadline=end()) and extra.read_bytes() == b"unowned"
    extra.unlink()


def test_registry_and_selected_converter(lab):
    owner, output = lab.start()
    assert owner._path_converter is lab.fixture.converter
    with pytest.raises(O.PipeOutputError):
        O.prepare_output(owner, output.spec, deadline=end(), cancel=None)
    assert O._OUTPUTS[owner.token] is output
    assert owner.close(timeout=3).confirmed
    assert not O.release_outputs(SimpleNamespace(token=owner.token), deadline=end())
    assert O._OUTPUTS[owner.token] is output


def test_no_record_release_is_noop():
    assert O.release_outputs(SimpleNamespace(token="absent"), deadline=end())


def recover_record(record):
    """거부를 확인한 합성 시험만 자기 inode의 정리 기준을 새로 잡는다."""
    record.initial = os.fstat(record.fd)
    record.seal = None


@pytest.mark.parametrize("mode", ["replace", "symlink", "hardlink", "parent"])
def test_chunk_identity_change_never_accepts_or_removes_foreign(lab, mode):
    owner, output = lab.start()
    chunk = output.create_chunk(0, "primary", 256, deadline=end())
    output.command("dump_image", chunk, address_or_offset=0x1000)
    path = chunk.local_path
    original = path.with_suffix(".original")
    if mode == "parent":
        parent = output.output.path
        moved = parent.with_name(parent.name + "-moved")
        parent.rename(moved)
        parent.mkdir()
        (parent / path.name).write_bytes(b"x"*256)
    elif mode == "hardlink":
        os.link(path, original)
        path.write_bytes(b"x"*256)
    else:
        path.rename(original)
        if mode == "symlink": path.symlink_to(original.name)
        else: path.write_bytes(b"foreign")
    with pytest.raises(O.PipeOutputError):
        output.accept_chunk(chunk, deadline=end(), cancel=None)
    assert output.done == 0
    assert owner.close(timeout=3).confirmed and not O.release_outputs(owner, deadline=end())
    if mode == "parent":
        (parent / path.name).unlink()
        parent.rmdir()
        moved.rename(parent)
    elif mode == "hardlink":
        original.unlink()
    else:
        path.unlink()
        original.rename(path)


def test_flash_verify_file_change_is_not_accepted(lab):
    owner, output = lab.start(kind="flash", address=None, bank=0, bank_size=1024, verify=True)
    chunk = output.create_chunk(0, "primary", 256, deadline=end())
    output.command("read_bank", chunk, address_or_offset=0)
    chunk.local_path.write_bytes(b"a"*256)
    output.command("verify_bank", chunk, address_or_offset=0)
    chunk.local_path.write_bytes(b"b"*256)
    with pytest.raises(O.PipeOutputError):
        output.accept_chunk(chunk, deadline=end(), cancel=None)
    assert output.done == 0 and owner.close(timeout=3).confirmed
    assert not O.release_outputs(owner, deadline=end())
    recover_record(output.active["primary"]["file"])


def test_checkpoint_failure_keeps_previous_done(lab, monkeypatch):
    owner, output = lab.start()
    initial = lab.case.path("jtag/sample.state.json").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(output, "_checkpoint", lambda *a: (_ for _ in ()).throw(O.PipeOutputError("openocd_output_changed")))
        with pytest.raises(O.PipeOutputError):
            fill(output)
    assert output.done == 0 and lab.case.path("jtag/sample.part").stat().st_size == 256
    assert lab.case.path("jtag/sample.state.json").read_bytes() == initial
    assert owner.close(timeout=3).confirmed and O.release_outputs(owner, deadline=end())
    _, resumed = lab.start()
    assert resumed.done == 0 and lab.case.path("jtag/sample.part").stat().st_size == 0


@pytest.mark.parametrize("mode", ["part-during-final-hash", "metadata", "cancel", "entry", "duplicate"])
def test_final_locked_check_refuses_changes(lab, monkeypatch, mode):
    owner, output = lab.start(length=256)
    fill(output)
    assert owner.close(timeout=3).confirmed
    original_register = lab.case.register_artifact
    original_hash = output._hash
    cancelled = [False]
    def registering(path, **kw):
        if mode == "metadata":
            os.pwrite(output.meta.fd, b"X", 0)
        if mode == "cancel": cancelled[0] = True
        if mode == "entry":
            check = kw["check"]
            kw["check"] = lambda entry: check({**entry, "size": True})
        if mode == "duplicate":
            original_register(path, kind="other", producer="synthetic", compute_hash=False)
        if mode == "part-during-final-hash":
            def corrupting(record, length, check):
                result = original_hash(record, length, check)
                if record is output.final:
                    os.pwrite(output.part.fd, b"X", 0)
                return result
            monkeypatch.setattr(output, "_hash", corrupting)
        return original_register(path, **kw)
    monkeypatch.setattr(lab.case, "register_artifact", registering)
    with pytest.raises(O.PipeOutputError):
        output.publish(owner_confirmed=True, deadline=end(), cancel=lambda: cancelled[0])
    assert output.receipt is None
    if mode == "metadata":
        assert not O.release_outputs(owner, deadline=end())
        recover_record(output.meta)
    if mode == "part-during-final-hash":
        assert not O.release_outputs(owner, deadline=end())
        recover_record(output.part)


def test_postcommit_close_failure_warning_keeps_artifact(lab, monkeypatch):
    owner, output = lab.start(length=256)
    fill(output)
    assert owner.close(timeout=3).confirmed
    original_close = os.close
    target = output.part.fd
    def fail_close(fd):
        if fd == target:
            raise OSError("SYNTHETIC_PRIVATE")
        return original_close(fd)
    with monkeypatch.context() as patch:
        patch.setattr(O.os, "close", fail_close)
        result = output.publish(owner_confirmed=True, deadline=end(), cancel=None)
        assert result["warnings"] == ["output_close_unconfirmed"]
        assert not O.release_outputs(owner, deadline=end())
    assert lab.case.path(result["path"]).exists()


def test_postcommit_path_resolution_is_not_repeated(lab, monkeypatch):
    owner, output = lab.start(length=256)
    fill(output)
    assert owner.close(timeout=3).confirmed
    def committed(entry):
        monkeypatch.setattr(lab.case, "rel", lambda p: (_ for _ in ()).throw(ValueError("PRIVATE")))
    result = output.publish(owner_confirmed=True, deadline=end(), cancel=None, on_commit=committed)
    assert result["metadata_path"] == "jtag/sample.json" and result["warnings"] == []


def test_deadline_and_callback_failure_are_fixed(lab):
    owner, output = lab.start()
    with pytest.raises(O.PipeOutputError) as caught:
        output.create_chunk(0, "primary", 256, deadline=time.monotonic()-1)
    assert caught.value.code == "timeout"


def test_converter_mutation_checked_before_command(lab):
    owner, output = lab.start()
    def converter(path, deadline):
        path.write_bytes(b"not empty")
        return "C:/fixed/chunk.bin"
    owner._path_converter = converter
    chunk = output.create_chunk(0, "primary", 256, deadline=end())
    with pytest.raises(O.PipeOutputError):
        output.command("dump_image", chunk, address_or_offset=0x1000)
