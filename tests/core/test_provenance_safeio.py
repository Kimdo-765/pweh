"""출처 접수 기록의 fd 고정·링크 거부 회귀. 합성 케이스만 사용한다."""
import hashlib
import os

import pytest

from pweh import safeio
from pweh.provenance import ProvenanceError
from pweh.runtime import get_runtime

SOURCE = {"server": "forensics-mcp", "tool": "forensics_intake_start"}


def _record(workspace, auth):
    runtime = get_runtime("test")
    case = runtime.cases.create(title="합성 접수 기록", authorization=auth, case_id="safe-import")
    path = case.dir / "forensics" / "images" / "EV-0001" / "EV-0001.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"synthetic":true}')
    return runtime, case, path


@pytest.mark.parametrize("link_kind", ["hardlink", "symlink", "parent-link"])
def test_provenance_intake_refuses_links(workspace, auth, tmp_path, link_kind):
    runtime, case, path = _record(workspace, auth)
    rel = path.relative_to(case.dir)
    if link_kind == "hardlink":
        os.link(path, tmp_path / "alias")
    elif link_kind == "symlink":
        target = path.with_name("target.json")
        path.rename(target)
        path.symlink_to(target.name)
    else:
        parent = path.parent
        target = parent.with_name("other")
        parent.rename(target)
        parent.symlink_to(target.name, target_is_directory=True)
    with pytest.raises(safeio.UnsafeFile):
        runtime.provenance.record_import(case, rel, SOURCE)
    assert runtime.provenance.entries(case) == []


def test_provenance_hash_and_size_use_same_fd_and_detect_name_swap(workspace, auth, monkeypatch):
    runtime, case, path = _record(workspace, auth)
    hash_fd = safeio.hash_fd
    def replace_after_hash(fd, size, **kwargs):
        result = hash_fd(fd, size, **kwargs)
        path.rename(path.with_name("old.json"))
        os.mkfifo(path)
        return result
    monkeypatch.setattr(safeio, "hash_fd", replace_after_hash)
    with pytest.raises(ProvenanceError, match="파일이 바뀌었습니다"):
        runtime.provenance.record_import(case, path, SOURCE)
    assert runtime.provenance.entries(case) == []


def test_provenance_generic_hardlink_compatibility(workspace, auth, tmp_path):
    runtime, case, path = _record(workspace, auth)
    ordinary = case.dir / "dumps" / "ordinary.bin"
    ordinary.write_bytes(b"synthetic")
    os.link(ordinary, tmp_path / "alias")
    rec = runtime.provenance.record_device_read(case, ordinary, {"server": "test", "tool": "synthetic"})
    assert rec["sha256"] == hashlib.sha256(b"synthetic").hexdigest() and rec["size"] == 9
