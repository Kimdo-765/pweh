"""pweh.evidence 의 보호 폴더 판정(forensics/·emu/): 맞은 폴더 이름, 링크를 푼 경로·풀기 전 경로, fail closed, 기존 forensics 함수 불변."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pweh import evidence as E
from pweh.case import CaseStore


@pytest.fixture
def case(workspace, auth):
    return CaseStore(workspace["cases_dir"]).create(title="보호 폴더", authorization=auth, case_id="guardcase")


def _session(case, sid: str = "emu-001") -> Path:
    """pweh-emu 세션 디렉터리 모양만 흉내 낸다(서버 없이)."""
    d = case.dir / "emu" / sid
    d.mkdir(parents=True)
    (d / "console.bin").write_bytes(b"wifi_password=EMU-SENTINEL-7731\r\n")
    (d / "meta.json").write_text("{}", encoding="utf-8")
    return d


def test_protected_dirs_and_emu_refusal_text():
    assert E.PROTECTED_DIRS == ("forensics", "emu")
    assert (E.FORENSICS_DIR, E.EMU_DIR) == E.PROTECTED_DIRS
    # 계약 문구(docs/design/emulation.md) — 모든 서버가 이 상수를 쓴다
    assert E.EMU_REFUSAL_MESSAGE.startswith("에뮬레이터 세션 파일(emu/)에는 마스킹하지 않은 원시 콘솔이 있어 이 도구로 읽지 않습니다")
    assert E.EMU_REFUSAL_HINT.startswith("콘솔은 emu_read 로만 본다")
    for name in ("PROTECTED_DIRS", "EMU_DIR", "EMU_REFUSAL_MESSAGE", "EMU_REFUSAL_HINT", "under_any_case_protected",
                 "is_protected_path", "contains_protected_dir"):
        assert name in E.__all__


def test_under_any_case_protected_names_the_subtree(case, tmp_path):
    sess = _session(case)
    fdir = E.ensure_forensics_dir(case)
    root = case.dir.parent
    assert E.under_any_case_protected(sess / "console.bin", root) == "emu"
    assert E.under_any_case_protected(case.dir / "emu", root) == "emu"  # 폴더 자체
    assert E.under_any_case_protected(case.dir / "emu" / "emu-009" / "not-yet.bin", root) == "emu"  # 없는 경로도
    assert E.under_any_case_protected(fdir / "images" / "EV-0001" / "x.img", root) == "forensics"
    assert E.under_any_case_protected(case.dir / "dumps" / "a.bin", root) is None
    assert E.under_any_case_protected(case.dir, root) is None
    assert E.under_any_case_protected(tmp_path / "elsewhere", root) is None
    # 케이스 루트가 아닌 깊은 곳의 같은 이름(추출한 rootfs 의 emu/ 등)은 보호 폴더가 아니다
    assert E.under_any_case_protected(case.dir / "extract" / "rootfs-001" / "emu" / "x", root) is None
    # 다른 케이스의 emu/
    other = CaseStore(root).create(title="다른 케이스", case_id="othercase")
    assert E.under_any_case_protected(_session(other) / "console.bin", root) == "emu"
    # 풀기 전 경로의 '..' 는 정규화해서 본다
    assert E.under_any_case_protected(case.dir / "dumps" / ".." / "emu" / "emu-001" / "console.bin", root) == "emu"


def test_under_any_case_protected_checks_raw_and_resolved_paths(case, workspace, tmp_path):
    sess = _session(case)
    root = case.dir.parent
    # dumps/ 의 링크 → 링크를 푼 경로가 emu/
    (case.dir / "dumps" / "innocent.bin").symlink_to(sess / "console.bin")
    assert E.under_any_case_protected(case.dir / "dumps" / "innocent.bin", root) == "emu"
    # 케이스 밖의 링크 → 케이스의 emu/
    outside_link = tmp_path / "outside.bin"
    outside_link.symlink_to(sess / "console.bin")
    assert E.under_any_case_protected(outside_link, root) == "emu"
    # emu/ 를 케이스 밖으로 옮기고 링크로 되돌림 → 링크를 푼 경로는 케이스 밖이지만 풀기 전 경로가 emu/
    moved = tmp_path / "moved-emu"
    os.rename(case.dir / "emu", moved)
    (case.dir / "emu").symlink_to(moved)
    assert E.under_any_case_protected(case.dir / "emu" / "emu-001" / "console.bin", root) == "emu"
    assert E.under_any_case_protected(moved / "emu-001" / "console.bin", root) is None  # 케이스와 무관한 실제 위치


def test_forensics_only_predicates_are_unchanged(case, tmp_path):
    """기존 호출자를 위한 forensics 전용 함수는 emu/ 를 보지 않고, 동작이 그대로다."""
    sess = _session(case)
    root = case.dir.parent
    assert E.under_any_case_forensics(sess / "console.bin", root) is False
    assert E.is_forensics_path(case, sess / "console.bin") is False
    assert E.contains_forensics_dir(case, case.dir / "emu") is False
    # 풀기 전 경로는 emu/, 링크를 푼 경로는 다른 케이스의 forensics/: forensics 전용 함수는 여전히 참, 보호 판정은 먼저 맞은 emu
    other = CaseStore(root).create(title="SD", case_id="sdcase")
    rec = E.ensure_forensics_dir(other) / "recovered"
    rec.mkdir()
    (rec / "clip.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
    (sess / "clip-link.mp4").symlink_to(rec / "clip.mp4")
    assert E.under_any_case_forensics(sess / "clip-link.mp4", root) is True
    assert E.under_any_case_protected(sess / "clip-link.mp4", root) == "emu"
    # 반대로 풀기 전 경로가 forensics/ 면 보호 판정은 forensics
    (rec / "console-link.bin").symlink_to(sess / "console.bin")
    assert E.under_any_case_protected(rec / "console-link.bin", root) == "forensics"
    assert E.under_any_case_forensics(rec / "console-link.bin", root) is True


def test_is_protected_path(case, tmp_path, monkeypatch):
    sess = _session(case)
    fdir = E.ensure_forensics_dir(case)
    monkeypatch.chdir(tmp_path)  # 상대 경로를 서버의 작업 디렉터리 기준으로 풀지 않는다(케이스 기준)
    assert E.is_protected_path(case, sess / "console.bin") == "emu"
    assert E.is_protected_path(case, "emu/emu-001/console.bin") == "emu"
    assert E.is_protected_path(case, "emu") == "emu"
    assert E.is_protected_path(case, case.dir / "emu" / "emu-002" / "not-yet.bin") == "emu"
    assert E.is_protected_path(case, fdir / "images") == "forensics"
    assert E.is_protected_path(case, "forensics/images/EV-0001/x.img") == "forensics"
    assert E.is_protected_path(case, case.dir / "dumps" / "x.bin") is None
    assert E.is_protected_path(case, "dumps/x.bin") is None
    assert E.is_protected_path(case, case.dir) is None
    assert E.is_protected_path(case, "extract/rootfs-001/emu/console.bin") is None
    # 링크를 풀어 판단한다 (파일 링크·디렉터리 링크)
    (case.dir / "dumps" / "innocent.bin").symlink_to(sess / "console.bin")
    (case.dir / "dumps" / "sessions").symlink_to(case.dir / "emu")
    assert E.is_protected_path(case, "dumps/innocent.bin") == "emu"
    assert E.is_protected_path(case, case.dir / "dumps" / "sessions" / "emu-001" / "meta.json") == "emu"
    assert E.is_protected_path(case, "dumps/sessions") == "emu"


def test_is_protected_path_fails_closed(case, monkeypatch):
    _session(case)
    real_resolve = Path.resolve

    def broken(self, strict=False):
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(Path, "resolve", broken)
    assert E.is_protected_path(case, case.dir / "dumps" / "x.bin") == "forensics"  # 경로를 풀 수 없음 → 막는 쪽(첫 이름)
    assert E.contains_protected_dir(case, case.dir / "dumps") == "emu"  # 있는 보호 폴더 중 첫 이름

    def emu_broken(self, strict=False):
        if self.name == "emu":
            raise RuntimeError("Symlink loop")
        return real_resolve(self, strict)

    monkeypatch.setattr(Path, "resolve", emu_broken)
    assert E.is_protected_path(case, case.dir / "dumps" / "x.bin") == "emu"  # emu/ 쪽을 풀 수 없음 → emu 로 막음
    assert E.contains_protected_dir(case, case.dir / "dumps") == "emu"


def test_contains_protected_dir_counts_only_existing_subtrees(case, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # 보호 폴더가 없는 케이스는 루트도 훑을 수 있다
    assert E.contains_protected_dir(case, case.dir) is None
    assert E.contains_protected_dir(case, ".") is None
    _session(case)
    assert E.contains_protected_dir(case, case.dir) == "emu"
    assert E.contains_protected_dir(case, ".") == "emu"  # 케이스 기준 상대 경로
    assert E.contains_protected_dir(case, "emu") == "emu"
    assert E.contains_protected_dir(case, case.dir / "dumps") is None
    assert E.contains_protected_dir(case, case.dir / "extract") is None
    # 세션 디렉터리(보호 폴더 안쪽)는 is_protected_path 가 막는다 — contains 는 '훑으면 보호 폴더를 지나는가'만 본다
    assert E.contains_protected_dir(case, "emu/emu-001") is None and E.is_protected_path(case, "emu/emu-001") == "emu"
    # 둘 다 있으면 앞의 이름(forensics)
    E.ensure_forensics_dir(case)
    assert E.contains_protected_dir(case, case.dir) == "forensics"
    assert E.contains_protected_dir(case, "emu") == "emu"


def test_contains_protected_dir_follows_a_link_named_emu(workspace, auth, tmp_path):
    """emu 라는 이름이 링크여도 있는 것으로 센다(lexists): 링크를 푼 실제 위치를 품은 디렉터리를 훑지 않는다.
    케이스 밖을 가리키면 링크를 따르지 않는 순회가 그 너머를 지나지 않으므로 세지 않는다."""
    store = CaseStore(workspace["cases_dir"])
    inside = store.create(title="안쪽 링크", case_id="inlink")
    hidden = inside.dir / "dumps" / "hidden"
    (hidden / "emu-001").mkdir(parents=True)
    (inside.dir / "emu").symlink_to(hidden)
    assert E.contains_protected_dir(inside, inside.dir) == "emu"
    assert E.contains_protected_dir(inside, inside.dir / "dumps") == "emu"
    assert E.is_protected_path(inside, hidden / "emu-001") == "emu"  # 링크를 푼 emu/ 의 실제 위치
    out = store.create(title="바깥 링크", case_id="outlink")
    target = tmp_path / "elsewhere-emu"
    target.mkdir()
    (out.dir / "emu").symlink_to(target)
    assert E.contains_protected_dir(out, out.dir) is None
    dangling = store.create(title="끊긴 링크", case_id="dangling")
    (dangling.dir / "emu").symlink_to(dangling.dir / "dumps" / "gone")
    assert E.contains_protected_dir(dangling, dangling.dir) == "emu"  # 이름이 있으면 센다(막는 쪽)
