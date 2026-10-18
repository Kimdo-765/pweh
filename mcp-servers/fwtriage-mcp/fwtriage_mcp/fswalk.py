"""추출된 rootfs 순회 (심볼릭 링크를 절대 따라가지 않음).

추출된 트리 안의 절대 경로 심볼릭 링크(예: etc/shadow -> /tmp/passwd, bin/sh -> /bin/busybox)를 그대로
따라가면 '호스트' 파일을 읽게 된다. 그래서:
- 순회는 os.walk(followlinks=False) + lstat
- 링크 해석은 chroot 방식: 절대 대상은 rootfs 루트 기준, '..' 는 루트에서 멈춤, 홉 수 제한
- 읽기는 일반 파일만, O_NOFOLLOW|O_NONBLOCK, 크기 상한 (FIFO 를 열어 멈추는 일 없음)
- 하드링크(busybox 등)는 (st_dev, st_ino) 로 중복 제거
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .common import Ctl, read_regular_file


@dataclass
class Entry:
    rel: str  # rootfs 기준 '/etc/passwd' 형식
    path: str  # 디스크 절대 경로
    st: os.stat_result

    @property
    def kind(self) -> str:
        m = self.st.st_mode
        if stat.S_ISLNK(m):
            return "symlink"
        if stat.S_ISDIR(m):
            return "dir"
        if stat.S_ISREG(m):
            return "file"
        return "other"

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]


def walk_tree(root: Path, ctl: Ctl, *, max_entries: int = 300000) -> Iterator[Entry]:
    root_s = str(root)
    n = 0

    def onerror(_exc: OSError) -> None:
        return None

    for dirpath, dirnames, filenames in os.walk(root_s, followlinks=False, onerror=onerror):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, root_s)
        rel_dir = "" if rel_dir == "." else "/" + rel_dir.replace(os.sep, "/")
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            n += 1
            if n > max_entries:
                return
            if (n & 0x7FF) == 0:
                ctl.check()
            yield Entry(f"{rel_dir}/{name}", p, st)


def resolve_in_root(root: Path, rel: str, *, max_hops: int = 40) -> str | None:
    """rootfs 안에서만 심볼릭 링크를 해석한 최종 rootfs 상대 경로('/a/b'). 없거나 루프면 None."""
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    resolved: list[str] = []
    hops = 0
    while parts:
        comp = parts.pop(0)
        if comp == "..":
            if resolved:
                resolved.pop()
            continue
        cand = root.joinpath(*resolved, comp)
        try:
            st = os.lstat(cand)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > max_hops:
                return None
            try:
                target = os.readlink(cand)
            except OSError:
                return None
            tparts = [p for p in target.split("/") if p not in ("", ".")]
            if target.startswith("/"):
                resolved = []
            parts = tparts + parts
            continue
        resolved.append(comp)
    return "/" + "/".join(resolved)


def read_in_root(root: Path, rel: str, max_bytes: int) -> tuple[bytes | None, str | None]:
    """rootfs 상대 경로를 (링크는 루트 안에서 해석해) 읽기. (데이터 또는 None, 최종 경로)."""
    final = resolve_in_root(root, rel)
    if final is None:
        return None, None
    data = read_regular_file(root.joinpath(*[p for p in final.split("/") if p]), max_bytes)
    return data, final


def is_text(sample: bytes) -> bool:
    """간단한 텍스트 판별: NUL 없음 + 인쇄 가능/공백 비율 90% 이상 (UTF-8 다바이트 허용)."""
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13) or b >= 0x80)
    return printable / len(sample) >= 0.9


def load_manifest(root: Path) -> dict[str, dict[str, Any]] | None:
    """fw_extract_squashfs 가 만든 '<rootfs_dir>.manifest.json' 이 있으면 경로→항목 매핑."""
    mp = root.parent / f"{root.name}.manifest.json"
    if not mp.is_file():
        return None
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entries = data.get("entries")
    if not isinstance(entries, list):
        return None
    return {e.get("path"): e for e in entries if isinstance(e, dict) and e.get("path")}
