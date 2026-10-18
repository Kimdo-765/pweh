"""문자열 휴리스틱 탐색 (fw_strings_hunt).

cctv-hunt-patterns.yaml 의 scope 의미:
- strings: 바이너리에서 뽑은 인쇄 가능 ASCII 문자열(+ UTF-16LE 문자열)의 각 줄
- text: 텍스트 파일의 각 줄
- raw: 파일 전체 바이트 (bytes 정규식)
- any: strings + text

히트는 '조사 출발점'일 뿐이다. critical/high 히트는 REA(search_strings → xrefs → procedure_pseudo_code)로 확인한다.

경로 규칙 (hits / commented_hits / top_files, 단일 파일·디렉터리 모드 공통):
- ``file``: 파일이 속한 rootfs 의 절대 경로('/usr/bin/Sofia', finding.location.file 에 그대로 쓴다).
  rootfs 루트는 RootfsLocator 가 찾는다. 추출 트리 밖의 파일(덤프, fw_carve 파티션 이미지 등)은 null.
- ``path``: 케이스 상대 경로 (다른 fwtriage 도구나 REA open_binary(<케이스 디렉터리>/<path>) 에 넘기는 값). 항상 있다.
- ``checks[].evidence_ref``: ``<file>@<offset_hex>`` (file 이 null 이면 ``<path>@<offset_hex>``).
"""

from __future__ import annotations

import bisect
import os
import re
import stat
from pathlib import Path
from typing import Any

from .common import Ctl, clip, hexs, printable, severity_key
from .fswalk import is_text, walk_tree
from .patterns import VENDOR_FAMILY, StringHeuristic, finding_category

CHUNK = 16 << 20
OVERLAP = 64 << 10
_NL_RX = re.compile("\n")


def _lstat_mode(p: str) -> int | None:
    try:
        return os.lstat(p).st_mode
    except OSError:
        return None


class RootfsLocator:
    """케이스 안 파일이 속한 rootfs 루트 찾기 (심볼릭 링크는 따라가지 않고 lstat 만 쓴다).

    파일의 상위 디렉터리를 케이스 디렉터리 아래 깊이 2(``extract/<label>-NNN``)까지 거슬러 올라가며
    1) ``extract/<label>-NNN`` 이고 옆에 ``<label>-NNN.manifest.json`` 이 있으면(fw_extract_squashfs 출력 트리) → 그 디렉터리.
       매니페스트는 ``extract/`` 바로 아래에서만 인정한다: 펌웨어 안에 'usr.manifest.json' 같은 파일이 있어도 루트로 오인하지 않게
    2) 없으면 ``etc`` 와 ``bin``/``sbin`` 을 가진 가장 바깥 디렉터리(REA/unblob·수동 추출 트리.
       '가장 바깥' 이라 /usr/etc + /usr/bin 이 있는 /usr 를 루트로 오인하지 않는다)
    3) 둘 다 없으면 None (덤프·파티션 이미지 등 rootfs 밖의 파일)
    """

    def __init__(self, case_dir: Path) -> None:
        self.base = os.path.normpath(str(case_dir))
        self.extract_dir = os.path.join(self.base, "extract")
        self._root_of: dict[str, str | None] = {}
        self._manifest: dict[str, bool] = {}
        self._shape: dict[str, bool] = {}
        self.roots_used: set[str] = set()

    def _has_manifest(self, d: str) -> bool:
        v = self._manifest.get(d)
        if v is None:
            if os.path.dirname(d) != self.extract_dir:
                v = self._manifest[d] = False  # 펌웨어 내용이 만든 '<dir>.manifest.json' 은 신뢰하지 않는다
            else:
                m = _lstat_mode(d + ".manifest.json")
                v = self._manifest[d] = m is not None and stat.S_ISREG(m)
        return v

    def _rootfs_shaped(self, d: str) -> bool:
        v = self._shape.get(d)
        if v is None:

            def present(name: str) -> bool:
                m = _lstat_mode(os.path.join(d, name))
                return m is not None and (stat.S_ISDIR(m) or stat.S_ISLNK(m))

            v = self._shape[d] = present("etc") and (present("bin") or present("sbin"))
        return v

    def root_of_dir(self, d: str) -> str | None:
        d = os.path.normpath(d)
        if d in self._root_of:
            return self._root_of[d]
        chain: list[str] = []
        cur = d
        while cur.startswith(self.base + os.sep):
            rel = cur[len(self.base) + 1 :]
            if rel.count(os.sep) < 1:  # 케이스 바로 아래(dumps/, extract/ ...)는 rootfs 루트가 될 수 없다
                break
            chain.append(cur)
            cur = os.path.dirname(cur)
        root = next((c for c in chain if self._has_manifest(c)), None)
        if root is None:
            shaped = [c for c in chain if self._rootfs_shaped(c)]
            root = shaped[-1] if shaped else None
        self._root_of[d] = root
        return root

    def case_rel(self, abs_path: str) -> str:
        p = os.path.normpath(abs_path)
        if p.startswith(self.base + os.sep):
            return p[len(self.base) + 1 :].replace(os.sep, "/")
        return os.path.relpath(p, self.base).replace(os.sep, "/")

    def locate(self, abs_path: str) -> tuple[str, str | None]:
        """(케이스 상대 경로, rootfs 절대 경로 또는 None)."""
        p = os.path.normpath(abs_path)
        root = self.root_of_dir(os.path.dirname(p))
        rootfs_path = None
        if root is not None:
            self.roots_used.add(root)
            rootfs_path = "/" + p[len(root) + 1 :].replace(os.sep, "/")
        return self.case_rel(p), rootfs_path


class HuntState:
    def __init__(self, heuristics: list[StringHeuristic], *, max_hits: int, per_pattern_cap: int, per_file_pattern_cap: int) -> None:
        self.heuristics = heuristics
        self.max_hits = max_hits
        self.per_pattern_cap = per_pattern_cap
        self.per_file_pattern_cap = per_file_pattern_cap
        self.hits: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {}
        self.stored: dict[str, int] = {}
        # 파일 단위 집계는 케이스 상대 경로(path)로 한다: 여러 트리를 한 번에 보면 rootfs 경로(file)가 겹치거나 null 일 수 있다
        self.files_with: dict[str, set[str]] = {}
        self.file_counts: dict[str, dict[str, int]] = {}
        self.file_of: dict[str, str | None] = {}
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.skipped_large: list[str] = []
        self.errors: list[str] = []
        self.commented: list[dict[str, Any]] = []
        self.commented_count = 0

    def record_commented(self, h: StringHeuristic, where: tuple[str, str | None], offset: int, line: int | None, context: str) -> None:
        """'#' 주석 줄의 히트: 주 집계/checks 에는 넣지 않고 따로 보관 (비활성 설정의 단서)."""
        self.commented_count += 1
        if len(self.commented) < 100:
            path, file = where
            self.commented.append({"file": file, "path": path, "offset": offset, "offset_hex": hexs(offset), "line": line, "pattern_id": h.id, "context": clip(context, 200)})

    def record(self, h: StringHeuristic, where: tuple[str, str | None], offset: int, match: str, context: str, *, scope: str, encoding: str, line: int | None = None) -> None:
        path, file = where
        self.counts[h.id] = self.counts.get(h.id, 0) + 1
        self.files_with.setdefault(h.id, set()).add(path)
        self.file_of[path] = file
        fc = self.file_counts.setdefault(path, {})
        fc[h.id] = fc.get(h.id, 0) + 1
        if fc[h.id] > self.per_file_pattern_cap:
            return
        if self.stored.get(h.id, 0) >= self.per_pattern_cap or len(self.hits) >= self.max_hits:
            return
        self.stored[h.id] = self.stored.get(h.id, 0) + 1
        hit = {
            "file": file,
            "path": path,
            "offset": offset,
            "offset_hex": hexs(offset),
            "pattern_id": h.id,
            "category": h.category,
            "finding_category": finding_category(h.category),
            "severity": h.severity,
            "vendor": h.vendor,
            "scope": scope,
            "encoding": encoding,
            "match": clip(match, 120),
            "context": clip(context, 240),
        }
        if line is not None:
            hit["line"] = line
        self.hits.append(hit)


_ASCII_RX_CACHE: dict[int, re.Pattern[bytes]] = {}
_UTF16_RX_CACHE: dict[int, re.Pattern[bytes]] = {}


def _ascii_rx(n: int) -> re.Pattern[bytes]:
    rx = _ASCII_RX_CACHE.get(n)
    if rx is None:
        rx = _ASCII_RX_CACHE[n] = re.compile(rb"[\x20-\x7e\t]{%d,}" % n)
    return rx


def _utf16_rx(n: int) -> re.Pattern[bytes]:
    rx = _UTF16_RX_CACHE.get(n)
    if rx is None:
        rx = _UTF16_RX_CACHE[n] = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n)
    return rx


def extract_strings(data: bytes, min_len: int, utf16: bool) -> tuple[str, list[int], list[int], list[str]]:
    """(말뭉치(줄바꿈 결합), 말뭉치 내 시작 위치, 파일 오프셋, 인코딩)."""
    items: list[tuple[int, str, str]] = []
    for m in _ascii_rx(min_len).finditer(data):
        items.append((m.start(), m.group(0).decode("latin-1"), "ascii"))
    if utf16:
        for m in _utf16_rx(min_len).finditer(data):
            items.append((m.start(), m.group(0).decode("utf-16-le", "replace"), "utf16le"))
        items.sort(key=lambda t: t[0])
    starts: list[int] = []
    offs: list[int] = []
    encs: list[str] = []
    parts: list[str] = []
    pos = 0
    for off, s, enc in items:
        starts.append(pos)
        offs.append(off)
        encs.append(enc)
        parts.append(s)
        pos += len(s) + 1
    return "\n".join(parts), starts, offs, encs


def _context(corpus: str, a: int, b: int) -> str:
    ls = corpus.rfind("\n", 0, a) + 1
    le = corpus.find("\n", b)
    if le < 0:
        le = len(corpus)
    line = corpus[ls:le]
    if len(line) > 240:
        rel = a - ls
        lo = max(0, rel - 80)
        line = ("…" if lo else "") + line[lo : lo + 230]
    return line


def scan_buffer(state: HuntState, data: bytes, base: int, where: tuple[str, str | None], text_file: bool, *, min_len: int, utf16: bool, seen: set[tuple[str, int]]) -> None:
    # 길이 0 일치(예: 're:(?=x)', '\b')는 모든 위치가 히트가 되어 의미 없이 메모리를 쓰므로 건너뛴다
    for h in state.heuristics:
        if h.scope == "raw" and h.rx_bytes is not None:
            for m in h.rx_bytes.finditer(data):
                if m.end() == m.start():
                    continue
                off = base + m.start()
                if (h.id, off) in seen:
                    continue
                seen.add((h.id, off))
                ctx = printable(data[max(0, m.start() - 24) : m.end() + 48], 160)
                state.record(h, where, off, printable(m.group(0), 120), ctx, scope="raw", encoding="bytes")
    if text_file:
        text = data.decode("latin-1")
        base_line = 0  # 청크 분할된 큰 텍스트 파일은 첫 청크만 줄 번호를 보고한다 (offset 은 항상 정확)
        lower_cache: list[str] = []

        def lower() -> str:
            if not lower_cache:
                lower_cache.append(text.lower())
            return lower_cache[0]

        nl: list[int] | None = None
        for h in state.heuristics:
            if h.rx is None or not h.applies("text") or not h.prefilter(text, lower):
                continue
            for m in h.rx.finditer(text):
                g = m.group(0)
                if not g:
                    continue
                lead = len(g) - len(g.lstrip(" \t\r\n;&|(/"))
                start = m.start() + (lead if lead < len(g) else 0)
                if nl is None:
                    nl = [mm.start() for mm in _NL_RX.finditer(text)]
                li = bisect.bisect_right(nl, start - 1) if start else 0
                line = li + 1 + base_line
                key = (h.id, -(base + line)) if base == 0 else (h.id, base + start)
                if key in seen:
                    continue  # 같은 줄의 같은 패턴은 1회만
                seen.add(key)
                ls = nl[li - 1] + 1 if li > 0 else 0
                le = nl[li] if li < len(nl) else len(text)
                line_text = text[ls:le]
                ctx = _context(text, start, m.end())
                if line_text.lstrip().startswith("#"):
                    state.record_commented(h, where, base + start, line if base == 0 else None, ctx)
                    continue
                state.record(h, where, base + start, g[lead:] if lead < len(g) else g, ctx, scope="text", encoding="latin1", line=line if base == 0 else None)
        return
    corpus, starts, offs, encs = extract_strings(data, min_len, utf16)
    if not corpus:
        return
    lower_cache2: list[str] = []

    def lower2() -> str:
        if not lower_cache2:
            lower_cache2.append(corpus.lower())
        return lower_cache2[0]

    for h in state.heuristics:
        if h.rx is None or not h.applies("strings") or not h.prefilter(corpus, lower2):
            continue
        for m in h.rx.finditer(corpus):
            if m.end() == m.start():
                continue
            i = bisect.bisect_right(starts, m.start()) - 1
            if i < 0:
                continue
            within = m.start() - starts[i]
            off = base + offs[i] + within * (2 if encs[i] == "utf16le" else 1)
            if (h.id, off) in seen:
                continue
            seen.add((h.id, off))
            state.record(h, where, off, m.group(0), _context(corpus, m.start(), m.end()), scope="strings", encoding=encs[i])


def scan_file(state: HuntState, path: str, where: tuple[str, str | None], size: int, ctl: Ctl, *, min_len: int, utf16: bool, max_file_size: int) -> None:
    display = where[1] or where[0]
    if size > max_file_size:
        state.skipped_large.append(display)
        size = max_file_size
    seen: set[tuple[str, int]] = set()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        state.errors.append(f"{display}: {exc}")
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return
        pos = 0
        first = True
        text_file = False
        while pos < size:
            ctl.check()
            want = min(CHUNK + OVERLAP, size - pos)
            os.lseek(fd, pos, os.SEEK_SET)
            data = b""
            while len(data) < want:
                b = os.read(fd, want - len(data))
                if not b:
                    break
                data += b
            if not data:
                break
            if first:
                text_file = is_text(data[:65536])
                first = False
            scan_buffer(state, data, pos, where, text_file, min_len=min_len, utf16=utf16, seen=seen)
            state.bytes_scanned += len(data) if pos == 0 else max(0, len(data) - OVERLAP)
            if len(data) < want:
                break
            pos += CHUNK
    finally:
        os.close(fd)
    state.files_scanned += 1


def hunt(target: Path, is_dir: bool, case_dir: Path, ctl: Ctl, heuristics: list[StringHeuristic], *, max_hits: int, per_pattern_cap: int, max_file_size: int,
         min_len: int = 4, utf16: bool = True, include_rx: list[re.Pattern[str]] | None = None, max_files: int = 200000) -> dict[str, Any]:
    """target(케이스 안의 파일 또는 디렉터리, resolve 된 절대 경로)을 검색. include_rx 는 target 기준 상대 경로에 적용."""
    state = HuntState(heuristics, max_hits=max_hits, per_pattern_cap=per_pattern_cap, per_file_pattern_cap=max(3, per_pattern_cap // 4))
    loc = RootfsLocator(case_dir)
    truncated = False
    if is_dir:
        seen_ino: set[tuple[int, int]] = set()
        n = 0
        for e in walk_tree(target, ctl):
            if e.kind != "file":
                continue
            if include_rx and not any(rx.match(e.rel.lstrip("/")) for rx in include_rx):
                continue
            ino = (e.st.st_dev, e.st.st_ino)
            if ino in seen_ino:
                continue
            seen_ino.add(ino)
            if ctl.expired():
                truncated = True
                break
            n += 1
            if n > max_files:
                truncated = True
                break
            if (n & 0x3F) == 0:
                ctl.progress(n, None, f"{n}개 파일 검사")
            scan_file(state, e.path, loc.locate(e.path), e.st.st_size, ctl, min_len=min_len, utf16=utf16, max_file_size=max_file_size)
    else:
        size = target.stat().st_size
        scan_file(state, str(target), loc.locate(str(target)), size, ctl, min_len=min_len, utf16=utf16, max_file_size=max_file_size)
    # 정리 ---------------------------------------------------------------
    state.hits.sort(key=lambda h: (severity_key(h["severity"]), h["pattern_id"], h["path"], h["offset"]))
    by_sev: dict[str, int] = {}
    by_pattern: dict[str, dict[str, Any]] = {}
    hmap = {h.id: h for h in heuristics}
    for pid, cnt in state.counts.items():
        h = hmap[pid]
        by_sev[h.severity] = by_sev.get(h.severity, 0) + cnt
        by_pattern[pid] = {"count": cnt, "files": len(state.files_with.get(pid, ())), "severity": h.severity, "category": h.category, "vendor": h.vendor}
    vendor_ids: dict[str, set[str]] = {}
    for pid in state.counts:
        v = hmap[pid].vendor
        if v not in ("generic", "custom"):
            vendor_ids.setdefault(v, set()).add(pid)
    vendor_scores = {v: len(ids) for v, ids in vendor_ids.items()}
    top_vendor = max(vendor_scores.items(), key=lambda kv: kv[1])[0] if vendor_scores else None
    file_scores = []
    for p_, pc in state.file_counts.items():
        score = sum((5 - severity_key(hmap[p].severity)) * min(c, 5) for p, c in pc.items())
        file_scores.append({"file": state.file_of.get(p_), "path": p_, "score": score, "patterns": sorted(pc, key=lambda p: severity_key(hmap[p].severity))[:12]})
    file_scores.sort(key=lambda x: (-x["score"], x["path"]))
    first_hit: dict[str, str] = {}
    for hit in state.hits:
        first_hit.setdefault(hit["pattern_id"], f"{hit['file'] or hit['path']}@{hit['offset_hex']}")
    checks = [
        {"id": h.id, "description": clip(h.rationale, 160) if h.rationale else h.id, "result": "match" if state.counts.get(h.id) else "no-match",
         "evidence_ref": first_hit.get(h.id), "count": state.counts.get(h.id, 0), "severity": h.severity, "vendor": h.vendor}
        for h in heuristics
    ]
    return {
        "hits": state.hits,
        "summary": {
            "files_scanned": state.files_scanned,
            "bytes_scanned": state.bytes_scanned,
            "hits_total": sum(state.counts.values()),
            "hits_stored": len(state.hits),
            "by_severity": by_sev,
            "patterns_matched": len(state.counts),
            "patterns_selected": len(heuristics),
            "vendor_scores": vendor_scores,
            "vendor_family_guess": VENDOR_FAMILY.get(top_vendor or "", "generic") if top_vendor else None,
            "skipped_large_files": len(state.skipped_large),
            "truncated": truncated or ctl.timed_out,
            # hits[].file 을 계산한 rootfs 루트(케이스 상대 경로). 비어 있으면 모든 file 이 null (rootfs 밖의 입력)
            "rootfs_dirs": sorted(loc.case_rel(r) for r in loc.roots_used)[:20],
        },
        "by_pattern": dict(sorted(by_pattern.items(), key=lambda kv: (severity_key(kv[1]["severity"]), -kv[1]["count"]))),
        "top_files": file_scores[:50],
        "checks": checks,
        "commented_hits": state.commented,
        "commented_hit_count": state.commented_count,
        "skipped_large_files": state.skipped_large[:100],
        "errors": state.errors[:50],
    }
