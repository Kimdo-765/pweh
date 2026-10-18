"""squashfs 추출 (fw_extract_squashfs): unsquashfs / sasquatch 래퍼 + 사전 안전 검사.

순서:
1. Python 으로 superblock 검증 (정확한 오류 메시지, 크기·압축·엔디안 확인)
2. root 로 실행 중이면 거부 (root 로 풀면 장치 노드와 setuid-root 파일이 호스트에 생긴다)
3. ``unsquashfs -lln`` 목록을 받아 검사:
   - 비정상 줄(개행 포함 파일 이름 등)이 있으면 기본 거부 (목록 위조 가능성)
   - '..'/빈 경로 요소, 심볼릭 링크 '아래'에 있는 항목(CVE-2021-41072 형태의 디렉터리 탈출) → 거부
   - 일반 파일 논리 크기 합이 max_output_bytes 를 넘으면 거부 (압축 폭탄)
4. ``extract/<label>-NNN`` 을 mkdir 로 확보한 뒤 ``unsquashfs -f -d <dir> -n -no-xattrs -p N [-o offset]``
   실행 (시간 초과, 디스크 사용량 감시, 취소 시 프로세스 그룹 종료). 비root 이므로 장치 노드는 만들어지지 않는다.
5. 목록 기반 매니페스트(모드/uid/gid/링크 대상 — 비root 추출로 사라지는 setuid·소유자 정보 보존)를
   ``extract/<label>-NNN.manifest.json`` 에 저장하고, fw_rootfs_audit 가 자동으로 사용한다.
"""

from __future__ import annotations

import os
import re
import shutil
import stat as _stat
from pathlib import Path
from typing import Any

from pweh.case import Case
from pweh.errors import SafetyDenied, ToolMissing, ValidationFailed
from pweh.fsutil import atomic_write_json, utcnow_iso

from .common import PRODUCER, TOOL_VERSION, Ctl, claim_numbered_dir, file_info, hexs, open_mmap, safe_label, sanitize
from .procutil import run_process, tree_usage, which_tool
from .signatures import parse_squashfs_superblock

_LIST_RE = re.compile(
    r"^(?P<mode>[-dlcbps][-rwxsStT]{9})\s+(?P<uid>[^/\s]+)/(?P<gid>\S+)\s+(?P<size>\d+|\d+,\s*\d+)\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s(?P<rest>squashfs-root(?:/.*)?)$"
)
_TYPE = {"-": "file", "d": "dir", "l": "symlink", "c": "chardev", "b": "blockdev", "p": "fifo", "s": "socket"}
_TYPE_BITS = {"-": 0o100000, "d": 0o040000, "l": 0o120000, "c": 0o020000, "b": 0o060000, "p": 0o010000, "s": 0o140000}
_VERSION_RE = re.compile(r"unsquashfs version (\S+)")


def mode_from_ls(s: str) -> int:
    mode = _TYPE_BITS.get(s[0], 0)
    for i, (r, w, x) in enumerate((s[1:4], s[4:7], s[7:10])):
        shift = 6 - 3 * i
        if r == "r":
            mode |= 4 << shift
        if w == "w":
            mode |= 2 << shift
        if x in ("x", "s", "t"):
            mode |= 1 << shift
        if x in ("s", "S"):
            mode |= 0o4000 if i == 0 else 0o2000
        if x in ("t", "T") and i == 2:
            mode |= 0o1000
    return mode


def resolve_tools(config: Any) -> dict[str, str | None]:
    tools_dir = os.environ.get("PWEH_TOOLS_DIR") or os.path.expanduser("~/pweh-tools")
    cfg_val = None
    try:
        cfg_val = config.tool_path("unsquashfs")
    except Exception:  # pragma: no cover
        cfg_val = None
    return {
        "unsquashfs": which_tool([cfg_val, os.environ.get("PWEH_UNSQUASHFS"), f"{tools_dir}/bin/unsquashfs", "unsquashfs"]),
        "sasquatch": which_tool([os.environ.get("PWEH_SASQUATCH"), f"{tools_dir}/extractors/bin/sasquatch", "sasquatch"]),
        "sasquatch_v4be": which_tool([os.environ.get("PWEH_SASQUATCH_V4BE"), f"{tools_dir}/extractors/bin/sasquatch-v4be", "sasquatch-v4be"]),
    }


def tool_version(tool: str, ctl: Ctl) -> str | None:
    try:
        res = run_process([tool, "-version"], ctl=ctl, timeout=10, max_stdout=65536)
    except (OSError, ValueError):
        return None
    m = _VERSION_RE.search((res.stdout + res.stderr).decode("utf-8", "replace"))
    return m.group(1) if m else None


def parse_listing(text: str) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    anomalies: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _LIST_RE.match(line)
        if not m:
            anomalies.append(line[:200])
            continue
        mode_s = m.group("mode")
        rest = m.group("rest")
        typ = _TYPE.get(mode_s[0], "other")
        target = None
        if typ == "symlink" and " -> " in rest:
            rest, target = rest.split(" -> ", 1)
        rel = rest[len("squashfs-root"):]
        ent: dict[str, Any] = {
            "path": rel or "/",
            "type": typ,
            "mode": oct(mode_from_ls(mode_s) & 0o7777),
            "mode_str": mode_s,
            "uid": int(m.group("uid")) if m.group("uid").isdigit() else (0 if m.group("uid") == "root" else m.group("uid")),
            "gid": int(m.group("gid")) if m.group("gid").isdigit() else (0 if m.group("gid") == "root" else m.group("gid")),
        }
        size_s = m.group("size")
        if "," in size_s:
            ent["rdev"] = re.sub(r"\s+", "", size_s)
        else:
            ent["size"] = int(size_s)
        if target is not None:
            ent["target"] = target
        entries.append(ent)
    return {"entries": entries, "anomalies": anomalies}


def check_listing(entries: list[dict[str, Any]]) -> list[str]:
    """디렉터리 탈출 형태 검사. 문제 목록(비어 있으면 안전)."""
    problems: list[str] = []
    symlinks = {e["path"] for e in entries if e["type"] == "symlink"}
    for e in entries:
        p = e["path"]
        if p == "/":
            continue
        comps = p.split("/")[1:]
        if any(c in ("", ".", "..") for c in comps) or "\x00" in p:
            problems.append(f"비정상 경로 요소: {p!r}")
            continue
        prefix = ""
        for c in comps[:-1]:
            prefix += "/" + c
            if prefix in symlinks:
                problems.append(f"심볼릭 링크 아래의 항목(디렉터리 탈출 시도 형태): {p!r} (링크 {prefix!r})")
                break
        if len(problems) >= 20:
            break
    return problems


def listing_stats(entries: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    total = 0
    setuid: list[dict[str, Any]] = []
    setgid: list[dict[str, Any]] = []
    world_writable = 0
    for e in entries:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
        if e["type"] == "file":
            total += e.get("size", 0)
            m = int(e["mode"], 8)
            if m & 0o4000:
                setuid.append({"path": e["path"], "mode": e["mode"], "uid": e["uid"], "gid": e["gid"]})
            if m & 0o2000:
                setgid.append({"path": e["path"], "mode": e["mode"], "uid": e["uid"], "gid": e["gid"]})
            if m & 0o002:
                world_writable += 1
    return {"counts": counts, "total_file_bytes": total, "setuid": setuid, "setgid": setgid, "world_writable_files": world_writable}


def extract_squashfs(
    case: Case,
    src: Path,
    *,
    offset: int,
    label: str,
    ctl: Ctl,
    config: Any,
    timeout: float,
    max_output_bytes: int,
    engine: str = "auto",
    allow_listing_anomalies: bool = False,
    processors: int | None = None,
) -> dict[str, Any]:
    if os.name == "posix" and os.geteuid() == 0:
        raise SafetyDenied(
            "root 권한으로 실행 중인 서버에서는 squashfs 를 풀지 않습니다 (장치 노드·setuid-root 파일이 호스트에 생성될 수 있음).",
            hint="MCP 서버를 일반 사용자 계정으로 실행하세요.",
        )
    size = src.stat().st_size
    if offset >= size:
        raise ValidationFailed(f"offset(0x{offset:x})이 파일 크기({size})보다 큽니다.")
    with open_mmap(src) as mm:
        sb = parse_squashfs_superblock(bytes(mm[offset : offset + 128]), size - offset)
    if sb is None:
        raise ValidationFailed(
            f"offset 0x{offset:x} 에 유효한 squashfs superblock 이 없습니다.",
            hint="fw_identify 로 squashfs 영역의 정확한 offset 을 확인하세요 (kind='squashfs').",
        )
    if sb.get("truncated"):
        ctl_note = f"superblock 의 bytes_used({sb['bytes_used']})가 남은 파일 크기({size - offset})보다 큽니다: 잘린 이미지일 수 있음"
    else:
        ctl_note = None

    tools = resolve_tools(config)
    be_v4 = sb["version"].startswith("4") and sb["endianness"] == "big"
    order: list[tuple[str, str]] = []
    if engine == "unsquashfs":
        if tools["unsquashfs"]:
            order.append(("unsquashfs", tools["unsquashfs"]))
    elif engine == "sasquatch":
        if be_v4 and tools["sasquatch_v4be"]:
            order.append(("sasquatch-v4be", tools["sasquatch_v4be"]))
        if tools["sasquatch"]:
            order.append(("sasquatch", tools["sasquatch"]))
    else:
        prefer_sasq = sb.get("nonstandard") or be_v4
        if prefer_sasq:
            if be_v4 and tools["sasquatch_v4be"]:
                order.append(("sasquatch-v4be", tools["sasquatch_v4be"]))
            if tools["sasquatch"]:
                order.append(("sasquatch", tools["sasquatch"]))
        if tools["unsquashfs"]:
            order.append(("unsquashfs", tools["unsquashfs"]))
        if not prefer_sasq and tools["sasquatch"]:
            order.append(("sasquatch", tools["sasquatch"]))
    if not order:
        raise ToolMissing(
            f"squashfs 추출 도구를 찾을 수 없습니다 (engine={engine}).",
            hint=(
                "squashfs-tools 를 설치하거나(예: apt install squashfs-tools, 또는 ~/pweh-tools/bin/unsquashfs), "
                "pipeline-config.yaml 의 tools.unsquashfs / 환경변수 PWEH_UNSQUASHFS 로 경로를 지정하세요. "
                "벤더 변형 squashfs 는 sasquatch 가 필요합니다. 대안: REA extract_firmware(unblob)."
            ),
        )
    nproc = processors or max(1, min(4, os.cpu_count() or 1))
    off_args = ["-o", str(offset)] if offset else []
    attempts: list[dict[str, Any]] = []
    for name, tool in order:
        ctl.check()
        version = tool_version(tool, ctl)
        lst = run_process([tool, "-lln", *off_args, str(src)], ctl=ctl, timeout=min(timeout, 300), max_stdout=64 << 20)
        if not lst.timed_out and lst.returncode not in (0, 2):
            # 구버전(4.4 미만)은 -lln 이 없다: -lls (소유자 이름 표기)로 재시도
            lst = run_process([tool, "-lls", *off_args, str(src)], ctl=ctl, timeout=min(timeout, 300), max_stdout=64 << 20)
        if lst.timed_out or lst.returncode not in (0, 2):
            attempts.append({"tool": name, "path": tool, "version": version, "stage": "list", "returncode": lst.returncode, "timed_out": lst.timed_out, "stderr_tail": lst.stderr_tail(8)})
            continue
        if lst.stdout_truncated:
            raise ValidationFailed("unsquashfs 목록이 너무 큽니다 (64MiB 초과) — 비정상 이미지로 보고 중단합니다.")
        parsed = parse_listing(lst.stdout.decode("utf-8", "replace"))
        entries = parsed["entries"]
        if not entries:
            attempts.append({"tool": name, "path": tool, "version": version, "stage": "list", "returncode": lst.returncode, "error": "목록이 비어 있음", "stderr_tail": lst.stderr_tail(8)})
            continue
        problems = check_listing(entries)
        if problems:
            raise SafetyDenied(
                "squashfs 목록에 디렉터리 탈출 형태의 항목이 있어 추출을 거부합니다: " + "; ".join(problems[:5]),
                hint="악의적이거나 손상된 이미지일 수 있습니다. 격리된 환경(별도 계정/VM)에서 REA extract_firmware 로 분석하세요.",
                data={"problems": problems},
            )
        if parsed["anomalies"] and not allow_listing_anomalies:
            raise SafetyDenied(
                f"squashfs 목록에 해석할 수 없는 줄이 {len(parsed['anomalies'])}개 있습니다 (개행 문자를 포함한 파일 이름 등). "
                "목록 기반 안전 검사를 신뢰할 수 없어 추출을 거부합니다.",
                hint="내용을 확인한 뒤 allow_listing_anomalies=true 로 재시도하거나(사용 도구가 CVE-2021-40153/41072 수정 버전인지 확인), REA extract_firmware 를 사용하세요.",
                data={"anomalies": parsed["anomalies"][:10]},
            )
        stats = listing_stats(entries)
        if stats["total_file_bytes"] > max_output_bytes:
            raise ValidationFailed(
                f"압축 해제 후 크기({stats['total_file_bytes']} bytes)가 max_output_bytes({max_output_bytes})를 넘습니다.",
                hint="정말 필요한 경우 max_output_bytes 를 늘려 재시도하세요 (디스크 여유 공간 확인).",
            )
        dest = claim_numbered_dir(case.subdir("extract"), safe_label(label, "rootfs"))
        argv = [tool, "-f", "-d", str(dest), "-n", "-no-xattrs", "-p", str(nproc), *off_args, str(src)]
        limit_bytes = max_output_bytes + (64 << 20)

        def monitor() -> str | None:
            used, _logical, _n = tree_usage(dest)
            if used > limit_bytes:
                return f"출력 디스크 사용량 {used} bytes 가 상한({limit_bytes})을 넘음"
            return None

        ext = run_process(argv, ctl=ctl, timeout=timeout, max_stdout=1 << 20, on_poll=monitor, poll_every=1.0)
        used, logical, nent = tree_usage(dest)
        stderr_lines = ext.stderr_tail(200)
        dev_skipped = sum(1 for ln in stderr_lines if "could not create" in ln and ("device" in ln or "fifo" in ln or "socket" in ln))
        ok = ext.returncode in (0, 2) and not ext.timed_out and not ext.killed_reason
        attempt = {
            "tool": name, "path": tool, "version": version, "stage": "extract", "returncode": ext.returncode,
            "timed_out": ext.timed_out, "killed_reason": ext.killed_reason, "elapsed_seconds": ext.elapsed,
            "stderr_tail": stderr_lines[-12:],
        }
        attempts.append(attempt)
        if not ok:
            if nent == 0:
                shutil.rmtree(dest, ignore_errors=True)
                continue
            status = "partial"
        else:
            status = "complete"
        # 결과 정리 -------------------------------------------------------
        extracted_counts = _count_tree(dest)
        manifest_path = dest.parent / f"{dest.name}.manifest.json"
        manifest = {
            "schema": "pweh.fwtriage.squashfs-manifest/v1",
            "producer": TOOL_VERSION,
            "generated_at": utcnow_iso(),
            "source": file_info(case, src, with_hash=True),
            "offset": offset,
            "superblock": sb,
            "output_dir": case.rel(dest),
            "tool": {"name": name, "path": tool, "version": version},
            "note": "비root 추출이라 디스크의 소유자/setuid 비트는 원본과 다르다. 원본 메타데이터는 entries 를 기준으로 한다.",
            "entries": entries,
        }
        atomic_write_json(manifest_path, sanitize(manifest))
        case.register_artifact(manifest_path, kind="triage-report", producer=PRODUCER, description=f"squashfs 매니페스트 ({case.rel(dest)})")
        art = case.register_artifact(
            dest, kind="extracted-tree", producer=PRODUCER,
            description=f"squashfs v{sb['version']} {sb['compression']} @ {case.rel(src)}+0x{offset:x} ({name})",
            extra={"source": case.rel(src), "offset": offset, "manifest": case.rel(manifest_path), "status": status},
        )
        warnings: list[str] = []
        if ctl_note:
            warnings.append(ctl_note)
        if dev_skipped or stats["counts"].get("chardev") or stats["counts"].get("blockdev"):
            warnings.append(
                f"장치 노드 {stats['counts'].get('chardev', 0) + stats['counts'].get('blockdev', 0)}개는 만들지 않았습니다 (비root 추출, 의도된 동작). "
                "목록 정보는 매니페스트에 있습니다."
            )
        if stats["setuid"]:
            warnings.append("비root 추출이라 디스크의 setuid 비트가 제거되었습니다. setuid 정보는 매니페스트(fw_rootfs_audit 가 자동 사용)를 기준으로 하세요.")
        if parsed["anomalies"]:
            warnings.append(f"목록 비정상 줄 {len(parsed['anomalies'])}개 (allow_listing_anomalies=true 로 진행)")
        if status != "complete":
            warnings.append("추출이 완전히 끝나지 않았습니다 (부분 결과). attempts 의 stderr 를 확인하세요.")
        return {
            "status": status,
            "output_dir": case.rel(dest),
            "output_dir_abs": str(dest),
            "manifest_path": case.rel(manifest_path),
            "artifact_id": art.get("id"),
            "superblock": sb,
            "tool": {"name": name, "version": version},
            "listing": {
                "entries": len(entries),
                "counts": stats["counts"],
                "total_file_bytes": stats["total_file_bytes"],
                "setuid": stats["setuid"][:50],
                "setgid": stats["setgid"][:50],
                "world_writable_files": stats["world_writable_files"],
            },
            "extracted": {**extracted_counts, "disk_bytes": used, "logical_bytes": logical},
            "attempts": attempts,
            "warnings": warnings,
            "offset_hex": hexs(offset),
        }
    raise ValidationFailed(
        "squashfs 추출에 실패했습니다 (모든 도구 시도 실패).",
        hint=(
            "attempts 의 stderr 를 확인하세요. 벤더 변형 압축이면 sasquatch, 아니면 REA extract_firmware(unblob)를 시도하세요. "
            "구버전 unsquashfs 는 -offset 을 지원하지 않으므로 offset 이 0 이 아니면 fw_carve 로 squashfs 영역을 먼저 잘라 offset=0 으로 실행하세요."
        ),
        data={"attempts": attempts},
    )


def _count_tree(root: Path) -> dict[str, int]:
    files = dirs = links = other = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.islink(p):
                links += 1
            else:
                dirs += 1
        for f in filenames:
            p = os.path.join(dirpath, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if _stat.S_ISLNK(st.st_mode):
                links += 1
            elif _stat.S_ISREG(st.st_mode):
                files += 1
            else:
                other += 1
    return {"files": files, "dirs": dirs, "symlinks": links, "other": other}
