"""fwtriage-mcp: 오프라인 펌웨어 트리아지 MCP 서버 (pweh-fwtriage, docs/architecture.md 6.6).

외부 도구 없이(순수 Python + PyYAML) 동작하는 빠른 1차 분석. REA(binwalk/unblob/Ghidra)를 대체하지 않고 보완한다.
하드웨어를 건드리지 않으므로 안전 게이트는 없지만, 펌웨어에서 나온 어떤 것도 실행하지 않고(unsquashfs 같은
우리 도구만 실행), 모든 입출력은 케이스 디렉터리 안으로 제한한다.

모든 도구는 case_id 를 받고, 입력은 케이스 안의 경로(케이스 상대 경로 권장), 출력은 analysis/ 또는
extract/<label>-NNN/ 에 쓰고 아티팩트로 등록한다. 응답은 요약 + 전체 결과 JSON 경로(result_path)이며,
목록은 max_results 로 자른다. 오래 걸릴 수 있는 도구는 background=true 로 job 실행 후 fwtriage_job_status 로 폴링.
"""

from __future__ import annotations

import json
import re
import struct
import threading
from pathlib import Path
from typing import Any, Callable

import anyio
import anyio.to_thread

from pweh.errors import ValidationFailed
from pweh.jobs import JobCancelled
from pweh.mcpkit import ANN_LOCAL_WRITE, ANN_READ_ONLY, create_server, register_job_tools, safe_tool
from pweh.runtime import Runtime, get_runtime

from . import elfinfo
from .common import (
    DEFAULT_MAX_RESULTS,
    HARD_MAX_RESULTS,
    Cancelled,
    Ctl,
    ResultFile,
    base_payload,
    clamp_int,
    clip,
    compact_list,
    file_info,
    hexs,
    mask_secret,
    open_mmap,
    parse_int_arg,
    read_regular_file,
    resolve_case_path,
    sanitize,
    resolve_input_dir,
    resolve_input_file,
    severity_key,
)
from .entropy import entropy_scan
from .fswalk import walk_tree
from .hashes import crack_entries, crypt_module_available, parse_hash_input
from .hunt import hunt
from .patterns import glob_to_regex, load_default_passwords, load_patterns
from .rootfs import Auditor
from .signatures import MARKER_KINDS, ScanCtx, padding_runs, scan_regions
from .squashfs import extract_squashfs
from .uboot import carve, env_scan, resolve_layout, uimage_info

SERVER_NAME = "fwtriage-mcp"

server = create_server(
    SERVER_NAME,
    title="PWEH Firmware Triage",
    instructions=(
        "오프라인 펌웨어 트리아지 서버 (외부 도구 없이 동작, REA 를 보완). 권장 순서: "
        "fw_identify(덤프 지도: uImage/FIT/squashfs/jffs2/UBI/env 위치) → fw_uboot_env(env, mtdparts) → "
        "fw_carve(파티션 분할) → fw_extract_squashfs(rootfs 추출) → fw_rootfs_audit(계정/부팅 서비스/웹/키/자격증명) → "
        "fw_strings_hunt(CCTV 인증 우회·백도어 문자열 휴리스틱) → fw_elf_info(웹 서버/CGI 의 위험 임포트·보호기법) → "
        "fw_crack_hashes(펌웨어 해시를 공개 기본 비밀번호와 오프라인 대조). 결과는 '후보'이며 확정은 REA "
        "(search_strings→xrefs→procedure_pseudo_code)와 소유 기기 검증으로 한다. 모든 결과 JSON 은 케이스의 "
        "analysis/ 에, 추출물은 extract/<label>-NNN/ 에 저장되고 아티팩트로 등록된다. 큰 입력은 background=true 로 실행 후 "
        "fwtriage_job_status 로 폴링한다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


register_job_tools(server, rt, "fwtriage")


# ---------------------------------------------------------------------------
# 실행 헬퍼 (인라인: 취소 가능한 스레드 / background: job)
# ---------------------------------------------------------------------------


async def _execute(*, kind: str, case_id: str, background: bool, max_seconds: float | None, description: str, fn: Callable[[Ctl], dict[str, Any]]) -> dict[str, Any]:
    r = rt()
    if background:

        def job_fn(jctx: Any) -> dict[str, Any]:
            ctl = Ctl(cancelled=lambda: jctx.cancelled, progress=jctx.progress, max_seconds=max_seconds)
            try:
                return sanitize(fn(ctl))
            except Cancelled as exc:
                raise JobCancelled() from exc

        job = r.jobs.start(kind, job_fn, description=description, case_id=case_id)
        return {
            "ok": True,
            "background": True,
            "job_id": job.id,
            "status": job.status,
            "message": "백그라운드 작업을 시작했습니다. fwtriage_job_status(job_id, wait_seconds=30) 으로 결과(result)를 확인하세요.",
        }
    ev = threading.Event()
    ctl = Ctl(ev, max_seconds=max_seconds)
    try:
        return sanitize(await anyio.to_thread.run_sync(lambda: fn(ctl), abandon_on_cancel=True))
    except anyio.get_cancelled_exc_class():
        ev.set()
        raise


def _seconds(v: Any, default: float, hi: float = 3600.0) -> float:
    try:
        f = float(v) if v is not None else default
    except (TypeError, ValueError):
        raise ValidationFailed(f"초 단위 값이 잘못되었습니다: {v!r}")
    return max(1.0, min(hi, f))


def _write(case: Any, prefix: str, payload: dict[str, Any], description: str) -> str:
    rf = ResultFile(case, prefix)
    try:
        rf.write(payload, description=description)
    except BaseException:
        rf.discard()
        raise
    return rf.rel


def _small(d: Any, limit: int = 700) -> bool:
    try:
        return len(json.dumps(d, ensure_ascii=False, default=str)) <= limit
    except (TypeError, ValueError):
        return False


def _compact_region(d: dict[str, Any]) -> dict[str, Any]:
    out = {k: d[k] for k in ("offset_hex", "kind", "size", "confidence", "description") if k in d}
    for k in ("truncated", "parent_kind"):
        if d.get(k):
            out[k] = d[k]
    det = d.get("details") or {}
    if det:
        if _small(det):
            out["details"] = det
        else:
            keep = {}
            for k in ("name", "arch", "os", "type", "compression", "load_address", "entry_point", "data_crc_ok", "header_crc_ok", "version", "endianness",
                      "block_size", "inodes", "bytes_used", "nodes", "peb_size", "peb_count", "fs_type", "model", "compatible", "label", "payload", "fit"):
                if k in det and _small(det[k], 300):
                    keep[k] = det[k]
            if det.get("images"):
                keep["images"] = [{kk: im.get(kk) for kk in ("name", "type", "arch", "compression", "data_size") if im.get(kk) is not None} for im in det["images"][:8]]
            if det.get("volumes"):
                keep["volumes"] = [{kk: v.get(kk) for kk in ("vol_id", "name", "pebs_used")} for v in det["volumes"][:12]]
            out["details"] = keep
    return out


def _strip_private(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ---------------------------------------------------------------------------
# fw_identify
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "펌웨어/플래시 덤프 시그니처 스캔(헤더 검증으로 오탐 억제): uImage(헤더·데이터 CRC), FIT/DTB, squashfs(v1~4, 벤더 매직), "
        "jffs2(노드 CRC), UBI/UBIFS(CRC, 볼륨 이름), cramfs/romfs/erofs/ext2·3·4, gzip/xz/lzma/bzip2(시험 해제로 정확한 크기), "
        "zstd/lz4(프레임 검증), ELF, cpio, ARM zImage, zip, PEM 키/인증서, U-Boot env(CRC), U-Boot·커널 버전 문자열, 'PWEH SYNTHETIC' 마커. "
        "offset 순 영역 목록(offset/kind/크기 추정/설명/신뢰도)과 0xFF/0x00 패딩 구간을 analysis/identify-NNN.json 에 저장. "
        "offset/length 로 일부만 스캔 가능(16진 문자열 '0x...' 허용). include_nested=true 면 컨테이너 안쪽 항목도 응답에 포함."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_identify(
    case_id: str,
    path: str,
    offset: int | str = 0,
    length: int | str | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
    include_nested: bool = False,
    max_seconds: float = 120.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    off = parse_int_arg(offset, "offset", allow_none=False) or 0
    ln = parse_int_arg(length, "length")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    secs = _seconds(max_seconds, 120.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        size = info["size"]
        start = min(off, size)
        end = size if ln is None else min(size, start + ln)
        with open_mmap(src) as mm:
            ctx = ScanCtx(ctl)
            regions = scan_regions(mm, start, end, ctx)
            pads = padding_runs(mm, start, end, ctl) if size else []
        all_d = [r.to_dict() for r in regions]
        top = [d for d in all_d if d.get("parent_offset") is None or d["kind"] in MARKER_KINDS]
        nested = [d for d in all_d if not (d.get("parent_offset") is None or d["kind"] in MARKER_KINDS)]
        kinds: dict[str, int] = {}
        for d in top:
            kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
        covered = sum(d["size"] or 0 for d in top if d["kind"] not in MARKER_KINDS)
        arch = sorted({str((d.get("details") or {}).get("arch")) for d in top if d["kind"] in ("uimage",) and (d.get("details") or {}).get("arch")}
                      | {str((d.get("details") or {}).get("machine")) for d in all_d if d["kind"] == "elf" and (d.get("details") or {}).get("machine")})
        summary = {
            "scanned_range": [hexs(start), hexs(end)],
            "region_count": len(top),
            "nested_count": len(nested),
            "kinds": kinds,
            "coverage_ratio": round(covered / max(1, end - start), 4),
            "arch_hints": arch[:8],
            "uboot_versions": [d["details"]["text"] for d in top if d["kind"] == "uboot-version"][:5],
            "linux_versions": [d["details"]["text"] for d in top if d["kind"] == "linux-version"][:3],
            "synthetic_marker": any(d["kind"] == "pweh-synthetic-marker" for d in top),
            "padding_bytes": sum(p["size"] for p in pads),
            "timed_out": ctl.timed_out,
        }
        steps = []
        for d in top:
            k = d["kind"]
            if k == "uboot-env" and not any("fw_uboot_env" in s for s in steps):
                steps.append("U-Boot env 발견 → fw_uboot_env(path) 로 bootargs/mtdparts 확인, fw_carve 로 파티션 분할")
            elif k == "squashfs":
                steps.append(f"squashfs @ {d['offset_hex']} → fw_extract_squashfs(path, offset='{d['offset_hex']}')")
            elif k in ("uimage", "fit"):
                steps.append(f"{k} @ {d['offset_hex']} → fw_uimage_info(path, offset='{d['offset_hex']}')")
            elif k in ("jffs2", "ubi", "ubifs", "cramfs", "ext", "erofs"):
                steps.append(f"{k} @ {d['offset_hex']} → fw_carve 로 분리 후 REA extract_firmware(unblob) 로 추출")
        if not [d for d in top if d["kind"] not in MARKER_KINDS]:
            steps.append("알려진 형식을 찾지 못함 → fw_entropy 로 암호화/난독화 여부 확인, REA inspect_firmware_regions 와 비교")
        payload = base_payload("fw_identify", case, schema="identify", input_info=info, params={"offset": start, "length": ln, "include_nested": include_nested})
        payload.update({"summary": summary, "regions": top, "nested_regions": nested, "padding_runs": pads, "stats": ctx.stats, "notes": ctx.notes, "elapsed_seconds": ctl.elapsed()})
        rel = _write(case, "identify", payload, f"fw_identify {info['path']}")
        rt().audit({"event": "fwtriage_identify", "input": info["path"], "result": rel, "regions": len(top)}, case.id)
        listed = top + (nested if include_nested else [])
        listed.sort(key=lambda d: d["offset"] if "offset" in d else 0)
        items, trunc = compact_list([_compact_region(d) for d in listed], mr)
        return {
            "ok": True,
            "tool": "fw_identify",
            "result_path": rel,
            "input": info,
            "summary": summary,
            "regions": items,
            "regions_total": len(listed),
            "truncated": trunc,
            "nested_omitted": 0 if include_nested else len(nested),
            "padding_runs": pads[:12],
            "warnings": ctx.notes[:12],
            "next_steps": steps[:10],
        }

    return await _execute(kind="fw_identify", case_id=case.id, background=background, max_seconds=secs, description=f"fw_identify {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# fw_entropy
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "블록 Shannon 엔트로피(0~8) 계산. 높은 엔트로피 연속 구간을 압축/암호화 '후보'로 표시하고 카이제곱으로 균일(암호화·강한 압축) / "
        "비균일(일반 압축)을 구분, annotate=true 면 알려진 시그니처와의 겹침도 표시(설명되지 않는 고엔트로피 = 암호화·난독화 의심). "
        "낮은 엔트로피 구간(패딩), 한 줄 프로파일 문자열 포함. 전체 블록 값은 analysis/entropy-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_entropy(
    case_id: str,
    path: str,
    block_size: int | str = 65536,
    offset: int | str = 0,
    length: int | str | None = None,
    high_threshold: float = 7.5,
    annotate: bool = True,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_seconds: float = 120.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    bs = parse_int_arg(block_size, "block_size", allow_none=False) or 65536
    if bs < 256 or bs > (64 << 20):
        raise ValidationFailed("block_size 는 256 바이트 ~ 64MiB 사이여야 합니다.")
    off = parse_int_arg(offset, "offset", allow_none=False) or 0
    ln = parse_int_arg(length, "length")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    thr = max(1.0, min(8.0, float(high_threshold)))
    secs = _seconds(max_seconds, 120.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        size = info["size"]
        start = min(off, size)
        end = size if ln is None else min(size, start + ln)
        with open_mmap(src) as mm:
            res = entropy_scan(mm, start, end, bs, ctl, high=thr, annotate=annotate)
        payload = base_payload("fw_entropy", case, schema="entropy", input_info=info, params={"block_size": bs, "offset": start, "length": ln, "high_threshold": thr})
        payload.update(res)
        payload["elapsed_seconds"] = ctl.elapsed()
        rel = _write(case, "entropy", payload, f"fw_entropy {info['path']}")
        hi, hi_tr = compact_list(res["high_runs"], mr)
        lo, lo_tr = compact_list(res["low_runs"], mr)
        unexplained = [r for r in res["high_runs"] if r.get("known_coverage", 1.0) < 0.5]
        return {
            "ok": True,
            "tool": "fw_entropy",
            "result_path": rel,
            "input": info,
            "block_size": bs,
            "stats": res["stats"],
            "profile": res["profile"],
            "profile_legend": res["profile_legend"],
            "high_runs": hi,
            "high_runs_total": len(res["high_runs"]),
            "low_runs": lo,
            "low_runs_total": len(res["low_runs"]),
            "unexplained_high_entropy_runs": len(unexplained),
            "truncated": hi_tr or lo_tr or res["truncated"],
            "note": "엔트로피는 휴리스틱입니다. 압축/암호화 확정은 fw_identify·REA 결과와 함께 판단하세요.",
        }

    return await _execute(kind="fw_entropy", case_id=case.id, background=background, max_seconds=secs, description=f"fw_entropy {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# fw_uboot_env
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "덤프/파티션에서 U-Boot 환경변수 블록 탐색 (pweh.formats.find_uboot_env: 후보 크기별 CRC 검증, redundant 플래그; 빅엔디안 CRC 보완). "
        "env 전체, 주요 변수(bootcmd/bootargs/mtdparts/ethaddr ...), mtdparts 해석(pweh.formats.parse_mtdparts, '-' 크기는 파일 끝까지), "
        "redundant 쌍의 활성본 추정, CRC 없는 기본 env(U-Boot 바이너리 내장) 후보와 이미지 속 'mtdparts=' 문자열을 반환. "
        "sizes 로 env 크기 후보 지정 가능(예: [16384, 65536])."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_uboot_env(
    case_id: str,
    path: str,
    sizes: list[int] | None = None,
    align: int = 4096,
    include_default_env: bool = True,
    max_results: int = 16,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    al = clamp_int(align, 16, 1 << 20, "align")
    sz = tuple(int(s) for s in sizes) if sizes else None
    if sz and any(s < 64 or s > (16 << 20) for s in sz):
        raise ValidationFailed("sizes 의 각 값은 64 ~ 16MiB 사이여야 합니다.")
    mr = clamp_int(max_results, 1, 64, "max_results")

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        with open_mmap(src) as mm:
            res = env_scan(mm, info["size"], ctl, sizes=sz, align=al, max_hits=mr, include_default=include_default_env)
        payload = base_payload("fw_uboot_env", case, schema="uboot-env", input_info=info, params={"sizes": list(sz) if sz else None, "align": al})
        payload.update(res)
        rel = _write(case, "uboot-env", payload, f"fw_uboot_env {info['path']}")
        layout = None
        for e in res["envs"] + res["embedded_default_envs"]:
            for m in e.get("mtdparts") or []:
                if m.get("partitions"):
                    layout = {"source": m["source"], "text": m["text"], "partitions": [{"name": p["name"], "device": p["device"], "offset_hex": hexs(p["offset"]), "size": p["size"], "ro": p["ro"]} for p in m["partitions"]], "warnings": m.get("warnings")}
                    break
            if layout:
                break

        def trim_env(env: dict[str, str]) -> dict[str, str]:
            out = {}
            for i, (k, v) in enumerate(env.items()):
                if i >= 200:
                    out["…"] = f"{len(env) - 200}개 변수 생략 (result_path 참고)"
                    break
                out[k] = v if len(v) <= 512 else v[:512] + "…"
            return out

        envs = [{**{k: e[k] for k in ("offset_hex", "size", "redundant", "flags", "crc", "crc_endian", "variable_count") if k in e}, "active_guess": e.get("active_guess"), "env": trim_env(e["env"]),
                 "mtdparts": [{"source": m["source"], "text": m["text"], "partition_count": len(m["partitions"] or []), "warnings": m["warnings"]} for m in e["mtdparts"]]} for e in res["envs"]]
        defaults = [{**{k: d[k] for k in ("offset_hex", "size", "source", "variable_count")}, "key_vars": d["key_vars"], "mtdparts": [m["text"] for m in d["mtdparts"]]} for d in res["embedded_default_envs"][:8]]
        steps = []
        if layout:
            steps.append("fw_carve(path) 를 인자 없이 호출하면 이 레이아웃으로 자동 분할합니다 (mtdparts='...' 로 지정도 가능).")
        if not res["envs"]:
            steps.append("CRC 가 맞는 env 가 없습니다: env 파티션이 비었거나(기본 env 사용) 크기 후보가 다릅니다. embedded_default_envs 와 UART printenv 결과를 참고하세요.")
        return {
            "ok": True,
            "tool": "fw_uboot_env",
            "result_path": rel,
            "input": info,
            "env_count": len(res["envs"]),
            "envs": envs,
            "redundant_note": res["redundant_note"],
            "embedded_default_envs": defaults,
            "mtdparts_strings": res["mtdparts_strings"][:10],
            "recommended_layout": layout,
            "next_steps": steps,
        }

    return await _execute(kind="fw_uboot_env", case_id=case.id, background=False, max_seconds=120.0, description=f"fw_uboot_env {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# fw_carve
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "덤프를 파티션으로 분할: mtdparts 문자열(예: 'mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),-(rootfs)') 또는 "
        "partitions 목록([{name, offset, size}], 16진 문자열/크기 문자열 허용, size 생략 시 끝까지)을 사용. 둘 다 없으면 이미지 안의 "
        "U-Boot env(mtdparts/bootargs) → 기본 env → 'mtdparts=' 문자열 → DTB partition 노드 순으로 자동 결정. "
        "extract/<label>-NNN/<idx>-<name>.bin + index.json 생성(partitions[].path = 케이스 상대 경로, file 은 같은 값의 별칭), "
        "각 파티션을 아티팩트(partition)로 등록하고 시작 위치의 형식(squashfs 등)을 판별. "
        "mtdparts 에 장치가 여럿이면 mtd_device 로 선택(기본 첫 장치)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_carve(
    case_id: str,
    path: str,
    mtdparts: str | None = None,
    partitions: list[dict[str, Any]] | None = None,
    output_label: str = "parts",
    mtd_device: str | None = None,
    probe: bool = True,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        with open_mmap(src) as mm:
            layout = resolve_layout(mm, info["size"], ctl, mtdparts=mtdparts, partitions=partitions, mtd_device=mtd_device)
            res = carve(case, src, mm, info["size"], layout, label=output_label, ctl=ctl, probe=probe)
        payload = base_payload("fw_carve", case, schema="carve", input_info=info, params={"mtdparts": mtdparts, "partitions": partitions, "mtd_device": mtd_device, "output_label": output_label})
        payload.update(res)
        rel = _write(case, "carve", payload, f"fw_carve {info['path']} → {res['output_dir']}")
        rt().audit({"event": "fwtriage_carve", "input": info["path"], "output_dir": res["output_dir"], "partitions": len(res["partitions"])}, case.id)
        parts = []
        steps = []
        for p in res["partitions"]:
            c = p.get("content") or {}
            parts.append({k: p.get(k) for k in ("index", "name", "offset_hex", "size", "status", "path", "file", "truncated", "reason") if p.get(k) is not None} | ({"content": c.get("kind"), "content_description": clip(c.get("description") or "", 160)} if c else {}))
            if c.get("kind") == "squashfs" and p.get("path"):
                steps.append(f"fw_extract_squashfs(path='{p['path']}')")
            elif c.get("kind") in ("jffs2", "ubi", "ubifs", "cramfs") and p.get("path"):
                steps.append(f"{p['name']}: {c['kind']} → REA extract_firmware 로 추출 (fwtriage 는 squashfs 만 추출)")
            elif c.get("kind") in ("uimage", "fit") and p.get("path"):
                steps.append(f"fw_uimage_info(path='{p['path']}')")
        return {
            "ok": True,
            "tool": "fw_carve",
            "result_path": rel,
            "input": info,
            "output_dir": res["output_dir"],
            "index_path": res["index_path"],
            "layout": res["layout"],
            "partitions": parts,
            "warnings": res["warnings"][:12],
            "next_steps": steps[:10],
        }

    return await _execute(kind="fw_carve", case_id=case.id, background=False, max_seconds=600.0, description=f"fw_carve {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# fw_uimage_info
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "offset 의 legacy uImage 헤더 파싱(이름, load/entry 주소, OS/arch/type/압축, 헤더·데이터 CRC 검증, multi 이미지 크기표, "
        "실제 페이로드 형식과 헤더 압축 표시 일치 여부) 또는 FIT/DTB 해석(images: type/arch/compression/load/entry/data 크기/해시, "
        "configurations; DTB 면 model/compatible/bootargs/partition 노드). 매직이 없으면 파일 안의 uImage/FIT 위치를 안내."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_uimage_info(case_id: str, path: str, offset: int | str = 0) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    off = parse_int_arg(offset, "offset", allow_none=False) or 0

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        with open_mmap(src) as mm:
            res = uimage_info(mm, info["size"], off, ctl)
        payload = base_payload("fw_uimage_info", case, schema="uimage", input_info=info, params={"offset": off})
        payload["image"] = res
        rel = _write(case, "uimage", payload, f"fw_uimage_info {info['path']}@0x{off:x}")
        out = dict(res)
        if out.get("images") and not _small(out["images"], 4000):
            out["images"] = [{k: im.get(k) for k in ("name", "description", "type", "arch", "os", "compression", "load", "entry", "data_size") if im.get(k) is not None} for im in out["images"][:16]]
        return {"ok": True, "tool": "fw_uimage_info", "result_path": rel, "input": info, "offset_hex": hexs(off), "image": out}

    return await _execute(kind="fw_uimage_info", case_id=case.id, background=False, max_seconds=120.0, description="fw_uimage_info", fn=work)


# ---------------------------------------------------------------------------
# fw_extract_squashfs
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "squashfs 추출 (unsquashfs: 설정 tools.unsquashfs / PWEH_UNSQUASHFS / ~/pweh-tools/bin; 비표준 매직·v4 빅엔디안은 sasquatch 우선). "
        "superblock 을 먼저 검증하고, 'unsquashfs -lln' 목록으로 디렉터리 탈출(.., 링크 아래 항목)·비정상 줄·압축 폭탄(max_output_bytes)을 "
        "검사한 뒤 extract/<label>-NNN/ 에 비root 로 추출(장치 노드 생성 안 함, 시간 제한·디스크 사용량 감시). 원본 모드/소유자/setuid 는 "
        "extract/<label>-NNN.manifest.json 에 보존(fw_rootfs_audit 가 자동 사용). 도구가 없으면 tool_missing 오류와 설치 힌트."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_extract_squashfs(
    case_id: str,
    path: str,
    offset: int | str = 0,
    output_label: str = "rootfs",
    timeout_seconds: float = 600.0,
    max_output_bytes: int | str = "2G",
    engine: str = "auto",
    allow_listing_anomalies: bool = False,
    background: bool = False,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    src = resolve_input_file(case, path)
    off = parse_int_arg(offset, "offset", allow_none=False) or 0
    mob = parse_int_arg(max_output_bytes, "max_output_bytes", allow_none=False) or (2 << 30)
    if engine not in ("auto", "unsquashfs", "sasquatch"):
        raise ValidationFailed("engine 은 auto | unsquashfs | sasquatch 중 하나입니다.")
    tmo = _seconds(timeout_seconds, 600.0, hi=7200.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        res = extract_squashfs(case, src, offset=off, label=output_label, ctl=ctl, config=r.config, timeout=tmo, max_output_bytes=mob, engine=engine, allow_listing_anomalies=allow_listing_anomalies)
        info = file_info(case, src, with_hash=False)
        payload = base_payload("fw_extract_squashfs", case, schema="extract-squashfs", input_info=info, params={"offset": off, "engine": engine, "max_output_bytes": mob})
        payload.update({k: v for k, v in res.items() if k != "output_dir_abs"})
        rel = _write(case, "extract-squashfs", payload, f"fw_extract_squashfs → {res['output_dir']}")
        r.audit({"event": "fwtriage_extract_squashfs", "input": info["path"], "offset": off, "output_dir": res["output_dir"], "status": res["status"], "tool": res["tool"]}, case.id)
        return {
            "ok": True,
            "tool": "fw_extract_squashfs",
            "result_path": rel,
            **{k: res[k] for k in ("status", "output_dir", "output_dir_abs", "manifest_path", "superblock", "tool", "listing", "extracted", "warnings", "offset_hex")},
            "attempts": [{k: a.get(k) for k in ("tool", "stage", "returncode", "timed_out", "killed_reason") if a.get(k) is not None} for a in res["attempts"]],
            "next_steps": [f"fw_rootfs_audit(rootfs_dir='{res['output_dir']}')", f"fw_strings_hunt(path_or_dir='{res['output_dir']}')", f"fw_elf_info(path='{res['output_dir']}') (디렉터리 모드: 위험 임포트 순위)"],
        }

    return await _execute(kind="fw_extract_squashfs", case_id=case.id, background=background, max_seconds=None, description=f"fw_extract_squashfs {case.rel(src)}@0x{off:x}", fn=work)


# ---------------------------------------------------------------------------
# fw_elf_info
# ---------------------------------------------------------------------------


def _elf_compact(rel: str, info: dict[str, Any], risk: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": rel,
        "summary": info.get("summary"),
        "type": info.get("type"),
        "interpreter": info.get("interpreter"),
        "static": info.get("static"),
        "needed": info.get("needed", [])[:12],
        "risky": {k: v["functions"] for k, v in risk["builtin"].items() if k not in ("network-server", "dynamic-loading", "privilege")},
        "network_facing_hint": risk["network_facing_hint"],
        "hardening": {k: info["hardening"].get(k) for k in ("nx", "relro", "pie", "stack_canary")},
        "score": risk["score"],
    }


@server.tool(
    description=(
        "순수 Python ELF 분석: class/엔디언/타입/e_machine, e_flags 해석(MIPS ISA·ABI(o32/n32/n64)·ASE, .MIPS.abiflags FP ABI, ARM EABI·float ABI), "
        "인터프리터, DT_NEEDED/SONAME/RPATH, 임포트 심볼(섹션 헤더 없는 sstrip 바이너리도 PT_DYNAMIC 로), 보호기법(NX/RELRO/PIE/카나리/FORTIFY), "
        "위험 임포트(system/popen/exec*/strcpy/sprintf/sscanf..., cctv-hunt-patterns.yaml function_heuristics 매칭, 폭 없는 %s/%[ sscanf 포맷). "
        "path 가 디렉터리면 모든 ELF 를 분석해 위험 점수 순위를 만든다 (analysis/elf-info-NNN.json)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_elf_info(
    case_id: str,
    path: str,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_files: int = 3000,
    max_seconds: float = 180.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    p = resolve_case_path(case, path)
    is_dir = p.is_dir()
    if not is_dir:
        p = resolve_input_file(case, path)
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    mf = clamp_int(max_files, 1, 200000, "max_files")
    secs = _seconds(max_seconds, 180.0)
    patterns = load_patterns()

    def analyze(fpath: Path, limit: int = 256 << 20) -> tuple[dict[str, Any], dict[str, Any]]:
        with open_mmap(fpath) as mm:
            size = len(mm)
            if size > limit:
                raise ValidationFailed(f"파일이 너무 큽니다 ({size} bytes)")
            try:
                info = elfinfo.parse_elf(mm, size)
            except (elfinfo.ElfError, struct.error) as exc:
                raise ValidationFailed(f"ELF 분석 실패 ({fpath.name}): {exc}") from exc
            strings = None
            if {"sscanf", "fscanf", "scanf", "vsscanf", "vfscanf"} & set(info.get("_all_funcs") or []):
                strings = [m.group(0).decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{3,}", mm[: min(size, 32 << 20)]) if b"%" in m.group(0)][:20000]
            risk = elfinfo.risky_analysis(info, patterns.function_heuristics, strings)
        return info, risk

    def work(ctl: Ctl) -> dict[str, Any]:
        if not is_dir:
            info_f = file_info(case, p)
            info, risk = analyze(p)
            payload = base_payload("fw_elf_info", case, schema="elf-info", input_info=info_f, params={})
            payload.update({"elf": _strip_private(info), "risk": risk})
            rel = _write(case, "elf-info", payload, f"fw_elf_info {info_f['path']}")
            out = _strip_private(info)
            imports, imp_tr = compact_list(out.pop("imports", []), max(mr, 0) * 4 if mr else 0)
            out.pop("exports_sample", None)
            return {"ok": True, "tool": "fw_elf_info", "mode": "file", "result_path": rel, "input": info_f, "elf": out, "imports": imports, "imports_truncated": imp_tr, "risk": risk}
        # 디렉터리 모드
        bins: list[dict[str, Any]] = []
        errors: list[str] = []
        arch: dict[str, int] = {}
        interps: dict[str, int] = {}
        seen: set[tuple[int, int]] = set()
        truncated = False
        for e in walk_tree(p, ctl):
            if e.kind != "file" or e.st.st_size < 52:
                continue
            ino = (e.st.st_dev, e.st.st_ino)
            if ino in seen:
                continue
            seen.add(ino)
            head = read_regular_file(Path(e.path), 4)
            if head != b"\x7fELF":
                continue
            if len(bins) >= mf or ctl.expired():
                truncated = True
                break
            try:
                info, risk = analyze(Path(e.path))
            except Exception as exc:  # 손상된 ELF 는 건너뛴다
                errors.append(f"{e.rel}: {type(exc).__name__}: {clip(str(exc), 120)}")
                continue
            rec = _elf_compact(e.rel, info, risk)
            rec["heuristics"] = {k: v["functions"] for k, v in risk["heuristics"].items()}
            if risk["unbounded_scanf_formats"]:
                rec["unbounded_scanf_formats"] = risk["unbounded_scanf_formats"][:5]
            bins.append(rec)
            arch[info["summary"].split(", ", 1)[-1]] = arch.get(info["summary"].split(", ", 1)[-1], 0) + 1
            if info.get("interpreter"):
                interps[info["interpreter"]] = interps.get(info["interpreter"], 0) + 1
            if len(bins) % 50 == 0:
                ctl.progress(len(bins), None, f"ELF {len(bins)}개 분석")
        bins.sort(key=lambda b: -b["score"])
        dinfo = {"path": case.rel(p), "type": "directory"}
        summary = {
            "elf_count": len(bins),
            "arch": arch,
            "interpreters": interps,
            "with_command_exec": sum(1 for b in bins if b["risky"].get("command-exec")),
            "network_facing_hint": sum(1 for b in bins if b["network_facing_hint"]),
            "without_nx": sum(1 for b in bins if b["hardening"].get("nx") is False),
            "without_canary": sum(1 for b in bins if not b["hardening"].get("stack_canary")),
            "truncated": truncated,
            "errors": len(errors),
        }
        payload = base_payload("fw_elf_info", case, schema="elf-info-dir", input_info=dinfo, params={"max_files": mf})
        payload.update({"summary": summary, "binaries": bins, "errors": errors[:200]})
        rel = _write(case, "elf-info", payload, f"fw_elf_info {dinfo['path']} (디렉터리)")
        top, tr = compact_list(bins, mr)
        return {"ok": True, "tool": "fw_elf_info", "mode": "directory", "result_path": rel, "input": dinfo, "summary": summary, "binaries": top, "truncated": tr,
                "note": "score 는 위험 임포트/네트워크 서버 함수/보호기법으로 만든 단순 순위입니다. 상위 바이너리를 REA 로 분석하세요."}

    return await _execute(kind="fw_elf_info", case_id=case.id, background=background, max_seconds=secs, description=f"fw_elf_info {case.rel(p)}", fn=work)


# ---------------------------------------------------------------------------
# fw_rootfs_audit
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "추출된 rootfs 감사: passwd/shadow(빈/약한 해시와 알고리즘, uid 0 추가 계정, 공개 하드코딩 해시, 내장 기본 비밀번호 오프라인 대조), "
        "inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트(telnetd·-l /bin/sh, dropbear -B, nc -e 셸, getty 자동 로그인/콘솔 셸, remserial, "
        "쓰기 가능한 영구 저장소 스크립트 실행, world-writable 시작 스크립트), 웹 서버/메인 앱 바이너리·설정·CGI, setuid(매니페스트 기준), "
        "개인키/인증서(지문만), 설정/스크립트의 하드코딩 자격증명(마스킹), 영구 쓰기 가능 마운트, YAML credential_patterns/interesting_paths. "
        "심볼릭 링크는 rootfs 안에서만 해석(호스트 파일을 읽지 않음). 결과: analysis/rootfs-audit-NNN.json (항목마다 파일/줄/발췌/category/severity)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_rootfs_audit(
    case_id: str,
    rootfs_dir: str,
    max_results: int = DEFAULT_MAX_RESULTS,
    crack_defaults: bool = True,
    crack_seconds: float = 30.0,
    max_file_size: int | str = "16M",
    max_seconds: float = 300.0,
    background: bool = False,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    root = resolve_input_dir(case, rootfs_dir)
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    mfs = parse_int_arg(max_file_size, "max_file_size", allow_none=False) or (16 << 20)
    secs = _seconds(max_seconds, 300.0)
    csecs = _seconds(crack_seconds, 30.0, hi=600.0)
    patterns = load_patterns()
    try:
        profile = r.config.profile(case.load().get("profile"))
    except Exception:
        profile = {}

    def work(ctl: Ctl) -> dict[str, Any]:
        words, wl_path = load_default_passwords()
        words = list(dict.fromkeys(words + patterns.candidate_passwords))
        aud = Auditor(root, ctl, patterns, persistent_paths=list(r.config.safety.persistent_paths), profile=profile, max_file_size=mfs,
                      crack=crack_defaults, crack_seconds=csecs, words=words, max_entries=300000)
        res = aud.run()
        res["rootfs"]["path"] = case.rel(root)
        manifest_path = root.parent / f"{root.name}.manifest.json"
        if manifest_path.is_file():
            try:
                sb = json.loads(manifest_path.read_text(encoding="utf-8")).get("superblock") or {}
                res["rootfs"]["fs_type"] = f"squashfs {sb.get('version', '')} {sb.get('compression', '')}".strip()
            except (OSError, ValueError):
                pass
        dinfo = {"path": case.rel(root), "type": "directory"}
        payload = base_payload("fw_rootfs_audit", case, schema="rootfs-audit", input_info=dinfo,
                               params={"crack_defaults": crack_defaults, "crack_seconds": csecs, "max_file_size": mfs, "patterns": {"source": patterns.source, "sha256": patterns.sha256}, "wordlist": wl_path})
        payload.update(res)
        rel = _write(case, "rootfs-audit", payload, f"fw_rootfs_audit {dinfo['path']}")
        r.audit({"event": "fwtriage_rootfs_audit", "input": dinfo["path"], "result": rel, "items": len(res["items"])}, case.id)
        items, tr = compact_list(res["items"], mr)
        accounts = []
        crack_by_user = {}
        for h in res["hash_checks"]:
            crack_by_user.setdefault(h.get("user"), []).append({"algorithm": h["algorithm"], "status": h["status"], "password": h.get("password_masked") if h.get("status") == "cracked" else None, "known_hash": (h.get("known_hash") or {}).get("id")})
        for a in res["accounts"][:60]:
            accounts.append({"user": a["user"], "uid": a.get("uid"), "shell": a.get("shell"), "hashes": [hh["algorithm"] for hh in a.get("hashes", [])], "checks": crack_by_user.get(a["user"])})
        steps = []
        if any(it["severity"] in ("critical", "high") for it in res["items"]):
            steps.append("critical/high 항목은 case_add_finding 으로 기록하고 (evidence: result_path + file/line), REA 로 관련 바이너리를 확인하세요.")
        if res["web"]["servers"]:
            steps.append("웹/메인 앱 바이너리: fw_elf_info(path=...) 와 fw_strings_hunt(path_or_dir=...) 로 인증 우회·명령 주입 앵커를 찾으세요.")
        steps.append(f"fw_strings_hunt(path_or_dir='{case.rel(root)}') 로 CCTV 패턴 전체 검색")
        return {
            "ok": True,
            "tool": "fw_rootfs_audit",
            "result_path": rel,
            "input": dinfo,
            "summary": res["summary"],
            "rootfs": res["rootfs"],
            "platform": {k: res["platform"].get(k) for k in ("arch", "endianness", "arch_flags", "busybox", "libc", "release_files")},
            "items": items,
            "items_total": len(res["items"]),
            "truncated": tr,
            "accounts": accounts,
            "services": [{k: s[k] for k in ("service", "file", "line", "command")} for s in res["services"][:30]],
            "web_servers": res["web"]["servers"][:20],
            "cgi_count": len(res["web"]["cgi"]),
            "vendor": res["vendor"],
            "binaries_of_interest": res["binaries_of_interest"][:30],
            "limitations": res["limitations"],
            "next_steps": steps,
        }

    return await _execute(kind="fw_rootfs_audit", case_id=case.id, background=background, max_seconds=secs, description=f"fw_rootfs_audit {case.rel(root)}", fn=work)


# ---------------------------------------------------------------------------
# fw_strings_hunt
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "인증 우회/백도어/명령 주입/하드코딩 자격증명 문자열 휴리스틱 검색 (src/pweh/data/cctv-hunt-patterns.yaml 의 string_heuristics, "
        "scope: strings=바이너리의 ASCII·UTF-16LE 문자열, text=텍스트 파일 줄, raw=바이트). patterns='cctv'(전체) 또는 목록: 휴리스틱 id/"
        "category/vendor/severity 선택자, 'xm-*' 접두사, 're:<정규식>', 'raw:<바이트 정규식>', 'lit:<문자열>'. 파일/디렉터리 모두 가능. "
        "히트마다 파일/오프셋(텍스트는 줄)/패턴 id/category/severity/문맥. checks 목록은 auth-hunt 스키마 checks[] 로 바로 쓸 수 있다. "
        "max_hits 는 저장 상한(패턴별 per_pattern_cap), 응답에는 max_results 개. 히트의 file 은 두 모드 모두 rootfs 절대 경로(rootfs 밖의 "
        "덤프·파티션 이미지는 null), path 는 케이스 상대 경로. 결과: analysis/strings-hunt-NNN.json"
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_strings_hunt(
    case_id: str,
    path_or_dir: str,
    patterns: str | list[str] = "cctv",
    max_hits: int = 500,
    max_results: int = DEFAULT_MAX_RESULTS,
    min_severity: str | None = None,
    include: list[str] | None = None,
    min_length: int = 4,
    utf16: bool = True,
    per_pattern_cap: int = 50,
    max_file_size: int | str = "128M",
    max_seconds: float = 240.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    p = resolve_case_path(case, path_or_dir)
    is_dir = p.is_dir()
    if not is_dir:
        p = resolve_input_file(case, path_or_dir)
    ps = load_patterns()
    if min_severity is not None and min_severity not in ("critical", "high", "medium", "low", "info"):
        raise ValidationFailed("min_severity 는 critical|high|medium|low|info 중 하나입니다.")
    selected, notes = ps.select(patterns, min_severity=min_severity)
    if not selected:
        # 건너뛴 이유(컴파일 실패, 빈 문자열과 일치하는 패턴 등)를 함께 알려 준다
        raise ValidationFailed("선택된 패턴이 없습니다." + (" " + " / ".join(notes[:5]) if notes else ""),
                               hint="fw_hunt_patterns 로 사용 가능한 id/category/vendor 를 확인하세요.")
    mh = clamp_int(max_hits, 1, 100000, "max_hits")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    ml = clamp_int(min_length, 3, 64, "min_length")
    ppc = clamp_int(per_pattern_cap, 1, 100000, "per_pattern_cap")
    mfs = parse_int_arg(max_file_size, "max_file_size", allow_none=False) or (128 << 20)
    inc = [glob_to_regex(g) for g in include] if include else None
    secs = _seconds(max_seconds, 240.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = {"path": case.rel(p), "type": "directory"} if is_dir else file_info(case, p, with_hash=False)
        res = hunt(p, is_dir, case.dir, ctl, selected, max_hits=mh, per_pattern_cap=ppc, max_file_size=mfs, min_len=ml, utf16=utf16, include_rx=inc)
        payload = base_payload("fw_strings_hunt", case, schema="strings-hunt", input_info=info,
                               params={"patterns": patterns, "min_severity": min_severity, "include": include, "max_hits": mh, "per_pattern_cap": ppc, "pattern_source": ps.source, "pattern_sha256": ps.sha256})
        payload.update(res)
        payload["notes"] = notes + ([f"패턴 파일 경고: {e}" for e in ps.errors[:10]])
        payload["elapsed_seconds"] = ctl.elapsed()
        rel = _write(case, "strings-hunt", payload, f"fw_strings_hunt {info['path']}")
        rt().audit({"event": "fwtriage_strings_hunt", "input": info["path"], "result": rel, "hits": res["summary"]["hits_total"]}, case.id)
        hits, tr = compact_list(res["hits"], mr)
        matched = [{"id": c["id"], "count": c["count"], "severity": c["severity"], "evidence_ref": c["evidence_ref"]} for c in res["checks"] if c["result"] == "match"]
        matched.sort(key=lambda c: (severity_key(c["severity"]), -c["count"]))
        return {
            "ok": True,
            "tool": "fw_strings_hunt",
            "result_path": rel,
            "input": info,
            "summary": res["summary"],
            "hits": hits,
            "truncated": tr or res["summary"]["truncated"],
            "matched_checks": matched[:60],
            "no_match_checks": sum(1 for c in res["checks"] if c["result"] == "no-match"),
            "top_files": res["top_files"][:10],
            "patterns": {"source": ps.source, "sha256": ps.sha256[:16], "selected": len(selected)},
            "notes": notes[:10],
        }

    return await _execute(kind="fw_strings_hunt", case_id=case.id, background=background, max_seconds=secs, description=f"fw_strings_hunt {case.rel(p)}", fn=work)


@server.tool(
    description="fw_strings_hunt / fw_rootfs_audit / fw_elf_info 가 쓰는 휴리스틱 목록(cctv-hunt-patterns.yaml: id/category/severity/scope/vendor, function_heuristics, web_server_binaries)과 패턴 파일 출처·해시·오류.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def fw_hunt_patterns(vendor: str | None = None, category: str | None = None) -> dict[str, Any]:
    ps = load_patterns()
    sh = [h.brief() | {"references": h.references} for h in ps.string_heuristics if (not vendor or h.vendor == vendor) and (not category or h.category == category)]
    return {
        "ok": True,
        "source": ps.source,
        "sha256": ps.sha256,
        "version": ps.version,
        "errors": ps.errors,
        "string_heuristics": sh,
        "credential_patterns": [{"id": c.id, "category": c.category, "severity": c.severity, "files": c.files} for c in ps.credential_patterns],
        "function_heuristics": [{"id": f["id"], "category": f.get("category"), "severity_hint": f.get("severity_hint"), "pattern_class": f.get("pattern_class"), "functions": f.get("functions", [])} for f in ps.function_heuristics],
        "web_server_binaries": ps.web_server_binaries,
        "interesting_paths_count": len(ps.interesting_paths),
        "known_hashes": len(ps.known_hashes),
        "candidate_passwords": len(ps.candidate_passwords),
    }


# ---------------------------------------------------------------------------
# fw_crack_hashes
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "펌웨어에서 나온 비밀번호 해시를 공개 기본 비밀번호 사전(builtin-defaults: src/pweh/data/default-passwords.txt + YAML candidate_passwords)과 "
        "오프라인 대조 — 소유 기기 감사용, 네트워크 로그인 시도 없음. hashes: 'user:hash:...' 줄 / 순수 해시 / {user, hash, type} 목록, 또는 "
        "source_path(케이스 안의 passwd/shadow/htpasswd 파일). 지원: DES crypt, md5crypt($1$), apr1, sha256/512crypt($5$/$6$), XiongMai Sofia "
        "(hash_type='xm-sofia'), 솔트 없는 md5/sha1/sha256 hex; bcrypt/yescrypt 는 crypt 모듈 지원 시. 공개 하드코딩 해시(known hash)도 표시. "
        "wordlist 는 'builtin-defaults' 또는 케이스 안의 파일 경로. 평문은 기본 마스킹(reveal=true 로 응답에 표시), 전체는 analysis/crack-hashes-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_crack_hashes(
    case_id: str,
    hashes: list[Any] | None = None,
    source_path: str | None = None,
    wordlist: str = "builtin-defaults",
    extra_words: list[str] | None = None,
    hash_type: str | None = None,
    max_seconds: float = 60.0,
    reveal: bool = False,
    max_results: int = DEFAULT_MAX_RESULTS,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    entries: list[dict[str, Any]] = []
    for item in hashes or []:
        e = parse_hash_input(item)
        if e:
            if hash_type and not e.get("hint"):
                e["hint"] = hash_type
            entries.append(e)
    src_rel = None
    if source_path:
        sp = resolve_input_file(case, source_path)
        src_rel = case.rel(sp)
        data = read_regular_file(sp, 4 << 20) or b""
        for ln, line in enumerate(data.decode("latin-1").split("\n"), 1):
            if not line or line.startswith("#") or ":" not in line:
                continue
            f = line.split(":")
            if len(f) >= 2 and f[0] and f[1] not in ("x", "*", "!", "!!"):
                entries.append({"user": f[0], "hash": f[1], "hint": hash_type, "source": f"{src_rel}:{ln}"})
    if not entries:
        raise ValidationFailed("대조할 해시가 없습니다.", hint="hashes=['root:$1$...'] 또는 source_path='extract/rootfs-001/etc/shadow' 를 주세요.")
    if len(entries) > 5000:
        raise ValidationFailed("해시가 너무 많습니다 (최대 5000).")
    secs = _seconds(max_seconds, 60.0, hi=3600.0)
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    ps = load_patterns()
    if wordlist in (None, "", "builtin-defaults", "builtin"):
        words, wl_desc = load_default_passwords()
        words = list(dict.fromkeys(words + ps.candidate_passwords))
    else:
        wp = resolve_input_file(case, wordlist)
        raw = read_regular_file(wp, 64 << 20) or b""
        words = [w for w in raw.decode("utf-8", "replace").splitlines() if w][:2_000_000]
        wl_desc = case.rel(wp)
    if extra_words:
        words = list(dict.fromkeys([str(w) for w in extra_words[:10000]] + words))

    def work(ctl: Ctl) -> dict[str, Any]:
        import time as _time

        deadline = _time.monotonic() + secs
        results = crack_entries(entries, words, deadline=deadline, known_hashes=ps.known_hashes, progress=ctl.progress)
        payload = base_payload("fw_crack_hashes", case, schema="crack-hashes", input_info={"source_path": src_rel, "count": len(entries)},
                               params={"wordlist": wl_desc, "words": len(words), "hash_type": hash_type, "crypt_module": crypt_module_available()})
        payload["results"] = results
        payload["note"] = "평문 비밀번호가 포함되어 있습니다. 케이스 디렉터리 밖으로 반출하지 말고 보고서에는 마스킹하세요."
        rel = _write(case, "crack-hashes", payload, "fw_crack_hashes (평문 포함, 반출 주의)")
        out = []
        for r_ in results:
            d = {k: r_.get(k) for k in ("user", "algorithm", "status", "candidates_tried", "source", "note") if r_.get(k) is not None}
            d["hash"] = (r_["hash"][:12] + "…") if len(r_["hash"]) > 14 else r_["hash"]
            if "password" in r_:
                d["password"] = r_["password"] if reveal else mask_secret(r_["password"])
            if r_.get("known_hash"):
                d["known_hash"] = {k: r_["known_hash"].get(k) for k in ("id", "severity_hint", "references")}
            out.append(d)
        items, tr = compact_list(out, mr)
        counts: dict[str, int] = {}
        for r_ in results:
            counts[r_["status"]] = counts.get(r_["status"], 0) + 1
        return {
            "ok": True,
            "tool": "fw_crack_hashes",
            "result_path": rel,
            "wordlist": wl_desc,
            "words": len(words),
            "counts": counts,
            "results": items,
            "truncated": tr,
            "revealed": bool(reveal),
            "note": "공개 기본 비밀번호와 일치하면 동일 펌웨어의 모든 기기가 같은 자격증명을 가질 가능성이 높습니다 (finding: hardcoded-credential).",
        }

    return await _execute(kind="fw_crack_hashes", case_id=case.id, background=background, max_seconds=None, description=f"fw_crack_hashes ({len(entries)} hashes)", fn=work)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
