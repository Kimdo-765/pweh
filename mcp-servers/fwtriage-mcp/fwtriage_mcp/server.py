"""fwtriage-mcp: 오프라인 펌웨어 트리아지 MCP 서버 (pweh-fwtriage, docs/architecture.md 6.6).

외부 도구 없이(순수 Python + PyYAML) 동작하는 빠른 1차 분석. REA(binwalk/unblob/Ghidra)를 대체하지 않고 보완한다.
하드웨어를 건드리지 않으므로 안전 게이트는 없지만, 펌웨어에서 나온 어떤 것도 실행하지 않고(unsquashfs 같은
우리 도구만 실행), 모든 입출력은 케이스 디렉터리 안으로 제한한다.

모든 도구는 case_id 를 받고, 입력은 케이스 안의 경로(케이스 상대 경로 권장), 출력은 analysis/ 또는
extract/<label>-NNN/ 에 쓰고 아티팩트로 등록한다. 응답은 요약 + 전체 결과 JSON 경로(result_path)이며,
목록은 max_results 로 자른다. 오래 걸릴 수 있는 도구는 background=true 로 job 실행 후 fwtriage_job_status 로 폴링.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import struct
import threading
from pathlib import Path
from typing import Any, Callable

import anyio
import anyio.to_thread

from pweh.errors import ValidationFailed
from pweh.fsutil import atomic_write_bytes
from pweh.jobs import JobCancelled
from pweh.mcpkit import ANN_LOCAL_WRITE, ANN_READ_ONLY, Context, create_server, register_job_tools, safe_tool
from pweh.provenance import KIND_PATCH_PLAN
from pweh.runtime import Runtime, get_runtime
from pweh.safety import attestation_response
from pweh.safety.attestations import display_text
from pweh.safety.masking import mask_secret as core_mask_secret
from pweh.toolsdir import tools_env

from . import elfinfo, espfmt, saves
from .androidlayout import android_layout, carve_android, check_output_budget
from .androidsurface import AndroidSurface
from .androidformats import hash_buffer
from .common import (
    DEFAULT_MAX_RESULTS,
    HARD_MAX_RESULTS,
    PRODUCER,
    Cancelled,
    Ctl,
    ResultFile,
    base_payload,
    clamp_int,
    claim_numbered_dir,
    claim_numbered_file,
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
    safe_label,
    safe_name,
    severity_key,
)
from .entropy import entropy_scan
from .fswalk import walk_tree
from .hashes import crack_entries, crypt_module_available, parse_hash_input
from .hunt import hunt
from .patterns import DEFAULT_PACK, PACKS, glob_to_regex, load_default_passwords, load_patterns, split_pack_spec
from .rootfs import Auditor
from .sdsurface import SdSurface, attach_sd_boot, compact_result, compact_sd_boot
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
        "fw_strings_hunt(CCTV 인증 우회·백도어 문자열 휴리스틱, patterns='game' 이면 게임 세이브·해금 단서) → fw_elf_info(웹 서버/CGI 의 위험 임포트·보호기법) → "
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
        "env 마다 sd_boot(SD 부팅 신호: fatload/ext4load/load mmc(장치 자리 변수 'fatload ${bootdev}' 는 같은 env 의 'bootdev=mmc' 로 읽음), "
        "mmc 에서 읽는 boot.scr·uEnv.txt·env import(tftp·ubi·nand·sf·usb 출처는 notes 만), distro boot, "
        "mmc 를 플래시보다 먼저 시도하는지, verify 값과 꺼짐 여부(env_get_yesno 기준: 값이 있고 첫 글자가 1/y/Y/t/T 가 아니면 꺼짐, 없으면 켬), "
        "SD 업데이트(sdupdate·hiupdate·do_auto_update 같은 명령, 또는 mmc 에서 읽어 플래시에 쓰는 값 — 이름만 autoupdate 인 TFTP 업데이트는 아님), CRC 유효 env 면 saveenv 로 쓰기 가능, "
        "run 펼침은 변수당 16 KiB·env 전체 2 MiB 상한)를 붙인다 — mmc 장치 번호로는 SD 와 eMMC 를 구분하지 못한다. "
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
        sd_summary = attach_sd_boot(res)  # envs[]·embedded_default_envs[] 마다 sd_boot
        payload = base_payload("fw_uboot_env", case, schema="uboot-env", input_info=info, params={"sizes": list(sz) if sz else None, "align": al})
        payload.update(res)
        payload["sd_boot_summary"] = sd_summary
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
                 "mtdparts": [{"source": m["source"], "text": m["text"], "partition_count": len(m["partitions"] or []), "warnings": m["warnings"]} for m in e["mtdparts"]],
                 "sd_boot": compact_sd_boot(e["sd_boot"])} for e in res["envs"]]
        defaults = [{**{k: d[k] for k in ("offset_hex", "size", "source", "variable_count")}, "key_vars": d["key_vars"], "mtdparts": [m["text"] for m in d["mtdparts"]],
                     "sd_boot": compact_sd_boot(d["sd_boot"])} for d in res["embedded_default_envs"][:8]]
        steps = []
        if layout:
            steps.append("fw_carve(path) 를 인자 없이 호출하면 이 레이아웃으로 자동 분할합니다 (mtdparts='...' 로 지정도 가능).")
        if not res["envs"]:
            steps.append("CRC 가 맞는 env 가 없습니다: env 파티션이 비었거나(기본 env 사용) 크기 후보가 다릅니다. embedded_default_envs 와 UART printenv 결과를 참고하세요.")
        if sd_summary["envs_with_mmc_boot"] or sd_summary["update_from_card"]:
            steps.append(f"SD 부팅·업데이트 신호(sd_boot): fw_sd_surface(image_path='{info['path']}') 로 SD-01~09 체크리스트를 만드세요 (mmc 장치가 SD 슬롯인지 eMMC 인지는 보드에서 확인).")
        elif sd_summary["verify_off"]:
            # verify=n 만으로는 SD 신호가 아니다 — 부팅 이미지 검증이 꺼졌다는 일반 사항만 알린다
            steps.append("verify 가 '아니오'인 env 가 있습니다 (env_get_yesno 기준): U-Boot 가 부팅 이미지(FIT 서명 포함)를 검증하지 않습니다. "
                         "부팅 소스(플래시·네트워크)와 이미지 쓰기 경로를 함께 확인하세요.")
        return {
            "ok": True,
            "tool": "fw_uboot_env",
            "result_path": rel,
            "input": info,
            "env_count": len(res["envs"]),
            "sd_boot_summary": sd_summary,
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
        "raw GPT/LP → U-Boot env(mtdparts/bootargs) → 기본 env → 'mtdparts=' 문자열 → DTB partition 노드 순으로 자동 결정. "
        "extract/<label>-NNN/<idx>-<name>.bin + index.json 생성(partitions[].path = 케이스 상대 경로, file 은 같은 값의 별칭), "
        "각 파티션을 아티팩트(partition)로 등록하고 시작 위치의 형식(squashfs 등)을 판별. "
        "mtdparts 에 장치가 여럿이면 mtd_device 로 선택(기본 첫 장치). layout_source=auto|mtd|gpt|lp, lp_slot=0(활성 slot 추정 아님). "
        "GPT CRC·LP SHA256/extent를 검증하고 LP의 여러 extent를 순서대로 결합하며 ZERO는 0으로 채운다. 외부 device·disabled·잘린 LP partition은 건너뛴다. "
        "sparse 자동 분할은 미지원(확장 CRC 미검증). max_output_bytes는 모든 방식의 출력 합계 상한(기본 4GiB, 최대 16GiB)."
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
    layout_source: str = "auto",
    lp_slot: int = 0,
    max_output_bytes: int | str = "4G",
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    if layout_source not in ("auto", "mtd", "gpt", "lp"):
        raise ValidationFailed("layout_source는 auto|mtd|gpt|lp 중 하나여야 합니다.")
    if (partitions or mtdparts or mtd_device) and layout_source in ("gpt", "lp"):
        raise ValidationFailed("explicit partitions/mtd 인자는 GPT/LP selector와 함께 쓸 수 없습니다.")
    maximum = parse_int_arg(max_output_bytes, "max_output_bytes", allow_none=False)
    if maximum is None or not 1 <= maximum <= 16 << 30:
        raise ValidationFailed("max_output_bytes는 1바이트~16GiB여야 합니다.")
    if type(lp_slot) is not int or not 0 <= lp_slot < 16:
        raise ValidationFailed("lp_slot은 0~15 정수여야 합니다.")

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src, with_hash=False)
        with open_mmap(src) as mm:
            layout = None if partitions or mtdparts or layout_source == "mtd" else android_layout(mm, info["size"], ctl, selector=layout_source, slot=lp_slot)
            if layout is None:
                layout = resolve_layout(mm, info["size"], ctl, mtdparts=mtdparts, partitions=partitions, mtd_device=mtd_device)
                check_output_budget(layout["partitions"], info["size"], maximum)
                info["sha256"] = hash_buffer(mm, info["size"], ctl)
                res = carve(case, src, mm, info["size"], layout, label=output_label, ctl=ctl, probe=probe)
            else:
                check_output_budget(layout["partitions"], info["size"], maximum)
                info["sha256"] = hash_buffer(mm, info["size"], ctl)
                res = carve_android(case, src, mm, info["size"], layout, label=output_label, ctl=ctl, probe=probe, source_sha256=info["sha256"])
        payload = base_payload("fw_carve", case, schema="carve", input_info=info, params={"mtdparts": mtdparts, "partitions": partitions, "mtd_device": mtd_device, "output_label": output_label,
                                                                                  "layout_source": layout_source, "lp_slot": lp_slot, "max_output_bytes": maximum})
        payload.update(res)
        rel = _write(case, "carve", payload, f"fw_carve {info['path']} → {res['output_dir']}")
        rt().audit({"event": "fwtriage_carve", "input": info["path"], "output_dir": res["output_dir"], "partitions": len(res["partitions"])}, case.id)
        parts = []
        steps = []
        for p in res["partitions"]:
            c = p.get("content") or {}
            parts.append({k: p.get(k) for k in ("index", "name", "offset", "offset_hex", "size", "status", "path", "file", "sha256", "mapping", "attributes", "raw_name", "truncated", "reason") if p.get(k) is not None} | ({"content": c.get("kind"), "content_description": clip(c.get("description") or "", 160)} if c else {}))
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
        "Android 펌웨어 정적 점검 AN-01~09: ADB 통신/인증, debug/root 빌드, test-keys, SELinux permissive, AVB disabled flags, "
        "init 서비스 권한, OTA 검증 구성, 특권 APK/permission XML, 하드코딩 자격증명. rootfs_dir(이미 추출한 트리) 또는 "
        "image_path(boot/vendor_boot/vbmeta 이미지) 중 하나 이상. 기기 접촉·코드 실행·파일 시스템 해독·증거 bridge 없음. "
        "found/not-found/unknown은 제공한 입력 범위에 한정; 누락·크기/시간 제한·미해결 import는 coverage/limitations로 표시. "
        "AVB 구조 검사는 서명 검증이 아니고 init/priv-app/OTA 키 존재는 정보성 inventory다. 자격증명은 마스킹. "
        "max_file_size는 rootfs 텍스트 1개 상한(기본 1MiB, 최대 8MiB), max_evidence는 점검별 상한. "
        "결과 analysis/android-surface-NNN.json. background=true면 fwtriage_job_status로 조회."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_android_surface(
    case_id: str,
    rootfs_dir: str | None = None,
    image_path: str | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_evidence: int = 20,
    max_file_size: int | str = "1M",
    max_seconds: float = 300.0,
    background: bool = False,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    if not rootfs_dir and not image_path:
        raise ValidationFailed("rootfs_dir 또는 image_path 중 하나 이상이 필요합니다.")
    root = resolve_input_dir(case, rootfs_dir) if rootfs_dir else None
    src = resolve_input_file(case, image_path) if image_path else None
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    me = clamp_int(max_evidence, 1, 200, "max_evidence")
    mfs = parse_int_arg(max_file_size, "max_file_size", allow_none=False)
    if mfs is None or not 1 <= mfs <= 8 << 20:
        raise ValidationFailed("max_file_size는 1바이트~8MiB여야 합니다.")
    secs = _seconds(max_seconds, 300.0, 600.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        audit = AndroidSurface(ctl, max_evidence=me, max_file_size=mfs)
        inputs: dict[str, Any] = {"rootfs_dir": {"path": case.rel(root), "type": "directory"} if root else None, "image": None}
        if root is not None:
            audit.scan_rootfs(root)
        if src is not None:
            info = file_info(case, src, with_hash=False)
            with open_mmap(src) as mm:
                info["sha256"] = hash_buffer(mm, info["size"], ctl)
                audit.scan_image(mm, info["size"], info["path"])
            inputs["image"] = info
        result = audit.result()
        payload = base_payload("fw_android_surface", case, schema="android-surface", input_info=inputs,
                               params={"max_evidence": me, "max_file_size": mfs, "max_seconds": secs})
        payload.update(result)
        rel = _write(case, "android-surface", payload, "Android 펌웨어 정적 표면 점검")
        r.audit({"event": "fwtriage_android_surface", "result": rel, "counts": result["counts"]}, case.id)
        return {"ok": True, "tool": "fw_android_surface", "result_path": rel, "input": inputs,
                **result, "checks": result["checks"][:mr], "checks_omitted": max(0, len(result["checks"]) - mr)}

    return await _execute(kind="fw_android_surface", case_id=case.id, background=background, max_seconds=secs,
                          description="fw_android_surface", fn=work)


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
        "쓰기 가능한 영구 저장소 스크립트 실행(VAR=값·nohup·setsid·env·command·time·start-stop-daemon -x(멈춤 명령 제외) 뒤 포함 — 대입·래퍼 건너뛰기는 셸 문법 파일만, "
        "systemd 'ExecStart=프로그램 경로' 의 경로는 인자), world-writable 시작 스크립트), 웹 서버/메인 앱 바이너리·설정·CGI, setuid(매니페스트 기준), "
        "개인키/인증서(지문만), 설정/스크립트의 하드코딩 자격증명(마스킹), 영구 쓰기 가능 마운트, YAML credential_patterns/interesting_paths. "
        "핫플러그 처리기(mdev.conf @/$/*, udev RUN+=, /etc/hotplug*)도 시작 스크립트처럼 따라간다. "
        "시작 스크립트는 셸 논리 줄 전체를 본다(줄 끝 '\\'·|·||·&& 로 이어진 줄은 한 명령 — 연산자 뒤의 빈 줄·주석 줄 포함, 연산자 뒤 줄 끝 주석은 판정에서 지움, "
        "줄 끝 주석 안의 연산자·'\\|'·'\\&&' 와 here-document 본문(구분자는 셸 낱말 전체, 끝 구분자 줄이 없으면 본문 아님)은 잇지 않고, "
        "inittab·inetd·udev·systemd 유닛처럼 셸이 아닌 파일은 줄 끝 '\\' 만; 항목 줄 번호는 첫 줄; 긴 줄·키워드 반복에서도 자르거나 "
        "규칙을 건너뛰지 않음). 같은 최종 파일(심볼릭·하드 링크)은 한 번만 읽고, 항목은 같은 파일의 같은 규칙마다 20개, 시작 스크립트 전체에서 같은 규칙마다 "
        "500개까지 적고 나머지는 summary.items_suppressed·limitations 로 센다. 시간 예산·스크립트 큐(실행 문맥 참조 2000개)·"
        "파일 크기(1 MiB) 상한에 걸리면 summary.startup_scan_complete=false 와 limitations 의 '[시작 스크립트 검사 미완료]' 로 알린다. "
        "sd_surface=true 면 SD 카드 공격 표면의 rootfs 쪽(SD-01~09: 카드 내용 실행·업데이트·설정·로그·마운트 옵션·네트워크 노출, SD 마운트 지점, "
        "sd_paths_referenced) 섹션 sd_surface 를 더한다(U-Boot 쪽은 보지 않으므로 rootfs 근거가 없는 SD-02·SD-03 은 unknown — U-Boot 쪽은 fw_sd_surface(image_path) 로). "
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
    sd_surface: bool = False,
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
        sd_section = None
        if sd_surface:
            # rootfs 쪽만 (같은 Auditor 의 순회·시작 스크립트·웹 결과를 다시 쓴다). 시간 예산이 남지 않으면 해당 점검은 unknown
            sds = SdSurface(ctl, patterns, max_binary_file=mfs)
            sds.scan_rootfs(aud, {"startup_files": res["startup_files"]}, res["web"])
            sd_section = sds.result(rootfs_given=True, image_given=False)
        params = {"crack_defaults": crack_defaults, "crack_seconds": csecs, "max_file_size": mfs, "patterns": {"source": patterns.source, "sha256": patterns.sha256}, "wordlist": wl_path}
        if sd_surface:
            params["sd_surface"] = True
        payload = base_payload("fw_rootfs_audit", case, schema="rootfs-audit", input_info=dinfo, params=params)
        payload.update(res)
        if sd_section is not None:
            payload["sd_surface"] = sd_section
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
        if sd_section is not None:
            if sd_section["risk_found"]:
                steps.append(f"SD 표면 found({', '.join(sd_section['risk_found'])}): REA 로 호출 경로를 확인하고, U-Boot 쪽은 fw_sd_surface(rootfs_dir='{case.rel(root)}', image_path=<플래시 덤프>) 로 SD-02·SD-03 까지")
            else:
                steps.append(f"SD 표면 U-Boot 쪽(SD-02·SD-03)은 fw_sd_surface(rootfs_dir='{case.rel(root)}', image_path=<플래시 덤프>) 로")
        out = {
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
        if sd_section is not None:
            out["sd_surface"] = compact_result(sd_section, mr)
        return out

    return await _execute(kind="fw_rootfs_audit", case_id=case.id, background=background, max_seconds=secs, description=f"fw_rootfs_audit {case.rel(root)}", fn=work)


# ---------------------------------------------------------------------------
# fw_sd_surface
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "펌웨어 쪽 SD 카드 공격 표면 정적 점검 SD-01~09 (오프라인·관찰만: 기기와 카드를 건드리지 않고 펌웨어 안의 어떤 것도 실행하지 않는다, "
        "docs/design/sd-forensics.md 5.1). rootfs_dir(추출된 rootfs)과 image_path(플래시 덤프 또는 U-Boot·env 파티션) 중 하나 이상이 필요하다. "
        "rootfs: 시작·핫플러그 스크립트(rcS/init.d/inittab/cron, mdev.conf @/$/*, udev RUN+=, hotplug)·설정·바이너리 문자열에서 카드 경로의 실행(복사·복호화 뒤 실행 포함)·"
        "플래시 쓰기·설정 가져오기·로그 쓰기·웹/FTP/Samba 노출, SD 마운트(fstab·mount 명령·핫플러그·흔한 경로 /mnt/sd*(sdk·sda1 같은 SCSI 디스크 이름 제외)·/mnt/mmc*·/media/mmc*·/tmp/sd·"
        "/mnt/tf·/mnt/tf<숫자>·/mnt/tfcard<숫자>·/sdcard·/system/sdcard·/mnt/disc*, media·storage 같은 일반 이름은 FAT 계열 fs 일 때만)와 마운트 옵션. 펌웨어의 mdev 정규식·udev glob 은 실행하지 않는다"
        "(장치 이름 표본에 자체 해석기로만 맞춘다). 셸 스크립트의 줄 이어쓰기는 한 명령으로 보고(fw_rootfs_audit 와 같은 규칙), echo·logger 문구 속 cd·sh x 와 "
        "start-stop-daemon 멈춤(-K·--stop)의 -x 경로는 실행이 아니며, 명령 앞 대입 접두는 셸 문법 파일만 본다(systemd ExecStart 의 인자는 실행 아님). "
        "커널 모듈(.ko·/lib/modules)의 문자열은 보지 않는다. "
        "image: U-Boot env(CRC 유효·내장 기본)의 mmc 부팅·mmc 에서 읽는 boot.scr/uEnv.txt(장치 자리 변수 ${bootdev} 는 같은 env 의 값으로)·env import·"
        "verify(env_get_yesno 기준 첫 글자가 1/y/Y/t/T 가 아니면 비활성 환경값; 실제 검증 강제는 빌드·부팅 경로·신뢰 키 확인 필요)·"
        "env 쓰기 가능성, 업데이트 표지(sdupdate·sdupgrade·hiupdate·do_auto_update·au_check_cksum_valid) 문자열. "
        "fit_security는 같은 image의 비압축 FDT v17에서 이미지/설정 서명 선언과 control-DTB 형태의 키 후보 구조를 제한 관찰한다. "
        "최대256 MiB 검색·64후보·32구조·128항목·결과64 KiB, 기존 호출의 남은 시간만 사용한다. "
        "검사 범위·완료도와 한계를 따로 기록하며 새 구조 정보로 SD 위험 상태를 바꾸지 않는다. "
        "서명 수학 검증·키 신뢰·부팅 검증 강제·SD 경로 연결은 확인하지 않는다. rootfs만 주면 not-examined다. "
        "점검마다 status(found / not-found / unknown — 필요한 입력이 없거나 시간·크기·줄 길이(16 KiB)·문자열 히트 상한으로 일부만 보거나 "
        "시작 스크립트 검사가 끝나지 않으면 unknown. "
        "SD-07 녹화 암호화만 found 가 보호 근거), "
        "severity_hint, category(finding 어휘), evidence(source rootfs/uboot-env/image-strings, file·line 또는 image·offset_hex, 마스킹된 excerpt, rule), rationale, "
        "references(설계 표의 CVE), next_steps. 물리 버튼·GPIO 로만 열리는 업데이트는 같은 파일·위치의 원격 쓰기 경로가 보이지 않을 때만 SD-02 심각도를 낮춘다. "
        "mount_points(발견 근거), sd_paths_referenced(펌웨어가 실행·읽기·플래시하는 카드 경로 — 나중에 카드 내용과 대조). 결과: analysis/sd-surface-NNN.json"
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_sd_surface(
    case_id: str,
    rootfs_dir: str | None = None,
    image_path: str | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_evidence: int = 20,
    max_file_size: int | str = "64M",
    max_seconds: float = 300.0,
    background: bool = False,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    if not (isinstance(rootfs_dir, str) and rootfs_dir.strip()) and not (isinstance(image_path, str) and image_path.strip()):
        raise ValidationFailed(
            "rootfs_dir 와 image_path 중 하나 이상이 필요합니다.",
            hint="rootfs_dir = fw_extract_squashfs 의 output_dir(예: extract/rootfs-001), image_path = 플래시 덤프(예: dumps/flash.bin) 또는 fw_carve 의 U-Boot·env 파티션",
        )
    root = resolve_input_dir(case, rootfs_dir) if rootfs_dir else None
    src = resolve_input_file(case, image_path) if image_path else None
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    me = clamp_int(max_evidence, 1, 200, "max_evidence")
    mfs = parse_int_arg(max_file_size, "max_file_size", allow_none=False) or (64 << 20)
    secs = _seconds(max_seconds, 300.0)
    patterns = load_patterns()
    try:
        profile = r.config.profile(case.load().get("profile"))
    except Exception:
        profile = {}

    def work(ctl: Ctl) -> dict[str, Any]:
        sds = SdSurface(ctl, patterns, max_evidence=me, max_binary_file=mfs)
        inputs: dict[str, Any] = {"rootfs_dir": None, "image": None}
        uboot = None
        if root is not None:
            # 계정·해시 대조 없이 순회 + 시작·핫플러그 스크립트 + 웹 설정만
            aud = Auditor(root, ctl, patterns, persistent_paths=list(r.config.safety.persistent_paths), profile=profile, max_file_size=mfs,
                          crack=False, crack_seconds=1.0, words=[], max_entries=300000)
            aud.walk()
            ctl.progress(1, 4, "시작·핫플러그 스크립트")
            startup = aud.audit_startup()
            web = aud.audit_web()
            ctl.progress(2, 4, "rootfs SD 표면")
            sds.scan_rootfs(aud, startup, web)
            inputs["rootfs_dir"] = {"path": case.rel(root), "type": "directory"}
        if src is not None:
            ctl.progress(3, 4, "U-Boot env·이미지 문자열")
            info = file_info(case, src)
            with open_mmap(src) as mm:
                scan = env_scan(mm, info["size"], ctl, include_default=True)
                summary = attach_sd_boot(scan, ctl)
                scan["sd_boot_summary"] = summary
                sds.scan_image(mm, info["size"], info["path"], scan)
            inputs["image"] = info
            uboot = {
                "sd_boot_summary": summary,
                "envs": [{**{k: e.get(k) for k in ("offset_hex", "size", "redundant", "crc", "variable_count", "key_vars")}, "sd_boot": e["sd_boot"]} for e in scan["envs"]],
                "embedded_default_envs": [{**{k: d.get(k) for k in ("offset_hex", "size", "variable_count", "key_vars")}, "sd_boot": d["sd_boot"]} for d in scan["embedded_default_envs"]],
            }
        res = sds.result(rootfs_given=root is not None, image_given=src is not None)
        payload = base_payload("fw_sd_surface", case, schema="sd-surface", input_info=inputs,
                               params={"max_evidence": me, "max_file_size": mfs, "max_seconds": secs, "patterns": {"source": patterns.source, "sha256": patterns.sha256}})
        payload.update(res)
        payload["uboot"] = uboot
        payload["timed_out"] = ctl.timed_out
        payload["elapsed_seconds"] = ctl.elapsed()
        label = " + ".join(x for x in (case.rel(root) if root is not None else None, inputs["image"]["path"] if inputs["image"] else None) if x)
        rel = _write(case, "sd-surface", payload, f"fw_sd_surface {label}")
        r.audit({"event": "fwtriage_sd_surface", "input": label, "result": rel, "counts": res["counts"], "risk_found": res["risk_found"]}, case.id)
        out: dict[str, Any] = {"ok": True, "tool": "fw_sd_surface", "result_path": rel, "input": inputs}
        out.update(compact_result(res, mr))
        if uboot is not None:
            out["uboot"] = {
                "env_count": len(uboot["envs"]),
                "embedded_default_env_count": len(uboot["embedded_default_envs"]),
                "sd_boot_summary": uboot["sd_boot_summary"],
                "envs": [{"offset_hex": e["offset_hex"], "storage": e["sd_boot"]["storage"], **compact_sd_boot(e["sd_boot"])}
                         for e in (uboot["envs"] + uboot["embedded_default_envs"])[:8]],
            }
        steps: list[str] = []
        if res["risk_found"]:
            steps.append("found 점검은 REA(search_strings → xrefs → procedure_pseudo_code)로 호출 경로를 확인한 뒤 case_add_finding "
                         "(evidence: type=triage, ref=result_path + evidence 의 file/line 또는 image@offset_hex).")
        if "SD-05" in res["risk_found"]:
            steps.append("SD-05: 카드에서 읽은 값이 system()/popen 으로 흐르는지 REA 로 확인 (cctv-auth-bypass-hunt 의 AH-04 와 교차).")
        if src is None:
            steps.append("U-Boot 쪽(SD-02·SD-03)은 image_path(플래시 덤프 또는 U-Boot·env 파티션)를 주고 다시 실행.")
        if root is None:
            steps.append("rootfs 쪽(SD-01·SD-04·SD-05·SD-06·SD-08·SD-09)은 rootfs_dir(fw_extract_squashfs 의 output_dir)를 주고 다시 실행.")
        if any(c["status"] == "unknown" and (c.get("unknown_reason") or "").startswith("시간") for c in res["checks"]):
            steps.append("일부 점검이 시간·크기 예산으로 unknown 입니다: max_seconds·max_file_size 를 늘리거나 background=true 로 다시 실행.")
        steps.append("부팅 로그 수동 관찰은 uart_capture_boot 의 sd_events 로만 (카드 없음 vs 사람이 동의한 새 빈 시험 카드 — 증거 카드는 다시 넣지 않음).")
        if res["sd_paths_total"]:
            steps.append("카드 이미지가 있으면 이 전체 결과 JSON과 forensics_fs_list 전체 목록을 forensics_sd_ioc_scan으로 대조합니다. "
                         "이름 일치는 추가 검사 후보입니다. 정상 업데이트·설정 파일도 일치할 수 있으며 실행·침해를 증명하지 않습니다.")
        out["next_steps"] = steps
        return out

    label0 = " + ".join(x for x in (case.rel(root) if root is not None else None, case.rel(src) if src is not None else None) if x)
    return await _execute(kind="fw_sd_surface", case_id=case.id, background=background, max_seconds=secs, description=f"fw_sd_surface {label0}", fn=work)


# ---------------------------------------------------------------------------
# fw_strings_hunt
# ---------------------------------------------------------------------------


#: 게임 팩 히트 문맥에서 가리는 값: key=값 꼴(토큰·키·코드·비밀번호·PIN·라이선스·시리얼), URL 의 사용자:비밀번호@, Bearer 토큰, JWT
_HIT_SECRET_RXS = (
    re.compile(r"(?i)((?:token|key|code|secret|pass(?:word|wd)?|pwd|pin|license|licence|serial)[\w.-]{0,24}\s*[=:]\s*[\"']?)([^\s&;,\"'<>]{3,})"),
    re.compile(r"(://[^/@:\s]+:)([^@/\s]+)@"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"()(\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?)"),
)


def _mask_hit_secrets(hits: Any) -> int:
    """히트의 match·context 에서 비밀 모양의 값을 <masked> 로 바꾼다(제자리). 한 히트에서 찾은 값은 두 필드 모두에서 가린다. 반환: 가린 히트 수."""
    n = 0
    for h in hits or []:
        if not isinstance(h, dict):
            continue
        texts = [h.get(k) for k in ("match", "context") if isinstance(h.get(k), str)]
        found: set[str] = set()
        for t in texts:
            for rx in _HIT_SECRET_RXS:
                found.update(m.group(2) for m in rx.finditer(t) if len(m.group(2)) >= 3)
        if not found:
            continue
        for k in ("match", "context"):
            v = h.get(k)
            if isinstance(v, str):
                for sec in sorted(found, key=len, reverse=True):
                    v = v.replace(sec, "<masked>")
                h[k] = v
        h["masked"] = True
        n += 1
    return n


@server.tool(
    description=(
        "인증 우회/백도어/명령 주입/하드코딩 자격증명 문자열 휴리스틱 검색 (기본 CCTV 팩: src/pweh/data/cctv-hunt-patterns.yaml 의 string_heuristics, "
        "scope: strings=바이너리의 ASCII·UTF-16LE 문자열, text=텍스트 파일 줄, raw=바이트). patterns='cctv'(전체) 또는 목록: 휴리스틱 id/"
        "category/vendor/severity 선택자, 'xm-*' 접두사, 're:<정규식>', 'raw:<바이트 정규식>', 'lit:<문자열>'. "
        "게임 팩: patterns='game' 이면 src/pweh/data/game-hunt-patterns.yaml 전체(debug-menu/cheat-input/unlock-condition/save-format/"
        "save-integrity/nfc-tag/clock/online-sync/entitlement 단서, severity info/low — 소유 게임기·장난감의 해금 조건·세이브 위치 출발점, "
        "entitlement 는 보고만), 'game:<category|id|vendor|severity|접두사*>'(목록 가능)는 그 일부이고 게임 팩에 없는 선택자는 오류다. "
        "두 팩은 한 호출에서 섞지 않는다(CCTV 선택자를 함께 주면 오류, 사용자 패턴 re:/raw:/lit: 는 함께 가능). 파일/디렉터리 모두 가능. "
        "히트마다 파일/오프셋(텍스트는 줄)/패턴 id/category/severity/문맥. checks 목록은 auth-hunt 스키마 checks[] 로 바로 쓸 수 있다. "
        "max_hits 는 저장 상한(패턴별 per_pattern_cap), 응답에는 max_results 개. 히트의 file 은 두 모드 모두 rootfs 절대 경로(rootfs 밖의 "
        "덤프·파티션 이미지는 null), path 는 케이스 상대 경로. 쓴 팩은 응답 patterns.pack 과 결과 JSON params.pack(게임 팩이면 "
        "summary.vendor_family_guess 는 null, 히트의 key=값·URL 자격증명·Bearer·JWT 값은 <masked> — summary.masked_values). 결과: analysis/strings-hunt-NNN.json"
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
    # 팩 결정: 'game' / 'game:<선택자>' 가 있으면 게임 팩(다른 팩 선택자와 섞으면 ValidationFailed), 아니면 기존 CCTV 팩 그대로
    pack, spec = split_pack_spec(patterns)
    ps = load_patterns(pack=pack)
    if min_severity is not None and min_severity not in ("critical", "high", "medium", "low", "info"):
        raise ValidationFailed("min_severity 는 critical|high|medium|low|info 중 하나입니다.")
    selected, notes = ps.select(spec, min_severity=min_severity, strict=pack != DEFAULT_PACK)
    if not selected:
        # 건너뛴 이유(컴파일 실패, 빈 문자열과 일치하는 패턴 등)를 함께 알려 준다
        raise ValidationFailed("선택된 패턴이 없습니다." + (" " + " / ".join(notes[:5]) if notes else ""),
                               hint="fw_hunt_patterns 로 사용 가능한 id/category/vendor 를 확인하세요." if pack == DEFAULT_PACK
                               else f"fw_hunt_patterns(pack='{pack}') 로 사용 가능한 id/category/vendor/severity 를 확인하세요.")
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
        if pack != DEFAULT_PACK:
            # vendor_family_guess 는 auth-hunt 의 vendor_family(CCTV 팩의 벤더 키) 추정이라 다른 팩에서는 의미가 없다
            res["summary"]["vendor_family_guess"] = None
            # 게임 팩은 라이선스·구매·URL 단서를 찾으므로 히트 문맥에 토큰·키·URL 자격증명이 섞이기 쉽다 → 값만 가린다
            masked = _mask_hit_secrets(res.get("hits")) + _mask_hit_secrets(res.get("commented_hits"))
            if masked:
                res["summary"]["masked_values"] = masked
        payload = base_payload("fw_strings_hunt", case, schema="strings-hunt", input_info=info,
                               params={"patterns": patterns, "pack": pack, "min_severity": min_severity, "include": include, "max_hits": mh, "per_pattern_cap": ppc, "pattern_source": ps.source, "pattern_sha256": ps.sha256})
        payload.update(res)
        payload["notes"] = notes + ([f"패턴 파일 경고: {e}" for e in ps.errors[:10]])
        payload["elapsed_seconds"] = ctl.elapsed()
        rel = _write(case, "strings-hunt", payload, f"fw_strings_hunt {info['path']}")
        rt().audit({"event": "fwtriage_strings_hunt", "input": info["path"], "result": rel, "hits": res["summary"]["hits_total"], "pack": pack}, case.id)
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
            "patterns": {"pack": pack, "source": ps.source, "sha256": ps.sha256[:16], "selected": len(selected)},
            "notes": notes[:10],
        }

    return await _execute(kind="fw_strings_hunt", case_id=case.id, background=background, max_seconds=secs, description=f"fw_strings_hunt {case.rel(p)}", fn=work)


@server.tool(
    description=(
        "휴리스틱 목록과 패턴 파일 출처·해시·오류. pack='cctv'(기본): fw_strings_hunt / fw_rootfs_audit / fw_elf_info 가 쓰는 "
        "cctv-hunt-patterns.yaml(string_heuristics 의 id/category/severity/scope/vendor, function_heuristics, web_server_binaries). "
        "pack='game': fw_strings_hunt(patterns='game') 이 쓰는 game-hunt-patterns.yaml(string_heuristics 만, category 9종: debug-menu/"
        "cheat-input/unlock-condition/save-format/save-integrity/nfc-tag/clock/online-sync/entitlement). vendor·category 로 거른다. "
        "응답 pack·packs(사용 가능한 팩)."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def fw_hunt_patterns(vendor: str | None = None, category: str | None = None, pack: str = "cctv") -> dict[str, Any]:
    ps = load_patterns(pack=pack)
    sh = [h.brief() | {"references": h.references} for h in ps.string_heuristics if (not vendor or h.vendor == vendor) and (not category or h.category == category)]
    return {
        "ok": True,
        "pack": ps.pack,
        "packs": list(PACKS),
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


# ---------------------------------------------------------------------------
# ESP32 형식 (fw_esp_*) — 게임 세이브·해금 오프라인 분석 (docs/design/game-console-flipper-rf.md §3.5)
# ---------------------------------------------------------------------------

#: ESP 도구가 한 번에 읽는 최대 크기 (ESP 플래시는 수십 MiB 이하)
ESP_MAX_BYTES = 128 << 20
#: 세이브 비교·체크섬 도구의 스냅샷 수 한도
SNAPSHOT_MIN, SNAPSHOT_MAX = 2, 16
#: 스냅샷 전체 크기 상한(메모리 보호 — 세이브는 작다): 바이트 비교 합계 64 MiB, 체크섬 찾기 합계 8 MiB(합 계열 접두합이 입력의
#: 10배 남짓 메모리를 쓴다), 치트 표 16 MiB
SAVE_DIFF_MAX_TOTAL = 64 << 20
CHECKSUM_MAX_TOTAL = 8 << 20
SEQ_TABLES_MAX_BYTES = 16 << 20
#: NVS 해석 입력 상한 (NVS 파티션은 보통 수십 KiB — 항목마다 dict 를 만들므로 큰 입력을 NVS 로 해석하지 않게), nvs 비교 합계 상한
NVS_MAX_BYTES = 1 << 20
NVS_DIFF_MAX_TOTAL = 4 << 20
#: REA 호환 RISC-V e_flags: EF_RISCV_RVC(0x1) | EF_RISCV_FLOAT_ABI_DOUBLE(0x4)
ELF_RISCV_REA_EFLAGS = 0x5
#: 치트 입력 표를 찾지 않는 세그먼트 kind (코드·패딩)
_CODE_SEGMENT_KINDS = ("flash-text", "iram", "rtc-text", "rom-text", "padding")
#: 세이브로 보이는 NVS 키 이름 (다음 단계 안내용)
_SAVE_KEY_RE = re.compile(r"score|hiscore|high|best|rank|level|stage|world|unlock|coin|gold|gem|life|lives|progress|save|slot|clear|star|exp|xp", re.I)


_LIB_ERRORS = (espfmt.EspFormatError, espfmt.NvsError, saves.SaveFormatError)


def _lib(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """라이브러리 호출: 형식·인자 오류(EspFormatError·NvsError·SaveFormatError)는 validation_failed 로 알린다."""
    try:
        return fn(*args, **kwargs)
    except _LIB_ERRORS as exc:
        raise ValidationFailed(str(exc)) from None


def _pread_regular(path: Path, start: int, n: int) -> bytes:
    """일반 파일의 [start, start+n) 을 읽는다(심볼릭 링크·특수 파일 거부)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValidationFailed(f"일반 파일이 아닙니다: {path.name}")
        chunks: list[bytes] = []
        pos, left = start, n
        while left > 0:
            b = os.pread(fd, min(left, 1 << 20), pos)
            if not b:
                break
            chunks.append(b)
            pos += len(b)
            left -= len(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _esp_table(src: Path, size: int) -> dict[str, Any]:
    """파일 앞부분(최대 1 MiB + 4 KiB)에서 파티션 표를 찾는다. 범위 검사는 실제 파일 크기(data_len)로 한다."""
    head = _pread_regular(src, 0, min(size, 0x101000))
    return _lib(espfmt.parse_partition_table, head, data_len=size)


def _esp_range(src: Path, offset: Any, length: Any, partition: str | None, *, what: str) -> dict[str, Any]:
    """offset/length 또는 partition(전체 플래시 덤프의 파티션 label)으로 읽을 범위를 정한다."""
    size = src.stat().st_size
    off = parse_int_arg(offset, "offset")
    ln = parse_int_arg(length, "length")
    ent = None
    table_offset = None
    if partition:
        if off is not None or ln is not None:
            raise ValidationFailed("partition 과 offset/length 는 함께 줄 수 없습니다.", hint="파티션 전체를 쓰거나, offset/length 로 범위를 직접 준다.")
        table = _esp_table(src, size)
        if not table.get("found"):
            raise ValidationFailed("파티션 표를 찾지 못했습니다 — partition 은 ESP 전체 플래시 덤프에만 쓸 수 있습니다.",
                                   hint="offset/length 로 범위를 직접 주거나 fw_esp_partitions 로 표 위치를 확인하세요.")
        ent = espfmt.find_partition(table, partition)
        if ent is None:
            labels = ", ".join(str(e.get("label")) for e in table.get("entries", []))
            raise ValidationFailed(f"파티션 '{partition}' 이 없습니다.", hint=f"있는 파티션: {labels}")
        off, ln = int(ent["offset"]), int(ent["size"])
        table_offset = table.get("offset")
    start = off or 0
    if start < 0 or start > size:
        raise ValidationFailed(f"offset 이 파일 밖입니다: {hexs(start)} (파일 크기 {size})")
    avail = size - start
    n = avail if ln is None else min(int(ln), avail)
    if n > ESP_MAX_BYTES:
        raise ValidationFailed(f"{what} 입력이 너무 큽니다 ({n} 바이트).", hint="offset/length 또는 partition 으로 범위를 좁히세요.")
    out: dict[str, Any] = {"start": start, "length": n, "start_hex": hexs(start), "end_hex": hexs(start + n)}
    if ent is not None:
        out["partition"] = {k: ent.get(k) for k in ("label", "type_name", "subtype_name", "offset", "size", "encrypted", "write_class")}
        out["table_offset"] = table_offset
        if ln is not None and int(ln) > avail:
            out["truncated"] = True
    return out


def _esp_read(src: Path, rng: dict[str, Any]) -> bytes:
    return _pread_regular(src, rng["start"], rng["length"])


def _seg_brief(s: dict[str, Any], base: int = 0) -> dict[str, Any]:
    """세그먼트 요약. file_offset 은 이미지 기준, file_offset_abs 는 입력 파일 기준(base = 이미지 시작)."""
    fo = s.get("file_offset")
    return {"index": s.get("index"), "load_addr": hexs(s.get("load_addr")), "size": s.get("size"),
            "file_offset": hexs(fo), "file_offset_abs": hexs(base + fo) if isinstance(fo, int) else None,
            "region": s.get("region"), "kind": s.get("kind")}


def _abs_segments(img: dict[str, Any], base: int) -> None:
    """결과 파일의 세그먼트에 입력 파일 기준 오프셋(file_offset_abs)을 더한다."""
    for sg in img.get("segments") or []:
        if isinstance(sg.get("file_offset"), int):
            sg["file_offset_abs"] = base + sg["file_offset"]


@server.tool(
    description=(
        "ESP32 계열 플래시 덤프의 파티션 표 해석(기본 0x8000, 없으면 4 KiB 경계 탐색): label, type/subtype 이름, offset, size, flags(암호화·읽기 전용), "
        "MD5 항목 검증, 겹침·범위 밖 경고, 세이브 쓰기 분류 write_class(nvs / raw-user-data / filesystem-analysis-only / not-a-save)와 "
        "write_blockers(암호화 플래그, nvs_keys 파티션 = NVS 암호화 가능). fat/spiffs/littlefs 는 파일 시스템 해석 전까지 분석만 한다. "
        "결과: analysis/esp-partitions-NNN.json. 앱은 fw_esp_image_info, NVS 는 fw_esp_nvs(partition=label) 로 이어 간다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_esp_partitions(case_id: str, path: str, offset: int | str | None = None, max_results: int = DEFAULT_MAX_RESULTS) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    off = parse_int_arg(offset, "offset")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        size = info["size"]
        if off is not None:
            if off < 0 or off >= size:
                raise ValidationFailed(f"offset 이 파일 밖입니다: {hexs(off)}")
            # 표 자리(최대 0xC00 + MD5 항목)만 읽는다 — 큰 offset 에서 [0, offset) 을 읽지 않게
            data = _pread_regular(src, off, min(size - off, espfmt.PARTITION_TABLE_MAX_LEN + 32))
            table = _lib(espfmt.parse_partition_table, data, off, data_len=size, base_offset=off)  # offset 은 절대 위치
        else:
            table = _esp_table(src, size)
        payload = base_payload("fw_esp_partitions", case, schema="esp-partitions", input_info=info, params={"offset": off})
        payload.update(table)
        rel = _write(case, "esp-partitions", payload, f"fw_esp_partitions {info['path']}")
        ents = table.get("entries") or []
        rt().audit({"event": "fwtriage_esp_partitions", "input": info["path"], "result": rel, "found": bool(table.get("found")), "entries": len(ents)}, case.id)
        steps: list[str] = []
        brief = []
        for e in ents:
            brief.append({"label": e.get("label"), "type": e.get("type_name"), "subtype": e.get("subtype_name"), "offset": hexs(e.get("offset")),
                          "size": e.get("size"), "encrypted": e.get("encrypted"), "readonly": e.get("readonly"),
                          "write_class": e.get("write_class"), "write_blockers": e.get("write_blockers") or []})
            if e.get("type_name") == "app" and e.get("offset", 0) + 0x20 <= size:
                steps.append(f"앱 '{e.get('label')}' → fw_esp_image_info(path='{info['path']}', partition='{e.get('label')}') → fw_esp_to_elf")
            elif e.get("write_class") == "nvs":
                steps.append(f"NVS '{e.get('label')}' → fw_esp_nvs(path='{info['path']}', partition='{e.get('label')}'), 스냅샷 여러 개면 fw_save_diff(partition='{e.get('label')}')")
            elif e.get("write_class") == "raw-user-data":
                steps.append(f"원시 데이터 '{e.get('label')}' → 스냅샷 비교 fw_save_diff(partition='{e.get('label')}') · fw_checksum_find")
            elif e.get("write_class") == "filesystem-analysis-only":
                steps.append(f"'{e.get('label')}' 은 파일 시스템({e.get('subtype_name')}) — 파일 시스템 해석 전까지 분석만 (REA extract_firmware 로 풀어 본다)")
        if not table.get("found"):
            steps.append("파티션 표를 찾지 못함 → 전체 플래시 덤프인지 확인(esp32-flash-dump), 플래시 암호화면 표도 암호문이다(fw_entropy, esp_security_info)")
        items, tr = compact_list(brief, mr)
        return {
            "ok": True,
            "tool": "fw_esp_partitions",
            "result_path": rel,
            "input": info,
            "found": bool(table.get("found")),
            "table_offset": hexs(table.get("offset")),
            "partitions": items,
            "partitions_total": len(brief),
            "truncated": tr,
            "md5": table.get("md5"),
            "nvs_keys_present": table.get("nvs_keys_present"),
            "warnings": (table.get("warnings") or [])[:12],
            "errors": (table.get("errors") or [])[:12],
            "next_steps": steps[:12],
        }

    return await _execute(kind="fw_esp_partitions", case_id=case.id, background=False, max_seconds=60.0, description=f"fw_esp_partitions {case.rel(src)}", fn=work)


@server.tool(
    description=(
        "ESP32 계열 앱(또는 2단계 부트로더) 이미지 해석: 칩(chip_id → 이름·아키텍처), entry, SPI 설정, 세그먼트(load 주소·크기·메모리 영역), "
        "체크섬·덧붙은 SHA256 검증, 앱 설명(esp_app_desc: 프로젝트 이름, 버전, IDF 버전, 빌드 시각, ELF sha256). "
        "partition=label(전체 플래시 덤프의 앱 파티션) 또는 offset 으로 위치를 준다. 결과: analysis/esp-image-NNN.json. ELF 로 바꾸려면 fw_esp_to_elf."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_esp_image_info(case_id: str, path: str, offset: int | str | None = None, partition: str | None = None) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        rng = _esp_range(src, offset, None, partition, what="앱 이미지")
        img = _lib(espfmt.parse_app_image, _esp_read(src, rng), 0)
        _abs_segments(img, rng["start"])
        payload = base_payload("fw_esp_image_info", case, schema="esp-image", input_info=info, params={"offset": rng["start"], "partition": partition})
        payload.update({"range": rng, "image": img})
        rel = _write(case, "esp-image", payload, f"fw_esp_image_info {info['path']}@{rng['start_hex']}")
        rt().audit({"event": "fwtriage_esp_image_info", "input": info["path"], "offset": rng["start_hex"], "result": rel, "ok": bool(img.get("ok")), "chip": img.get("chip")}, case.id)
        steps = []
        warnings = list(img.get("warnings") or [])
        if (rng.get("partition") or {}).get("encrypted"):
            warnings.insert(0, "파티션에 암호화 플래그가 있다 — 플래시 암호화면 이 이미지는 암호문이라 해석이 맞지 않는다")
        if img.get("ok"):
            loc = f"partition='{partition}'" if partition else f"offset='{rng['start_hex']}'"
            steps.append(f"fw_esp_to_elf(path='{info['path']}', {loc}) → REA open_binary(ELF 절대 경로) 로 디컴파일")
            steps.append(f"치트 입력 표 후보: fw_find_seq_tables(path='{info['path']}', {loc}) · 문자열 단서: fw_strings_hunt(patterns='game')")
        return {
            "ok": True,
            "tool": "fw_esp_image_info",
            "result_path": rel,
            "input": info,
            "range": rng,
            "valid": bool(img.get("ok")),
            "chip": img.get("chip"),
            "arch": img.get("arch"),
            "entry": hexs(img.get("entry")),
            "segments": [_seg_brief(s, rng["start"]) for s in (img.get("segments") or [])][:32],
            "checksum": img.get("checksum"),
            "sha256": img.get("sha256"),
            "app_desc": img.get("app_desc"),
            "image_size": img.get("image_size"),
            "warnings": warnings[:12],
            "errors": (img.get("errors") or [])[:12],
            "next_steps": steps,
        }

    return await _execute(kind="fw_esp_image_info", case_id=case.id, background=False, max_seconds=60.0, description=f"fw_esp_image_info {case.rel(src)}", fn=work)


@server.tool(
    description=(
        "ESP32 계열 앱 이미지를 ELF32 로 바꾼다(세그먼트마다 PT_LOAD + 영역 이름의 섹션, e_machine 94 Xtensa / 243 RISC-V, entry 유지, 심볼 없음). "
        "REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못하고, RISC-V(C3·C6·H2·P4 …)는 rea_compat=true 로 만든 ELF(e_flags 를 double-float ABI 로 표시 — "
        "부동소수점 인자 해석만 틀릴 수 있음)만 연다. partition=label 또는 offset. "
        "출력: extract/<output_label>-NNN/<name>.elf (firmware-image 아티팩트) + analysis/esp-to-elf-NNN.json. 응답의 elf_path_abs 를 REA 에 넘긴다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_esp_to_elf(case_id: str, path: str, offset: int | str | None = None, partition: str | None = None, output_label: str = "esp-app",
                        rea_compat: bool = False) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    label = safe_label(output_label, "esp-app")

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src, with_hash=False)
        rng = _esp_range(src, offset, None, partition, what="앱 이미지")
        data = _esp_read(src, rng)
        img = espfmt.parse_app_image(data, 0)
        if not img.get("ok") or not img.get("segments"):
            raise ValidationFailed("유효한 ESP 앱 이미지가 아닙니다: " + "; ".join((img.get("errors") or ["세그먼트 없음"])[:3]),
                                   hint="fw_esp_image_info 로 먼저 확인하세요(플래시 암호화면 바꿀 수 없다).")
        elf = _lib(espfmt.image_to_elf, data, img)
        _abs_segments(img, rng["start"])
        notes: list[str] = []
        if img.get("arch") == "riscv" and rea_compat:
            # REA 는 RISC-V ELF 중 double-float ABI 표시(e_flags 0x4)가 있는 것만 연다. ESP RISC-V 칩은 soft-float(C3·C6·H2…)
            # 또는 single-float(P4) 이므로 표시만 바꾼다 — 정수 코드 해석은 같고, 부동소수점 인자·반환값 해석만 틀릴 수 있다.
            elf = elf[:36] + struct.pack("<I", ELF_RISCV_REA_EFLAGS) + elf[40:]
            notes.append("rea_compat: e_flags 를 RVC|double-float(0x5)로 표시했다(실제 칩 ABI 와 다름 — 부동소수점 인자·반환값 해석은 틀릴 수 있다)")
        elif img.get("arch") == "xtensa":
            notes.append("REA 는 Xtensa ELF(ESP32·S2·S3)를 열지 못한다(지원 아키텍처 아님) — 디컴파일 없이 문자열·패턴·표 도구와 세이브 비교로 분석한다")
        elif img.get("arch") == "riscv":
            notes.append("REA 는 이 RISC-V ELF(soft/single-float 표시)를 열지 않는다 — REA 로 디컴파일하려면 rea_compat=true 로 다시 만든다")
        out_dir = claim_numbered_dir(case.subdir("extract"), label)
        name = safe_name(((img.get("app_desc") or {}).get("project_name") or partition or "app"), "app") + ".elf"
        out = out_dir / name
        atomic_write_bytes(out, elf)
        art = case.register_artifact(out, kind="firmware-image", producer=PRODUCER, description=f"ESP 앱 이미지 → ELF ({img.get('chip')})",
                                     extra={"type": "esp-app-elf", "source": info["path"], "offset": rng["start_hex"], "chip": img.get("chip"),
                                            "e_machine": img.get("e_machine")})
        payload = base_payload("fw_esp_to_elf", case, schema="esp-to-elf", input_info=info,
                               params={"offset": rng["start"], "partition": partition, "output_label": label, "rea_compat": bool(rea_compat)})
        payload.update({"range": rng, "elf_path": art["path"], "elf_sha256": art.get("sha256"), "chip": img.get("chip"), "e_machine": img.get("e_machine"),
                        "entry": img.get("entry"), "segments": img.get("segments"), "notes": notes})
        rel = _write(case, "esp-to-elf", payload, f"fw_esp_to_elf {info['path']}@{rng['start_hex']} → {art['path']}")
        rt().audit({"event": "fwtriage_esp_to_elf", "input": info["path"], "offset": rng["start_hex"], "elf": art["path"], "result": rel}, case.id)
        return {
            "ok": True,
            "tool": "fw_esp_to_elf",
            "result_path": rel,
            "elf_path": art["path"],
            "elf_path_abs": str(out),
            "elf_sha256": art.get("sha256"),
            "chip": img.get("chip"),
            "arch": img.get("arch"),
            "e_machine": img.get("e_machine"),
            "entry": hexs(img.get("entry")),
            "segments": [_seg_brief(s, rng["start"]) for s in img.get("segments") or []][:32],
            "notes": notes,
            "next_steps": ([f"REA open_binary(path='{out}') → search_strings · xrefs · procedure_pseudo_code (심볼이 없어 함수 이름은 주소다)"]
                           if img.get("arch") == "riscv" and rea_compat else
                           ["fw_strings_hunt(patterns='game')·fw_find_seq_tables·fw_save_diff 로 분석한다(이 ELF 는 REA 로 열 수 없다)"]),
        }

    return await _execute(kind="fw_esp_to_elf", case_id=case.id, background=False, max_seconds=120.0, description=f"fw_esp_to_elf {case.rel(src)}", fn=work)


def _render_value(v: Any, *, full: bool) -> Any:
    """NVS 값 표시: 정수·문자열은 그대로, 바이트는 크기·sha256·hex(응답은 앞 64바이트, 결과 파일은 64 KiB 까지)."""
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        lim = 65536 if full else 64
        out: dict[str, Any] = {"size": len(b), "sha256": hashlib.sha256(b).hexdigest(), "hex": b[:lim].hex()}
        if len(b) > lim:
            out["hex_truncated"] = True
        return out
    return v


def _mask_item_value(case_id: str, value: Any) -> dict[str, Any]:
    """비밀로 보이는 NVS 값: 원문 대신 마스킹 + 케이스 솔트 다이제스트(응답·결과 파일 모두)."""
    raw = bytes(value) if isinstance(value, (bytes, bytearray)) else str(value)
    return {"masked": core_mask_secret(raw), "digest": rt().secret_digest(case_id, raw)}


def _as_raw(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if v is None or isinstance(v, (bool, int)):
        return b""
    return str(v).encode("utf-8", "surrogatepass")


def _secret_raws(entries: Any) -> list[bytes]:
    """비밀 항목의 원문 바이트(4바이트 이상) — 다른 키의 값(설정 blob 등)에 같은 비밀이 들어 있는지 찾는 데 쓴다."""
    out: set[bytes] = set()
    for it in entries or []:
        if it.get("secret") or espfmt.secret_hint(it.get("namespace"), it.get("key")):
            b = _as_raw(it.get("value"))
            if len(b) >= 4:
                out.add(b)
    return sorted(out, key=len, reverse=True)


def _is_secret(it: dict[str, Any], raws: list[bytes]) -> bool:
    """키 이름이 비밀로 보이거나, 값에 다른 비밀 항목의 원문이 들어 있으면 비밀로 다룬다."""
    if it.get("secret") or espfmt.secret_hint(it.get("namespace"), it.get("key")):
        return True
    b = _as_raw(it.get("value"))
    return bool(b) and any(r in b for r in raws)


def _public_value(case_id: str, it: dict[str, Any], raws: list[bytes], *, full: bool) -> tuple[bool, Any]:
    if _is_secret(it, raws):
        v = it.get("value")
        return True, (_mask_item_value(case_id, v) if v is not None else None)
    return False, _render_value(it.get("value"), full=full)


def _nvs_items_public(case_id: str, items: list[dict[str, Any]], raws: list[bytes], *, full: bool, base: int = 0) -> list[dict[str, Any]]:
    """NVS 항목 표시용 사본. offset 은 NVS 파티션 기준, offset_abs 는 입력 파일 기준(base = NVS 시작)."""
    out = []
    for it in items:
        d = {k: it.get(k) for k in ("namespace", "key", "type_name", "state", "live", "page", "entry", "span", "chunk_index", "size")}
        off = it.get("offset")
        d["offset"] = hexs(off)
        if isinstance(off, int):
            d["offset_abs"] = hexs(base + off)
        d["crc_ok"] = (it.get("crc") or {}).get("ok")
        if it.get("data_crc_ok") is not None:
            d["data_crc_ok"] = it.get("data_crc_ok")
        secret, d["value"] = _public_value(case_id, it, raws, full=full)
        if secret:
            d["secret"] = True
        out.append(d)
    return out


def _nvs_blobs_public(case_id: str, blobs: list[dict[str, Any]], raws: list[bytes], *, full: bool) -> list[dict[str, Any]]:
    out = []
    for b in blobs:
        d = {k: b.get(k) for k in ("namespace", "key", "size", "chunks", "complete")}
        secret, d["value"] = _public_value(case_id, b, raws, full=full)
        if secret:
            d["secret"] = True
        out.append(d)
    return out


def _abs_duplicates(dups: Any, base: int) -> list[Any]:
    """live 중복 목록의 항목 오프셋에 입력 파일 기준 오프셋(offset_abs)을 더한다(원본은 바꾸지 않음)."""
    out = []
    for dup in dups or []:
        if isinstance(dup, dict):
            dup = dict(dup)
            ents = []
            for e in dup.get("entries") or []:
                if isinstance(e, dict) and isinstance(e.get("offset"), int):
                    e = dict(e, offset_abs=hexs(base + e["offset"]))
                ents.append(e)
            if ents:
                dup["entries"] = ents
        out.append(dup)
    return out


@server.tool(
    description=(
        "ESP NVS 파티션 해석(4 KiB 페이지): 페이지 상태·seq·버전, 헤더·항목·데이터 CRC 유효 개수, 네임스페이스, 항목(namespace/key/type/값 — 정수, 문자열, "
        "blob v1·v2 를 이어 붙인 값), 최신(live) 여부와 지워진 이전 값(include_erased=true), 같은 키의 live 중복. "
        "비밀로 보이는 값(nvs.net80211 의 모든 값, 비밀번호·PIN·PSK·API 키·개인키·인증 토큰·자격증명 모양의 키, 그리고 그런 비밀의 원문을 담은 다른 값)은 "
        "응답과 결과 파일 모두 마스킹 + 케이스 솔트 다이제스트만 남긴다(키 이름 휴리스틱 — 평범한 이름에 숨긴 비밀은 못 가릴 수 있다). "
        "partition=label(전체 플래시 덤프) 또는 offset/length, NVS 파티션 파일이면 그대로(최대 1 MiB). export_blobs=true 면 비밀이 아닌 blob 을 "
        "extract/nvs-blobs-NNN/ 에 파일로 남긴다(fw_save_diff 로 비교). offset 은 NVS 기준, offset_abs 는 입력 파일 기준. "
        "결과: analysis/esp-nvs-NNN.json. CRC 규칙(nvs_crc32)은 실기 검증 전이다 — crc_summary 로 확인."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_esp_nvs(
    case_id: str,
    path: str,
    offset: int | str | None = None,
    length: int | str | None = None,
    partition: str | None = None,
    namespace: str | None = None,
    key: str | None = None,
    include_erased: bool = False,
    export_blobs: bool = False,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        rng = _esp_range(src, offset, length, partition, what="NVS")
        if rng["length"] > NVS_MAX_BYTES:
            raise ValidationFailed(f"NVS 입력이 너무 큽니다(한도 {NVS_MAX_BYTES >> 20} MiB).", hint="partition=<NVS 파티션 label> 로 NVS 파티션만 고르세요(fw_esp_partitions).")
        base = rng["start"]
        nvs = _lib(espfmt.parse_nvs, _esp_read(src, rng), include_erased=True, ctl=ctl)
        all_items = nvs.get("items") or []
        raws = _secret_raws(list(all_items) + list(nvs.get("blobs") or []))
        items = [it for it in all_items
                 if (namespace is None or it.get("namespace") == namespace) and (key is None or it.get("key") == key)]
        shown = [it for it in items if include_erased or it.get("live")]
        blobs = [b for b in nvs.get("blobs") or [] if (namespace is None or b.get("namespace") == namespace) and (key is None or b.get("key") == key)]
        exported: list[str] = []
        renamed: list[str] = []
        if export_blobs:
            todo = [b for b in blobs if b.get("value") and not _is_secret(b, raws)]
            todo += [it for it in items if it.get("live") and it.get("type_name") == "BLOB" and isinstance(it.get("value"), (bytes, bytearray))
                     and not _is_secret(it, raws)]
            if todo:
                out_dir = claim_numbered_dir(case.subdir("extract"), "nvs-blobs")
                for b in todo:
                    stem = f"{safe_name(str(b.get('namespace')), 'ns')}.{safe_name(str(b.get('key')), 'key')}"
                    p = out_dir / f"{stem}.bin"
                    n = 2
                    while p.exists() or p.is_symlink():  # 정리한 이름이 겹치면 번호를 붙인다(덮어쓰지 않음)
                        p = out_dir / f"{stem}-{n}.bin"
                        n += 1
                    if n > 2:
                        renamed.append(f"{b.get('namespace')}/{b.get('key')} → {p.name}")
                    atomic_write_bytes(p, bytes(b["value"]))
                    a = case.register_artifact(p, kind="other", producer=PRODUCER, description=f"NVS blob {b.get('namespace')}/{b.get('key')}",
                                               extra={"type": "nvs-blob", "source": info["path"], "range": rng["start_hex"],
                                                      "namespace": b.get("namespace"), "key": b.get("key")})
                    exported.append(a["path"])
        payload = base_payload("fw_esp_nvs", case, schema="esp-nvs", input_info=info,
                               params={"range": rng, "namespace": namespace, "key": key, "include_erased": include_erased, "export_blobs": export_blobs})
        payload.update({k: nvs.get(k) for k in ("page_size", "pages", "namespaces", "crc_summary", "crc_convention", "versions_seen", "warnings", "errors", "truncated")})
        payload.update({"range": rng, "items": _nvs_items_public(case.id, items, raws, full=True, base=base),
                        "blobs": _nvs_blobs_public(case.id, blobs, raws, full=True), "duplicates": _abs_duplicates(nvs.get("duplicates"), base),
                        "exported_blobs": exported, "renamed_blobs": renamed})
        rel = _write(case, "esp-nvs", payload, f"fw_esp_nvs {info['path']}@{rng['start_hex']}")
        crc = nvs.get("crc_summary") or {}
        rt().audit({"event": "fwtriage_esp_nvs", "input": info["path"], "range": rng["start_hex"], "result": rel, "items": len(items),
                    "secrets_masked": sum(1 for it in items if _is_secret(it, raws))}, case.id)
        warnings = list(nvs.get("warnings") or [])
        ent = crc.get("entry") or {}
        if ent.get("bad") and not ent.get("ok"):
            warnings.insert(0, "항목 CRC 가 하나도 맞지 않습니다 — NVS CRC 규칙(nvs_crc32)이 이 이미지와 다를 수 있습니다(실기 검증 전). 값은 참고만 하고, 패치는 거부됩니다.")
        elif ent.get("bad"):
            warnings.insert(0, f"항목 CRC 불일치 {ent.get('bad')}개 (손상·기록 중단 가능 — 해당 항목은 기기가 무시할 수 있다)")
        if rng.get("partition") and rng["partition"].get("write_class") not in (None, "nvs"):
            warnings.append(f"파티션 '{partition}' 은 NVS 가 아니다(write_class={rng['partition'].get('write_class')})")
        if renamed:
            warnings.append(f"정리한 blob 파일 이름이 겹쳐 번호를 붙였다: {', '.join(renamed[:5])}")
        steps = []
        save_keys = sorted({f"{it.get('namespace')}/{it.get('key')}" for it in items
                            if it.get("live") and not _is_secret(it, raws) and _SAVE_KEY_RE.search(str(it.get("key") or ""))})
        if save_keys:
            steps.append("세이브로 보이는 키: " + ", ".join(save_keys[:10]) + " → 점수·진행이 바뀔 때마다 덤프(≥3회) 후 fw_save_diff(paths=[…], mode='nvs', observations=[…])")
        if nvs.get("duplicates"):
            steps.append("같은 키의 live 항목이 여럿이다(기록 중단 흔적) — 기기는 최신 하나만 쓴다. 이 키는 패치 대상에서 빠진다")
        public, tr = compact_list(_nvs_items_public(case.id, shown, raws, full=False, base=base), mr)
        return {
            "ok": True,
            "tool": "fw_esp_nvs",
            "result_path": rel,
            "input": info,
            "range": rng,
            "pages": [{k: p.get(k) for k in ("index", "state_name", "seq", "version", "written", "erased")} | {"header_crc_ok": (p.get("header_crc") or {}).get("ok")}
                      for p in (nvs.get("pages") or [])][:64],
            "namespaces": nvs.get("namespaces"),
            "crc_summary": crc,
            "crc_convention": nvs.get("crc_convention"),
            "items": public,
            "items_total": len(shown),
            "truncated": tr or bool(nvs.get("truncated")),
            "blobs": _nvs_blobs_public(case.id, blobs, raws, full=False)[:20],
            "duplicates": _abs_duplicates(nvs.get("duplicates"), base)[:20],
            "exported_blobs": exported[:50],
            "warnings": warnings[:12],
            "errors": (nvs.get("errors") or [])[:12],
            "next_steps": steps,
        }

    return await _execute(kind="fw_esp_nvs", case_id=case.id, background=False, max_seconds=120.0, description=f"fw_esp_nvs {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# 세이브 비교·체크섬·치트 입력 표 (fw_save_diff, fw_checksum_find, fw_find_seq_tables)
# ---------------------------------------------------------------------------


def _snapshot_sources(case: Any, paths: Any) -> list[Path]:
    """스냅샷 파일 경로 확인(시간 순서, 케이스 안의 일반 파일)."""
    if not isinstance(paths, list) or not SNAPSHOT_MIN <= len(paths) <= SNAPSHOT_MAX:
        raise ValidationFailed(f"paths 는 스냅샷 파일 {SNAPSHOT_MIN}~{SNAPSHOT_MAX}개의 목록이어야 합니다(시간 순서).")
    return [resolve_input_file(case, str(p)) for p in paths]


def _snapshots(case: Any, srcs: list[Path], offset: Any, length: Any, partition: str | None, *, max_total: int) -> tuple[list[dict[str, Any]], list[bytes], dict[str, Any]]:
    """스냅샷 파일들의 같은 범위를 읽는다(합계 max_total 바이트까지). 반환: (파일 정보, 바이트, 범위)."""
    infos, blobs = [], []
    rng0: dict[str, Any] | None = None
    total = 0
    for src in srcs:
        rng = _esp_range(src, offset, length, partition, what="스냅샷")
        total += rng["length"]
        if total > max_total:
            raise ValidationFailed(f"스냅샷 합계가 너무 큽니다(한도 {max_total >> 20} MiB).",
                                   hint="partition 이나 offset/length 로 세이브 영역만 고르거나(예: NVS 파티션) 스냅샷 수를 줄이세요.")
        if rng0 is None:
            rng0 = rng
        elif (rng["start"], (rng.get("partition") or {}).get("size")) != (rng0["start"], (rng0.get("partition") or {}).get("size")):
            raise ValidationFailed("스냅샷마다 파티션 위치가 다릅니다 — 같은 기기·같은 레이아웃의 덤프만 비교한다.")
        infos.append(file_info(case, src))
        blobs.append(_esp_read(src, rng))
    assert rng0 is not None
    return infos, blobs, rng0


def _labels(labels: Any, n: int) -> list[str]:
    if labels is None:
        return [f"s{i + 1}" for i in range(n)]
    if not isinstance(labels, list) or len(labels) != n:
        raise ValidationFailed("labels 는 paths 와 같은 길이의 목록이어야 합니다.")
    return [clip(str(x), 40) for x in labels]


def _check_observations(observations: Any, n: int) -> list[dict[str, Any]] | None:
    if observations is None:
        return None
    if not isinstance(observations, list) or not observations:
        raise ValidationFailed("observations 는 [{label, values}] 목록입니다(values 는 스냅샷마다 하나, 모르면 null).")
    out = []
    for o in observations[:8]:
        if not isinstance(o, dict) or not isinstance(o.get("values"), list) or len(o["values"]) != n:
            raise ValidationFailed("observations[].values 는 스냅샷 수와 같은 길이여야 합니다.")
        vals = []
        for v in o["values"]:
            if v is None:
                vals.append(None)
            elif isinstance(v, bool) or not isinstance(v, (int, str)):
                raise ValidationFailed("observations 값은 정수(또는 숫자 문자열)나 null 입니다.")
            elif isinstance(v, int):
                vals.append(v)
            else:
                try:
                    vals.append(int(v.strip(), 0))  # 음수·16진('0x…') 허용
                except ValueError:
                    raise ValidationFailed(f"observations 값을 정수로 읽을 수 없습니다: {v!r}") from None
        out.append({"label": clip(str(o.get("label") or "value"), 40), "values": vals})
    return out


_NVS_LIVE_STATES = (0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8)


def _looks_like_nvs(blob: bytes) -> bool:
    """NVS 페이지 형식인지: 어느 페이지든 상태가 active/full/freeing 이고 헤더 CRC 가 맞거나(싸다),
    작은 입력이면 네임스페이스가 해석되는지(CRC 규칙이 다른 기기 대비). 지운 페이지가 맨 앞이어도 찾는다."""
    P = espfmt.NVS_PAGE_SIZE
    if len(blob) < P or len(blob) % P:
        return False
    live = [o for o in range(0, len(blob), P) if struct.unpack_from("<I", blob, o)[0] in _NVS_LIVE_STATES]
    if not live:
        return False
    for o in live[:4096]:
        if struct.unpack_from("<I", blob, o + 28)[0] == espfmt.nvs_crc32(blob[o + 4:o + 28]):
            return True
    return len(blob) <= NVS_MAX_BYTES and bool(espfmt.parse_nvs(blob, include_erased=False).get("namespaces"))


def _nvs_reason(src0: Path, rng: dict[str, Any], blobs: list[bytes]) -> tuple[str, str] | None:
    """범위가 NVS 를 담고 있으면 (이유, 종류). 바이트 비교·체크섬 찾기는 NVS 의 비밀값(Wi-Fi 비밀번호 등)을 가리지 못하므로 막는 데 쓴다.

    종류: 'partition'(NVS 파티션을 골랐다), 'overlap'(범위가 NVS 파티션과 겹치지만 그 파티션만은 아니다 — 전체 플래시 등),
    'format'(표 없이 스냅샷 자체가 NVS 페이지 형식). nvs 모드로 바꿔도 되는 것은 partition·format 뿐이다."""
    part = rng.get("partition") or {}
    if part:
        if part.get("write_class") == "nvs" or part.get("subtype_name") in ("nvs", "nvs_keys"):
            return f"파티션 '{part.get('label')}' 은 NVS 다", "partition"
        return None
    table = _esp_table(src0, src0.stat().st_size)
    if table.get("found"):
        s0, e0 = rng["start"], rng["start"] + rng["length"]
        for ent in table.get("entries") or []:
            if ent.get("write_class") == "nvs" or ent.get("subtype_name") in ("nvs", "nvs_keys"):
                o, z = int(ent.get("offset") or 0), int(ent.get("size") or 0)
                if o < e0 and s0 < o + z:
                    return f"범위가 NVS 파티션 '{ent.get('label')}'({hexs(o)}) 과 겹친다", "overlap"
    if any(_looks_like_nvs(b) for b in blobs):
        return "스냅샷이 NVS 페이지 형식이다", "format"
    return None


def _nvs_diff_public(case_id: str, entries: Any, raws: list[bytes]) -> list[dict[str, Any]]:
    """nvs_item_diff 의 changed/added/removed 표시용 사본 — 비밀 값은 마스킹 + 다이제스트."""
    out = []
    for c in entries or []:
        d = {k: c.get(k) for k in ("namespace", "key", "type_name")}
        vals = c.get("values") or []
        if c.get("secret") or espfmt.secret_hint(c.get("namespace"), c.get("key")) or any(_is_secret({"value": v}, raws) for v in vals):
            d["secret"] = True
            d["values"] = [None if v is None else _mask_item_value(case_id, v) for v in vals]
        else:
            d["values"] = [_render_value(v, full=True) for v in vals]
        out.append(d)
    return out


@server.tool(
    description=(
        "세이브 스냅샷 비교(시간 순서 2~16개 — 점수·진행이 바뀔 때마다 덤프): mode='bytes' 는 바뀐 바이트 범위와 인코딩 해석(u8/u16/u32 LE·BE, BCD)·추세, "
        "mode='nvs' 는 NVS 키 단위 변화(changed·added·removed — 비밀 값은 마스킹), auto 는 NVS 파티션·NVS 형식이면 nvs. "
        "바이트 비교는 비밀값을 가리지 못하므로 NVS 를 담은 범위(NVS 파티션과 겹치거나 NVS 형식)는 bytes 로 비교하지 않는다(validation_failed). "
        "observations=[{label, values}] 로 스냅샷마다 화면에서 본 값(예: 점수, 음수 가능)을 주면 그 값과 정확히 같은 위치·인코딩(또는 NVS 키)을 찾는다. "
        "범위는 partition=label 또는 offset/length(모든 스냅샷에 같게). 결과는 후보다 — fw_checksum_find·디컴파일로 확인한다. 결과: analysis/save-diff-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_save_diff(
    case_id: str,
    paths: list[str],
    labels: list[str] | None = None,
    offset: int | str | None = None,
    length: int | str | None = None,
    partition: str | None = None,
    mode: str = "auto",
    observations: list[dict[str, Any]] | None = None,
    merge_gap: int = 0,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> dict[str, Any]:
    case = rt().case(case_id)
    if mode not in ("auto", "bytes", "nvs"):
        raise ValidationFailed("mode 는 auto | bytes | nvs 입니다.")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    gap = clamp_int(merge_gap, 0, 64, "merge_gap")
    srcs = _snapshot_sources(case, paths)

    def work(ctl: Ctl) -> dict[str, Any]:
        infos, blobs, rng = _snapshots(case, srcs, offset, length, partition, max_total=SAVE_DIFF_MAX_TOTAL)
        labs = _labels(labels, len(blobs))
        obs = _check_observations(observations, len(blobs))
        m = mode
        if m in ("auto", "bytes"):
            found = _nvs_reason(srcs[0], rng, blobs)
            if found:
                reason, kind = found
                whole = kind == "partition" or (kind == "format" and all(_looks_like_nvs(b) for b in blobs))
                if m == "auto" and whole:
                    m = "nvs"
                else:
                    raise ValidationFailed(f"바이트 비교는 NVS 의 비밀값(Wi-Fi 비밀번호·토큰 등)을 가리지 못해 거부합니다 — {reason}.",
                                           hint="NVS 는 partition=<NVS label> 과 mode='nvs' 로 비교하고, 다른 영역은 offset/length 로 NVS 를 빼고 비교하세요. "
                                                "blob 안의 값은 fw_esp_nvs(export_blobs=true) 로 내보낸 파일을 비교한다.")
            elif m == "auto":
                m = "bytes"
        base = rng["start"]
        payload = base_payload("fw_save_diff", case, schema="save-diff", input_info={"snapshots": infos},
                               params={"labels": labs, "range": rng, "mode": m, "observations": obs, "merge_gap": gap})
        resp: dict[str, Any] = {"ok": True, "tool": "fw_save_diff", "mode": m, "range": rng, "labels": labs,
                                "snapshots": [{"path": i["path"], "sha256": i.get("sha256")} for i in infos]}
        if m == "nvs":
            if any(len(b) > NVS_MAX_BYTES for b in blobs) or sum(len(b) for b in blobs) > NVS_DIFF_MAX_TOTAL:
                raise ValidationFailed(f"NVS 스냅샷이 너무 큽니다(스냅샷마다 {NVS_MAX_BYTES >> 20} MiB, 합계 {NVS_DIFF_MAX_TOTAL >> 20} MiB).",
                                       hint="partition=<NVS 파티션 label> 로 NVS 파티션만 고르세요.")
            parsed = [_lib(espfmt.parse_nvs, b, include_erased=True, ctl=ctl) for b in blobs]
            raws = _secret_raws([x for pn in parsed for x in list(pn.get("items") or []) + list(pn.get("blobs") or [])])
            diff = _lib(espfmt.nvs_item_diff, parsed, labs, ctl=ctl)
            changed = _nvs_diff_public(case.id, diff.get("changed"), raws)
            added = _nvs_diff_public(case.id, diff.get("added"), raws)
            removed = _nvs_diff_public(case.id, diff.get("removed"), raws)
            matches = []
            for o in obs or []:
                for c in changed + added + removed:  # 중간에 생긴(added)·사라진(removed) 키도 맞춰 본다 — 비밀이 아닌 정수 값만
                    vals = c.get("values") or []
                    if c.get("secret") or not all(isinstance(v, int) or v is None for v in vals):
                        continue
                    known = [(v, w) for v, w in zip(vals, o["values"]) if w is not None and v is not None]
                    if len(known) >= 2 and len({w for _, w in known}) > 1 and all(v == w for v, w in known):
                        matches.append({"label": o["label"], "namespace": c.get("namespace"), "key": c.get("key"), "type_name": c.get("type_name")})
            crc_bad = sum(((pn.get("crc_summary") or {}).get("entry") or {}).get("bad", 0) for pn in parsed)
            payload.update({"changed": changed, "added": added, "removed": removed, "unchanged_count": diff.get("unchanged_count"),
                            "observation_matches": matches, "crc_bad_entries": crc_bad})
            items, tr = compact_list(changed, mr)
            resp.update({"changed": items, "changed_total": len(changed), "truncated": tr or any(pn.get("truncated") for pn in parsed),
                         "added": added[:20], "removed": removed[:20], "unchanged_count": diff.get("unchanged_count"), "observation_matches": matches[:20]})
            if crc_bad:
                resp["warnings"] = [f"스냅샷의 NVS 항목 CRC 불일치 {crc_bad}개 — fw_esp_nvs 의 crc_summary 확인"]
        else:
            diff = _lib(saves.diff_snapshots, blobs, labels=labs, merge_gap=gap, ctl=ctl)
            for r_ in diff.get("ranges") or []:
                r_["offset_abs"] = hexs(base + int(r_["offset"]))
                for it in r_.get("interpretations") or []:
                    if isinstance(it.get("offset"), int):
                        it["offset_abs"] = hexs(base + it["offset"])
            om = _lib(saves.match_observations, blobs, obs, ctl=ctl) if obs else None
            if om:
                for x in om.get("matches") or []:
                    x["offset_abs"] = hexs(base + int(x["offset"]))
            payload.update({"diff": diff, "observations": om})
            items, tr = compact_list(diff.get("ranges") or [], mr)
            resp.update({"changed_bytes": diff.get("changed_bytes"), "ranges": items, "ranges_total": diff.get("ranges_total", len(diff.get("ranges") or [])),
                         "truncated": tr or bool(diff.get("truncated")), "observation_matches": (om or {}).get("matches", [])[:50],
                         "warnings": (diff.get("warnings") or [])[:12] + ((om or {}).get("warnings") or [])[:6]})
        rel = _write(case, "save-diff", payload, f"fw_save_diff {len(blobs)} snapshots ({m})")
        rt().audit({"event": "fwtriage_save_diff", "snapshots": [i["path"] for i in infos], "mode": m, "result": rel}, case.id)
        resp["result_path"] = rel
        steps = []
        if resp.get("observation_matches"):
            steps.append("관찰값과 맞는 위치를 찾았다 → 그 범위로 fw_checksum_find(paths=같은 스냅샷) 로 보호 체크섬을 찾고, REA 에서 그 주소를 읽고 쓰는 코드(xrefs)를 확인")
        elif m == "bytes":
            steps.append("observations 에 스냅샷마다 화면의 값(점수 등)을 주면 정확한 위치를 좁힐 수 있다")
        resp["next_steps"] = steps
        return resp

    return await _execute(kind="fw_save_diff", case_id=case.id, background=False, max_seconds=120.0, description="fw_save_diff", fn=work)


@server.tool(
    description=(
        "세이브 체크섬 찾기: 시간 순서 스냅샷(2~16개, 3개 이상 권장)에서 '저장값 = 알고리즘(데이터 범위)' 이 모든 스냅샷에 맞는 (알고리즘, 엔디언, 위치, 범위) 후보. "
        "알고리즘: sum8/16/32, xor8, negsum8, crc8(-maxim), crc16(ccitt-false/xmodem/modbus/arc), crc32, adler32, fletcher16. "
        "위치 후보는 스냅샷 사이에 바뀐 바이트에서만 고른다. 시험한 후보 수와 기대 오탐 수(expected_false_positives)를 함께 준다 — 8비트·스냅샷 2개 결과는 약하다(weak). "
        "범위는 partition=label 또는 offset/length(합계 8 MiB 까지). NVS 를 담은 범위는 거부한다(NVS 는 자체 CRC — fw_esp_nvs). "
        "결과: analysis/checksum-find-NNN.json (위치·범위는 파일 기준 절대 오프셋)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_checksum_find(
    case_id: str,
    paths: list[str],
    offset: int | str | None = None,
    length: int | str | None = None,
    partition: str | None = None,
    algorithms: list[str] | None = None,
    max_results: int = 20,
    max_seconds: float = 120.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    if algorithms is not None:
        bad = [a for a in algorithms if a not in saves.CHECKSUM_ALGORITHMS]
        if bad:
            raise ValidationFailed(f"모르는 알고리즘: {bad}", hint=f"허용: {', '.join(saves.CHECKSUM_ALGORITHMS)}")
    mr = clamp_int(max_results, 1, 200, "max_results")
    secs = _seconds(max_seconds, 120.0)
    srcs = _snapshot_sources(case, paths)

    def work(ctl: Ctl) -> dict[str, Any]:
        infos, blobs, rng = _snapshots(case, srcs, offset, length, partition, max_total=CHECKSUM_MAX_TOTAL)
        found = _nvs_reason(srcs[0], rng, blobs)
        if found:
            raise ValidationFailed(f"NVS 를 담은 범위에는 체크섬 찾기를 쓰지 않습니다 — {found[0]}. NVS 는 자체 CRC 로 보호되고, 후보의 저장값(CRC)이 비밀값의 단서가 될 수 있다.",
                                   hint="NVS 는 fw_esp_nvs 의 crc_summary 를 보고, blob 안의 체크섬은 fw_esp_nvs(export_blobs=true) 로 내보낸 파일로 찾는다.")
        res = _lib(saves.find_checksums, blobs, algorithms=algorithms, max_results=mr, ctl=ctl)
        base = rng["start"]
        for c in res.get("candidates") or []:
            c["location_abs"] = hexs(base + int(c["location"]))
            s, e = c.get("range") or [0, 0]
            c["range_abs"] = [hexs(base + int(s)), hexs(base + int(e))]
            if c.get("other_ranges"):
                c["other_ranges_abs"] = [[hexs(base + int(a)), hexs(base + int(b))] for a, b in c["other_ranges"][:8]]
        payload = base_payload("fw_checksum_find", case, schema="checksum-find", input_info={"snapshots": infos},
                               params={"range": rng, "algorithms": algorithms, "max_results": mr})
        payload.update(res)
        rel = _write(case, "checksum-find", payload, f"fw_checksum_find {len(blobs)} snapshots")
        cands = res.get("candidates") or []
        rt().audit({"event": "fwtriage_checksum_find", "snapshots": [i["path"] for i in infos], "result": rel, "candidates": len(cands),
                    "strong": sum(1 for c in cands if c.get("strength") == "strong")}, case.id)
        steps = []
        if any(c.get("strength") == "strong" for c in cands):
            steps.append("강한 후보를 REA 에서 확인한다: 저장 루틴(nvs_set·flash write 근처)에서 같은 알고리즘·범위를 계산하는 코드")
        elif cands:
            steps.append("약한 후보뿐이다 — 값이 다른 스냅샷을 더 모으거나(3개 이상) 범위를 좁혀 다시 실행")
        else:
            steps.append("후보 없음 — 체크섬이 없거나(또는 HMAC·서명), 범위 밖이거나, 지원하지 않는 알고리즘. REA 에서 저장 루틴을 직접 본다")
        return {
            "ok": True,
            "tool": "fw_checksum_find",
            "result_path": rel,
            "range": rng,
            "snapshots": [i["path"] for i in infos],
            "tested": res.get("tested"),
            "bytes_hashed": res.get("bytes_hashed"),
            "candidates": cands[:mr],
            "truncated": res.get("truncated"),
            "notes": (res.get("notes") or [])[:10],
            "next_steps": steps,
        }

    return await _execute(kind="fw_checksum_find", case_id=case.id, background=background, max_seconds=secs, description="fw_checksum_find", fn=work)


@server.tool(
    description=(
        "치트 입력(버튼 시퀀스) 표 후보 찾기: 작은 알파벳(버튼 id 0–15 또는 비트마스크)의 u8/u16/u32 배열, 코나미형(AABBCDCDEF) 모양, 반복 구조 점수. "
        "ESP 앱 이미지(partition=label 또는 offset 이 앱 이미지)면 플래시 rodata·데이터 세그먼트를 각자의 load 주소로 훑고(address = 디컴파일러 주소), "
        "그 밖에는 범위를 base_addr 기준으로 훑는다. 결과는 후보다 — REA xrefs 로 그 주소를 비교하는 입력 루틴을 확인한다. 결과: analysis/seq-tables-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_find_seq_tables(
    case_id: str,
    path: str,
    offset: int | str | None = None,
    length: int | str | None = None,
    partition: str | None = None,
    base_addr: int | str | None = None,
    min_len: int = 6,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_seconds: float = 120.0,
    background: bool = False,
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = resolve_input_file(case, path)
    ml = clamp_int(min_len, 4, 32, "min_len")
    mr = clamp_int(max_results, 0, HARD_MAX_RESULTS, "max_results")
    ba = parse_int_arg(base_addr, "base_addr")
    secs = _seconds(max_seconds, 120.0)

    def work(ctl: Ctl) -> dict[str, Any]:
        info = file_info(case, src)
        rng = _esp_range(src, offset, length, partition, what="입력")
        if rng["length"] > SEQ_TABLES_MAX_BYTES:
            raise ValidationFailed(f"입력이 너무 큽니다(한도 {SEQ_TABLES_MAX_BYTES >> 20} MiB).", hint="partition 으로 앱 파티션을 고르거나 offset/length 로 좁히세요.")
        data = _esp_read(src, rng)
        scanned: list[dict[str, Any]] = []
        cands: list[dict[str, Any]] = []
        lib_truncated = False
        lib_notes: list[str] = []
        img = _lib(espfmt.parse_app_image, data, 0) if data[:1] == b"\xe9" else None
        if img and img.get("ok") and img.get("segments"):
            for s in img["segments"]:
                if s.get("kind") in _CODE_SEGMENT_KINDS:
                    continue  # 코드·패딩 세그먼트는 건너뛴다(rodata·데이터만)
                fo = int(s["file_offset"])
                seg = data[fo: fo + int(s["size"])]
                r_ = _lib(saves.find_seq_tables, seg, base_addr=int(s["load_addr"]), min_len=ml, max_results=max(mr, 50), ctl=ctl)
                for c in r_.get("candidates") or []:
                    c["segment"] = s.get("index")
                    c["file_offset"] = hexs(rng["start"] + fo + int(c["offset"]))
                cands.extend(r_.get("candidates") or [])
                lib_truncated = lib_truncated or bool(r_.get("truncated"))
                lib_notes.extend(r_.get("notes") or [])
                scanned.append({"segment": s.get("index"), "load_addr": hexs(s["load_addr"]), "size": s.get("size"), "region": s.get("region"), "kind": s.get("kind")})
            mode_ = "esp-app-segments"
        else:
            r_ = _lib(saves.find_seq_tables, data, base_addr=rng["start"] if ba is None else ba, min_len=ml, max_results=max(mr, 50), ctl=ctl)
            for c in r_.get("candidates") or []:
                c["file_offset"] = hexs(rng["start"] + int(c["offset"]))
            cands.extend(r_.get("candidates") or [])
            lib_truncated = bool(r_.get("truncated"))
            lib_notes.extend(r_.get("notes") or [])
            scanned.append({"range": [rng["start_hex"], rng["end_hex"]], "base_addr": hexs(rng["start"] if ba is None else ba)})
            mode_ = "raw"
        cands.sort(key=lambda c: -float(c.get("score") or 0))
        for c in cands:
            if isinstance(c.get("address"), int):
                c["address_hex"] = hexs(c["address"])
        payload = base_payload("fw_find_seq_tables", case, schema="seq-tables", input_info=info,
                               params={"range": rng, "base_addr": ba, "min_len": ml, "mode": mode_})
        payload.update({"mode": mode_, "scanned": scanned, "candidates": cands, "truncated": lib_truncated, "notes": lib_notes})
        rel = _write(case, "seq-tables", payload, f"fw_find_seq_tables {info['path']}")
        rt().audit({"event": "fwtriage_seq_tables", "input": info["path"], "result": rel, "candidates": len(cands)}, case.id)
        items, tr = compact_list(cands, mr)
        return {
            "ok": True,
            "tool": "fw_find_seq_tables",
            "result_path": rel,
            "input": info,
            "mode": mode_,
            "scanned": scanned[:32],
            "candidates": items,
            "candidates_total": len(cands),
            "truncated": tr or lib_truncated,
            "notes": lib_notes[:10],
            "next_steps": ["상위 후보 주소를 REA xrefs 로 따라가 입력 비교 루틴인지 확인한다(코나미형이면 우선). 확인 전에는 '후보'로만 기록한다"] if cands else [],
        }

    return await _execute(kind="fw_find_seq_tables", case_id=case.id, background=background, max_seconds=secs, description=f"fw_find_seq_tables {case.rel(src)}", fn=work)


# ---------------------------------------------------------------------------
# 세이브 패치 (fw_patch_build, fw_verify_writeback) — 기기에는 사람이 쓰고, PWEH 는 패치를 만들고 쓴 결과를 확인한다
# docs/design/game-console-flipper-rf.md §3.5, master-prompt §1 규칙 3 의 예외(사용자가 명시적으로 원함 + 검증된 새 백업)
# ---------------------------------------------------------------------------

#: provenance 의 칩 이름 → esptool --chip 값. 이 밖의 칩은 쓰기 명령을 만들지 않는다.
_ESPTOOL_CHIPS = {"ESP32": "esp32", "ESP32-S2": "esp32s2", "ESP32-S3": "esp32s3", "ESP32-C3": "esp32c3", "ESP32-C2": "esp32c2",
                  "ESP32-C6": "esp32c6", "ESP32-H2": "esp32h2", "ESP32-P4": "esp32p4", "ESP32-C5": "esp32c5", "ESP32-C61": "esp32c61"}
_WIN_PORT_RE = re.compile(r"^COM[1-9][0-9]{0,3}$")
_LINUX_PORT_RE = re.compile(r"^/dev/(?:tty(?:ACM|USB)[0-9]{1,3}|serial/by-id/[A-Za-z0-9._:+-]{1,200})$")
PATCH_TARGET_TYPES = ("nvs", "raw-region")
PATCH_PURPOSES = ("score", "progress", "in-device-unlock")
PATCH_UNLOCK_SOURCES = ("in-device", "owned-tag")
PATCH_ONLINE = ("no", "unknown")
PATCH_MAX_EDITS = 16
#: 케이스당 patches/ 의 패치 파일 상한(같은 패치는 다시 쓰지 않고 재사용한다)
PATCH_MAX_FILES = 64
#: 사람 증명 요약의 최대 길이 — 넘으면 자르지 않고 거부한다(사람이 보는 변경 목록이 잘리지 않게)
PATCH_SUMMARY_MAX = 2000
#: 쓰기 전 사람 증명의 유효 시간(초) — 네트워크 차단·재부팅 없음은 시간이 지나면 의미가 없다
PATCH_ATTEST_VALID_S = 1800
PATCH_QUESTIONS: tuple[dict[str, Any], ...] = (
    {"id": "offline", "type": "yesno", "expected": "yes",
     "text": "기기의 네트워크(Wi-Fi·앱 연동)를 끊었고, 쓰기와 확인이 끝날 때까지 다시 연결하지 않는다"},
    {"id": "no_reboot", "type": "yesno", "expected": "yes",
     "text": "백업을 읽은 뒤 기기를 끄거나 재부팅·리셋하지 않았다(USB 케이블도 그대로다)"},
    {"id": "want_change", "type": "yesno", "expected": "yes",
     "text": "요약에 적힌 값 변경을 내가 직접 원하며, 결과를 온라인 순위·계정에 올리지 않는다"},
    {"id": "not_sold", "type": "yesno", "expected": "yes",
     "text": "바꾸는 값은 기기 안의 조건(점수·진행·내 태그)으로 여는 것이며, 따로 파는 토큰·DLC·온라인 구매로 여는 콘텐츠가 아니다"},
)


def _chip_arg(chip: Any) -> str | None:
    m = re.match(r"\s*(ESP32(?:-[A-Z0-9]+)?)", str(chip or "").upper())
    return _ESPTOOL_CHIPS.get(m.group(1)) if m else None


def _dump_record(case: Any, path: str, what: str) -> tuple[dict[str, Any], bytes, str]:
    """이 케이스에서 기기로 두 번 읽어 일치한 덤프(출처 원장 device-read)의 (원장 항목, 바이트, 케이스 상대 경로).
    바이트는 한 번만 읽고 원장의 sha256 과 맞춰 본 뒤 그 바이트만 쓴다(확인과 사용 사이에 파일이 바뀌어도 영향 없음)."""
    p = resolve_input_file(case, path)
    rel = case.rel(p)
    if p.stat().st_size > ESP_MAX_BYTES:
        raise ValidationFailed(f"{what} 이 너무 큽니다.")
    v = rt().provenance.verify(case, rel)
    if not v.get("trusted") or v.get("kind") != "device-read":
        raise ValidationFailed(f"{what} 은 이 케이스에서 기기로 읽은 덤프여야 합니다 (출처 확인: {v.get('reason')}).",
                               hint="esp_read_flash_start(verify='double') 로 읽은 파일을 쓴다. 가져온 파일·고친 파일은 쓸 수 없다.")
    rec = v["record"]
    src = rec.get("source") or {}
    if src.get("verify") != "double-read" or src.get("match") is not True:
        raise ValidationFailed(f"{what} 은 두 번 읽어 sha256 이 같은 덤프여야 합니다 (verify={src.get('verify')}, match={src.get('match')}).",
                               hint="esp_read_flash_start 를 verify='double'(기본)로 다시 읽는다.")
    if not (rec.get("extra") or {}).get("job_id"):
        raise ValidationFailed(f"{what} 의 원장 기록에 덤프 작업(job) id 가 없습니다.", hint="esp_read_flash_start 로 읽은 덤프만 쓴다.")
    data = _pread_regular(p, 0, p.stat().st_size)
    if hashlib.sha256(data).hexdigest() != rec.get("sha256"):
        raise ValidationFailed(f"{what} 이 원장 기록 뒤에 바뀌었습니다.", hint="기기에서 다시 읽는다.")
    return rec, data, rel


def _dump_offset(rec: dict[str, Any]) -> int:
    off = (rec.get("extra") or {}).get("offset")
    return int(off) if isinstance(off, int) and off >= 0 else 0


def _check_patch_args(target: Any, edits: Any, purpose: str, unlock_source: str, online_capable: str) -> tuple[str, str, dict[str, Any] | None]:
    if not isinstance(target, dict) or target.get("type") not in PATCH_TARGET_TYPES or not isinstance(target.get("partition"), str) or not target["partition"]:
        raise ValidationFailed("target 은 {type: 'nvs'|'raw-region', partition: <파티션 label>} 입니다(raw-region 은 checksum 선택).")
    if purpose not in PATCH_PURPOSES:
        raise ValidationFailed(f"purpose 는 {', '.join(PATCH_PURPOSES)} 중 하나입니다.")
    if unlock_source not in PATCH_UNLOCK_SOURCES:
        raise ValidationFailed(f"unlock_source={unlock_source!r} 인 패치는 만들지 않습니다.",
                               hint="판매 토큰·온라인 구매로 여는 콘텐츠(sold-token·online-purchase)는 보고만 한다. 출처를 모르면(unknown) 먼저 확인한다(in-device·owned-tag 만).")
    if online_capable not in PATCH_ONLINE:
        raise ValidationFailed("온라인과 동기화되는 기기(online_capable='yes')의 값은 바꾸지 않습니다(결과가 순위·계정에 올라갈 수 있다).",
                               hint="online_capable 은 'no' 또는 'unknown' 이어야 한다.")
    if not isinstance(edits, list) or not 1 <= len(edits) <= PATCH_MAX_EDITS or not all(isinstance(e, dict) for e in edits):
        raise ValidationFailed(f"edits 는 1~{PATCH_MAX_EDITS}개의 객체 목록입니다.")
    checksum = target.get("checksum")
    if checksum is not None:
        if target["type"] != "raw-region" or not isinstance(checksum, dict):
            raise ValidationFailed("checksum 은 raw-region 대상에만 줄 수 있다(fw_checksum_find 후보 그대로).")
        if int(checksum.get("range_variants") or 1) > 1:
            raise ValidationFailed("이 체크섬 후보는 범위가 하나로 정해지지 않았다(range_variants > 1) — 다시 계산하면 틀릴 수 있어 패치하지 않는다.",
                                   hint="스냅샷을 더 모아 fw_checksum_find 로 범위를 좁힌다.")
    return target["type"], target["partition"], checksum


def _flash_encryption_evidence(case: Any, base_rec: dict[str, Any], table: dict[str, Any], ent: dict[str, Any]) -> dict[str, Any]:
    """플래시 암호화 근거. 원장의 esp_security_info 가 켜짐이면 거부. 모르면(원조 ESP32 등) 파티션 단위 근거로 판단하고 무엇을 썼는지 남긴다."""
    mac = str((base_rec.get("source") or {}).get("mac") or "").lower()
    if not mac:
        raise ValidationFailed("base 의 원장 기록에 기기 MAC 이 없습니다.")
    # 같은 기기(MAC)의 사실만 쓴다 — MAC 없는 사실이나 다른 기기의 사실은 근거가 아니다. 하나라도 켜짐이면 거부
    facts = [f for f in rt().provenance.facts(case, "esp-security-info") if str((f.get("source") or {}).get("mac") or "").lower() == mac]
    if any((f.get("data") or {}).get("flash_encryption") is True for f in facts):
        raise ValidationFailed("플래시 암호화가 켜진 기기(esp_security_info)에는 세이브 패치를 만들지 않습니다.", hint="우회하지 않고 보고한다.")
    fact = facts[-1] if facts else None
    fe = (fact.get("data") or {}).get("flash_encryption") if fact else None
    evidence: dict[str, Any] = {"esp_security_info": "flash_encryption=false" if fe is False else "미확인(원장에 없음 또는 미지원 칩)",
                                "fact_seq": (fact or {}).get("seq"), "partition_encrypted_flag": bool(ent.get("encrypted")),
                                "nvs_keys_present": bool(table.get("nvs_keys_present")), "table_md5": (table.get("md5") or {}).get("ok")}
    if fe is not True and fe is not False and not (table.get("md5") or {}).get("ok"):
        raise ValidationFailed("플래시 암호화 여부를 확인할 수 없습니다(esp_security_info 없음·미지원, 파티션 표 MD5 확인 불가).",
                               hint="esp_security_info 를 먼저 실행하거나(지원 칩), 파티션 표에 MD5 항목이 있는 덤프에서만 패치한다.")
    return evidence


def _geometry_problems(table: dict[str, Any], ent: dict[str, Any]) -> list[str]:
    """대상 파티션의 경계 문제(쓰기 명령이 파티션 밖을 쓰거나 지우게 되는 경우). 펌웨어의 파티션 표는 조작됐을 수 있다."""
    probs: list[str] = []
    off, size = int(ent.get("offset") or 0), int(ent.get("size") or 0)
    if size <= 0:
        probs.append("크기가 0 이다")
    if off % 0x1000 or size % 0x1000:
        probs.append(f"오프셋·크기가 4 KiB 섹터 경계가 아니다({hexs(off)}+{hexs(size)}) — esptool 은 섹터 단위로 지워 옆 파티션까지 지운다")
    tbl_end = int(table.get("offset") or espfmt.PARTITION_TABLE_DEFAULT_OFFSET) + 0x1000
    if off < tbl_end:
        probs.append(f"부트로더·파티션 표 영역(0x0–{hexs(tbl_end)})과 겹친다")
    for other in table.get("entries") or []:
        if other.get("index") == ent.get("index"):
            continue
        o, z = int(other.get("offset") or 0), int(other.get("size") or 0)
        if o < off + size and off < o + z:
            probs.append(f"파티션 '{display_text(other.get('label'), 40)}'({hexs(o)}+{hexs(z)}) 과 겹친다")
    if [e.get("label") for e in table.get("entries") or []].count(ent.get("label")) > 1:
        probs.append("같은 이름의 파티션이 여럿이다")
    md5 = table.get("md5") or {}
    if md5.get("present") and md5.get("ok") is False:
        probs.append("파티션 표 MD5 가 맞지 않는다")
    if table.get("errors"):
        probs.append("파티션 표 오류: " + display_text("; ".join(str(x) for x in table["errors"][:3]), 200))
    return probs


def _later_device_activity(case: Any, after_seq: int, job_id: Any, mac: str) -> list[dict[str, Any]]:
    """원장에서 after_seq 뒤에 같은 기기(MAC — 모르면 같은 기기로 본다)에 연결한 기록(device-read·device-fact, 그 job 제외).
    esp 도구는 연결할 때마다 칩을 리셋해 게임이 돌 수 있으므로, 백업 뒤에 이런 기록이 있으면 백업은 낡았다."""
    out = []
    for e in rt().provenance.entries(case):
        if int(e.get("seq") or 0) <= after_seq or e.get("kind") not in ("device-read", "device-fact"):
            continue
        if job_id and (e.get("extra") or {}).get("job_id") == job_id:
            continue
        if str((e.get("source") or {}).get("mac") or mac).lower() == mac:
            out.append({"seq": e.get("seq"), "kind": e.get("kind"), "tool": (e.get("source") or {}).get("tool"), "fact_kind": e.get("fact_kind")})
    return out


def _patch_prepare(case: Any, base_path: str, target: Any, edits: Any, purpose: str, unlock_source: str, online_capable: str,
                   backup_path: str | None, description: str | None) -> dict[str, Any]:
    """base 확인 → 파티션·암호화 근거 → 패치를 메모리에서 만든다(파일은 쓰지 않음). backup_path 가 있으면 백업도 확인한다."""
    ttype, label, checksum = _check_patch_args(target, edits, purpose, unlock_source, online_capable)
    base_rec, base, base_rel = _dump_record(case, base_path, "base")
    if _dump_offset(base_rec) != 0:
        raise ValidationFailed("base 는 플래시 처음(offset 0)부터 읽은 전체 덤프여야 합니다(파티션 표로 위치를 정한다).")
    table = _lib(espfmt.parse_partition_table, base, data_len=len(base))
    if not table.get("found"):
        raise ValidationFailed("base 에서 파티션 표를 찾지 못했습니다(플래시 암호화·옮긴 표·잘못 읽은 덤프).")
    ent = espfmt.find_partition(table, label)
    if ent is None:
        raise ValidationFailed(f"파티션 '{label}' 이 없습니다.", hint="있는 파티션: " + ", ".join(str(e.get("label")) for e in table.get("entries") or []))
    want = "nvs" if ttype == "nvs" else "raw-user-data"
    if ent.get("write_class") != want:
        raise ValidationFailed(f"파티션 '{label}' 은 {ttype} 패치 대상이 아닙니다(write_class={ent.get('write_class')}).")
    if ent.get("write_blockers"):
        raise ValidationFailed(f"파티션 '{label}' 에는 쓰지 않습니다: {'; '.join(ent['write_blockers'])}")
    geo = _geometry_problems(table, ent)
    if geo:
        raise ValidationFailed(f"파티션 '{display_text(label, 40)}' 의 경계를 믿을 수 없어 쓰지 않습니다: {'; '.join(geo)}")
    off, size = int(ent["offset"]), int(ent["size"])
    if off + size > len(base):
        raise ValidationFailed("base 덤프가 대상 파티션 끝까지 닿지 않습니다(잘린 덤프).")
    fe = _flash_encryption_evidence(case, base_rec, table, ent)
    region = base[off:off + size]
    shown: list[dict[str, Any]] = []
    if ttype == "nvs":
        nvs = _lib(espfmt.parse_nvs, region, include_erased=False)
        raws = _secret_raws(list(nvs.get("items") or []) + list(nvs.get("blobs") or []))
        live = {(it.get("namespace"), it.get("key")): it for it in nvs.get("items") or [] if it.get("live")}
        norm = []
        for e in edits:
            ns, key, val = e.get("namespace"), e.get("key"), e.get("value")
            if not isinstance(ns, str) or not isinstance(key, str) or isinstance(val, bool) or not isinstance(val, int):
                raise ValidationFailed("NVS edits 는 [{namespace, key, value: 정수}] 입니다(기존 정수 항목만).")
            it = live.get((ns, key))
            if it is not None and _is_secret(it, raws):
                raise ValidationFailed(f"비밀로 보이는 키는 바꾸지 않습니다: {ns}/{key}")
            norm.append({"namespace": ns, "key": key, "value": val})
        new_region, changes = _lib(espfmt.nvs_set_primitives, region, norm)
        shown = [{k: c.get(k) for k in ("namespace", "key", "type_name", "before", "after")} for c in changes]
    else:
        new_region, changes = _lib(saves.apply_raw_edits, region, edits, checksum=checksum)
        shown = [c for c in changes]
    if new_region == region:
        raise ValidationFailed("바뀌는 값이 없습니다(이미 그 값이다).")
    src_b = base_rec.get("source") or {}
    prep: dict[str, Any] = {
        "ttype": ttype, "label": label, "abs_offset": off, "size": size, "region_sha256": hashlib.sha256(region).hexdigest(),
        "patch": bytes(new_region), "patch_sha256": hashlib.sha256(new_region).hexdigest(), "changes": shown, "checksum": checksum,
        "base": {"path": base_rel, "sha256": base_rec.get("sha256"), "seq": base_rec.get("seq"), "job_id": (base_rec.get("extra") or {}).get("job_id")},
        "device": {"chip": src_b.get("chip"), "mac": src_b.get("mac")}, "evidence": fe,
        "purpose": purpose, "unlock_source": unlock_source, "online_capable": online_capable, "description": clip(description or "", 300) or None,
        "partition": {k: ent.get(k) for k in ("label", "type_name", "subtype_name", "offset", "size", "write_class")},
    }
    if backup_path is not None:
        prep["backup"] = _check_backup(case, backup_path, base_rec, prep, region)
    return prep


def _check_backup(case: Any, backup_path: str, base_rec: dict[str, Any], prep: dict[str, Any], region: bytes) -> dict[str, Any]:
    """쓰기 직전 백업: base 뒤에 다른 job 으로 새로 두 번 읽었고, 마지막 읽기 뒤 앱이 돌지 않았고(after=no-reset-stub),
    같은 기기(MAC)이고, 대상 범위를 덮으며 그 바이트가 base 와 같아야 한다. 쓰기 명령의 포트·칩은 이 백업의 기록에서 가져온다."""
    rec, data, rel = _dump_record(case, backup_path, "백업")
    ex, src = rec.get("extra") or {}, rec.get("source") or {}
    if int(rec.get("seq") or 0) <= int(base_rec.get("seq") or 0):
        raise ValidationFailed("백업은 base 보다 뒤에 새로 읽은 덤프여야 합니다.")
    if ex.get("job_id") == (base_rec.get("extra") or {}).get("job_id"):
        raise ValidationFailed("백업은 base 와 다른 덤프 작업(job)이어야 합니다(같은 덤프의 두 번째 읽기는 백업이 아니다).")
    job_reads = [e for e in rt().provenance.entries(case, "device-read") if (e.get("extra") or {}).get("job_id") == ex.get("job_id")]
    final = [e for e in job_reads if (e.get("extra") or {}).get("role") == "verification-read"]
    if not final or (final[-1].get("extra") or {}).get("after") != "no-reset-stub":
        raise ValidationFailed("백업의 마지막 읽기 뒤에 기기가 재부팅됐습니다(after≠no-reset-stub) — 그사이 게임이 세이브를 바꿨을 수 있다.",
                               hint="esp_read_flash_start(…, verify='double', after='no-reset') 로 백업을 다시 읽는다(칩이 다운로드 모드에 머문다).")
    mac_b, mac_k = (base_rec.get("source") or {}).get("mac"), src.get("mac")
    if not mac_b or not mac_k or str(mac_b).lower() != str(mac_k).lower():
        raise ValidationFailed(f"백업과 base 가 같은 기기인지 확인할 수 없습니다(MAC {mac_b} / {mac_k}).")
    b_off = _dump_offset(rec)
    off, size = prep["abs_offset"], prep["size"]
    if not (b_off <= off and b_off + len(data) >= off + size):
        raise ValidationFailed(f"백업이 대상 범위({hexs(off)}+{hexs(size)})를 덮지 않습니다.",
                               hint=f"esp_read_flash_start(offset='{hexs(off)}', size='{hexs(size)}', verify='double', after='no-reset')")
    if data[off - b_off: off - b_off + size] != region:
        raise ValidationFailed("백업의 대상 범위가 base 와 다릅니다 — 그사이 기기의 세이브가 바뀌었다.",
                               hint="플래시 전체(offset 0)를 다시 두 번 읽어 새 base 로 패치를 다시 만든다.")
    last_seq = max(int(e.get("seq") or 0) for e in job_reads)
    later = _later_device_activity(case, last_seq, ex.get("job_id"), str(mac_k).lower())
    if later:
        raise ValidationFailed(f"백업 뒤에 이 기기에 다시 연결했습니다(원장 seq {', '.join(str(x['seq']) for x in later[:5])}: "
                               f"{', '.join(str(x.get('fact_kind') or x.get('tool')) for x in later[:3])}) — 그 연결로 칩이 리셋돼 게임이 세이브를 바꿨을 수 있다.",
                               hint="esp_read_flash_start(…, verify='double', after='no-reset') 로 백업을 새로 읽고, 그 뒤에는 기기에 연결하지 않는다.")
    chip_arg = _chip_arg(src.get("chip"))
    if chip_arg is None:
        raise ValidationFailed(f"쓰기 명령을 만들 수 없는 칩입니다: {src.get('chip')!r}")
    backend, port = src.get("backend"), str(src.get("port") or "")
    if backend == "windows":
        if not _WIN_PORT_RE.match(port):
            raise ValidationFailed(f"Windows 포트 형식이 아닙니다: {port!r}")
    elif backend == "linux":
        if not _LINUX_PORT_RE.match(port):
            raise ValidationFailed(f"리눅스 포트 형식이 아닙니다: {port!r}")
    else:
        raise ValidationFailed(f"알 수 없는 esptool 백엔드: {backend!r}")
    return {"path": rel, "sha256": rec.get("sha256"), "seq": rec.get("seq"), "job_id": ex.get("job_id"), "offset": b_off, "last_seq": last_seq,
            "chip": src.get("chip"), "chip_arg": chip_arg, "backend": backend, "port": port, "mac": str(mac_k).lower()}


def _write_patch_file(case: Any, label: str, data: bytes) -> tuple[Path, bool]:
    """패치 파일을 patches/ 에 쓴다. 같은 내용(sha256)의 파일이 이미 있으면 그것을 쓴다(반복 호출로 파일이 늘지 않게). 반환: (경로, 재사용 여부)."""
    d = case.subdir("patches")
    sha = hashlib.sha256(data).hexdigest()
    existing = sorted(x for x in d.glob("*.bin") if x.is_file() and not x.is_symlink())
    for x in existing:
        if x.stat().st_size == len(data) and hashlib.sha256(_pread_regular(x, 0, len(data))).hexdigest() == sha:
            return x, True
    if len(existing) >= PATCH_MAX_FILES:
        raise ValidationFailed(f"patches/ 의 패치 파일이 {PATCH_MAX_FILES}개를 넘었습니다.", hint="사람이 쓰지 않을 패치 파일을 정리한 뒤 다시 만든다.")
    out = claim_numbered_file(d, f"{safe_name(label, 'part')}-patch", ".bin")
    atomic_write_bytes(out, data)
    return out, False


def _write_command(case: Any, patch_rel: str, sha: str, bk: dict[str, Any], abs_offset: int) -> str:
    """사람이 WSL(또는 리눅스) bash 터미널에서 실행할 쓰기 명령. 쓰기 전에 증명된 sha256 을 확인하고, 끝나면 칩을 다운로드 모드에 둔다
    (after=no-reset-stub — 읽기 확인 전에 게임이 세이브를 다시 쓰지 않게). 인자는 모두 검증·인용한다."""
    exe = '"$PWEH_ESPTOOL_WIN"' if bk["backend"] == "windows" else '"$PWEH_ESPTOOL"'
    target = f'"$(wslpath -w {shlex.quote(patch_rel)})"' if bk["backend"] == "windows" else shlex.quote(patch_rel)
    return (f"source {shlex.quote(str(tools_env()))} && cd {shlex.quote(str(case.dir))} && "
            f"echo {shlex.quote(f'{sha}  {patch_rel}')} | sha256sum -c - && "
            f"{exe} --chip {bk['chip_arg']} --port {bk['port']} --after no-reset-stub write-flash {hexs(abs_offset)} {target}")


def _patch_payload(case: Any, prep: dict[str, Any], **extra: Any) -> dict[str, Any]:
    payload = base_payload("fw_patch_build", case, schema="patch-build", input_info={"base": prep["base"]},
                           params={"target": {"type": prep["ttype"], "partition": prep["label"]}, "purpose": prep["purpose"],
                                   "unlock_source": prep["unlock_source"], "online_capable": prep["online_capable"]})
    payload.update({k: prep[k] for k in ("abs_offset", "size", "region_sha256", "patch_sha256", "changes", "checksum", "device", "evidence",
                                          "partition", "description") if k in prep})
    if prep.get("backup"):
        payload["backup"] = {k: prep["backup"][k] for k in ("path", "sha256", "seq", "job_id", "offset")}
    payload.update(extra)
    return payload


@server.tool(
    description=(
        "세이브 값 패치 이미지 만들기(소유 기기, 사용자가 명시적으로 원할 때만). base_path = 이 케이스에서 esp_read_flash_start 로 두 번 읽어 일치한 "
        "전체 플래시 덤프(offset 0). target = {type: 'nvs', partition} (기존 정수 NVS 항목, edits=[{namespace, key, value}]) 또는 "
        "{type: 'raw-region', partition, checksum?} (사용자 데이터 파티션, edits=[{offset(파티션 기준), encoding, value}], checksum 은 fw_checksum_find 후보). "
        "purpose: score|progress|in-device-unlock, unlock_source: in-device|owned-tag(판매 토큰·온라인 구매는 거부), online_capable: no|unknown('yes' 는 거부). "
        "거부: 파티션 encrypted 플래그·nvs_keys(NVS 암호화)·플래시 암호화 켜짐, NVS CRC 규칙이 이 이미지에서 재현되지 않음, live 중복 키, 비밀로 보이는 키. "
        "backup_path 없이 부르면 패치를 patches/ 에 만들고(stage=planned) 백업 절차를 알려 준다. "
        "backup_path(base 뒤 다른 job 으로 새로 읽은 이중 읽기, after='no-reset', 같은 MAC, 대상 범위가 base 와 같음, 그 뒤 이 기기에 다른 연결 없음)를 주면 "
        "사람 증명(네트워크 차단·재부팅 없음·변경 의사·판매 토큰 콘텐츠 아님, 30분 — 패치·백업·편집·선언에 묶임)을 받고, 패치 sha256 을 출처 원장(patch-plan)에 남긴 뒤 "
        "사람이 별도 터미널에서 실행할 쓰기 명령을 보여 준다(stage=ready). 파티션 경계를 믿을 수 없으면(섹터 경계 아님·겹침·이름 중복) 거부한다. "
        "에이전트는 그 명령을 실행하지 않는다. 쓴 뒤 다시 읽어 fw_verify_writeback 으로 확인한다. 결과: analysis/patch-build-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_patch_build(
    case_id: str,
    base_path: str,
    target: dict[str, Any],
    edits: list[dict[str, Any]],
    purpose: str,
    unlock_source: str,
    online_capable: str,
    ctx: Context,
    backup_path: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    case = rt().case(case_id, hardware=True)  # 기기에 쓸 명령을 다루므로 소유/허가 증명이 있는 케이스만
    prep = await anyio.to_thread.run_sync(lambda: _patch_prepare(case, base_path, target, edits, purpose, unlock_source, online_capable,
                                                                 backup_path, description))
    tgt = {"type": prep["ttype"], "partition": prep["label"], "abs_offset": hexs(prep["abs_offset"]), "size": prep["size"]}
    if "backup" not in prep:
        def plan_work() -> dict[str, Any]:
            out, _reused = _write_patch_file(case, prep["label"], prep["patch"])
            art = case.register_artifact(out, kind="other", producer=PRODUCER, description=f"세이브 패치(계획) {display_text(prep['label'], 40)}",
                                         extra={"type": "save-patch", "stage": "planned", "sha256": prep["patch_sha256"]})
            rel = _write(case, "patch-build", _patch_payload(case, prep, stage="planned", patch_path=art["path"]),
                         f"fw_patch_build planned {prep['label']}")
            rt().audit({"event": "fwtriage_patch_planned", "patch": art["path"], "sha256": prep["patch_sha256"], "target": tgt}, case.id)
            return {"rel": rel, "patch": art["path"]}
        done = await anyio.to_thread.run_sync(plan_work)
        backup_call = (f"esp_read_flash_start(case_id='{case.id}', port='<포트>', offset='{hexs(prep['abs_offset'])}', size='{hexs(prep['size'])}', "
                       f"verify='double', after='no-reset', output_name='{safe_name(prep['label'], 'part')}-backup')")
        return {
            "ok": True, "tool": "fw_patch_build", "stage": "planned", "result_path": done["rel"], "patch_path": done["patch"],
            "patch_sha256": prep["patch_sha256"], "target": tgt, "changes": prep["changes"], "evidence": prep["evidence"],
            "next_steps": [
                "[사람 작업 필요] 기기를 네트워크에서 끊는다(Wi-Fi 공유기 차단·앱 연동 해제). 기기는 USB 로 연결된 그대로 둔다.",
                f"백업(쓰기 직전 새로 읽기): {backup_call} — 끝나면 칩이 다운로드 모드에 머문다(재부팅하지 않는다).",
                "같은 인자 + backup_path=<백업 파일> 로 fw_patch_build 를 다시 부른다 → 사람 증명(pweh attest) → 쓰기 명령.",
                "쓰기는 사람이 별도 터미널에서 한다. 이 패치 파일은 아직 증명되지 않았다(쓰지 않는다).",
            ],
        }
    bk = prep["backup"]
    edit_lines = []
    for c in prep["changes"]:
        if not isinstance(c, dict):
            continue
        if "key" in c:
            edit_lines.append(f"{display_text(c.get('namespace'), 40)}/{display_text(c.get('key'), 40)}: {display_text(c.get('before'), 40)} → {display_text(c.get('after'), 40)}")
        elif "checksum" in c:
            ck = c.get("checksum") or {}
            edit_lines.append(f"체크섬 {display_text(ck.get('algorithm'), 30)} @ {hexs(ck.get('location'))}: {display_text(ck.get('before'), 30)} → {display_text(ck.get('after'), 30)}")
        elif "offset" in c:
            edit_lines.append(f"{hexs(c.get('offset'))} ({display_text(c.get('encoding'), 12)}): {display_text(c.get('before_value'), 40)} → {display_text(c.get('after_value'), 40)}")
    summary = (f"세이브 패치 쓰기 전 확인 — 파티션 '{display_text(prep['label'], 40)}' @ {hexs(prep['abs_offset'])} ({prep['size']} B), 기기 {prep['device']['mac']}. "
               f"목적 {prep['purpose']}, 해금 출처 {prep['unlock_source']}, 온라인 가능 {prep['online_capable']}. 백업 {bk['path']}. "
               f"변경 {len(edit_lines)}건: " + "; ".join(edit_lines))
    if len(summary) > PATCH_SUMMARY_MAX:
        raise ValidationFailed(f"변경 목록이 너무 길어 사람이 한 번에 확인할 수 없습니다({len(summary)}자).", hint="편집을 나눠 여러 번에 걸쳐 패치한다.")
    edits_digest = hashlib.sha256(json.dumps(prep["changes"], sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
    subject = {"chip": prep["device"]["chip"], "mac": str(prep["device"]["mac"]).lower(), "partition": safe_name(prep["label"], "part"),
               "abs_offset": prep["abs_offset"], "size": prep["size"], "patch_sha256": prep["patch_sha256"],
               "edits": len(edit_lines), "edits_sha256": edits_digest, "purpose": prep["purpose"], "unlock_source": prep["unlock_source"],
               "online_capable": prep["online_capable"], "backup": {"sha256": bk["sha256"], "seq": bk["seq"], "job_id": bk["job_id"]}}
    dec = await rt().attest("console-offline", subject, {"scope": "case", "case_id": case.id}, list(PATCH_QUESTIONS), case.id, ctx, summary,
                            tool="fw_patch_build", valid_seconds=PATCH_ATTEST_VALID_S)
    if not dec.satisfied:
        return attestation_response(dec, tool="fw_patch_build", stage="awaiting-attestation", target=tgt, patch_sha256=prep["patch_sha256"],
                                    changes=prep["changes"])

    def ready_work() -> dict[str, Any]:
        # 증명을 기다리는 동안 다른 호출이 기기에 연결했을 수 있다 — 기록 직전에 다시 확인한다
        later = _later_device_activity(case, int(bk["last_seq"]), bk["job_id"], bk["mac"])
        if later:
            raise ValidationFailed("증명을 기다리는 동안 이 기기에 다시 연결했습니다(원장 seq " + ", ".join(str(x["seq"]) for x in later[:5]) + ") — 백업이 낡았다.",
                                   hint="백업을 새로 읽고 다시 시작한다.")
        out, _reused = _write_patch_file(case, prep["label"], prep["patch"])
        patch_rel = case.rel(out)
        source = {"server": SERVER_NAME, "tool": "fw_patch_build",
                  "base": {**prep["base"], "target_sha256": prep["region_sha256"]},
                  "backup": {k: bk[k] for k in ("path", "sha256", "seq", "job_id", "offset")},
                  "target": {"type": prep["ttype"], "label": prep["label"], "abs_offset": prep["abs_offset"], "size": prep["size"]},
                  "device": {"chip": bk["chip"], "mac": bk["mac"], "port": bk["port"], "backend": bk["backend"]}}
        extra = {"changes": prep["changes"], "purpose": prep["purpose"], "unlock_source": prep["unlock_source"],
                 "online_capable": prep["online_capable"], "evidence": prep["evidence"]}
        prior = rt().provenance.latest(case, KIND_PATCH_PLAN, patch_rel)
        if (prior and prior.get("sha256") == prep["patch_sha256"] and prior.get("attestation_id") == dec.attestation_id
                and ((prior.get("source") or {}).get("backup") or {}).get("seq") == bk["seq"]):
            entry = prior  # 같은 패치·백업·증명의 공개 기록이 이미 있다(반복 호출로 원장이 늘지 않게)
        else:
            entry = rt().provenance.record_patch_plan(case, patch_rel, source, extra, sha256=prep["patch_sha256"], attestation_id=dec.attestation_id)
        art = case.register_artifact(out, kind="other", producer=PRODUCER, description=f"세이브 패치(쓰기 준비) {display_text(prep['label'], 40)}",
                                     extra={"type": "save-patch", "stage": "ready", "sha256": prep["patch_sha256"], "ledger_seq": entry["seq"]})
        command = _write_command(case, patch_rel, prep["patch_sha256"], bk, prep["abs_offset"])
        rel = _write(case, "patch-build", _patch_payload(case, prep, stage="ready", patch_path=patch_rel, ledger_seq=entry["seq"],
                                                         attestation_id=dec.attestation_id, command=command), f"fw_patch_build ready {prep['label']}")
        rt().audit({"event": "fwtriage_patch_ready", "patch": patch_rel, "sha256": prep["patch_sha256"], "target": tgt, "ledger_seq": entry["seq"],
                    "attestation_id": dec.attestation_id, "command": command}, case.id)
        readback = (f"esp_read_flash_start(case_id='{case.id}', port='{bk['port']}', offset='{hexs(prep['abs_offset'])}', size='{hexs(prep['size'])}', "
                    f"verify='double', after='no-reset', output_name='{safe_name(prep['label'], 'part')}-readback')")
        return {
            "ok": True, "tool": "fw_patch_build", "stage": "ready", "result_path": rel, "patch_path": art["path"], "patch_sha256": prep["patch_sha256"],
            "ledger_seq": entry["seq"], "attestation_id": dec.attestation_id, "target": tgt, "changes": prep["changes"], "evidence": prep["evidence"],
            "command": command,
            "command_note": ("사람이 별도의 WSL(또는 리눅스) bash 터미널에서 직접 실행한다(PowerShell 아님). 에이전트는 이 명령을 실행하지 않는다. "
                             "명령은 먼저 패치 파일의 sha256 을 확인하고(다르면 쓰지 않음), 파티션 범위만 쓰며(erase·--force 없음), 끝나면 칩을 다운로드 모드에 둔다."),
            "next_steps": ["[사람 작업 필요] 위 명령을 별도 터미널에서 실행하고 결과를 알려 준다(기기는 재부팅하지 않는다).",
                           f"읽기 확인: {readback} → fw_verify_writeback(case_id='{case.id}', patch_path='{patch_rel}', readback_path=<읽은 파일>)",
                           "확인이 applied 면 사람이 RESET 으로 일반 부팅하고 오프라인 상태에서 화면으로 값을 확인한다(not-applied·differs 면 부팅하기 전에 사용자와 정한다)."],
        }

    return await anyio.to_thread.run_sync(ready_work)


@server.tool(
    description=(
        "세이브 패치를 쓴 결과 확인: patch_path = fw_patch_build(stage=ready) 가 출처 원장(patch-plan)에 남긴 패치, readback_path = 쓰기 명령 뒤 "
        "esp_read_flash_start 로 대상 범위를 두 번 읽은 덤프(같은 MAC, 원장에서 patch-plan 보다 뒤). 기대값은 원장의 sha256 만 쓴다(패치 파일·결과 파일은 "
        "증거가 아님). outcome: applied(패치와 같음) / not-applied(base 와 같음 — 쓰기가 안 됨) / differs(둘 다 아님 — 바뀐 바이트 수와 NVS 면 편집한 키의 값). "
        "결과: analysis/patch-verify-NNN.json."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def fw_verify_writeback(case_id: str, patch_path: str, readback_path: str) -> dict[str, Any]:
    case = rt().case(case_id)

    def work(ctl: Ctl) -> dict[str, Any]:
        patch_rel = case.rel(case.resolve_path(patch_path))
        plan = rt().provenance.latest(case, KIND_PATCH_PLAN, patch_rel)
        if plan is None:
            raise ValidationFailed(f"출처 원장에 공개된 패치 기록이 없습니다: {patch_rel}", hint="fw_patch_build(…, backup_path=…) 가 stage=ready 로 공개한 패치만 확인한다.")
        src = plan.get("source") or {}
        tgt = src.get("target") or {}
        abs_off, size = int(tgt.get("abs_offset") or 0), int(tgt.get("size") or 0)
        expected, base_sha = plan.get("sha256"), (src.get("base") or {}).get("target_sha256")
        rec, data, rb_rel = _dump_record(case, readback_path, "읽기 확인 덤프")
        if int(rec.get("seq") or 0) <= int(plan.get("seq") or 0):
            raise ValidationFailed("읽기 확인 덤프는 쓰기 명령을 공개한 뒤(원장의 patch-plan 다음)에 새로 읽은 것이어야 합니다.")
        mac_p, mac_r = (src.get("device") or {}).get("mac"), (rec.get("source") or {}).get("mac")
        if not mac_p or not mac_r or str(mac_p).lower() != str(mac_r).lower():
            raise ValidationFailed(f"읽기 확인 덤프가 같은 기기인지 확인할 수 없습니다(MAC {mac_p} / {mac_r}).")
        r_off = _dump_offset(rec)
        if not (r_off <= abs_off and r_off + len(data) >= abs_off + size):
            raise ValidationFailed(f"읽기 확인 덤프가 대상 범위({hexs(abs_off)}+{hexs(size)})를 덮지 않습니다.")
        got = data[abs_off - r_off: abs_off - r_off + size]
        got_sha = hashlib.sha256(got).hexdigest()
        outcome = "applied" if got_sha == expected else ("not-applied" if got_sha == base_sha else "differs")
        detail: dict[str, Any] = {}
        if outcome != "applied" and tgt.get("type") == "nvs":
            nvs = espfmt.parse_nvs(got, include_erased=False)
            live = {(it.get("namespace"), it.get("key")): it for it in nvs.get("items") or [] if it.get("live")}
            detail["edited_keys"] = [{"namespace": c.get("namespace"), "key": c.get("key"), "expected": c.get("after"),
                                      "actual": (live.get((c.get("namespace"), c.get("key"))) or {}).get("value"),
                                      "crc_ok": ((live.get((c.get("namespace"), c.get("key"))) or {}).get("crc") or {}).get("ok")}
                                     for c in (plan.get("extra") or {}).get("changes") or [] if isinstance(c, dict)]
        # 공개 뒤 ~ 읽기 확인 사이에 같은 기기에 연결한 기록(칩 리셋 → 게임이 세이브를 바꿨을 수 있음): 판정은 그대로, 경고만
        rb_job = (rec.get("extra") or {}).get("job_id")
        between = [x for x in _later_device_activity(case, int(plan.get("seq") or 0), rb_job, str(mac_p).lower()) if int(x.get("seq") or 0) < int(rec.get("seq") or 0)]
        warnings = []
        if between:
            warnings.append("쓰기 명령을 공개한 뒤 읽기 확인 전에 이 기기에 다시 연결한 기록이 있다(원장 seq " + ", ".join(str(x["seq"]) for x in between[:5])
                            + ") — 그 연결로 칩이 리셋돼 게임이 세이브를 바꿨거나, 사람이 쓰기 전에 기기 상태가 달라졌을 수 있다.")
        payload = base_payload("fw_verify_writeback", case, schema="patch-verify", input_info={"readback": rb_rel, "patch": patch_rel},
                               params={"ledger_seq": plan.get("seq")})
        payload.update({"outcome": outcome, "expected_sha256": expected, "base_target_sha256": base_sha, "readback_target_sha256": got_sha,
                        "abs_offset": abs_off, "size": size, "readback_seq": rec.get("seq"), "warnings": warnings, **detail})
        rel = _write(case, "patch-verify", payload, f"fw_verify_writeback {patch_rel} ← {rb_rel}: {outcome}")
        rt().audit({"event": "fwtriage_patch_verify", "patch": patch_rel, "readback": rb_rel, "outcome": outcome, "ledger_seq": plan.get("seq")}, case.id)
        msg = {"applied": "기기의 대상 범위가 공개한 패치와 같다(쓰기 확인).",
               "not-applied": "기기의 대상 범위가 쓰기 전(base)과 같다 — 쓰기가 되지 않았다. 명령 출력(sha256 확인·esptool)을 확인한다.",
               "differs": "패치와도 base 와도 다르다 — 쓰기 뒤 기기가 재부팅돼 게임이 세이브를 다시 썼거나, 다른 파일을 썼을 수 있다."}[outcome]
        out = {"ok": True, "tool": "fw_verify_writeback", "result_path": rel, "outcome": outcome, "message": msg, "expected_sha256": expected,
               "readback_target_sha256": got_sha, "target": {"abs_offset": hexs(abs_off), "size": size, "label": tgt.get("label")}, "warnings": warnings, **detail}
        if outcome == "differs":
            # 진단용: 원장 sha256 과 맞는 base·패치 파일이 남아 있으면 바이트 차이 수를 센다(증거는 아님)
            for name, rel_p, sha_p, sl in (("base", (src.get("base") or {}).get("path"), (src.get("base") or {}).get("sha256"), slice(abs_off, abs_off + size)),
                                           ("patch", patch_rel, expected, slice(0, size))):
                try:
                    fp = case.resolve_path(rel_p)
                    blob = _pread_regular(fp, 0, fp.stat().st_size) if fp.is_file() and fp.stat().st_size <= ESP_MAX_BYTES else b""
                except Exception:  # noqa: BLE001 - 진단 정보일 뿐이다
                    blob = b""
                if blob and hashlib.sha256(blob).hexdigest() == sha_p:
                    ref = blob[sl]
                    out[f"bytes_differing_from_{name}"] = sum(1 for a, b in zip(got, ref) if a != b)
        return out

    return await _execute(kind="fw_verify_writeback", case_id=case.id, background=False, max_seconds=120.0, description=f"fw_verify_writeback {case.rel(case.resolve_path(patch_path))}", fn=work)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
