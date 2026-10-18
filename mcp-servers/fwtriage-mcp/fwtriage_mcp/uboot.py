"""U-Boot env / mtdparts / 파티션 분할 / uImage·FIT 정보.

- env: pweh.formats.find_uboot_env (CRC 검증, redundant 플래그) + 빅엔디안 CRC 보완 + CRC 없는 기본 env 후보
- mtdparts: pweh.formats.parse_mtdparts (리눅스 cmdlinepart/memparse 규칙: 0x=16진, 선행 0=8진, K/M/G/T/P/E).
  선행 0 토큰은 8진수로 해석되므로, 10진수를 의도한 설정일 수 있음을 경고한다 (docs/references/uboot-and-boot-console.md 6.4).
- carve: mtdparts 문자열 / 명시적 파티션 목록 / 이미지 안에서 찾은 env·bootargs·DTB 파티션 노드
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from pweh.case import Case
from pweh.errors import PwehError, ValidationFailed
from pweh.formats import COMMON_ENV_SIZES, parse_mtdparts, parse_uimage_header
from pweh.fsutil import atomic_write_json

from .common import PRODUCER, Ctl, claim_numbered_dir, clip, hexs, parse_int_arg, safe_label, safe_name, sanitize
from .signatures import (
    ScanCtx,
    find_default_env_candidates,
    find_env_blocks,
    find_mtdparts_strings,
    fill_ratio,
    probe_at,
    scan_regions,
    v_fdt,
    v_uimage,
)

_MTD_TOKEN = re.compile(r"mtdparts=(\S+)")
_UBOOT_VER_RX = re.compile(rb"U-Boot(?: SPL)? (?:\d{4}\.\d{2}|\d+\.\d+\.\d+)[^\x00\r\n]{0,80}")
_OCTAL_TOKEN = re.compile(r"(?:^|[:,@])(0[0-7]+)[kKmMgG]?(?=[@(,;]|$)")


def mtdparts_sources(env: dict[str, str]) -> list[dict[str, str]]:
    """env 에서 mtdparts 문자열 후보: mtdparts 변수 + 모든 값 안의 'mtdparts=' 토큰 (bootargs 등)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    if env.get("mtdparts"):
        v = env["mtdparts"].strip()
        text = v if v.startswith("mtdparts=") else f"mtdparts={v}"
        seen.add(text)
        out.append({"source": "env:mtdparts", "text": text})
    for k, v in env.items():
        for m in _MTD_TOKEN.finditer(v or ""):
            text = "mtdparts=" + m.group(1)
            if text in seen:
                continue
            seen.add(text)
            out.append({"source": f"env:{k}", "text": text})
    return out


def parse_mtd(text: str, total_size: int | None) -> tuple[list[dict[str, Any]] | None, list[str]]:
    warnings: list[str] = []
    body = text.split("mtdparts=", 1)[-1]
    for m in _OCTAL_TOKEN.finditer(body):
        tok = m.group(1)
        if tok != "0":
            warnings.append(
                f"'{tok}' 는 리눅스 memparse 규칙대로 8진수(0 접두사)로 해석했습니다. 10진수를 의도한 설정이라면 실제 레이아웃과 다를 수 있습니다."
            )
    try:
        parts = parse_mtdparts(text, total_size=total_size)
    except (PwehError, ValueError) as exc:
        return None, warnings + [f"mtdparts 해석 실패: {exc}"]
    return parts, warnings


def _env_summary(env: dict[str, str]) -> dict[str, Any]:
    keys = ("bootcmd", "bootargs", "bootdelay", "baudrate", "mtdparts", "mtdids", "ethaddr", "ipaddr", "serverip", "loadaddr", "bootfile", "stdin", "stdout", "verify", "fileaddr", "sn", "serial#")
    return {k: env[k] for k in keys if k in env}


def env_scan(buf: Any, size: int, ctl: Ctl, *, sizes: tuple[int, ...] | None = None, align: int = 0x1000, max_hits: int = 16, include_default: bool = True) -> dict[str, Any]:
    hits = find_env_blocks(buf, sizes=sizes or COMMON_ENV_SIZES, align=align, max_hits=max_hits)
    envs: list[dict[str, Any]] = []
    for h in hits:
        ctl.check()
        srcs = mtdparts_sources(h["env"])
        parsed = []
        for s in srcs:
            parts, warns = parse_mtd(s["text"], size)
            parsed.append({**s, "partitions": parts, "warnings": warns})
        envs.append(
            {
                "offset": h["offset"],
                "offset_hex": hexs(h["offset"]),
                "size": h["size"],
                "redundant": h.get("redundant"),
                "flags": h.get("flags"),
                "crc": h.get("crc"),
                "crc_endian": h.get("crc_endian", "little"),
                "variable_count": len(h["env"]),
                "env": h["env"],
                "key_vars": _env_summary(h["env"]),
                "mtdparts": parsed,
            }
        )
    # redundant 쌍: 활성본 추정 (SPI/NOR: flags 1=ACTIVE, 0=OBSOLETE / NAND: 증가 카운터, 255 와 0 이면 0 이 최신)
    red = [e for e in envs if e["redundant"]]
    active_note = None
    if len(red) >= 2:
        a, b = red[0], red[1]
        fa, fb = a["flags"] or 0, b["flags"] or 0
        if {fa, fb} == {0, 1}:
            act = a if fa == 1 else b
            active_note = f"redundant env 쌍: flags 1(ACTIVE) 인 0x{act['offset']:x} 가 활성본 (SPI/NOR 방식)"
        else:
            if {fa, fb} == {0, 255}:
                act = a if fa == 0 else b
            else:
                act = a if fa > fb else b
            active_note = f"redundant env 쌍: 카운터 방식으로 0x{act['offset']:x} (flags={act['flags']}) 가 최신본으로 추정 (NAND 방식)"
        for e in red[:2]:
            e["active_guess"] = e is act
    defaults: list[dict[str, Any]] = []
    if include_default:
        excl = [(h["offset"], h["offset"] + h["size"]) for h in hits]
        for d in find_default_env_candidates(buf, size, exclude=excl):
            srcs = mtdparts_sources(d["env"])
            parsed = []
            for s in srcs:
                parts, warns = parse_mtd(s["text"], size)
                parsed.append({**s, "partitions": parts, "warnings": warns})
            defaults.append({"offset": d["offset"], "offset_hex": hexs(d["offset"]), "size": d["size"], "source": d["source"], "variable_count": len(d["env"]), "key_vars": _env_summary(d["env"]), "env": d["env"], "mtdparts": parsed})
    strings = find_mtdparts_strings(buf, size)
    return {"envs": envs, "redundant_note": active_note, "embedded_default_envs": defaults, "mtdparts_strings": strings}


# ---------------------------------------------------------------------------
# 파티션 레이아웃 결정
# ---------------------------------------------------------------------------


def _norm_partitions(partitions: list[Any], size: int) -> list[dict[str, Any]]:
    out = []
    if not isinstance(partitions, list) or not partitions:
        raise ValidationFailed("partitions 는 [{name, offset, size}] 형식의 비어 있지 않은 목록이어야 합니다.")
    for i, p in enumerate(partitions):
        if not isinstance(p, dict):
            raise ValidationFailed(f"partitions[{i}] 는 객체여야 합니다: {p!r}", hint="예: {\"name\": \"rootfs\", \"offset\": \"0x350000\", \"size\": \"10M\"}")
        off = parse_int_arg(p.get("offset", 0), f"partitions[{i}].offset", allow_none=False)
        sz = parse_int_arg(p.get("size"), f"partitions[{i}].size", allow_none=True)
        if sz is None:
            sz = max(0, size - off)  # type: ignore[operator]
        out.append({"name": str(p.get("name") or f"part{i}"), "offset": off, "size": sz, "ro": bool(p.get("ro", False)), "device": p.get("device")})
    return out


def resolve_layout(buf: Any, size: int, ctl: Ctl, *, mtdparts: str | None, partitions: list[Any] | None, mtd_device: str | None) -> dict[str, Any]:
    warnings: list[str] = []
    if partitions:
        if mtdparts:
            warnings.append("mtdparts 와 partitions 가 모두 주어져 partitions 를 사용합니다.")
        return {"source": "partitions-argument", "text": None, "device": None, "partitions": _norm_partitions(partitions, size), "warnings": warnings, "devices": []}
    candidates: list[dict[str, str]] = []
    if mtdparts:
        t = mtdparts.strip()
        if "mtdparts=" not in t:
            t = f"mtdparts={t}"
        candidates.append({"source": "mtdparts-argument", "text": t})
    else:
        scan = env_scan(buf, size, ctl, include_default=True)
        for e in scan["envs"]:
            for m in e["mtdparts"]:
                candidates.append({"source": f"uboot-env@0x{e['offset']:x}:{m['source'].split(':', 1)[-1]}", "text": m["text"]})
        for d in scan["embedded_default_envs"]:
            for m in d["mtdparts"]:
                candidates.append({"source": f"default-env@0x{d['offset']:x}:{m['source'].split(':', 1)[-1]}", "text": m["text"]})
        for s in scan["mtdparts_strings"]:
            candidates.append({"source": f"string@0x{s['offset']:x}", "text": s["text"]})
        if not candidates:
            # DTB 의 fixed-partitions 노드
            ctx = ScanCtx(ctl, decompress_budget=0)
            for r in scan_regions(buf, 0, size, ctx, kinds={"fdt"}, env_scan=False):
                parts = r.details.get("dt_partitions")
                if parts:
                    return {
                        "source": f"dtb@0x{r.offset:x}:partition-nodes", "text": None, "device": None,
                        "partitions": [{**p, "device": None} for p in parts], "warnings": ["DTB 의 partition@ 노드에서 레이아웃을 가져왔습니다."], "devices": [],
                    }
    if not candidates:
        raise ValidationFailed(
            "파티션 레이아웃을 찾지 못했습니다 (이미지 안에 CRC 가 맞는 env, mtdparts 문자열, DTB 파티션 노드가 없음).",
            hint=(
                "mtdparts 문자열(예: UART 의 /proc/cmdline 또는 printenv 의 bootargs) 이나 partitions 목록을 직접 주세요. "
                "/proc/mtd 결과(uart shell_identify 의 mtd[])를 offset 누적으로 partitions 로 바꿔 넣어도 됩니다."
            ),
        )
    errors = []
    for cand in candidates:
        parts, warns = parse_mtd(cand["text"], size)
        if not parts:
            errors.append(f"{cand['source']}: {'; '.join(warns) or '파티션 없음'}")
            continue
        devices = sorted({p["device"] for p in parts}, key=lambda d: [p["device"] for p in parts].index(d))
        dev = mtd_device or devices[0]
        if mtd_device and mtd_device not in devices:
            errors.append(f"{cand['source']}: mtd 장치 '{mtd_device}' 가 없음 (있는 장치: {devices})")
            continue
        chosen = [p for p in parts if p["device"] == dev]
        w = list(warnings) + warns
        if len(devices) > 1:
            w.append(f"mtdparts 에 장치가 {len(devices)}개 있습니다 {devices}. 이 이미지를 '{dev}' 의 덤프로 보고 그 장치의 파티션만 분할합니다 (다른 장치는 mtd_device 로 선택).")
        if len(candidates) > 1:
            w.append(f"레이아웃 후보 {len(candidates)}개 중 첫 번째 유효 후보({cand['source']})를 사용했습니다.")
        return {"source": cand["source"], "text": cand["text"], "device": dev, "partitions": chosen, "warnings": w, "devices": devices, "other_candidates": [c for c in candidates if c is not cand][:8]}
    raise ValidationFailed("mtdparts 후보를 해석하지 못했습니다: " + " | ".join(errors[:5]), hint="partitions 목록을 직접 주세요.")


def carve(case: Case, src: Path, buf: Any, size: int, layout: dict[str, Any], *, label: str, ctl: Ctl, probe: bool = True) -> dict[str, Any]:
    out_dir = claim_numbered_dir(case.subdir("extract"), safe_label(label, "parts"))
    results: list[dict[str, Any]] = []
    warnings = list(layout.get("warnings") or [])
    parts = layout["partitions"]
    prev_end = None
    total_parts = len(parts)
    for idx, p in enumerate(parts):
        ctl.check()
        ctl.progress(idx, total_parts, f"{p['name']} 분할 중")
        name = str(p["name"])
        off = int(p["offset"])
        psize = p.get("size")
        entry: dict[str, Any] = {"index": idx, "name": name, "offset": off, "offset_hex": hexs(off), "size": psize, "size_hex": hexs(psize), "ro": p.get("ro", False)}
        if prev_end is not None and off < prev_end:
            entry["overlaps_previous"] = True
        if psize is None:
            psize = max(0, size - off)
            entry["size"] = psize
            entry["size_hex"] = hexs(psize)
        if off >= size:
            entry.update(status="skipped", reason="이미지 끝을 넘는 offset (덤프가 플래시 전체보다 작거나 다른 장치의 파티션)")
            results.append(entry)
            warnings.append(f"파티션 '{name}' (0x{off:x}) 는 이미지 밖이라 건너뜀")
            continue
        if psize <= 0:
            entry.update(status="skipped", reason="크기 0")
            results.append(entry)
            continue
        end = min(size, off + psize)
        truncated = off + psize > size
        fname = f"{idx:02d}-{safe_name(name)}.bin"
        dest = out_dir / fname
        h = hashlib.sha256()
        with open(dest, "xb") as fh:
            pos = off
            while pos < end:
                chunk = bytes(buf[pos : min(end, pos + (4 << 20))])
                fh.write(chunk)
                h.update(chunk)
                pos += len(chunk)
                ctl.check()
        # path = 케이스 상대 경로 (다른 도구의 path 인자와 같은 이름). file 은 같은 값의 하위 호환 별칭
        entry.update(status="carved", path=case.rel(dest), file=case.rel(dest), bytes=end - off, sha256=h.hexdigest())
        if truncated:
            entry["truncated"] = True
            warnings.append(f"파티션 '{name}' 은 이미지 끝에서 잘렸습니다 ({end - off}/{psize} bytes)")
        if probe:
            content: dict[str, Any] = {}
            r = probe_at(buf, off, end, ctl)
            env_hit = None
            if r is None and end - off <= (1 << 20):
                for h in find_env_blocks(bytes(buf[off:end]), max_hits=2):
                    if h["offset"] == 0:
                        env_hit = h
                        break
            ub = None
            if r is None and env_hit is None:
                m = _UBOOT_VER_RX.search(bytes(buf[off : min(end, off + (1 << 20))]))
                ub = m.group(0).decode("latin-1") if m else None
            if r is not None:
                content = {"kind": r.kind, "description": r.description, "size": r.size}
            elif env_hit is not None:
                content = {"kind": "uboot-env", "description": f"U-Boot env 블록 (크기 {env_hit['size']}, 변수 {len(env_hit['env'])}개{', redundant' if env_hit.get('redundant') else ''})", "size": env_hit["size"]}
            elif ub:
                content = {"kind": "bootloader", "description": f"U-Boot 버전 문자열 포함: {ub}"}
            else:
                ff = fill_ratio(buf, off, end, 0xFF)
                if ff > 0.999:
                    content = {"kind": "erased", "description": "모두 0xFF (지워진/빈 파티션)"}
                elif fill_ratio(buf, off, end, 0x00) > 0.999:
                    content = {"kind": "zeros", "description": "모두 0x00"}
                else:
                    content = {"kind": "unknown", "description": f"시작 위치에서 알려진 형식이 확인되지 않음 (0xFF 비율 {ff:.1%}). fw_identify 로 파티션 내부를 스캔하세요."}
            entry["content"] = content
        art = case.register_artifact(dest, kind="partition", producer=PRODUCER, description=f"{name} @ 0x{off:x} ({end - off} bytes) from {case.rel(src)}", extra={"offset": off, "size": psize, "source": case.rel(src), "layout_source": layout.get("source")})
        entry["artifact_id"] = art.get("id")
        results.append(entry)
        prev_end = off + psize
    index = {
        "schema": "pweh.fwtriage.carve-index/v1",
        "source": case.rel(src),
        "source_size": size,
        "layout": {k: layout.get(k) for k in ("source", "text", "device", "devices", "other_candidates") if layout.get(k) is not None},
        "partitions": results,
        "warnings": warnings,
    }
    index_path = out_dir / "index.json"
    atomic_write_json(index_path, sanitize(index))
    case.register_artifact(index_path, kind="triage-report", producer=PRODUCER, description=f"파티션 분할 색인 ({case.rel(out_dir)})")
    return {"output_dir": case.rel(out_dir), "index_path": case.rel(index_path), "partitions": results, "warnings": warnings, "layout": index["layout"]}


# ---------------------------------------------------------------------------
# uImage / FIT
# ---------------------------------------------------------------------------


def uimage_info(buf: Any, size: int, offset: int, ctl: Ctl) -> dict[str, Any]:
    if offset >= size:
        raise ValidationFailed(f"offset 0x{offset:x} 이 파일 크기({size})를 넘습니다.")
    magic = bytes(buf[offset : offset + 4])
    ctx = ScanCtx(ctl, decompress_budget=256 << 20, max_stream_in=64 << 20, max_stream_out=256 << 20)
    if magic == b"\x27\x05\x19\x56":
        r = v_uimage(buf, offset, size, ctx)
        if r is None:
            hdr = bytes(buf[offset : offset + 64])
            info = parse_uimage_header(hdr, verify_data=False) if len(hdr) == 64 else None
            raise ValidationFailed(
                f"offset 0x{offset:x} 의 uImage 헤더 CRC 가 맞지 않습니다 (손상되었거나 우연한 매직 일치).",
                data={"header": info} if info else {},
            )
        out: dict[str, Any] = {"format": "legacy-uimage", **r.details, "truncated": r.truncated}
        data_size = r.details.get("data_size") or 0
        if not r.truncated and data_size:
            pr = probe_at(buf, offset + 64, offset + 64 + data_size, ctl)
            declared = r.details.get("compression")
            if pr is not None:
                out["payload_probe"] = {"kind": pr.kind, "description": pr.description, "size": pr.size}
                kind_map = {"gzip": "gzip", "lzma": "lzma", "xz": "lzma", "bzip2": "bzip2", "lz4-legacy": "lz4", "lz4": "lz4", "zstd": "zstd", "zimage": "none", "elf": "none"}
                if declared and declared != "none" and kind_map.get(pr.kind) not in (declared, None):
                    out["payload_mismatch"] = f"헤더의 압축 표시({declared})와 실제 데이터({pr.kind})가 다릅니다."
            else:
                out["payload_probe"] = None
        return out
    if magic == b"\xd0\x0d\xfe\xed":
        r = v_fdt(buf, offset, size, ctx)
        if r is None:
            raise ValidationFailed(f"offset 0x{offset:x} 의 FDT 헤더/구조가 유효하지 않습니다.")
        return {"format": "fit" if r.kind == "fit" else "dtb", **r.details, "truncated": r.truncated}
    # 안내: 파일 안의 uImage/FIT 위치
    ctx2 = ScanCtx(ctl, decompress_budget=0)
    found = [
        {"offset": rr.offset, "offset_hex": hexs(rr.offset), "kind": rr.kind, "description": clip(rr.description, 160)}
        for rr in scan_regions(buf, 0, size, ctx2, kinds={"uimage", "fdt"}, env_scan=False)
        if rr.kind in ("uimage", "fit", "dtb")
    ][:16]
    raise ValidationFailed(
        f"offset 0x{offset:x} 에 uImage(0x27051956) 또는 FIT/DTB(0xd00dfeed) 매직이 없습니다.",
        hint=("이 파일에서 찾은 위치: " + ", ".join(f"{f['kind']}@{f['offset_hex']}" for f in found)) if found else "fw_identify 로 커널 이미지 위치를 먼저 찾으세요.",
        data={"found": found},
    )
