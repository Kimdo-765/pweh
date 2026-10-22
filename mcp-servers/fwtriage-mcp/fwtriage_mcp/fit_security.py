"""입력 이미지의 비압축 FDT에서 FIT 서명 선언만 제한적으로 관찰한다.

서명·키·payload 원문은 반환하지 않으며 암호 검증이나 부팅 신뢰를 판정하지 않는다.
기존 FDT 소비자는 바꾸지 않고 명시 budget이 있는 strict parser만 사용한다.
"""

from __future__ import annotations

import json
import mmap
import struct
from dataclasses import dataclass, fields
from typing import Any

from pweh.errors import ValidationFailed

from .common import Ctl
from .signatures import FdtParseBudget, FdtStrictError, parse_fdt_tree


@dataclass(frozen=True)
class FitStructureLimits:
    """운영 상한. 합성 시험에서는 각 값을 낮출 수 있다."""

    max_scan_bytes: int = 256 << 20
    chunk_bytes: int = 64 << 10
    max_candidates: int = 64
    max_blobs: int = 32
    max_entries: int = 128
    max_blob_bytes: int = 64 << 20
    max_strings_bytes: int = 1 << 20
    max_nodes: int = 8192
    max_depth: int = 32
    max_properties: int = 32768
    max_tokens: int = 65536
    max_total_tokens: int = 131072
    max_owned_bytes: int = 2 << 20
    max_list_bytes: int = 8 << 10
    max_list_items: int = 100
    max_reservations: int = 1024
    max_output_bytes: int = 64 << 10

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if type(value) is not int or not 0 < value <= f.default:
                raise ValidationFailed("FIT 구조 관찰 한도가 올바르지 않습니다.")
        if self.max_output_bytes < 2048:
            raise ValidationFailed("FIT 구조 관찰 출력 한도가 올바르지 않습니다.")


_DEFAULTS = FitStructureLimits()
_MAGIC = b"\xd0\x0d\xfe\xed"
_REASONS = (
    "scan_limit", "candidate_limit", "blob_limit", "entry_limit", "token_limit",
    "node_limit", "property_limit", "depth_limit", "owned_bytes_limit",
    "output_limit", "time_limit", "malformed_fdt", "unsupported_fdt", "field_limit",
)
_KEY_MATERIAL = (
    "rsa,modulus", "rsa,exponent", "rsa,r-squared", "rsa,n0-inverse",
    "ecdsa,x-point", "ecdsa,y-point",
)


def not_examined_fit_security() -> dict[str, Any]:
    """image 입력이 없는 결과. 반환 컨테이너는 호출 사이에 공유하지 않는다."""
    return {
        "schema": "pweh.fit-security-structure/v1",
        "status": "not-examined",
        "scope": "input-image-uncompressed-fdt",
        "coverage": {
            "input_bytes": None, "search_end": 0, "positions_examined_end": 0,
            "search_complete": False, "pending_offset": None, "candidates_examined": 0,
            "structures_complete": False, "output_complete": False, "reasons": [],
        },
        "summary": {
            "blobs_reported": 0, "entries_reported": 0,
            "image_signatures_observed": 0, "configuration_signatures_observed": 0,
            "control_keys_observed": 0,
        },
        "blobs": [],
        "cryptographic_verification_performed": False,
        "key_trust_verified": False,
        "boot_enforcement_verified": False,
        "sd_route_link_verified": False,
    }


def _budget(ctl: Ctl, limits: FitStructureLimits) -> FdtParseBudget:
    return FdtParseBudget(
        ctl, max_blob_bytes=limits.max_blob_bytes, max_strings_bytes=limits.max_strings_bytes,
        max_properties=limits.max_properties, max_tokens=limits.max_tokens,
        max_total_tokens=limits.max_total_tokens, max_owned_bytes=limits.max_owned_bytes,
        max_reservations=limits.max_reservations,
    )


def _input(buf: Any, size: int, limits: FitStructureLimits) -> None:
    valid = type(buf) in (bytes, mmap.mmap) and type(size) is int and type(limits) is FitStructureLimits
    if valid:
        view = None
        try:
            valid = 0 <= size <= len(buf)
            if type(buf) is mmap.mmap:
                view = memoryview(buf)
                valid = valid and view.readonly
        except (ValueError, TypeError, BufferError, OSError):
            valid = False
        finally:
            if view is not None:
                view.release()
    if not valid:
        raise ValidationFailed("FIT 구조 관찰 입력이 올바르지 않습니다.")


def _json_size(value: Any) -> int:
    # 저장기의 들여쓰기까지 포함해 보수적으로 계산한다. 고정 ASCII 값만 남는다.
    return len(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")) + 1


def _reasons(values: set[str]) -> list[str]:
    return [r for r in _REASONS if r in values]


def _row(offset: int, size: int | None) -> dict[str, Any]:
    return {
        "index": 0, "offset": offset, "declared_size": size,
        "format": "unknown", "structure_status": "limited",
        "image_nodes": None, "configuration_nodes": None,
        "signature_presence": "unknown", "control_key_presence": "unknown",
        "required_mode": None, "entries_complete": False, "entries": [],
    }


@dataclass
class _Observation:
    row: dict[str, Any]
    reasons: set[str]
    counts: tuple[int, int, int] = (0, 0, 0)
    stop: bool = False


class _FieldLimit(Exception):
    """관련 선언 하나가 제한을 넘었음. 원문을 보유하지 않는다."""


def _length(value: Any) -> int | None:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, tuple) and len(value) == 3 and value[0] == "<blob>":
        return value[2]
    return None


def _read_value(value: Any, buf: Any, base: int, end: int,
                budget: FdtParseBudget, cap: int) -> bytes | None:
    """관련 선언만 같은 입력에서 읽는다. 이미 보유한 bytes는 재복사하지 않는다."""
    budget.check()
    length = _length(value)
    if length is None:
        return None
    if length > cap:
        raise _FieldLimit
    if isinstance(value, bytes):
        return value
    start = base + value[1]
    if start < base or start + length > end:
        raise FdtStrictError("malformed_fdt")
    budget.charge_owned(length)
    return bytes(buf[start:start + length])


def _text(value: bytes | None) -> bytes | None:
    if value is None or not value or value[-1:] != b"\0":
        return None
    body = value[:-1]
    if not body or any(c < 32 or c > 126 for c in body):
        return None
    return body


def _enum(props: dict[str, Any], key: str, allowed: tuple[str, ...],
          read: Any, issues: set[str]) -> str:
    if key not in props:
        return "absent"
    value = _text(read(props[key], 128))
    if value is None:
        issues.add("invalid_string")
        return "malformed"
    for candidate in allowed:
        if value == candidate.encode("ascii"):
            return candidate
    issues.add("unsupported_declaration")
    return "other"


def _list_count(value: bytes | None, budget: FdtParseBudget,
                limits: FitStructureLimits, issues: set[str]) -> int | None:
    if not value or value[-1:] != b"\0":
        issues.add("invalid_list")
        return None
    count, pos = 0, 0
    while pos < len(value):
        budget.check()
        end = value.find(b"\0", pos)
        if end == pos or any(c < 32 or c > 126 for c in value[pos:end]):
            issues.add("invalid_list")
            return None
        count += 1
        if count > limits.max_list_items:
            raise _FieldLimit
        pos = end + 1
    return count


def _entry(node: dict[str, Any], scope: str, owner: int, index: int,
           buf: Any, base: int, end: int, strings_size: int,
           budget: FdtParseBudget, limits: FitStructureLimits) -> tuple[dict[str, Any], bool]:
    props, issues = node["props"], set()
    limited = False

    def read(value: Any, cap: int) -> bytes | None:
        return _read_value(value, buf, base, end, budget, cap)

    out = {
        "scope": scope, "owner_index": owner, "index": index, "node_offset": node["_offset"],
        "digest": "absent", "signature_scheme": "absent",
        "value_bytes": _length(props.get("value")),
        "key_name_hint_present": "key-name-hint" in props,
        "required": "absent", "sign_images_count": None, "hashed_nodes_count": None,
        "hashed_strings_range_valid": None,
        "key_material_present": any((_length(props.get(k)) or 0) > 0 for k in _KEY_MATERIAL),
        "field_issues": [],
    }
    if scope != "control-key" and not out["value_bytes"]:
        issues.add("missing_value")
    if "algo" in props:
        try:
            raw = _text(read(props["algo"], 128))
            if raw is None:
                out["digest"] = out["signature_scheme"] = "malformed"
                issues.add("invalid_string")
            else:
                parts = raw.split(b",")
                out["digest"] = out["signature_scheme"] = "other"
                if len(parts) == 2:
                    for known in ("sha1", "sha256", "sha384", "sha512"):
                        if parts[0] == known.encode("ascii"):
                            out["digest"] = known
                    for known in ("rsa2048", "rsa3072", "rsa4096", "ecdsa256"):
                        if parts[1] == known.encode("ascii"):
                            out["signature_scheme"] = known
                if "other" in (out["digest"], out["signature_scheme"]):
                    issues.add("unsupported_declaration")
        except _FieldLimit:
            limited = True
            out["digest"] = out["signature_scheme"] = "other"
            issues.add("unsupported_declaration")
    try:
        out["required"] = _enum(props, "required", ("image", "conf"), read, issues)
    except _FieldLimit:
        limited = True
        out["required"] = "other"
        issues.add("unsupported_declaration")
    for key, field in (("sign-images", "sign_images_count"), ("hashed-nodes", "hashed_nodes_count")):
        if key in props:
            try:
                out[field] = _list_count(read(props[key], limits.max_list_bytes), budget, limits, issues)
            except _FieldLimit:
                limited = True
                issues.add("unsupported_declaration")
    if "hashed-strings" in props:
        # 정확한 두 BE32 선언만 읽고 실제 서명 영역을 계산하지 않는다.
        if _length(props["hashed-strings"]) != 8:
            issues.add("invalid_integer")
        else:
            value = read(props["hashed-strings"], 8)
            off, size = struct.unpack(">II", value)
            out["hashed_strings_range_valid"] = off <= strings_size and size <= strings_size - off
            if not out["hashed_strings_range_valid"]:
                issues.add("range_out_of_bounds")
    out["field_issues"] = sorted(issues)
    return out, limited


def _inspect(buf: Any, offset: int, limit: int, size: int, *, budget: FdtParseBudget,
             limits: FitStructureLimits, entry_slots: int) -> _Observation:
    row = _row(offset, None)
    observation = _Observation(row, set())
    try:
        budget.check()
        available = limit - offset
        if available >= 8:
            magic, declared = struct.unpack(">II", bytes(buf[offset:offset + 8]))
            row["declared_size"] = declared
            if magic != 0xD00DFEED or declared < 40:
                raise FdtStrictError("malformed_fdt")
            if offset + declared > size:
                raise FdtStrictError("malformed_fdt")
            if offset + declared > limit:
                observation.reasons.add("scan_limit")
                observation.stop = True
                return observation
        if available < 40:
            if limit < size:
                observation.reasons.add("scan_limit")
                observation.stop = True
                return observation
            raise FdtStrictError("malformed_fdt")
        tree = parse_fdt_tree(buf, offset, limit, max_nodes=limits.max_nodes,
                              max_depth=limits.max_depth, budget=budget)
    except FdtStrictError as exc:
        reason = exc.reason if exc.reason in _REASONS else "malformed_fdt"
        row["structure_status"] = ("malformed" if reason == "malformed_fdt" else
                                   "unsupported" if reason == "unsupported_fdt" else "limited")
        observation.reasons.add(reason)
        observation.stop = row["structure_status"] == "limited"
        return observation

    row["declared_size"] = tree["totalsize"]
    row["structure_status"] = "complete"
    roots = {n["name"]: n for n in tree["root"]["children"]}
    images, configs, keys = (roots.get(k) for k in ("images", "configurations", "signature"))
    row["format"] = "fit" if images is not None else "dtb"
    row["image_nodes"] = len(images["children"]) if images is not None else 0
    row["configuration_nodes"] = len(configs["children"]) if configs is not None else 0
    row["required_mode"] = "absent"
    counts = [0, 0, 0]
    entries_complete = True
    projection_complete = False
    output_full = False
    try:
        budget.check()
        if keys is not None:
            issues: set[str] = set()
            try:
                row["required_mode"] = _enum(
                    keys["props"], "required-mode", ("any", "all"),
                    lambda v, n: _read_value(v, buf, offset, offset + tree["totalsize"], budget, n), issues,
                )
            except _FieldLimit:
                row["required_mode"] = "other"
                observation.reasons.add("field_limit")
        groups = ((images, "image-signature"), (configs, "configuration-signature"), (keys, "control-key"))
        for group_index, (group, scope) in enumerate(groups):
            if group is None:
                continue
            for owner_index, owner in enumerate(group["children"]):
                budget.check()
                nodes = (owner,) if scope == "control-key" else owner["children"]
                for node in nodes:
                    budget.check()
                    if scope != "control-key" and not node["name"].startswith("signature"):
                        continue
                    counts[group_index] += 1
                    if len(row["entries"]) >= entry_slots:
                        entries_complete = False
                        observation.reasons.add("entry_limit")
                        continue
                    if output_full:
                        continue
                    entry, field_limited = _entry(
                        node, scope, owner_index, sum(counts) - 1, buf, offset,
                        offset + tree["totalsize"], tree["strings_size"], budget, limits,
                    )
                    if field_limited:
                        observation.reasons.add("field_limit")
                    row["entries"].append(entry)
                    budget.check()
                    if _json_size(row) > limits.max_output_bytes - 1536:
                        row["entries"].pop()
                        output_full = True
                        entries_complete = False
                        observation.reasons.add("output_limit")
        budget.check()
        projection_complete = True
    except FdtStrictError as exc:
        observation.reasons.add(exc.reason if exc.reason in _REASONS else "malformed_fdt")
        observation.stop = True
        entries_complete = False
    observation.counts = tuple(counts)
    row["entries_complete"] = entries_complete and projection_complete
    row["signature_presence"] = "present" if counts[0] + counts[1] else "absent" if projection_complete else "unknown"
    row["control_key_presence"] = "present" if counts[2] else "absent" if projection_complete else "unknown"
    return observation


def inspect_fit_security(buf: Any, offset: int, limit: int, *, ctl: Ctl,
                         budget: FdtParseBudget, limits: FitStructureLimits = _DEFAULTS) -> dict[str, Any]:
    """명시한 FDT 하나의 닫힌 row. 공개 도구의 별도 입력으로 쓰지 않는다."""
    _input(buf, limit, limits)
    if type(offset) is not int or not 0 <= offset < limit:
        raise ValidationFailed("FIT 구조 관찰 위치가 올바르지 않습니다.")
    # 동일 Ctl은 호출자가 만든 budget의 수명 계약이며 여기서 새 예산을 만들지 않는다.
    if ctl.expired():
        return _row(offset, None)
    return _inspect(buf, offset, limit, len(buf), budget=budget, limits=limits,
                    entry_slots=limits.max_entries).row


def scan_fit_security(buf: Any, size: int, *, ctl: Ctl, max_scan_bytes: int,
                      limits: FitStructureLimits = _DEFAULTS) -> dict[str, Any]:
    """같은 입력과 Ctl에서 magic 시작 위치를 차례로 관찰한다."""
    _input(buf, size, limits)
    if type(max_scan_bytes) is not int or max_scan_bytes < 0:
        raise ValidationFailed("FIT 구조 관찰 검색 범위가 올바르지 않습니다.")
    end = min(size, max_scan_bytes, limits.max_scan_bytes)
    positions = max(0, end - 3)
    report = not_examined_fit_security()
    report["status"] = "complete"
    coverage, summary = report["coverage"], report["summary"]
    coverage.update(input_bytes=size, search_end=end, structures_complete=True, output_complete=True)
    reasons: set[str] = set()
    budget = _budget(ctl, limits)
    pos = 0
    try:
        budget.check()
        while pos < positions:
            budget.check()
            chunk_positions_end = min(positions, pos + limits.chunk_bytes)
            hit = buf.find(_MAGIC, pos, chunk_positions_end + 3)
            if hit < 0:
                pos = chunk_positions_end
                coverage["positions_examined_end"] = pos
                continue
            coverage["positions_examined_end"] = hit
            coverage["pending_offset"] = hit
            if coverage["candidates_examined"] >= limits.max_candidates:
                reasons.add("candidate_limit")
                coverage["structures_complete"] = False
                break
            if len(report["blobs"]) >= limits.max_blobs:
                reasons.add("blob_limit")
                coverage["structures_complete"] = False
                coverage["output_complete"] = False
                break
            coverage["candidates_examined"] += 1
            observation = _inspect(buf, hit, end, size, budget=budget, limits=limits,
                                   entry_slots=limits.max_entries - summary["entries_reported"])
            row = observation.row
            row["index"] = len(report["blobs"])
            for key, count in zip(("image_signatures_observed", "configuration_signatures_observed", "control_keys_observed"), observation.counts):
                summary[key] += count
            reasons.update(observation.reasons)
            if row["structure_status"] != "complete" or observation.stop:
                coverage["structures_complete"] = False
            if not row["entries_complete"]:
                coverage["output_complete"] = False
            report["blobs"].append(row)
            summary["blobs_reported"] += 1
            summary["entries_reported"] += len(row["entries"])
            # 최종 reason/pending/status 표시가 늘어날 공간을 미리 남긴다.
            if _json_size(report) > limits.max_output_bytes - 1024:
                report["blobs"].pop()
                summary["blobs_reported"] -= 1
                summary["entries_reported"] -= len(row["entries"])
                coverage["output_complete"] = False
                reasons.add("output_limit")
                break
            if observation.stop:
                break
            coverage["pending_offset"] = None
            pos = hit + 1
            coverage["positions_examined_end"] = pos
        budget.check()
    except FdtStrictError as exc:
        reasons.add(exc.reason if exc.reason in _REASONS else "malformed_fdt")
        coverage["structures_complete"] = False
    if end < size:
        reasons.add("scan_limit")
    coverage["search_complete"] = pos == positions and end == size and coverage["pending_offset"] is None and "time_limit" not in reasons
    coverage["reasons"] = _reasons(reasons)
    if reasons or not all(coverage[k] for k in ("search_complete", "structures_complete", "output_complete")):
        report["status"] = "partial"
    # max_output_bytes의 최소값과 원자적 예약으로 종료 metadata까지 들어간다.
    if _json_size(report) > limits.max_output_bytes:
        raise ValidationFailed("FIT 구조 관찰 결과 한도를 초과했습니다.")
    return report
