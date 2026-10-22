"""펌웨어 시그니처 스캔 (fw_identify 의 핵심).

매직 바이트만 보고 보고하면 오탐이 많으므로, 후보마다 헤더를 검증한다:

- uImage: 헤더 CRC 필수(pweh.formats.parse_uimage_header), 데이터 CRC 확인
- FIT/DTB(0xd00dfeed): 헤더 필드 정합성 + 구조 블록 토큰 파싱 성공
- squashfs: 버전별 superblock(block_size == 1<<block_log, 압축 ID, 테이블 오프셋 < bytes_used)
- jffs2: 노드 헤더 CRC(커널 crc32(0,..) == zlib.crc32(d, 0xffffffff) ^ 0xffffffff), 노드 연쇄 확인
- UBI: EC 헤더 CRC(zlib.crc32(h[:60]) ^ 0xffffffff), PEB 간격 추정, 볼륨 테이블 이름
- UBIFS: superblock 노드 CRC
- cramfs/romfs/erofs/ext2·3·4: superblock 필드 정합성 (cramfs 는 CRC)
- gzip/xz/lzma/bzip2: stdlib(zlib/lzma/bz2)로 상한이 있는 시험 해제 + 정확한 스트림 크기
- zstd/lz4: 프레임/블록 헤더 연쇄 검증 (Python 3.10 표준 라이브러리에 해제기가 없음), lz4 는 xxh32 헤더 체크섬
- ELF/cpio/zImage/zip/PEM, U-Boot 버전 문자열, 'PWEH SYNTHETIC' 마커

형식 근거(1차 자료로 확인): binwalk 3.1.0 src/signatures·structures (로컬 crate 소스), unblob/jefferson/ubireader
핸들러(로컬 venv), glibc elf.h, erofs-utils include/erofs_fs.h, docs/references/uboot-and-boot-console.md.
"""

from __future__ import annotations

import bisect
import bz2
import datetime as _dt
import hashlib
import lzma
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

from pweh.formats import COMMON_ENV_SIZES, find_uboot_env, parse_uimage_header
from pweh.errors import ValidationFailed

from .common import Ctl, hexs, printable

# ---------------------------------------------------------------------------
# 기본 구조
# ---------------------------------------------------------------------------

M32 = 0xFFFFFFFF


@dataclass
class Region:
    offset: int
    kind: str
    description: str
    size: int | None = None
    size_basis: str = "header"  # header|stream|walk|estimate|unknown
    confidence: str = "high"  # high|medium|low
    details: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    parent: int | None = None
    parent_kind: str | None = None

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.offset + self.size

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "offset": self.offset,
            "offset_hex": hexs(self.offset),
            "kind": self.kind,
            "size": self.size,
            "end_hex": hexs(self.end),
            "size_basis": self.size_basis,
            "confidence": self.confidence,
            "description": self.description,
        }
        if self.truncated:
            d["truncated"] = True
        if self.parent is not None:
            d["parent_offset"] = self.parent
            d["parent_kind"] = self.parent_kind
        if self.details:
            d["details"] = self.details
        return d


class ScanCtx:
    """스캔 1회의 공유 상태: 제어, 해제 예산, 통계."""

    def __init__(self, ctl: Ctl, *, decompress_budget: int = 768 << 20, max_stream_in: int = 64 << 20, max_stream_out: int = 160 << 20) -> None:
        self.ctl = ctl
        self.decompress_budget = decompress_budget  # 스캔 전체에서 시험 해제에 쓸 입력 바이트 총량
        self.max_stream_in = max_stream_in
        self.max_stream_out = max_stream_out
        self.stats: dict[str, dict[str, int]] = {}
        self.notes: list[str] = []

    def stat(self, kind: str, key: str, n: int = 1) -> None:
        s = self.stats.setdefault(kind, {"candidates": 0, "validated": 0, "rejected": 0, "skipped_nested": 0})
        s[key] = s.get(key, 0) + n

    def spend(self, n: int) -> None:
        self.decompress_budget -= n

    @property
    def can_decompress(self) -> bool:
        return self.decompress_budget > 0


def _rd(buf: Any, off: int, n: int, limit: int) -> bytes | None:
    if off < 0 or off + n > limit:
        return None
    return bytes(buf[off : off + n])


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _ts(ts: int) -> str | None:
    if not ts:
        return None
    try:
        return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _cstr(buf: Any, off: int, limit: int, maxlen: int = 256) -> str | None:
    end = buf.find(b"\0", off, min(limit, off + maxlen))
    if end < 0:
        return None
    return bytes(buf[off:end]).decode("latin-1")


def _printable_ascii(b: bytes) -> bool:
    return all(0x20 <= c < 0x7F for c in b)


def jffs2_crc(data: bytes) -> int:
    """JFFS2 헤더 CRC: 커널 crc32(0, data) (반전 없음) == zlib.crc32(data, 0xffffffff) ^ 0xffffffff."""
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & M32


def ubi_crc(data: bytes) -> int:
    """UBI/UBIFS CRC: 커널 crc32(UBI_CRC32_INIT=0xffffffff, data) == zlib.crc32(data) ^ 0xffffffff."""
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & M32


def _crc32_range(buf: Any, a: int, b: int, crc: int = 0, chunk: int = 4 << 20) -> int:
    p = a
    while p < b:
        q = min(b, p + chunk)
        crc = zlib.crc32(buf[p:q], crc)
        p = q
    return crc & M32


# ---------------------------------------------------------------------------
# 시험 해제 (상한 있음)
# ---------------------------------------------------------------------------


@dataclass
class DryRun:
    ok: bool
    consumed: int | None  # 스트림 끝까지 확인했으면 압축 데이터 크기
    out_bytes: int
    error: str | None = None
    capped: bool = False


def dry_run_zlib(buf: Any, s: int, limit: int, ctx: ScanCtx, *, wbits: int, min_out_unverified: int = 65536) -> DryRun:
    d = zlib.decompressobj(wbits)
    pos = s
    end = min(limit, s + ctx.max_stream_in)
    fed = 0
    out = 0
    chunk = 1 << 16
    while pos < end:
        data = buf[pos : min(end, pos + chunk)]
        pos += len(data)
        fed += len(data)
        ctx.spend(len(data))
        try:
            produced = len(d.decompress(data, 1 << 20))
            while d.unconsumed_tail and not d.eof:
                if out + produced > ctx.max_stream_out:
                    # 출력 상한: 남은 입력(unconsumed_tail)을 버리면 스트림이 깨지므로 여기서 끝낸다
                    out += produced
                    return DryRun(out >= min_out_unverified, None, out, capped=True)
                produced += len(d.decompress(d.unconsumed_tail, 1 << 20))
        except zlib.error as exc:
            return DryRun(False, None, out, str(exc))
        out += produced
        if d.eof:
            return DryRun(True, fed - len(d.unused_data), out)
        if out > ctx.max_stream_out or not ctx.can_decompress:
            return DryRun(out >= min_out_unverified, None, out, capped=True)
        if chunk < (1 << 20):
            chunk <<= 1
    # 입력 끝(또는 입력 상한)에 도달했지만 스트림 끝은 못 봄
    return DryRun(out >= min_out_unverified, None, out, capped=pos < limit)


def dry_run_lzma_like(buf: Any, s: int, limit: int, ctx: ScanCtx, factory: Callable[[], Any], *, min_out_unverified: int = 65536) -> DryRun:
    try:
        d = factory()
    except (lzma.LZMAError, ValueError, MemoryError) as exc:
        return DryRun(False, None, 0, str(exc))
    pos = s
    end = min(limit, s + ctx.max_stream_in)
    fed = 0
    out = 0
    chunk = 1 << 16
    try:
        while True:
            if d.eof:
                return DryRun(True, fed - len(d.unused_data), out)
            if getattr(d, "needs_input", True):
                if pos >= end:
                    break
                data = buf[pos : min(end, pos + chunk)]
                pos += len(data)
                fed += len(data)
                ctx.spend(len(data))
                out += len(d.decompress(data, 1 << 20))
                if chunk < (1 << 20):
                    chunk <<= 1
            else:
                out += len(d.decompress(b"", 1 << 20))
            if out > ctx.max_stream_out or not ctx.can_decompress:
                return DryRun(out >= min_out_unverified, None, out, capped=True)
    except (lzma.LZMAError, OSError, EOFError, ValueError, MemoryError) as exc:
        return DryRun(False, None, out, str(exc))
    if d.eof:
        return DryRun(True, fed - len(d.unused_data), out)
    return DryRun(out >= min_out_unverified, None, out, capped=pos < limit)


# ---------------------------------------------------------------------------
# 개별 검증기: (buf, start, limit, ctx) -> Region | None
# ---------------------------------------------------------------------------


def v_uimage(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    hdr = _rd(buf, s, 64, limit)
    if hdr is None:
        return None
    h = bytearray(hdr)
    stored = struct.unpack(">I", hdr[4:8])[0]
    h[4:8] = b"\0\0\0\0"
    if (zlib.crc32(bytes(h)) & M32) != stored:
        return None
    size = struct.unpack(">I", hdr[12:16])[0]
    avail = limit - s - 64
    truncated = size > avail
    verify = not truncated and size <= (512 << 20)
    info = parse_uimage_header(bytes(buf[s : s + 64 + (size if verify else 0)]), verify_data=verify)
    info["timestamp_iso"] = _ts(info.get("timestamp") or 0)
    conf = "high"
    note = ""
    if info.get("data_crc_ok") is False:
        conf = "medium"
        note = " (데이터 CRC 불일치)"
    if truncated:
        note += " (이미지가 파일 끝에서 잘림)"
    if info.get("type") == "multi" and not truncated:
        sizes = []
        p = s + 64
        while p + 4 <= limit and len(sizes) < 64:
            v = struct.unpack(">I", bytes(buf[p : p + 4]))[0]
            p += 4
            if v == 0:
                break
            sizes.append(v)
        info["multi_image_sizes"] = sizes
    desc = (
        f"uImage '{info['name']}' {info['os']}/{info['arch']} {info['type']}, 압축={info['compression']}, "
        f"load={info['load_address']} entry={info['entry_point']}, 데이터 {size} bytes{note}"
    )
    return Region(s, "uimage", desc, size=64 + size if not truncated else limit - s, size_basis="header", confidence=conf, details=info, truncated=truncated)


# -- FDT (FIT / DTB) ---------------------------------------------------------

FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


class FdtError(Exception):
    pass


class FdtStrictError(FdtError):
    """새 구조 관찰의 고정 실패 이유. 입력의 이름·값·예외 원문을 싣지 않는다."""

    _REASONS = frozenset({
        "malformed_fdt", "unsupported_fdt", "token_limit", "node_limit",
        "property_limit", "depth_limit", "owned_bytes_limit", "field_limit", "time_limit",
    })

    def __init__(self, reason: str) -> None:
        self.reason = reason if type(reason) is str and reason in self._REASONS else "malformed_fdt"
        super().__init__("FDT 구조 검사를 완료하지 못했습니다.")


class FdtParseBudget:
    """한 스캔에서 공유하는 구조 토큰·보유 바이트 예산. 실패 비용도 환급하지 않는다.

    운영 상한은 inventory가 정한다. 이 객체는 전달된 상한을 집행하며 동일 Ctl을
    참조한다. 후보별 카운터만 parser 진입 시 초기화하고 동시에 사용하지 않는다.
    """

    def __init__(
        self, ctl: Ctl, *, max_blob_bytes: int, max_strings_bytes: int,
        max_properties: int, max_tokens: int, max_total_tokens: int,
        max_owned_bytes: int, max_reservations: int,
    ) -> None:
        caps = (max_blob_bytes, max_strings_bytes, max_properties, max_tokens,
                max_total_tokens, max_owned_bytes, max_reservations)
        if any(type(n) is not int or n <= 0 for n in caps):
            raise FdtStrictError("field_limit")
        self._ctl = ctl
        (self._max_blob_bytes, self._max_strings_bytes, self._max_properties,
         self._max_tokens, self._max_total_tokens, self._max_owned_bytes,
         self._max_reservations) = caps
        self._total_tokens = self._owned_bytes = 0
        self._begin_blob()

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    @property
    def owned_bytes(self) -> int:
        return self._owned_bytes

    @property
    def blob_tokens(self) -> int:
        return self._blob_tokens

    @property
    def blob_nodes(self) -> int:
        return self._blob_nodes

    @property
    def blob_properties(self) -> int:
        return self._blob_properties

    @property
    def blob_reservations(self) -> int:
        return self._blob_reservations

    def check(self) -> None:
        """같은 Ctl의 취소를 전달하고 기존 마감 만료를 고정 이유로 알린다."""
        if self._ctl.expired():
            raise FdtStrictError("time_limit")

    def charge_owned(self, n: int) -> None:
        """이름·작은 값·추가 선언 목록을 복사하기 전에 누적 바이트를 예약한다."""
        self.check()
        if type(n) is not int or n < 0:
            raise FdtStrictError("field_limit")
        if n > self._max_owned_bytes - self._owned_bytes:
            raise FdtStrictError("owned_bytes_limit")
        self._owned_bytes += n

    def _begin_blob(self) -> None:
        self._blob_tokens = self._blob_nodes = self._blob_properties = self._blob_reservations = 0

    def _token(self) -> None:
        self.check()
        if self._blob_tokens >= self._max_tokens or self._total_tokens >= self._max_total_tokens:
            raise FdtStrictError("token_limit")
        self._blob_tokens += 1
        self._total_tokens += 1


def _parse_fdt_strict(
    buf: Any, base: int, limit: int, *, max_nodes: int, max_depth: int, budget: FdtParseBudget,
) -> dict[str, Any]:
    """v17 구조만 엄격하게 관찰한다. 실패한 tree나 원문 오류를 반환하지 않는다."""
    budget._begin_blob()
    budget.check()
    if any(type(n) is not int or n <= 0 for n in (max_nodes, max_depth)):
        raise FdtStrictError("field_limit")
    if type(base) is not int or type(limit) is not int or not 0 <= base < limit <= len(buf):
        raise FdtStrictError("malformed_fdt")

    def malformed() -> None:
        raise FdtStrictError("malformed_fdt")

    def read(start: int, length: int, end: int) -> bytes:
        if start < base or length < 0 or start + length > end:
            malformed()
        data = bytes(buf[start:start + length])
        if len(data) != length:
            malformed()
        return data

    def overlaps(start: int, end: int, other_start: int, other_end: int) -> bool:
        return start < end and other_start < other_end and start < other_end and other_start < end

    hdr = read(base, 40, limit)
    (magic, totalsize, off_struct, off_strings, off_rsvmap, version, last_comp,
     cpuid, size_strings, size_struct) = struct.unpack(">10I", hdr)
    if magic != 0xD00DFEED:
        malformed()
    if version != 17:
        raise FdtStrictError("unsupported_fdt")
    if not 16 <= last_comp <= version:
        malformed()
    if totalsize < 40 or base + totalsize > limit:
        malformed()
    if min(off_struct, off_strings, off_rsvmap) < 40 or off_struct % 4 or off_rsvmap % 8:
        malformed()
    if size_struct == 0 or size_struct % 4:
        malformed()
    if off_struct + size_struct > totalsize or off_strings + size_strings > totalsize or off_rsvmap >= totalsize:
        malformed()
    if totalsize > budget._max_blob_bytes or size_strings > budget._max_strings_bytes:
        raise FdtStrictError("field_limit")
    struct_start, struct_end = base + off_struct, base + off_struct + size_struct
    str_start, str_end = base + off_strings, base + off_strings + size_strings
    blob_end = base + totalsize
    if overlaps(struct_start, struct_end, str_start, str_end):
        malformed()
    budget.check()

    # 예약 표는 종결까지 제한해서 읽고 다른 블록 안의 바이트를 표로 해석하지 않는다.
    p = base + off_rsvmap
    while True:
        budget.check()
        if overlaps(p, p + 16, struct_start, struct_end) or overlaps(p, p + 16, str_start, str_end):
            malformed()
        address, length = struct.unpack(">QQ", read(p, 16, blob_end))
        p += 16
        if address == 0 and length == 0:
            break
        if budget._blob_reservations >= budget._max_reservations:
            raise FdtStrictError("field_limit")
        budget._blob_reservations += 1

    def name_at(start: int, end: int, maximum: int) -> tuple[str, int]:
        budget.check()
        stop = buf.find(b"\0", start, min(end, start + maximum + 1))
        if not start <= stop < min(end, start + maximum + 1):
            malformed()
        budget.charge_owned(stop - start)
        return read(start, stop - start, end).decode("latin-1"), stop + 1

    p = struct_start
    root: dict[str, Any] | None = None
    # 각 열린 노드의 형제 이름 집합은 같은 이름 객체를 참조하며 문자열을 복제하지 않는다.
    stack: list[tuple[dict[str, Any], set[str]]] = []
    ended = False
    while p < struct_end:
        budget._token()
        token_offset = p
        tok = struct.unpack(">I", read(p, 4, struct_end))[0]
        p += 4
        if tok == FDT_BEGIN_NODE:
            if budget._blob_nodes >= max_nodes:
                raise FdtStrictError("node_limit")
            if len(stack) > max_depth:
                raise FdtStrictError("depth_limit")
            name, name_end = name_at(p, struct_end, 255)
            p = base + _align(name_end - base, 4)
            if p > struct_end:
                malformed()
            if not stack:
                if root is not None or name != "":
                    malformed()
            elif not name or name in stack[-1][1]:
                malformed()
            node = {"name": name, "props": {}, "children": [], "_offset": token_offset}
            budget._blob_nodes += 1
            if stack:
                stack[-1][1].add(name)
                stack[-1][0]["children"].append(node)
            else:
                root = node
            stack.append((node, set()))
        elif tok == FDT_END_NODE:
            if not stack:
                malformed()
            stack.pop()
        elif tok == FDT_PROP:
            if not stack or stack[-1][0]["children"]:
                malformed()
            if budget._blob_properties >= budget._max_properties:
                raise FdtStrictError("property_limit")
            budget._blob_properties += 1
            length, nameoff = struct.unpack(">II", read(p, 8, struct_end))
            p += 8
            value_end = p + length
            aligned_end = base + _align(value_end - base, 4)
            if aligned_end > struct_end or nameoff >= size_strings:
                malformed()
            name, _ = name_at(str_start + nameoff, str_end, 128)
            props = stack[-1][0]["props"]
            if not name or name in props:
                malformed()
            if length <= 1024 and name not in {"data", "value"} and not name.startswith(("rsa,", "ecdsa,")):
                budget.charge_owned(length)
                props[name] = read(p, length, struct_end)
            else:
                props[name] = ("<blob>", p - base, length)
            p = aligned_end
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            if root is None or stack or p != struct_end:
                malformed()
            ended = True
            break
        else:
            malformed()
    if not ended:
        malformed()
    budget.check()
    return {
        "totalsize": totalsize, "version": version, "last_comp_version": last_comp,
        "boot_cpuid": cpuid, "root": root,
        "strings_offset": str_start, "strings_size": size_strings,
    }


def parse_fdt_tree(
    buf: Any, base: int, limit: int, *, max_nodes: int = 8192, max_depth: int = 32,
    budget: FdtParseBudget | None = None,
) -> dict[str, Any]:
    """FDT 헤더 + 구조 블록을 제자리(buf 의 오프셋)에서 파싱. 큰 data 속성은 복사하지 않고 길이/오프셋만 기록."""
    if budget is not None:
        if not isinstance(budget, FdtParseBudget):
            raise FdtStrictError("field_limit")
        try:
            return _parse_fdt_strict(buf, base, limit, max_nodes=max_nodes, max_depth=max_depth, budget=budget)
        except (IndexError, ValueError, TypeError, OverflowError, struct.error, BufferError, OSError, AttributeError):
            raise FdtStrictError("malformed_fdt") from None
    hdr = _rd(buf, base, 40, limit)
    if hdr is None:
        raise FdtError("헤더가 잘림")
    (magic, totalsize, off_struct, off_strings, off_rsvmap, version, last_comp, cpuid, size_strings, size_struct) = struct.unpack(">10I", hdr)
    if magic != 0xD00DFEED:
        raise FdtError("magic 불일치")
    if not (16 <= last_comp <= version <= 17):
        raise FdtError(f"지원하지 않는 버전 {version}/{last_comp}")
    if totalsize < 40 or off_struct < 40 or off_strings < 40 or off_rsvmap < 40:
        raise FdtError("헤더 오프셋 비정상")
    if off_rsvmap % 8 or off_struct % 4:
        raise FdtError("정렬 비정상")
    if off_struct >= totalsize or off_strings > totalsize or off_strings + size_strings > totalsize:
        raise FdtError("블록이 totalsize 밖")
    if version >= 17 and off_struct + size_struct > totalsize:
        raise FdtError("구조 블록이 totalsize 밖")
    avail_end = min(limit, base + totalsize)
    struct_end = base + off_struct + (size_struct if version >= 17 else totalsize - off_struct)
    struct_end = min(struct_end, avail_end)
    str_base = base + off_strings
    str_end = min(str_base + size_strings, avail_end)

    def prop_name(nameoff: int) -> str:
        if nameoff >= size_strings:
            raise FdtError("속성 이름 오프셋 비정상")
        nm = _cstr(buf, str_base + nameoff, str_end, 128)
        if nm is None:
            raise FdtError("속성 이름이 끝나지 않음")
        return nm

    p = base + off_struct
    root: dict[str, Any] | None = None
    stack: list[dict[str, Any]] = []
    node: dict[str, Any] | None = None
    nodes = 0
    ended = False
    while p + 4 <= struct_end:
        tok = struct.unpack(">I", bytes(buf[p : p + 4]))[0]
        p += 4
        if tok == FDT_BEGIN_NODE:
            nm_end = buf.find(b"\0", p, min(struct_end, p + 256))
            if nm_end < 0:
                raise FdtError("노드 이름이 끝나지 않음")
            name = bytes(buf[p:nm_end]).decode("latin-1")
            p = base + _align(nm_end + 1 - base, 4)  # 정렬은 blob 시작 기준
            new = {"name": name, "props": {}, "children": []}
            nodes += 1
            if nodes > max_nodes:
                raise FdtError("노드가 너무 많음")
            if node is None:
                if root is not None:
                    raise FdtError("루트 노드가 둘 이상")
                root = new
            else:
                node["children"].append(new)
                stack.append(node)
                if len(stack) > max_depth:
                    raise FdtError("노드 깊이 초과")
            node = new
        elif tok == FDT_END_NODE:
            if node is None:
                raise FdtError("짝이 없는 END_NODE")
            node = stack.pop() if stack else None
        elif tok == FDT_PROP:
            if node is None or p + 8 > struct_end:
                raise FdtError("PROP 위치 비정상")
            ln, nameoff = struct.unpack(">II", bytes(buf[p : p + 8]))
            p += 8
            if p + ln > struct_end:
                raise FdtError("속성 값이 구조 블록 밖")
            name = prop_name(nameoff)
            if ln <= 1024:
                node["props"][name] = bytes(buf[p : p + ln])
            else:
                node["props"][name] = ("<blob>", p - base, ln)
            p = base + _align(p + ln - base, 4)
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            ended = True
            break
        else:
            raise FdtError(f"알 수 없는 토큰 0x{tok:x}")
    if root is None or node is not None or not ended:
        raise FdtError("구조 블록이 완결되지 않음")
    return {
        "totalsize": totalsize,
        "version": version,
        "last_comp_version": last_comp,
        "boot_cpuid": cpuid,
        "root": root,
    }


def _prop_str(v: Any) -> str | None:
    if not isinstance(v, bytes) or not v:
        return None
    if v.endswith(b"\0"):
        parts = v[:-1].split(b"\0")
        if all(parts) and all(_printable_ascii(x) for x in parts):
            return ", ".join(x.decode("ascii") for x in parts)
    return None


def _prop_int(v: Any) -> int | None:
    if isinstance(v, bytes) and len(v) == 4:
        return struct.unpack(">I", v)[0]
    if isinstance(v, bytes) and len(v) == 8:
        return struct.unpack(">Q", v)[0]
    return None


def _prop_len(v: Any) -> int | None:
    if isinstance(v, tuple):
        return v[2]
    if isinstance(v, bytes):
        return len(v)
    return None


def _child(node: dict[str, Any], name: str) -> dict[str, Any] | None:
    for c in node.get("children", []):
        if c["name"] == name:
            return c
    return None


def summarize_fdt(tree: dict[str, Any]) -> dict[str, Any]:
    """FIT 이면 images/configurations 요약, 아니면 DTB model/compatible/bootargs/파티션 노드."""
    root = tree["root"]
    out: dict[str, Any] = {"fdt_version": tree["version"], "totalsize": tree["totalsize"]}
    images = _child(root, "images")
    if images is not None:
        out["fit"] = True
        out["description"] = _prop_str(root["props"].get("description"))
        ts = _prop_int(root["props"].get("timestamp"))
        if ts:
            out["timestamp"] = ts
            out["timestamp_iso"] = _ts(ts)
        imgs = []
        ext_end = 0
        for img in images["children"][:64]:
            pr = img["props"]
            item: dict[str, Any] = {"name": img["name"]}
            for key in ("description", "type", "arch", "os", "compression"):
                val = _prop_str(pr.get(key))
                if val is not None:
                    item[key] = val
            for key in ("load", "entry"):
                val = _prop_int(pr.get(key))
                if val is not None:
                    item[key] = hexs(val)
            if "data" in pr:
                item["data_size"] = _prop_len(pr["data"])
                blob = pr["data"]
                if isinstance(blob, tuple):
                    item["data_offset_in_fit"] = blob[1]
            else:
                dsz = _prop_int(pr.get("data-size"))
                doff = _prop_int(pr.get("data-offset"))
                dpos = _prop_int(pr.get("data-position"))
                if dsz is not None:
                    item["data_size"] = dsz
                if doff is not None:
                    item["external_data_offset"] = doff
                    if dsz is not None:
                        ext_end = max(ext_end, doff + dsz)
                if dpos is not None:
                    item["data_position"] = hexs(dpos)
            hashes = []
            for hc in img["children"]:
                if hc["name"].startswith("hash"):
                    algo = _prop_str(hc["props"].get("algo"))
                    val = hc["props"].get("value")
                    hashes.append({"algo": algo, "value": val.hex() if isinstance(val, bytes) else None})
                if hc["name"].startswith("signature"):
                    item.setdefault("signatures", []).append(
                        {"algo": _prop_str(hc["props"].get("algo")), "key_name_hint": _prop_str(hc["props"].get("key-name-hint"))}
                    )
            if hashes:
                item["hashes"] = hashes
            imgs.append(item)
        out["images"] = imgs
        confs = _child(root, "configurations")
        if confs is not None:
            out["default_configuration"] = _prop_str(confs["props"].get("default"))
            out["configurations"] = [
                {"name": c["name"], **{k: _prop_str(c["props"].get(k)) for k in ("kernel", "fdt", "ramdisk", "loadables") if _prop_str(c["props"].get(k))}}
                for c in confs["children"][:32]
            ]
        if ext_end:
            out["external_data_end"] = ext_end
    else:
        out["fit"] = False
        out["model"] = _prop_str(root["props"].get("model"))
        out["compatible"] = _prop_str(root["props"].get("compatible"))
        chosen = _child(root, "chosen")
        if chosen is not None:
            ba = _prop_str(chosen["props"].get("bootargs"))
            if ba:
                out["bootargs"] = ba
        parts: list[dict[str, Any]] = []

        def walk(n: dict[str, Any], depth: int = 0) -> None:
            if depth > 16 or len(parts) >= 64:
                return
            for c in n.get("children", []):
                if c["name"].startswith("partition@") or (c["name"] == "partitions"):
                    pass
                if c["name"].startswith("partition@"):
                    reg = c["props"].get("reg")
                    label = _prop_str(c["props"].get("label")) or c["name"]
                    if isinstance(reg, bytes) and len(reg) in (8, 16):
                        if len(reg) == 8:
                            off, size = struct.unpack(">II", reg)
                        else:
                            off, size = struct.unpack(">QQ", reg)
                        parts.append({"name": label, "offset": off, "size": size, "ro": "read-only" in c["props"]})
                walk(c, depth + 1)

        walk(root)
        if parts:
            out["dt_partitions"] = parts
    return out


def v_fdt(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    try:
        tree = parse_fdt_tree(buf, s, limit)
    except (FdtError, struct.error, UnicodeDecodeError):
        return None
    info = summarize_fdt(tree)
    total = tree["totalsize"]
    size = total
    if info.get("external_data_end"):
        size = _align(total, 4) + int(info["external_data_end"])
    truncated = s + size > limit
    if info.get("fit"):
        imgs = info.get("images", [])
        desc = f"FIT 이미지 (이미지 {len(imgs)}개: " + ", ".join(
            f"{i.get('name')}[{i.get('type', '?')}/{i.get('arch', '?')}/{i.get('compression', '?')}]" for i in imgs[:6]
        ) + ")"
        kind = "fit"
    else:
        desc = f"Device Tree Blob v{tree['version']}"
        if info.get("model"):
            desc += f", model='{info['model']}'"
        if info.get("compatible"):
            desc += f", compatible='{info['compatible'][:80]}'"
        kind = "dtb"
    return Region(s, kind, desc, size=min(size, limit - s), size_basis="header", confidence="high", details=info, truncated=truncated)


# -- squashfs ----------------------------------------------------------------

SQUASHFS_MAGICS = (b"hsqs", b"sqsh", b"sqlz", b"qshs", b"tqsh", b"hsqt", b"shsq")
SQUASHFS_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
SQUASHFS_FLAGS = {
    0x0001: "uncompressed_inodes",
    0x0002: "uncompressed_data",
    0x0008: "uncompressed_fragments",
    0x0010: "no_fragments",
    0x0020: "always_fragments",
    0x0040: "duplicates_removed",
    0x0080: "exportable",
    0x0100: "uncompressed_xattrs",
    0x0200: "no_xattrs",
    0x0400: "compressor_options",
    0x0800: "uncompressed_ids",
}
_NO_TABLE = 0xFFFFFFFFFFFFFFFF


def parse_squashfs_superblock(sb: bytes, avail: int) -> dict[str, Any] | None:
    """squashfs superblock 검증 + 요약 (v4 LE/BE, v1~v3 레거시). 유효하지 않으면 None."""
    if len(sb) < 96:
        return None
    magic = sb[:4]
    if magic not in SQUASHFS_MAGICS:
        return None
    orders = ("<", ">") if magic in (b"hsqs", b"qshs", b"hsqt", b"shsq") else (">", "<")
    for e in orders:
        major, minor = struct.unpack(e + "HH", sb[28:32])
        if major == 4 and len(sb) >= 96:
            (inodes, mkfs, block_size, frags, comp, block_log, flags, no_ids) = struct.unpack(e + "IIIIHHHH", sb[4:28])
            (root_inode, bytes_used, id_tab, xattr_tab, inode_tab, dir_tab, frag_tab, lookup_tab) = struct.unpack(e + "8Q", sb[32:96])
            if not (12 <= block_log <= 20 and block_size == (1 << block_log)):
                continue
            if comp not in SQUASHFS_COMP or minor != 0 or inodes == 0 or no_ids == 0:
                continue
            if bytes_used < 96 or not (96 <= inode_tab < dir_tab <= bytes_used) or id_tab >= bytes_used:
                continue
            if any(t != _NO_TABLE and t >= bytes_used for t in (xattr_tab, frag_tab, lookup_tab)):
                continue
            return {
                "version": f"{major}.{minor}",
                "endianness": "little" if e == "<" else "big",
                "magic": magic.decode("latin-1"),
                "compression": SQUASHFS_COMP[comp],
                "block_size": block_size,
                "inodes": inodes,
                "fragments": frags,
                "ids": no_ids,
                "bytes_used": bytes_used,
                "mkfs_time": mkfs,
                "mkfs_time_iso": _ts(mkfs),
                "flags": [name for bit, name in SQUASHFS_FLAGS.items() if flags & bit],
                "flags_raw": hexs(flags),
                "truncated": bytes_used > avail,
                "nonstandard": magic != (b"hsqs" if e == "<" else b"sqsh"),
            }
        if major in (1, 2, 3) and len(sb) >= 119:
            inodes = struct.unpack(e + "I", sb[4:8])[0]
            block_size_1, block_log = struct.unpack(e + "HH", sb[32:36])
            mkfs = struct.unpack(e + "i", sb[39:43])[0]
            if major == 3:
                block_size = struct.unpack(e + "I", sb[51:55])[0]
                bytes_used = struct.unpack(e + "Q", sb[63:71])[0]
                inode_tab, dir_tab = struct.unpack(e + "QQ", sb[87:103])
                ok_log = 12 <= block_log <= 20
            elif major == 2:
                block_size = struct.unpack(e + "I", sb[51:55])[0]
                bytes_used = struct.unpack(e + "I", sb[8:12])[0]
                inode_tab, dir_tab = struct.unpack(e + "II", sb[20:28])
                ok_log = 12 <= block_log <= 16
            else:
                block_size = block_size_1
                bytes_used = struct.unpack(e + "I", sb[8:12])[0]
                inode_tab, dir_tab = struct.unpack(e + "II", sb[20:28])
                ok_log = 12 <= block_log <= 15
            if not ok_log or block_size != (1 << block_log) or inodes == 0:
                continue
            if bytes_used < 64 or not (inode_tab < dir_tab <= bytes_used):
                continue
            return {
                "version": f"{major}.{minor}",
                "endianness": "little" if e == "<" else "big",
                "magic": magic.decode("latin-1"),
                "compression": "lzma(벤더 변형)" if magic in (b"sqlz", b"qshs") else "gzip",
                "block_size": block_size,
                "inodes": inodes,
                "bytes_used": bytes_used,
                "mkfs_time": mkfs,
                "mkfs_time_iso": _ts(mkfs) if mkfs > 0 else None,
                "truncated": bytes_used > avail,
                "nonstandard": magic not in (b"hsqs", b"sqsh"),
            }
    return None


def v_squashfs(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    sb = bytes(buf[s : min(limit, s + 128)])
    info = parse_squashfs_superblock(sb, limit - s)
    if info is None:
        return None
    size = info["bytes_used"]
    truncated = bool(info.pop("truncated"))
    desc = (
        f"SquashFS v{info['version']} {info['endianness']} endian, {info['compression']}, 블록 {info['block_size']}, "
        f"inode {info['inodes']}, 크기 {size} bytes"
    )
    if info.get("mkfs_time_iso"):
        desc += f", 생성 {info['mkfs_time_iso']}"
    if info.get("nonstandard"):
        desc += f" (비표준 매직 '{info['magic']}': sasquatch 등 벤더 변형 도구가 필요할 수 있음)"
    if truncated:
        desc += " (파일 끝에서 잘림)"
    conf = "high" if not truncated else "medium"
    return Region(s, "squashfs", desc, size=min(size, limit - s), size_basis="header", confidence=conf, details=info, truncated=truncated)


# -- JFFS2 -------------------------------------------------------------------

JFFS2_NODE_TYPES = {0xE001: "dirent", 0xE002: "inode", 0x2003: "cleanmarker", 0x2004: "padding", 0x2006: "summary", 0xE008: "xattr", 0xE009: "xref"}
JFFS2_MAGICS = (b"\x19\x85\xe0\x01", b"\x19\x85\xe0\x02", b"\x19\x85\x20\x03", b"\x85\x19\x01\xe0", b"\x85\x19\x02\xe0", b"\x85\x19\x03\x20")
_JFFS2_ACCURATE = 0x2000


def _jffs2_node(buf: Any, p: int, limit: int, e: str) -> tuple[int, int] | None:
    if p + 12 > limit:
        return None
    hdr = bytes(buf[p : p + 12])
    magic, ntype, totlen, hcrc = struct.unpack(e + "HHII", hdr)
    if magic != 0x1985:
        return None
    check = True
    if ntype not in JFFS2_NODE_TYPES:
        if (ntype | _JFFS2_ACCURATE) in JFFS2_NODE_TYPES:
            check = False  # obsolete 표시로 ACCURATE 비트가 지워진 노드는 CRC 가 맞지 않는다
        else:
            return None
    if check and jffs2_crc(hdr[:8]) != hcrc:
        return None
    if totlen < 12 or p + totlen > limit:
        return None
    return ntype, totlen


def _skip_byte_run(buf: Any, p: int, limit: int, byte: int, chunk: int = 1 << 16) -> int:
    target = bytes([byte])
    while p < limit:
        blk = bytes(buf[p : min(limit, p + chunk)])
        rest = blk.lstrip(target)
        if rest:
            return p + (len(blk) - len(rest))
        p += len(blk)
    return limit


def v_jffs2(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    e = ">" if buf[s] == 0x19 else "<"
    first = _jffs2_node(buf, s, limit, e)
    if first is None:
        return None
    magic2 = b"\x19\x85" if e == ">" else b"\x85\x19"
    counts: dict[str, int] = {}
    nodes = 0
    cleanmarkers: list[int] = []
    p = s
    end = s
    gap_limit = 0x20000
    while p < limit:
        if nodes and (nodes & 0x3FF) == 0 and ctx.ctl.expired():
            ctx.notes.append("jffs2 노드 순회가 시간 예산으로 중단됨 (크기는 최소값)")
            break
        n = _jffs2_node(buf, p, limit, e)
        if n is not None:
            ntype, totlen = n
            nodes += 1
            name = JFFS2_NODE_TYPES.get(ntype) or JFFS2_NODE_TYPES.get(ntype | _JFFS2_ACCURATE, "obsolete")
            counts[name] = counts.get(name, 0) + 1
            if ntype == 0x2003 and len(cleanmarkers) < 64:
                cleanmarkers.append(p)
            p = p + _align(totlen, 4)
            end = p
            continue
        b = buf[p]
        q = p
        if b in (0xFF, 0x00):
            q = _skip_byte_run(buf, p, limit, b)
            q = _align(q - s, 4) + s
            if q < limit and _jffs2_node(buf, q, limit, e) is not None:
                p = q
                continue
        # 작은 쓰레기 영역(dirty space) 뒤의 다음 노드를 찾는다
        found = None
        search = max(q, p + 1)
        stop = min(limit, max(q, p) + gap_limit)
        while True:
            i = buf.find(magic2, search, stop)
            if i < 0:
                break
            if (i - s) % 4 == 0 and _jffs2_node(buf, i, limit, e) is not None:
                found = i
                break
            search = i + 1
        if found is None:
            break
        p = found
    if nodes < 2:
        return None
    size = end - s
    erase_guess = None
    if len(cleanmarkers) >= 2:
        diffs = sorted({cleanmarkers[i + 1] - cleanmarkers[i] for i in range(len(cleanmarkers) - 1)})
        if diffs and diffs[0] > 0:
            erase_guess = diffs[0]
    details = {"endianness": "big" if e == ">" else "little", "nodes": nodes, "node_types": counts}
    if erase_guess:
        details["erase_block_guess"] = erase_guess
    desc = f"JFFS2 파일시스템 ({details['endianness']} endian, 노드 {nodes}개, 사용 영역 {size} bytes)"
    return Region(s, "jffs2", desc, size=size, size_basis="walk", confidence="high" if nodes >= 3 else "medium", details=details)


# -- UBI / UBIFS -------------------------------------------------------------

UBI_LAYOUT_VOLUME_ID = 0x7FFFEFFF


def _ubi_ec(buf: Any, p: int, limit: int) -> dict[str, int] | None:
    h = _rd(buf, p, 64, limit)
    if h is None or h[:4] != b"UBI#" or h[4] != 1 or h[5:8] != b"\0\0\0":
        return None
    ec, vid_off, data_off, image_seq = struct.unpack(">QIII", h[8:28])
    if h[28:60] != b"\0" * 32:
        return None
    if ubi_crc(h[:60]) != struct.unpack(">I", h[60:64])[0]:
        return None
    if vid_off < 64 or data_off < 64:
        return None
    return {"ec": ec, "vid_hdr_offset": vid_off, "data_offset": data_off, "image_seq": image_seq}


def _ubi_vid(buf: Any, p: int, limit: int) -> dict[str, int] | None:
    h = _rd(buf, p, 64, limit)
    if h is None or h[:4] != b"UBI!" or h[4] != 1:
        return None
    if ubi_crc(h[:60]) != struct.unpack(">I", h[60:64])[0]:
        return None
    vol_type, copy_flag, compat = h[5], h[6], h[7]
    vol_id, lnum = struct.unpack(">II", h[8:16])
    data_size, used_ebs, data_pad, data_crc = struct.unpack(">IIII", h[20:36])
    return {"vol_type": vol_type, "vol_id": vol_id, "lnum": lnum, "data_size": data_size, "used_ebs": used_ebs}


def _ubi_vtbl(buf: Any, p: int, limit: int) -> list[dict[str, Any]]:
    vols = []
    for i in range(128):
        rec = _rd(buf, p + i * 172, 172, limit)
        if rec is None:
            break
        if ubi_crc(rec[:168]) != struct.unpack(">I", rec[168:172])[0]:
            continue
        reserved_pebs, alignment, data_pad = struct.unpack(">III", rec[:12])
        vol_type, upd_marker = rec[12], rec[13]
        name_len = struct.unpack(">H", rec[14:16])[0]
        if not name_len or name_len > 127:
            continue
        name = rec[16 : 16 + name_len].decode("latin-1", "replace")
        vols.append({"vol_id": i, "name": name, "reserved_pebs": reserved_pebs, "type": {1: "dynamic", 2: "static"}.get(vol_type, str(vol_type)), "flags": rec[144]})
    return vols


def v_ubi(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    first = _ubi_ec(buf, s, limit)
    if first is None:
        return None
    peb = None
    p = s + 64
    stop = min(limit, s + (4 << 20) + 64)
    while True:
        i = buf.find(b"UBI#\x01\x00\x00\x00", p, stop)
        if i < 0:
            break
        if _ubi_ec(buf, i, limit) is not None:
            peb = i - s
            break
        p = i + 1
    details: dict[str, Any] = {"vid_hdr_offset": first["vid_hdr_offset"], "data_offset": first["data_offset"], "image_seq": first["image_seq"]}
    if peb is None:
        details["peb_count"] = 1
        return Region(s, "ubi", "UBI 이미지 (PEB 1개만 확인, 크기 미상)", size=None, size_basis="unknown", confidence="medium", details=details)
    count = 0
    q = s
    vol_pebs: dict[int, int] = {}
    vtbl: list[dict[str, Any]] = []
    truncated = False
    while q + 64 <= limit:
        if count and (count & 0xFF) == 0 and ctx.ctl.expired():
            ctx.notes.append("UBI PEB 순회가 시간 예산으로 중단됨")
            break
        ec = _ubi_ec(buf, q, limit)
        if ec is None:
            break
        count += 1
        vid = _ubi_vid(buf, q + ec["vid_hdr_offset"], limit)
        if vid is not None:
            vol_pebs[vid["vol_id"]] = vol_pebs.get(vid["vol_id"], 0) + 1
            if vid["vol_id"] == UBI_LAYOUT_VOLUME_ID and not vtbl:
                vtbl = _ubi_vtbl(buf, q + ec["data_offset"], limit)
        if q + peb > limit:
            truncated = True
        q += peb
    size = min(count * peb, limit - s)
    details.update({"peb_size": peb, "peb_count": count})
    if vtbl:
        for v in vtbl:
            v["pebs_used"] = vol_pebs.get(v["vol_id"], 0)
        details["volumes"] = vtbl
    names = ", ".join(v["name"] for v in vtbl[:8]) if vtbl else "볼륨 테이블 미확인"
    desc = f"UBI 이미지 (PEB {peb} bytes x {count}, 볼륨: {names})"
    pow2 = peb & (peb - 1) == 0
    return Region(s, "ubi", desc, size=size, size_basis="walk", confidence="high" if pow2 else "medium", details=details, truncated=truncated)


UBIFS_COMPR = {0: "none", 1: "lzo", 2: "zlib", 3: "zstd"}


def v_ubifs(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 128, limit)
    if h is None:
        return None
    magic, crc, sqnum, length, node_type, group_type = struct.unpack("<IIQIBB", h[:22])
    if node_type != 6 or group_type > 2 or h[22:24] != b"\0\0" or length != 4096:
        return None
    node = _rd(buf, s, length, limit)
    if node is None or ubi_crc(node[8:]) != crc:
        return None
    (flags, min_io, leb_size, leb_cnt, max_leb_cnt) = struct.unpack("<IIIII", node[28:48])
    fmt_version = struct.unpack("<I", node[80:84])[0]
    default_compr = struct.unpack("<H", node[84:86])[0]
    if leb_size == 0 or leb_cnt == 0:
        return None
    size = leb_size * leb_cnt
    details = {
        "min_io_size": min_io,
        "leb_size": leb_size,
        "leb_count": leb_cnt,
        "max_leb_count": max_leb_cnt,
        "fmt_version": fmt_version,
        "default_compression": UBIFS_COMPR.get(default_compr, str(default_compr)),
        "uuid": node[108:124].hex(),
    }
    truncated = s + size > limit
    desc = f"UBIFS superblock (LEB {leb_size} x {leb_cnt} = 볼륨 크기 {size} bytes, 압축 {details['default_compression']})"
    if truncated:
        desc += " (볼륨 크기가 남은 데이터보다 큼: mkfs.ubifs 이미지는 사용한 LEB 만 담으므로 정상일 수 있음)"
    return Region(s, "ubifs", desc, size=min(size, limit - s), size_basis="header", confidence="high", details=details, truncated=truncated)


# -- cramfs / romfs / erofs / ext --------------------------------------------


def v_cramfs(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 64, limit)
    if h is None:
        return None
    if h[:4] == b"\x45\x3d\xcd\x28":
        e = "<"
    elif h[:4] == b"\x28\xcd\x3d\x45":
        e = ">"
    else:
        return None
    size, flags, future = struct.unpack(e + "III", h[4:16])
    crc, edition, blocks, files = struct.unpack(e + "IIII", h[32:48])
    name = h[48:64].split(b"\0", 1)[0]
    if size < 76:
        return None
    truncated = s + size > limit
    details: dict[str, Any] = {
        "endianness": "little" if e == "<" else "big",
        "size": size,
        "flags_raw": hexs(flags),
        "edition": edition,
        "blocks": blocks,
        "files": files,
        "name": name.decode("latin-1", "replace"),
    }
    conf = "medium"
    if (flags & 0x1) and not truncated and size <= (256 << 20):
        c = zlib.crc32(bytes(buf[s : s + 32]))
        c = zlib.crc32(b"\0\0\0\0", c)
        c = _crc32_range(buf, s + 36, s + size, c)
        details["crc_ok"] = c == crc
        conf = "high" if c == crc else "low"
    desc = f"CramFS ({details['endianness']} endian, 파일 {files}개, 크기 {size} bytes, 이름 '{details['name']}')"
    if details.get("crc_ok") is False:
        desc += " (CRC 불일치)"
    return Region(s, "cramfs", desc, size=min(size, limit - s), size_basis="header", confidence=conf, details=details, truncated=truncated)


def v_romfs(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 16, limit)
    if h is None or h[:8] != b"-rom1fs-":
        return None
    full_size, checksum = struct.unpack(">II", h[8:16])
    if full_size < 32:
        return None
    n = min(512, full_size)
    blk = _rd(buf, s, _align(n, 4), limit)
    if blk is None:
        return None
    total = sum(struct.unpack(f">{len(blk) // 4}I", blk)) & M32
    if total != 0:
        return None
    name = _cstr(buf, s + 16, limit, 128) or ""
    truncated = s + full_size > limit
    return Region(s, "romfs", f"RomFS (볼륨 '{name}', 크기 {full_size} bytes)", size=min(full_size, limit - s), details={"volume_name": name}, truncated=truncated)


def v_erofs(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    sb = _rd(buf, s + 1024, 128, limit)
    if sb is None or struct.unpack("<I", sb[:4])[0] != 0xE0F5E1E2:
        return None
    feature_compat = struct.unpack("<I", sb[8:12])[0]
    blkszbits = sb[12]
    blocks_hi = struct.unpack("<H", sb[14:16])[0]
    inos = struct.unpack("<Q", sb[16:24])[0]
    blocks_lo = struct.unpack("<I", sb[36:40])[0]
    feature_incompat = struct.unpack("<I", sb[80:84])[0]
    if not (9 <= blkszbits <= 16) or inos == 0 or blocks_lo == 0:
        return None
    blocks = blocks_lo | ((blocks_hi << 32) if feature_incompat & 0x80 else 0)
    size = blocks << blkszbits
    name = sb[64:80].split(b"\0", 1)[0].decode("latin-1", "replace")
    truncated = s + size > limit
    details = {"block_size": 1 << blkszbits, "blocks": blocks, "inodes": inos, "volume_name": name, "uuid": sb[48:64].hex(), "feature_compat": hexs(feature_compat), "feature_incompat": hexs(feature_incompat)}
    return Region(s, "erofs", f"EROFS (블록 {1 << blkszbits} x {blocks}, inode {inos})", size=min(size, limit - s), confidence="medium", details=details, truncated=truncated)


EXT_MAGICS = tuple(b"\x53\xef" + st + er + b"\x00\x00" for st in (b"\x01\x00", b"\x02\x00") for er in (b"\x01\x00", b"\x02\x00", b"\x03\x00"))
EXT_OS = {0: "Linux", 1: "Hurd", 2: "Masix", 3: "FreeBSD", 4: "Lites"}


def v_ext(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    sb = _rd(buf, s + 1024, 0x160, limit)
    if sb is None:
        return None
    (inodes, blocks_lo, r_blocks, free_blocks, free_inodes, first_data_block, log_block_size, log_cluster_size,
     blocks_per_group, clusters_per_group, inodes_per_group, mtime, wtime) = struct.unpack("<13I", sb[:52])
    magic = struct.unpack("<H", sb[0x38:0x3A])[0]
    creator_os, rev_level = struct.unpack("<II", sb[0x48:0x50])
    if magic != 0xEF53 or creator_os not in EXT_OS or rev_level not in (0, 1) or log_block_size > 6:
        return None
    if inodes == 0 or blocks_lo == 0 or blocks_per_group == 0 or inodes_per_group == 0:
        return None
    block_size = 1024 << log_block_size
    if first_data_block != (1 if block_size == 1024 else 0):
        return None
    groups = (blocks_lo - first_data_block + blocks_per_group - 1) // blocks_per_group
    if groups == 0 or inodes != inodes_per_group * groups:
        return None
    feat_compat, feat_incompat, feat_ro = struct.unpack("<III", sb[0x5C:0x68])
    blocks = blocks_lo
    if feat_incompat & 0x80 and len(sb) >= 0x154:
        blocks |= struct.unpack("<I", sb[0x150:0x154])[0] << 32
    size = blocks * block_size
    if feat_incompat & (0x40 | 0x80 | 0x200):
        fstype = "ext4"
    elif feat_compat & 0x4:
        fstype = "ext3"
    else:
        fstype = "ext2"
    volname = sb[0x78:0x88].split(b"\0", 1)[0].decode("latin-1", "replace")
    last_mounted = sb[0x88:0xC8].split(b"\0", 1)[0].decode("latin-1", "replace")
    truncated = s + size > limit
    details = {
        "fs_type": fstype,
        "block_size": block_size,
        "blocks": blocks,
        "inodes": inodes,
        "free_blocks": free_blocks,
        "volume_name": volname,
        "last_mounted": last_mounted,
        "uuid": sb[0x68:0x78].hex(),
        "creator_os": EXT_OS[creator_os],
        "features": {"compat": hexs(feat_compat), "incompat": hexs(feat_incompat), "ro_compat": hexs(feat_ro)},
        "mtime_iso": _ts(mtime),
    }
    desc = f"{fstype} 파일시스템 (블록 {block_size} x {blocks}, inode {inodes}, 볼륨 '{volname}')"
    return Region(s, "ext", desc, size=min(size, limit - s), confidence="high", details=details, truncated=truncated)


# -- 압축 스트림 -------------------------------------------------------------

GZIP_OS = {0: "FAT", 1: "Amiga", 2: "VMS", 3: "Unix", 4: "VM/CMS", 5: "Atari", 6: "HPFS", 7: "Macintosh", 8: "Z-System", 9: "CP/M", 10: "TOPS-20", 11: "NTFS", 12: "QDOS", 13: "Acorn RISCOS", 255: "unknown"}


def v_gzip(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 10, limit)
    if h is None:
        return None
    flags, mtime, xfl, os_id = h[3], struct.unpack("<I", h[4:8])[0], h[8], h[9]
    if flags & 0xE0 or os_id not in GZIP_OS:
        return None
    details: dict[str, Any] = {"os": GZIP_OS[os_id], "mtime": mtime, "mtime_iso": _ts(mtime)}
    p = s + 10
    if flags & 0x04:
        x = _rd(buf, p, 2, limit)
        if x is None:
            return None
        p += 2 + struct.unpack("<H", x)[0]
    if flags & 0x08:
        nm = _cstr(buf, p, limit, 1024)
        if nm is None:
            return None
        details["original_name"] = nm
        p += len(nm) + 1
    if flags & 0x10:
        cm = _cstr(buf, p, limit, 4096)
        if cm is None:
            return None
        details["comment"] = cm[:200]
        p += len(cm) + 1
    if not ctx.can_decompress:
        return Region(s, "gzip", "gzip 압축 데이터 (헤더만 확인: 해제 예산 소진)", size=None, size_basis="unknown", confidence="low", details=details)
    dr = dry_run_zlib(buf, s, limit, ctx, wbits=31)
    if not dr.ok:
        return None
    details["decompressed_bytes" if dr.consumed is not None else "decompressed_bytes_at_least"] = dr.out_bytes
    if dr.consumed is not None:
        desc = f"gzip 압축 데이터 (압축 {dr.consumed} bytes -> 해제 {dr.out_bytes} bytes"
        desc += f", 원본 이름 '{details['original_name']}')" if details.get("original_name") else ")"
        return Region(s, "gzip", desc, size=dr.consumed, size_basis="stream", confidence="high", details=details)
    return Region(s, "gzip", f"gzip 압축 데이터 (해제 {dr.out_bytes} bytes 이상 확인, 끝은 미확인)", size=None, size_basis="unknown", confidence="medium", details=details)


XZ_CHECKS = {0: "none", 1: "crc32", 4: "crc64", 10: "sha256"}


def v_xz(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 12, limit)
    if h is None:
        return None
    flags = h[6:8]
    if flags[0] != 0 or flags[1] & 0xF0:
        return None
    if (zlib.crc32(flags) & M32) != struct.unpack("<I", h[8:12])[0]:
        return None
    details: dict[str, Any] = {"check": XZ_CHECKS.get(flags[1], str(flags[1]))}
    # 스트림 끝(footer: CRC32(backward size + flags) + 'YZ', 4바이트 정렬, flags 동일)
    size = None
    p = s + 12
    stop = min(limit, s + (256 << 20))
    while True:
        i = buf.find(b"YZ", p, stop)
        if i < 0:
            break
        fs = i - 10
        if fs >= s + 12 and (fs - s) % 4 == 0:
            f = bytes(buf[fs : fs + 12])
            if len(f) == 12 and f[8:10] == flags and (zlib.crc32(f[4:10]) & M32) == struct.unpack("<I", f[:4])[0]:
                size = fs + 12 - s
                break
        p = i + 1
        if ctx.ctl.expired():
            break
    if ctx.can_decompress:
        dr = dry_run_lzma_like(
            buf, s, min(limit, s + (size if size else (1 << 20))), ctx,
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=512 << 20), min_out_unverified=1,
        )
        if not dr.ok:
            return None
        if dr.consumed is not None:
            details["decompressed_bytes"] = dr.out_bytes
    if size is None:
        return Region(s, "xz", "XZ 압축 데이터 (스트림 끝 미확인)", size=None, size_basis="unknown", confidence="medium", details=details)
    return Region(s, "xz", f"XZ 압축 데이터 (크기 {size} bytes, 체크 {details['check']})", size=size, size_basis="stream", confidence="high", details=details)


LZMA_PROPS = (0x5D, 0x6E, 0x6D, 0x6C)
LZMA_MAGICS = tuple(bytes([p, 0, 0]) for p in LZMA_PROPS)


def _lzma_dict_ok(d: int) -> bool:
    if d < 4096 or d > (1 << 30):
        return False
    if d & (d - 1) == 0:
        return True
    hi = 1 << (d.bit_length() - 1)
    return d == hi + (hi >> 1)


def v_lzma(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 14, limit)
    if h is None:
        return None
    props, dict_size, usize = h[0], struct.unpack("<I", h[1:5])[0], struct.unpack("<Q", h[5:13])[0]
    if props not in LZMA_PROPS or h[13] != 0 or not _lzma_dict_ok(dict_size):
        return None
    if usize != 0xFFFFFFFFFFFFFFFF and not (256 <= usize <= (1 << 32)):
        return None
    if not ctx.can_decompress or dict_size > (256 << 20):
        return None
    lc = props % 9
    lp = (props // 9) % 5
    pb = props // 45
    dr = dry_run_lzma_like(buf, s, limit, ctx, lambda: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=512 << 20), min_out_unverified=65536)
    if not dr.ok:
        return None
    details = {"lc": lc, "lp": lp, "pb": pb, "dictionary_size": dict_size, "uncompressed_size": None if usize == 0xFFFFFFFFFFFFFFFF else usize}
    if dr.consumed is not None:
        details["decompressed_bytes"] = dr.out_bytes
        return Region(s, "lzma", f"LZMA(alone) 압축 데이터 (압축 {dr.consumed} bytes -> 해제 {dr.out_bytes} bytes, dict {dict_size})", size=dr.consumed, size_basis="stream", confidence="high", details=details)
    details["decompressed_bytes_at_least"] = dr.out_bytes
    return Region(s, "lzma", f"LZMA(alone) 압축 데이터 (해제 {dr.out_bytes} bytes 이상 확인, dict {dict_size})", size=None, size_basis="unknown", confidence="medium", details=details)


def v_bzip2(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 10, limit)
    if h is None or h[:3] != b"BZh" or not (0x31 <= h[3] <= 0x39) or h[4:10] != b"1AY&SY":
        return None
    details = {"block_size_100k": h[3] - 0x30}
    if not ctx.can_decompress:
        return Region(s, "bzip2", "bzip2 압축 데이터 (헤더만 확인)", size=None, size_basis="unknown", confidence="medium", details=details)
    dr = dry_run_lzma_like(buf, s, limit, ctx, bz2.BZ2Decompressor, min_out_unverified=1)
    if dr.error or not dr.ok:
        return None
    if dr.consumed is not None:
        details["decompressed_bytes"] = dr.out_bytes
        return Region(s, "bzip2", f"bzip2 압축 데이터 (압축 {dr.consumed} bytes -> 해제 {dr.out_bytes} bytes)", size=dr.consumed, size_basis="stream", confidence="high", details=details)
    return Region(s, "bzip2", "bzip2 압축 데이터 (끝 미확인)", size=None, size_basis="unknown", confidence="medium", details=details)


def v_zstd(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 18, limit)
    if h is None:
        return None
    fhd = h[4]
    fcs_flag, single, unused, reserved, checksum, did_flag = fhd >> 6, (fhd >> 5) & 1, (fhd >> 4) & 1, (fhd >> 3) & 1, (fhd >> 2) & 1, fhd & 3
    if reserved or unused:
        return None
    p = s + 5
    window_log = None
    if not single:
        wd = h[5]
        window_log = 10 + (wd >> 3)
        if window_log > 31:
            return None
        p += 1
    p += (0, 1, 2, 4)[did_flag]
    fcs_size = (1 if single else 0, 2, 4, 8)[fcs_flag]
    content_size = None
    if fcs_size:
        raw = _rd(buf, p, fcs_size, limit)
        if raw is None:
            return None
        content_size = int.from_bytes(raw, "little") + (256 if fcs_size == 2 else 0)
    p += fcs_size
    blocks = 0
    total_regen = 0
    while True:
        bh = _rd(buf, p, 3, limit)
        if bh is None:
            return None if blocks == 0 else Region(s, "zstd", "zstd 프레임 (파일 끝에서 잘림)", size=limit - s, size_basis="walk", confidence="low", truncated=True)
        v = int.from_bytes(bh, "little")
        last, btype, bsize = v & 1, (v >> 1) & 3, v >> 3
        if btype == 3 or bsize > (128 << 10):
            return None
        p += 3 + (1 if btype == 1 else bsize)
        total_regen += bsize if btype in (0, 1) else 0
        blocks += 1
        if p > limit:
            return None
        if last:
            break
        if blocks > 1_000_000 or ((blocks & 0x3FF) == 0 and ctx.ctl.expired()):
            return None
    if checksum:
        p += 4
    size = p - s
    if size > limit - s:
        return None
    details = {"blocks": blocks, "content_size": content_size, "window_log": window_log, "has_checksum": bool(checksum)}
    conf = "high" if blocks >= 2 or content_size is not None else "medium"
    return Region(s, "zstd", f"zstd 압축 프레임 (블록 {blocks}개, 크기 {size} bytes" + (f", 원본 {content_size} bytes)" if content_size is not None else ")"), size=size, size_basis="walk", confidence=conf, details=details)


_P1, _P2, _P3, _P4, _P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393


def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & M32


def xxh32(data: bytes, seed: int = 0) -> int:
    """xxHash32 (lz4 프레임 헤더 체크섬용)."""
    n = len(data)
    i = 0
    if n >= 16:
        v1 = (seed + _P1 + _P2) & M32
        v2 = (seed + _P2) & M32
        v3 = seed & M32
        v4 = (seed - _P1) & M32
        while i <= n - 16:
            a, b, c, d = struct.unpack_from("<4I", data, i)
            v1 = (_rotl32((v1 + a * _P2) & M32, 13) * _P1) & M32
            v2 = (_rotl32((v2 + b * _P2) & M32, 13) * _P1) & M32
            v3 = (_rotl32((v3 + c * _P2) & M32, 13) * _P1) & M32
            v4 = (_rotl32((v4 + d * _P2) & M32, 13) * _P1) & M32
            i += 16
        h = (_rotl32(v1, 1) + _rotl32(v2, 7) + _rotl32(v3, 12) + _rotl32(v4, 18)) & M32
    else:
        h = (seed + _P5) & M32
    h = (h + n) & M32
    while i + 4 <= n:
        h = (h + struct.unpack_from("<I", data, i)[0] * _P3) & M32
        h = (_rotl32(h, 17) * _P4) & M32
        i += 4
    while i < n:
        h = (h + data[i] * _P5) & M32
        h = (_rotl32(h, 11) * _P1) & M32
        i += 1
    h ^= h >> 15
    h = (h * _P2) & M32
    h ^= h >> 13
    h = (h * _P3) & M32
    h ^= h >> 16
    return h


def v_lz4(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 19, limit) or _rd(buf, s, 7, limit)
    if h is None:
        return None
    flg, bd = h[4], h[5]
    if (flg >> 6) != 1 or flg & 0x02 or bd & 0x8F:
        return None
    bmax_id = (bd >> 4) & 7
    if bmax_id < 4:
        return None
    block_max = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}[bmax_id]
    desc_len = 2 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0)
    desc = _rd(buf, s + 4, desc_len + 1, limit)
    if desc is None or ((xxh32(desc[:desc_len]) >> 8) & 0xFF) != desc[desc_len]:
        return None
    content_size = struct.unpack("<Q", desc[2:10])[0] if flg & 0x08 else None
    p = s + 4 + desc_len + 1
    blocks = 0
    while True:
        bs = _rd(buf, p, 4, limit)
        if bs is None:
            return None
        v = struct.unpack("<I", bs)[0]
        p += 4
        if v == 0:
            break
        n = v & 0x7FFFFFFF
        if n == 0 or n > block_max:
            return None
        p += n + (4 if flg & 0x10 else 0)
        blocks += 1
        if p > limit:
            return None
        if (blocks & 0x3FF) == 0 and ctx.ctl.expired():
            return None
    if flg & 0x04:
        p += 4
    if p > limit:
        return None
    size = p - s
    details = {"blocks": blocks, "block_max": block_max, "content_size": content_size}
    return Region(s, "lz4", f"LZ4 프레임 (블록 {blocks}개, 크기 {size} bytes)", size=size, size_basis="walk", confidence="high", details=details)


_LZ4_LEGACY_BOUND = (8 << 20) + (8 << 20) // 255 + 16


def v_lz4_legacy(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    p = s + 4
    blocks = 0
    while p + 4 <= limit and blocks < 4096:
        v = struct.unpack("<I", bytes(buf[p : p + 4]))[0]
        if v == 0x184C2102 or v == 0 or v > _LZ4_LEGACY_BOUND or p + 4 + v > limit:
            break
        p += 4 + v
        blocks += 1
    if blocks == 0:
        return None
    return Region(s, "lz4-legacy", f"LZ4 legacy 프레임 (리눅스 커널 lz4 형식, 블록 {blocks}개 추정)", size=p - s, size_basis="estimate", confidence="medium", details={"blocks": blocks})


# -- ELF / cpio / zImage / zip / PEM -----------------------------------------


def v_elf(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    from .elfinfo import describe_elf_header  # 순환 import 회피

    h = _rd(buf, s, 64, limit) or _rd(buf, s, 52, limit)
    if h is None:
        return None
    info = describe_elf_header(h)
    if info is None:
        return None
    size = None
    try:
        e = "<" if info["endianness"] == "little" else ">"
        ends = []
        if info["shnum"] and info["shoff"]:
            ends.append(info["shoff"] + info["shnum"] * info["shentsize"])
        if info["phnum"] and info["phoff"] and info["phnum"] <= 256:
            fmt = (e + "IIIIIIII") if info["class"] == 32 else (e + "IIQQQQQQ")
            ent = info["phentsize"]
            for i in range(info["phnum"]):
                ph = _rd(buf, s + info["phoff"] + i * ent, ent, limit)
                if ph is None:
                    break
                vals = struct.unpack(fmt, ph[: struct.calcsize(fmt)])
                if info["class"] == 32:
                    p_offset, p_filesz = vals[1], vals[4]
                else:
                    p_offset, p_filesz = vals[2], vals[5]
                if p_offset + p_filesz < (1 << 32):
                    ends.append(p_offset + p_filesz)
        if ends:
            size = max(ends)
    except struct.error:
        size = None
    truncated = size is not None and s + size > limit
    conf = "high" if info.get("machine_known") else "medium"
    return Region(s, "elf", f"ELF {info['summary']}", size=min(size, limit - s) if size else None, size_basis="header" if size else "unknown", confidence=conf, details=info, truncated=truncated)


_HEX8 = re.compile(rb"^[0-9A-Fa-f]{8}$")
_OCT = re.compile(rb"^[0-7]+$")


def _cpio_entry(buf: Any, p: int, limit: int) -> tuple[str, int, int] | None:
    """(이름, 헤더+이름 크기, 데이터 크기(패딩 포함)) 또는 None."""
    magic = _rd(buf, p, 6, limit)
    if magic in (b"070701", b"070702"):
        h = _rd(buf, p, 110, limit)
        if h is None:
            return None
        fields = [h[6 + i * 8 : 14 + i * 8] for i in range(13)]
        if not all(_HEX8.match(f) for f in fields):
            return None
        filesize = int(fields[6], 16)
        namesize = int(fields[11], 16)
        if not (1 <= namesize <= 4096):
            return None
        name_b = _rd(buf, p + 110, namesize, limit)
        if name_b is None or name_b[-1] != 0:
            return None
        hdr_total = _align(110 + namesize, 4)
        return name_b[:-1].decode("latin-1", "replace"), hdr_total, _align(filesize, 4)
    if magic == b"070707":
        h = _rd(buf, p, 76, limit)
        if h is None:
            return None
        fields = [h[6:12], h[12:18], h[18:24], h[24:30], h[30:36], h[36:42], h[42:48], h[48:59], h[59:65], h[65:76]]
        if not all(_OCT.match(f) for f in fields):
            return None
        namesize = int(h[59:65], 8)
        filesize = int(h[65:76], 8)
        if not (1 <= namesize <= 4096):
            return None
        name_b = _rd(buf, p + 76, namesize, limit)
        if name_b is None or name_b[-1] != 0:
            return None
        return name_b[:-1].decode("latin-1", "replace"), 76 + namesize, filesize
    return None


def v_cpio(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    p = s
    count = 0
    names: list[str] = []
    trailer = False
    fmt = bytes(buf[s : s + 6]).decode("latin-1")
    while p < limit and count < 200000:
        ent = _cpio_entry(buf, p, limit)
        if ent is None:
            break
        name, hsz, dsz = ent
        if p + hsz + dsz > limit:
            break
        p += hsz + dsz
        if name == "TRAILER!!!":
            trailer = True
            break
        count += 1
        if len(names) < 12:
            names.append(name)
        if (count & 0x3FF) == 0 and ctx.ctl.expired():
            break
    if count == 0 or (not trailer and count < 2):
        return None
    details = {"format": {"070701": "newc", "070702": "newc+crc", "070707": "odc"}.get(fmt, fmt), "entries": count, "first_names": names, "has_trailer": trailer}
    is_initramfs = any(n in ("init", "./init", "sbin/init", "bin/busybox") for n in names)
    desc = f"cpio 아카이브 ({details['format']}, 항목 {count}개" + (", initramfs 로 보임)" if is_initramfs else ")")
    return Region(s, "cpio", desc, size=p - s, size_basis="walk", confidence="high" if trailer else "medium", details=details, truncated=not trailer)


def v_zimage(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 0x38, limit)
    if h is None:
        return None
    mag = h[0x24:0x28]
    if mag == b"\x18\x28\x6f\x01":
        e = "<"
    elif mag == b"\x01\x6f\x28\x18":
        e = ">"
    else:
        return None
    start, end = struct.unpack(e + "II", h[0x28:0x30])
    size = (end - start) & M32
    if size < 0x30 or size > (64 << 20):
        return None
    nops = h[: 4 * 7] == b"\x00\x00\xa0\xe1" * 7 or h[: 4 * 7] == b"\xe1\xa0\x00\x00" * 7
    efi = h[:2] == b"MZ"
    details = {"endianness": "little" if e == "<" else "big", "start": hexs(start), "end": hexs(end), "nop_sled": nops, "efi_stub": efi}
    if struct.unpack("<I", h[0x30:0x34])[0] == 0x04030201:
        details["endian_flag"] = "little"
    elif struct.unpack(">I", h[0x30:0x34])[0] == 0x04030201:
        details["endian_flag"] = "big"
    truncated = s + size > limit
    conf = "high" if (nops or efi) else "medium"
    return Region(s, "zimage", f"ARM Linux zImage (크기 {size} bytes{', EFI stub' if efi else ''})", size=min(size, limit - s), confidence=conf, details=details, truncated=truncated)


_ZIP_METHODS = {0: "stored", 1: "shrunk", 6: "imploded", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 98: "ppmd", 99: "aes"}


def v_zip(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    h = _rd(buf, s, 30, limit)
    if h is None:
        return None
    ver, flags, method = struct.unpack("<HHH", h[4:10])
    csize, usize = struct.unpack("<II", h[18:26])
    nlen, xlen = struct.unpack("<HH", h[26:30])
    if ver > 100 or method not in _ZIP_METHODS or not (1 <= nlen <= 1024):
        return None
    name_b = _rd(buf, s + 30, nlen, limit)
    if name_b is None or not _printable_ascii(name_b.replace(b"\t", b" ")) and not (flags & 0x800):
        return None
    size = None
    eocd = buf.find(b"PK\x05\x06", s + 30, min(limit, s + (256 << 20)))
    entries = None
    if eocd >= 0:
        e = _rd(buf, eocd, 22, limit)
        if e is not None:
            entries = struct.unpack("<H", e[10:12])[0]
            cd_size, cd_off, clen = struct.unpack("<IIH", e[12:22])
            if cd_off + cd_size == eocd - s:
                size = eocd + 22 + clen - s
    details = {"first_entry": name_b.decode("utf-8", "replace"), "method": _ZIP_METHODS[method], "entries": entries}
    if size is None:
        return Region(s, "zip", f"ZIP 로컬 헤더 (첫 항목 '{details['first_entry']}', 끝 미확인)", size=None, size_basis="unknown", confidence="low", details=details)
    return Region(s, "zip", f"ZIP 아카이브 (항목 {entries}개, 크기 {size} bytes, 첫 항목 '{details['first_entry']}')", size=size, size_basis="header", confidence="high", details=details)


_PEM_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")


def v_pem(buf: Any, s: int, limit: int, ctx: ScanCtx) -> Region | None:
    head = _rd(buf, s, min(64, limit - s), limit) or b""
    m = _PEM_BEGIN.match(head)
    if not m:
        return None
    label = m.group(1)
    end_marker = b"-----END " + label + b"-----"
    e = buf.find(end_marker, s + m.end(), min(limit, s + (64 << 10)))
    if e < 0:
        return None
    size = e + len(end_marker) - s
    block = bytes(buf[s : s + size])
    lab = label.decode("ascii")
    if "PRIVATE KEY" in lab:
        kind = "pem-private-key"
    elif "CERTIFICATE" in lab:
        kind = "pem-certificate"
    else:
        kind = "pem-other"
    details = {"label": lab, "encrypted": ("ENCRYPTED" in lab) or (b"Proc-Type: 4,ENCRYPTED" in block), "sha256_16": hashlib.sha256(block).hexdigest()[:16]}
    return Region(s, kind, f"PEM 블록 '{lab}' ({size} bytes)" + (" (암호화됨)" if details["encrypted"] else ""), size=size, size_basis="header", details=details)


# ---------------------------------------------------------------------------
# 시그니처 표 (우선순위 순서: 컨테이너 → 압축 → 기타)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Sig:
    kind: str
    magics: tuple[bytes, ...]
    magic_offset: int
    validate: Callable[[Any, int, int, ScanCtx], Region | None]
    opaque: bool  # 안쪽 후보를 검증하지 않음(압축/압축 파일시스템)
    cap: int = 20000


def _android_validator(parser: Callable[..., dict[str, Any]]) -> Callable[..., Region | None]:
    def validate(buf: Any, start: int, limit: int, ctx: ScanCtx) -> Region | None:
        try:
            info = parser(buf, start, limit, ctx.ctl)
        except ValidationFailed:
            return None
        return Region(start, info["kind"], f"Android {info['kind']} 구조 (서명/파일 시스템 내용 검증 아님)",
                      size=info.get("size"), details=info, truncated=info.get("truncated", False))
    return validate


def _lp_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    from .androidlayout import lp_layout
    layout = lp_layout(buf, limit, ctl, base=start)
    size = (4096 + layout["metadata_bytes"]) if layout["metadata_only"] else layout["block_devices"][0]["size"]
    return {"kind": "android-lp", "size": size, "metadata_only": layout["metadata_only"],
            "geometry": layout["geometry"], "header_version": layout["header_version"],
            "header_flags": layout["header_flags"], "validation": layout["validation"],
            "selected_copy": layout["selected_copy"], "warnings": layout["warnings"],
            "partition_names": [p["name"] for p in layout["partitions"]], "truncated": start + size > limit}


from .androidformats import boot_info, vendor_boot_info, vbmeta_info, avb_footer_info, sparse_info, f2fs_info

SIGNATURES: tuple[Sig, ...] = (
    Sig("android-sparse", (b"\x3a\xff\x26\xed",), 0, _android_validator(sparse_info), opaque=True, cap=128),
    Sig("android-lp", (b"gDla",), 4096, _android_validator(_lp_info), opaque=False, cap=128),
    Sig("android-lp", (b"gDla",), 0, _android_validator(_lp_info), opaque=False, cap=128),
    Sig("android-boot", (b"ANDROID!",), 0, _android_validator(boot_info), opaque=False, cap=1024),
    Sig("android-vendor-boot", (b"VNDRBOOT",), 0, _android_validator(vendor_boot_info), opaque=False, cap=1024),
    Sig("android-vbmeta", (b"AVB0",), 0, _android_validator(vbmeta_info), opaque=False, cap=1024),
    Sig("android-avb-footer", (b"AVBf",), 0, _android_validator(avb_footer_info), opaque=False, cap=1024),
    Sig("f2fs", (b"\x10\x20\xf5\xf2",), 1024, _android_validator(f2fs_info), opaque=True, cap=1024),
    Sig("uimage", (b"\x27\x05\x19\x56",), 0, v_uimage, opaque=False),
    Sig("fdt", (b"\xd0\x0d\xfe\xed",), 0, v_fdt, opaque=False),
    Sig("squashfs", SQUASHFS_MAGICS, 0, v_squashfs, opaque=True),
    Sig("cramfs", (b"Compressed ROMFS",), 16, v_cramfs, opaque=True),
    Sig("jffs2", JFFS2_MAGICS, 0, v_jffs2, opaque=True, cap=200000),
    Sig("ubi", (b"UBI#\x01\x00\x00\x00",), 0, v_ubi, opaque=True, cap=200000),
    Sig("ubifs", (b"\x31\x18\x10\x06",), 0, v_ubifs, opaque=True),
    Sig("erofs", (b"\xe2\xe1\xf5\xe0",), 1024, v_erofs, opaque=True),
    Sig("romfs", (b"-rom1fs-",), 0, v_romfs, opaque=False),
    Sig("ext", EXT_MAGICS, 0x438, v_ext, opaque=False),
    Sig("cpio", (b"070701", b"070702", b"070707"), 0, v_cpio, opaque=False),
    Sig("zip", (b"PK\x03\x04",), 0, v_zip, opaque=False),
    Sig("gzip", (b"\x1f\x8b\x08",), 0, v_gzip, opaque=True),
    Sig("xz", (b"\xfd7zXZ\x00",), 0, v_xz, opaque=True),
    Sig("lzma", LZMA_MAGICS, 0, v_lzma, opaque=True),
    Sig("bzip2", (b"BZh",), 0, v_bzip2, opaque=True),
    Sig("zstd", (b"\x28\xb5\x2f\xfd",), 0, v_zstd, opaque=True),
    Sig("lz4", (b"\x04\x22\x4d\x18",), 0, v_lz4, opaque=True),
    Sig("lz4-legacy", (b"\x02\x21\x4c\x18",), 0, v_lz4_legacy, opaque=True),
    Sig("zimage", (b"\x18\x28\x6f\x01", b"\x01\x6f\x28\x18"), 0x24, v_zimage, opaque=True),
    Sig("elf", (b"\x7fELF",), 0, v_elf, opaque=False),
    Sig("pem", (b"-----BEGIN ",), 0, v_pem, opaque=False, cap=5000),
)

MARKER_PATTERNS: tuple[tuple[str, re.Pattern[bytes], str], ...] = (
    ("uboot-version", re.compile(rb"U-Boot(?: SPL)? (?:\d{4}\.\d{2}|\d+\.\d+\.\d+)[^\x00\r\n]{0,96}"), "U-Boot 버전 문자열"),
    ("linux-version", re.compile(rb"Linux version \d+\.\d+[^\x00\r\n]{0,200}"), "리눅스 커널 버전 문자열 (비압축 커널)"),
    ("pweh-synthetic-marker", re.compile(rb"PWEH SYNTHETIC[^\x00\r\n]{0,160}"), "PWEH 합성(테스트/시뮬레이터) 펌웨어 마커"),
)

# 컨테이너 종류 중 안쪽 항목을 '중첩'으로만 보고하는 것들 (opaque 는 아예 검증하지 않음)
MARKER_KINDS = {"uboot-version", "linux-version", "pweh-synthetic-marker", "pem-private-key", "pem-certificate", "pem-other"}


class _Intervals:
    """겹치지 않는(대부분) 구간 집합: 점이 구간 '안쪽'(시작 제외)에 있는지 빠르게 확인."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def add(self, a: int, b: int) -> None:
        i = bisect.bisect_left(self.starts, a)
        self.starts.insert(i, a)
        self.ends.insert(i, b)

    def inside(self, x: int) -> bool:
        i = bisect.bisect_right(self.starts, x) - 1
        checked = 0
        # 구간은 대부분 겹치지 않으므로 가장 가까운 것 몇 개만 확인하면 된다 (겹침 대비 16개)
        while i >= 0 and checked < 16:
            if self.starts[i] < x < self.ends[i]:
                return True
            i -= 1
            checked += 1
        return False


def _candidates(buf: Any, sig: Sig, start: int, end: int, ctx: ScanCtx) -> tuple[list[int], bool]:
    pos_list: list[int] = []
    capped = False
    for magic in sig.magics:
        pos = start + sig.magic_offset
        while True:
            i = buf.find(magic, pos, end)
            if i < 0:
                break
            pos = i + 1
            s = i - sig.magic_offset
            if s < start:
                continue
            pos_list.append(s)
            if len(pos_list) >= sig.cap:
                capped = True
                break
        if capped:
            break
    pos_list.sort()
    return pos_list, capped


def scan_regions(buf: Any, start: int, end: int, ctx: ScanCtx, *, kinds: set[str] | None = None, env_scan: bool = True) -> list[Region]:
    """[start, end) 구간의 모든 검증된 영역 (중첩 포함, offset 순 정렬, parent 표시)."""
    regions: list[Region] = []
    opaque = _Intervals()
    total = max(1, end - start)
    for sig_index, sig in enumerate(SIGNATURES):
        if kinds and sig.kind not in kinds:
            continue
        if ctx.ctl.expired():
            ctx.notes.append(f"시간 예산 초과로 '{sig.kind}' 이후 시그니처 검사를 생략함")
            break
        ctx.ctl.progress(sig_index, len(SIGNATURES), f"{sig.kind} 검사 중")
        cands, capped = _candidates(buf, sig, start, end, ctx)
        if capped:
            ctx.notes.append(f"'{sig.kind}' 후보가 {sig.cap}개를 넘어 이후 후보는 검사하지 않음")
        skip_until = -1
        for n, s in enumerate(cands):
            if s < skip_until:
                continue
            ctx.stat(sig.kind, "candidates")
            if opaque.inside(s):
                ctx.stat(sig.kind, "skipped_nested")
                continue
            if (n & 0x3F) == 0 and ctx.ctl.expired():
                ctx.notes.append(f"시간 예산 초과로 '{sig.kind}' 후보 일부를 검사하지 않음")
                break
            try:
                r = sig.validate(buf, s, end, ctx)
            except (struct.error, IndexError, ValueError, OverflowError, UnicodeDecodeError, MemoryError) as exc:
                r = None
                ctx.stat(sig.kind, "errors")
                if len(ctx.notes) < 200:
                    ctx.notes.append(f"{sig.kind}@0x{s:x} 검증 중 예외: {type(exc).__name__}")
            if r is None:
                ctx.stat(sig.kind, "rejected")
                continue
            ctx.stat(sig.kind, "validated")
            regions.append(r)
            if r.size:
                skip_until = s + r.size
                # 잘린(선언 크기가 파일 끝을 넘는) 영역은 실제 범위를 알 수 없으므로 뒤쪽 후보를 숨기지 않는다
                if sig.opaque and not r.truncated:
                    opaque.add(s, s + r.size)
    # U-Boot env (CRC 검증, pweh.formats.find_uboot_env)
    if env_scan and (not kinds or "uboot-env" in kinds) and not ctx.ctl.expired():
        try:
            for hit in find_env_blocks(buf, end_limit=end, max_hits=16):
                if start <= hit["offset"] < end:
                    r = Region(
                        hit["offset"], "uboot-env",
                        f"U-Boot 환경변수 블록 ({'redundant, ' if hit.get('redundant') else ''}크기 {hit['size']} bytes, 변수 {len(hit['env'])}개, CRC {hit.get('crc_endian', 'little')})",
                        size=hit["size"], size_basis="header",
                        details={
                            "redundant": hit.get("redundant"), "flags": hit.get("flags"), "crc": hit.get("crc"), "crc_endian": hit.get("crc_endian", "little"),
                            "variables": len(hit["env"]), "has_bootargs": "bootargs" in hit["env"], "has_mtdparts": "mtdparts" in hit["env"] or "mtdparts=" in hit["env"].get("bootargs", ""),
                            "bootcmd": (hit["env"].get("bootcmd") or "")[:200] or None,
                        },
                    )
                    regions.append(r)
                    ctx.stat("uboot-env", "validated")
        except Exception as exc:  # pragma: no cover - 방어
            ctx.notes.append(f"env 스캔 실패: {type(exc).__name__}: {exc}")
    # 마커 문자열
    for kind, rx, label in MARKER_PATTERNS:
        if kinds and kind not in kinds:
            continue
        if ctx.ctl.expired():
            break
        seen = 0
        last_text = None
        for m in rx.finditer(buf, start, end):
            text = printable(m.group(0), 200)
            if text == last_text:
                continue
            last_text = text
            regions.append(Region(m.start(), kind, f"{label}: {text}", size=len(m.group(0)), size_basis="header", confidence="medium" if kind == "linux-version" else "high", details={"text": text}))
            ctx.stat(kind, "validated")
            seen += 1
            if seen >= 64:
                ctx.notes.append(f"'{kind}' 마커가 64개를 넘어 이후는 생략")
                break
    _assign_parents(regions)
    return regions


def _assign_parents(regions: list[Region]) -> None:
    regions.sort(key=lambda r: (r.offset, -(r.size or 0)))
    stack: list[Region] = []
    for r in regions:
        while stack and (stack[-1].end is None or stack[-1].end <= r.offset):
            stack.pop()
        if stack and stack[-1].offset < r.offset:
            parent = stack[-1]
            r.parent = parent.offset
            r.parent_kind = parent.kind
            if parent.kind == "uimage" and r.offset == parent.offset + 64 and "payload" not in parent.details:
                parent.details["payload"] = {"kind": r.kind, "description": r.description, "size": r.size}
        if r.size and r.kind not in MARKER_KINDS and not r.truncated:
            stack.append(r)


def probe_at(buf: Any, off: int, limit: int, ctl: Ctl) -> Region | None:
    """주어진 오프셋에서 시작하는 형식만 빠르게 확인 (fw_carve 의 파티션 내용 판별용)."""
    ctx = ScanCtx(ctl, decompress_budget=64 << 20, max_stream_in=8 << 20, max_stream_out=16 << 20)
    for sig in SIGNATURES:
        for magic in sig.magics:
            mo = off + sig.magic_offset
            if mo + len(magic) <= limit and bytes(buf[mo : mo + len(magic)]) == magic:
                try:
                    r = sig.validate(buf, off, limit, ctx)
                except (struct.error, IndexError, ValueError, OverflowError, UnicodeDecodeError, MemoryError):
                    r = None
                if r is not None:
                    return r
                break
    return None


# ---------------------------------------------------------------------------
# U-Boot env (코어 + big-endian CRC 보완 + CRC 없는 기본 env 후보)
# ---------------------------------------------------------------------------

_ENV_HINT = re.compile(rb"(bootcmd|bootargs|bootdelay|baudrate)=")


def _env_vars(payload: bytes) -> dict[str, str]:
    end = payload.find(b"\0\0")
    body = payload[: end if end >= 0 else len(payload)]
    env: dict[str, str] = {}
    for item in body.split(b"\0"):
        if not item or b"=" not in item:
            continue
        k, v = item.split(b"=", 1)
        env[k.decode("latin-1")] = v.decode("utf-8", "replace")
    return env


def find_env_blocks(buf: Any, *, end_limit: int | None = None, sizes: tuple[int, ...] = COMMON_ENV_SIZES, align: int = 0x1000, max_hits: int = 16) -> list[dict[str, Any]]:
    """CRC 가 맞는 U-Boot env 블록. 코어 find_uboot_env(리틀/빅엔디안 CRC 모두 검사) + 보완 스캔."""
    n = len(buf) if end_limit is None else min(len(buf), end_limit)
    view = buf if end_limit is None or end_limit >= len(buf) else buf[:n]
    hits = [dict(h, crc_endian=h.get("crc_endian", "little")) for h in find_uboot_env(view, sizes=sizes, align=align, max_hits=max_hits)]
    found = {h["offset"] for h in hits}
    for off in range(0, n, align):
        if len(hits) >= max_hits:
            break
        if off in found or not _ENV_HINT.search(buf, off + 4, min(n, off + 4 + 2048)):
            continue
        for size in sizes:
            if off + size > n:
                continue
            blk = bytes(buf[off : off + size])
            stored = struct.unpack(">I", blk[:4])[0]
            if stored == struct.unpack("<I", blk[:4])[0]:
                continue  # 대칭 값이면 이미 LE 검사에서 처리됨
            red = None
            if (zlib.crc32(blk[4:]) & M32) == stored:
                red = False
            elif (zlib.crc32(blk[5:]) & M32) == stored:
                red = True
            if red is None:
                continue
            env = _env_vars(blk[5:] if red else blk[4:])
            if env:
                h: dict[str, Any] = {"offset": off, "redundant": red, "crc": f"0x{stored:08x}", "size": size, "env": env, "crc_endian": "big"}
                if red:
                    h["flags"] = blk[4]
                hits.append(h)
                break
    hits.sort(key=lambda h: h["offset"])
    return hits


_DEFAULT_ENV_KEY = re.compile(rb"(?:bootcmd|bootargs)=")


def find_default_env_candidates(buf: Any, limit: int, *, max_hits: int = 8, exclude: list[tuple[int, int]] | None = None) -> list[dict[str, Any]]:
    """CRC 없이 바이너리(U-Boot 기본 env, CONFIG_EXTRA_ENV_SETTINGS 등)에 박힌 'k=v\\0k=v\\0...' 목록 후보."""
    out: list[dict[str, Any]] = []
    pos = 0
    exclude = exclude or []
    while len(out) < max_hits:
        m = _DEFAULT_ENV_KEY.search(buf, pos, limit)
        if not m:
            break
        i = m.start()
        pos = m.end()
        if any(a <= i < b for a, b in exclude):
            continue
        # 시작점: 앞쪽으로 'k=v\0' 항목들을 거슬러 올라간다 (최대 16KiB)
        start = i
        back_limit = max(0, i - 16384)
        while start > back_limit:
            j = start - 1
            if buf[j] != 0:
                break
            k = j - 1
            while k >= back_limit and 0x20 <= buf[k] < 0x7F:
                k -= 1
            item = bytes(buf[k + 1 : j])
            if not item or b"=" not in item or item.startswith(b"="):
                break
            start = k + 1
        # 끝: '\0\0' 또는 인쇄 불가 문자
        p = start
        items: list[bytes] = []
        while p < limit and len(items) < 512:
            q = p
            while q < limit and 0x20 <= buf[q] < 0x7F and q - p < 4096:
                q += 1
            if q >= limit or buf[q] != 0 or q == p:
                break
            item = bytes(buf[p:q])
            if b"=" not in item or item.startswith(b"="):
                break
            items.append(item)
            p = q + 1
        if len(items) < 3:
            continue
        env = {}
        for it in items:
            k, v = it.split(b"=", 1)
            env[k.decode("latin-1")] = v.decode("latin-1")
        if not re.fullmatch(r"[A-Za-z0-9_.#-]+", next(iter(env))):
            continue
        out.append({"offset": start, "size": p - start, "env": env, "source": "embedded-default-env (CRC 없음)"})
        pos = max(pos, p)
    return out


_MTDPARTS_STR = re.compile(rb"mtdparts=[A-Za-z0-9_.:,;@()\-+ ]{4,1024}")


def find_mtdparts_strings(buf: Any, limit: int, max_hits: int = 16) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for m in _MTDPARTS_STR.finditer(buf, 0, limit):
        text = m.group(0).split(b" ", 1)[0].decode("latin-1")
        if text in seen:
            continue
        seen.add(text)
        out.append({"offset": m.start(), "text": text})
        if len(out) >= max_hits:
            break
    return out


# ---------------------------------------------------------------------------
# 패딩(지워진 플래시 0xFF / 0x00) 구간
# ---------------------------------------------------------------------------


def padding_runs(buf: Any, start: int, end: int, ctl: Ctl, *, min_run: int = 0x10000, block: int = 0x1000, max_runs: int = 256) -> list[dict[str, Any]]:
    ff = b"\xff" * block
    zz = b"\x00" * block
    runs: list[dict[str, Any]] = []
    cur_kind = None
    cur_start = 0
    off = start
    n = 0
    while off + block <= end:
        blk = buf[off : off + block]
        kind = "erased-0xff" if blk == ff else ("zero-0x00" if blk == zz else None)
        if kind != cur_kind:
            if cur_kind is not None and off - cur_start >= min_run:
                runs.append({"offset": cur_start, "offset_hex": hexs(cur_start), "size": off - cur_start, "kind": cur_kind})
            cur_kind = kind
            cur_start = off
        off += block
        n += 1
        if (n & 0xFFF) == 0 and ctl.expired():
            break
    if cur_kind is not None and off - cur_start >= min_run:
        runs.append({"offset": cur_start, "offset_hex": hexs(cur_start), "size": off - cur_start, "kind": cur_kind})
    if len(runs) > max_runs:
        runs = sorted(sorted(runs, key=lambda r: -r["size"])[:max_runs], key=lambda r: r["offset"])
    return runs


def fill_ratio(buf: Any, a: int, b: int, byte: int, chunk: int = 1 << 20) -> float:
    if b <= a:
        return 0.0
    target = bytes([byte])
    cnt = 0
    p = a
    while p < b:
        blk = bytes(buf[p : min(b, p + chunk)])
        cnt += blk.count(target)
        p += len(blk)
    return cnt / (b - a)
