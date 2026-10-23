"""exFAT 해석 (Microsoft exFAT 파일 시스템 사양을 바탕으로 한 깨끗한 재구현).

다루는 것
- 주 부트 영역(섹터 0~11)과 백업 부트 영역(12~23): 부트 체크섬(섹터 0~10, VolumeFlags 106~107·PercentInUse 112 제외)을
  섹터 11 의 반복 값과 비교, 확장 부트 서명, 주/백업 일치. VolumeFlags(ActiveFat, VolumeDirty, MediaFailure, ClearToZero).
- 기하: FAT·클러스터 힙, NumberOfFats=2 이면 ActiveFat 이 FAT 과 할당 비트맵을 고른다.
- 루트의 할당 비트맵(0x81), up-case 표(0x82, 표 체크섬 확인·압축 해제 — 이름 해시 확인과 경로 비교에만 씀),
  볼륨 레이블(0x83), 볼륨 GUID(0xA0).
- 디렉터리 항목 집합: File(0x85) + Stream Extension(0xC0) + File Name(0xC1) [+ 벤더 0xE0/0xE1], SetChecksum 확인,
  NameHash 확인(up-case 적용), 속성, DataLength / ValidDataLength, NoFatChain, 시각(10ms 증분·UtcOffset).
- 삭제 항목 집합: InUse 비트만 지워진 0x05/0x40/0x41 — 체크섬은 InUse 비트를 되돌려 확인하고,
  클러스터가 지금 비트맵에서 비었는지 함께 보고한다. 일부가 새 항목에 덮인 집합은 남은 조각만 쓰고 고아 조각도 보고한다.
- 내용: NoFatChain 은 연속, FAT 체인은 따라간다. 삭제된 FAT 체인 파일은 남은(stale) FAT 체인을 따라간다
  (Linux 5.7~6.12 exFAT 은 삭제 때 FAT 항목을 쓰지 않는다) — 클러스터마다 비트맵과 충돌을 확인한다.
  내용은 항상 ValidDataLength 에서 자르고, ValidDataLength~DataLength 는 region='residual' 로 따로 읽는다
  (미리 할당하는 녹화기는 이 구간에 이전 녹화가 남는다).
- NoFatChain 파일·디렉터리의 FAT 항목은 정의되지 않았으므로 읽지 않는다. 루트 디렉터리는 항상 FAT 체인이다.
- 디렉터리 검증(base.py 설명): 클러스터마다 모든 슬롯이 엄격한 검사를 통과해야 해석한다 — 사용 중 항목 형식은 아는 것만(모르는 형식은 실패),
  SecondaryCount 범위, 파일 속성 예약 비트, 10ms 증분(0~199), 스트림·이름 항목 플래그, NameLength ≥ 1, AllocationPossible 과
  클러스터·크기의 일관성, 클러스터 번호 범위, 볼륨 레이블(CharacterCount ≤ 11)·비트맵·up-case·GUID 는 루트에만, 완전한 항목 집합의
  SetChecksum 일치(삭제 집합은 InUse 를 되돌려 계산). 해석하는 삭제 형식(0x05·0x40·0x41·0x03·0x60·0x61)도 같은 검사를 받는다.
  예약 바이트가 0 인지는 보지 않는다 — Linux exFAT 드라이버(5.x)는 다시 쓰는 슬롯의 예약 바이트를 지우지 않아 정상 디렉터리에도 이전
  내용이 남는다. 해석하지 않는 다른 InUse=0 슬롯(빈 자리)은 내용을 보지 않는다(내보내는 것도 없다).
- 목록용 삭제 항목 할당 요약(allocation_now)은 항목당 상한(FAT 체인 4096 클러스터, NoFatChain 비트맵 1M 클러스터)까지만 대조하고
  구간 단위로 센다. 예산 안에서만 한다.

ref 와 dirspec 은 base.py 설명과 같다: root, c<클러스터>[+<바이트>](FAT 체인), n<클러스터>+<바이트>(연속, NoFatChain).
"""

from __future__ import annotations

import re
import struct
from array import array
from bisect import bisect_right
from collections import OrderedDict, deque
from typing import Any, Iterator

from .base import DirCtx, DirResult, Peek, VolumeBase
from .fat import _CLUSTER_REASONS, _cluster_inspection, _cluster_reason
from .common import (
    CONFIDENCE_ORDER,
    Budget,
    ContentPlan,
    FsError,
    Limits,
    Warnings,
    ceil_div,
    decode_utf16le,
    display_name,
    exfat_timestamp,
    guard,
)
from .tables import BitSet, Chain, ClusterBitmap, FatTable, follow_chain

__all__ = ["ExfatVolume", "parse_exfat_boot", "probe_exfat_boot_sector", "boot_checksum", "entry_set_checksum",
           "name_hash", "upcase_table_checksum"]

EXFAT_EOC = 0xFFFFFFFF
EXFAT_BAD = 0xFFFFFFF7
MAX_DIR_BYTES = 256 << 20  # 사양: 디렉터리 최대 256 MiB
UPCASE_MAX_BYTES = 65536 * 2
_ATTR_NAMES = ((0x01, "readonly"), (0x02, "hidden"), (0x04, "system"), (0x08, "reserved1"),
               (0x10, "directory"), (0x20, "archive"))
_SPEC_RE = re.compile(r"^(?:(root)|c(\d{1,10})(?:\+(\d{1,10}))?|n(\d{1,10})\+(\d{1,10}))$")
_SECONDARY_LIVE = (0xC1, 0xE0, 0xE1)
_SECONDARY_DEL = (0x41, 0x60, 0x61)
_DELETED_STATUS_CHECK = 4096  # 목록용 요약: 삭제 항목 하나에 대해 FAT 체인을 따라가 비트맵과 대조할 최대 클러스터 수
_DELETED_STATUS_CHECK_CONTIG = 1 << 20  # 목록용 요약: NoFatChain(연속) 삭제 항목의 비트맵 대조 상한 (바이트 popcount)


def boot_checksum(sectors: bytes, bytes_per_sector: int) -> int:
    """주/백업 부트 영역 섹터 0~10 의 32비트 회전 체크섬 (VolumeFlags·PercentInUse 바이트 제외)."""
    s = 0
    for i in range(bytes_per_sector * 11):
        if i == 106 or i == 107 or i == 112:
            continue
        s = ((((s & 1) << 31) | (s >> 1)) + sectors[i]) & 0xFFFFFFFF
    return s


def entry_set_checksum(entries: list[bytes], *, force_in_use: bool = False) -> int:
    """항목 집합의 16비트 SetChecksum (첫 항목의 2~3 바이트 제외). force_in_use 면 각 항목 형식 바이트의 InUse 비트를 켠 값으로 계산."""
    data = bytearray(b"".join(bytes(e[:32]) for e in entries))
    if force_in_use:
        for k in range(0, len(data), 32):
            data[k] |= 0x80
    s = 0
    for b in data[:2]:
        s = ((((s & 1) << 15) | (s >> 1)) + b) & 0xFFFF
    for b in data[4:]:
        s = ((((s & 1) << 15) | (s >> 1)) + b) & 0xFFFF
    return s


def name_hash(upcased_utf16le: bytes) -> int:
    """up-case 한 이름(UTF-16LE 바이트)의 16비트 NameHash."""
    h = 0
    for b in upcased_utf16le:
        h = ((((h & 1) << 15) | (h >> 1)) + b) & 0xFFFF
    return h


def upcase_table_checksum(data: bytes) -> int:
    s = 0
    for b in data:
        s = ((((s & 1) << 31) | (s >> 1)) + b) & 0xFFFFFFFF
    return s


def parse_exfat_boot(bs: bytes, w: Warnings | None = None) -> dict[str, Any]:
    """주 부트 섹터 해석. exFAT 가 아니면 FsError(reason="not_exfat")."""
    w = w if w is not None else Warnings()
    if len(bs) < 512 or bytes(bs[3:11]) != b"EXFAT   ":
        raise FsError("exFAT 부트 섹터가 아닙니다(FileSystemName 이 'EXFAT   ' 이 아님).", reason="not_exfat")
    (part_off, vol_len, fat_off, fat_len, heap_off, count, root, serial, rev, flags, bps_sh, spc_sh, nfats, drive,
     pct) = struct.unpack_from("<QQIIIIIIHHBBBBB", bs, 64)
    if bytes(bs[0:3]) != b"\xeb\x76\x90":
        w.add("exfat_bad_jump", "JumpBoot 가 EB 76 90 이 아닙니다.", value=bytes(bs[0:3]).hex())
    if any(bs[11:64]):
        w.add("exfat_mbz_nonzero", "MustBeZero 영역(바이트 11~63)이 0 이 아닙니다.")
    if not 9 <= bps_sh <= 12:
        raise FsError(f"BytesPerSectorShift 값이 잘못됐습니다: {bps_sh}", reason="not_exfat")
    if spc_sh > 25 - bps_sh:
        raise FsError(f"SectorsPerClusterShift 값이 잘못됐습니다: {spc_sh}", reason="not_exfat")
    if nfats == 0:
        raise FsError("NumberOfFats 가 0 입니다.", reason="not_exfat")
    if nfats > 2:
        w.add("exfat_number_of_fats", f"NumberOfFats {nfats} 는 사양 밖입니다(1 로 읽음).")
        nfats = 1
    if fat_len == 0:
        raise FsError("FatLength 가 0 입니다.", reason="not_exfat")
    if count == 0 or count > 0xFFFFFFF5:
        raise FsError(f"ClusterCount 값이 잘못됐습니다: {count}", reason="not_exfat")
    if bs[510] != 0x55 or bs[511] != 0xAA:
        w.add("boot_signature_missing", "부트 섹터 끝 서명 0x55AA 가 없습니다.")
    if fat_off < 24:
        w.add("exfat_fat_offset_small", f"FatOffset {fat_off} 가 24 보다 작습니다(부트 영역과 겹침).")
    if heap_off < fat_off + fat_len * nfats:
        w.add("exfat_heap_overlaps_fat", "ClusterHeapOffset 이 FAT 영역과 겹칩니다.")
    if vol_len < ((1 << 20) >> bps_sh):
        w.add("exfat_volume_small", "VolumeLength 가 1 MiB 보다 작습니다.")
    bps = 1 << bps_sh
    spc = 1 << spc_sh
    eff = count
    max_by_len = (vol_len - heap_off) >> spc_sh if vol_len > heap_off else 0
    if eff > max_by_len:
        w.add("exfat_cluster_count_exceeds_volume", "ClusterCount 가 볼륨 길이로 담을 수 있는 수보다 큽니다(줄여서 읽음).",
              cluster_count=count, max_by_length=max_by_len)
        eff = max_by_len
    fat_cap = (fat_len * bps) // 4
    if fat_cap < eff + 2:
        w.add("exfat_fat_too_small", "FAT 이 모든 클러스터를 담기에 작습니다(줄여서 읽음).", capacity=fat_cap)
        eff = max(0, fat_cap - 2)
    if eff < 1:
        raise FsError("사용할 수 있는 클러스터가 없습니다.", reason="not_exfat")
    if not 2 <= root <= eff + 1:
        w.add("exfat_root_cluster_invalid", f"루트 디렉터리 클러스터 {root} 가 범위를 벗어났습니다.")
    if (rev >> 8) != 1:
        w.add("exfat_revision", f"FileSystemRevision {rev >> 8}.{rev & 0xFF:02d} 은 1.x 가 아닙니다.")
    if pct > 100 and pct != 0xFF:
        w.add("exfat_percent_in_use", f"PercentInUse 값이 잘못됐습니다: {pct}")
    return {
        "partition_offset": part_off,
        "volume_length": vol_len,
        "fat_offset": fat_off,
        "fat_length": fat_len,
        "cluster_heap_offset": heap_off,
        "cluster_count": count,
        "cluster_count_effective": eff,
        "root_cluster": root,
        "volume_serial": serial,
        "fs_revision": rev,
        "volume_flags": flags,
        "bytes_per_sector_shift": bps_sh,
        "sectors_per_cluster_shift": spc_sh,
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "cluster_size": bps * spc,
        "number_of_fats": nfats,
        "drive_select": drive,
        "percent_in_use": pct,
    }


def probe_exfat_boot_sector(bs: bytes) -> dict[str, Any] | None:
    try:
        return parse_exfat_boot(bs, Warnings(0))
    except FsError:
        return None
    except Exception:  # noqa: BLE001
        return None


class _Peek:
    """앞을 내다볼 수 있는 반복자 (항목 집합은 최대 19 슬롯)."""

    __slots__ = ("it", "buf")

    def __init__(self, it: Iterator[tuple[int, int, bytes]]) -> None:
        self.it = it
        self.buf: deque[tuple[int, int, bytes]] = deque()

    def _fill(self, n: int) -> None:
        while len(self.buf) < n:
            try:
                self.buf.append(next(self.it))
            except StopIteration:
                return

    def pop(self) -> tuple[int, int, bytes] | None:
        self._fill(1)
        return self.buf.popleft() if self.buf else None

    def peek(self, n: int) -> list[tuple[int, int, bytes]]:
        self._fill(n)
        return [self.buf[i] for i in range(min(n, len(self.buf)))]


def _attr_flags(attr: int) -> list[str]:
    return [name for bit, name in _ATTR_NAMES if attr & bit]


class ExfatVolume(VolumeBase):
    """exFAT 볼륨 (읽기 전용)."""

    kind = "exfat"
    max_slot = MAX_DIR_BYTES // 32

    @guard
    def __init__(self, src: Any, *, limits: Limits | None = None, budget: Budget | None = None,
                 metadata_mode: str = "full") -> None:
        if type(metadata_mode) is not str or metadata_mode not in ("full", "allocation"):
            raise FsError("메타데이터 모드가 올바르지 않습니다.", reason="bad_argument")
        self.metadata_mode = metadata_mode
        self.src = src
        self.limits = limits or Limits()
        self.base_offset = int(getattr(src, "base_offset", 0))
        self._w = Warnings(self.limits.max_warnings)
        if src.size < 512:
            raise FsError("exFAT 부트 섹터를 읽을 수 없습니다(512바이트 미만).", reason="not_exfat")
        boot_bytes = src.read(0, 512)
        b = parse_exfat_boot(boot_bytes, self._w)
        self.boot = b
        bps = b["bytes_per_sector"]
        self.bytes_per_sector = bps
        self.cluster_size = b["cluster_size"]
        self.cluster_count = b["cluster_count_effective"]
        self.max_cluster = self.cluster_count + 1
        self.heap_offset = b["cluster_heap_offset"] * bps
        self.volume_size = b["volume_length"] * bps
        self.volume_flags = b["volume_flags"]
        self.root_cluster = b["root_cluster"]
        nf = b["number_of_fats"]
        self.active_fat = (self.volume_flags & 1) if nf == 2 else 0
        if self.volume_flags & 1 and nf != 2:
            self._w.add("exfat_active_fat_invalid", "ActiveFat=1 인데 FAT 이 하나뿐입니다(첫 FAT 사용).")
        self.fat_offset = (b["fat_offset"] + self.active_fat * b["fat_length"]) * bps
        self._fat = FatTable(src, self.fat_offset, b["fat_length"] * bps, 32, self.max_cluster)
        if self.volume_size > src.size:
            self._w.add("volume_truncated", "이미지(또는 파티션)가 볼륨 크기보다 짧습니다 — 뒷부분 클러스터는 읽을 수 없습니다.",
                        volume_size=self.volume_size, available=src.size)
        self.boot_region = self._check_boot_regions()
        self._dir_cache: "OrderedDict[str, DirResult]" = OrderedDict()
        self._live_cache: dict[str, Any] | None = None
        self._bitmap: ClusterBitmap | None = None
        self._upcase: array | None = None
        self._fold_map: dict[int, int] | None = None
        self.bitmap_info: dict[str, Any] = {"present": False}
        self.upcase_info: dict[str, Any] = {"present": False}
        self.label: str | None = None
        self.volume_guid: str | None = None
        # full의 기존 선택·fallback은 그대로 두고 검사 완료도에 필요한 사실만 남긴다.
        self._cluster_metadata_reasons: set[str] = set()
        self._cluster_metadata_map_complete = True
        self._cluster_metadata_allocation_complete = True
        if boot_bytes[110] not in (1, 2) or (self.volume_flags & 1 and boot_bytes[110] != 2):
            self._cluster_metadata_reasons.add("metadata_inconsistent")
            self._cluster_metadata_allocation_complete = False
        if budget is None:
            budget = self._budget()
        else:
            budget.raise_steps(self.step_cap())  # 호출자가 이 볼륨에 함께 쓸 예산 — 이 볼륨의 단계 상한까지 올린다
        if metadata_mode == "full":
            self._load_root_metadata(budget)
        else:
            self.allocation_status = "unknown"
            self.allocation_reason: str | None = "volume_metadata_inconsistent"
            original_nfats = boot_bytes[110]
            if original_nfats not in (1, 2) or (self.volume_flags & 1 and original_nfats != 2):
                self.allocation_reason = "active_fat_invalid"
            elif self._allocation_geometry_valid(boot_bytes):
                self._load_allocation_metadata(budget)

    # ------------------------------------------------------------------
    # 기본 도우미
    # ------------------------------------------------------------------
    def _fs_name(self) -> str:
        return "exfat"

    def cluster_offset(self, c: int) -> int:
        return self.heap_offset + (c - 2) * self.cluster_size

    def fat_entry(self, c: int) -> int | None:
        return self._fat.get(c)

    def _kind(self, v: int | None) -> str:
        if v is None:
            return "unreadable"
        if v == EXFAT_EOC:
            return "eoc"
        if v == EXFAT_BAD:
            return "bad"
        if 2 <= v <= self.max_cluster:
            return "next"
        if v == 0:
            return "free"
        return "invalid"

    def _follow(self, start: int, limit: int, budget: Budget | None = None) -> Chain:
        return follow_chain(self._fat.get, self._kind, start, limit, self.max_cluster, max_runs=self.limits.max_runs,
                            budget=budget)

    def _count_allocated_runs(self, starts: Any, lens: Any) -> tuple[int, int]:
        """구간들 안의 비트맵 1 비트 수와 읽은 비트 수 (구간마다 바이트 popcount — 클러스터 목록을 만들지 않는다)."""
        ones = seen = 0
        if self._bitmap is None:
            return 0, 0
        for s0, k in zip(starts, lens):
            o, n = self._bitmap.count_range(int(s0) - 2, int(s0) - 2 + int(k))
            ones += o
            seen += n
        return ones, seen

    def allocated(self, c: int) -> bool | None:
        """비트맵에서 클러스터 c 가 할당됐는지 (비트맵이 없거나 읽을 수 없으면 None)."""
        if self._bitmap is None:
            return None
        return self._bitmap.get(c - 2)

    def _count_allocated_run(self, start: int, n: int) -> tuple[int, int] | None:
        if self._bitmap is None:
            return None
        return self._bitmap.count_range(start - 2, start - 2 + n)

    # ------------------------------------------------------------------
    # 부트 영역
    # ------------------------------------------------------------------
    def _region_info(self, data: bytes, bps: int) -> dict[str, Any]:
        if len(data) < 12 * bps:
            return {"readable": False, "checksum_ok": None}
        calc = boot_checksum(data, bps)
        words = struct.unpack_from(f"<{bps // 4}I", data, 11 * bps)
        match = sum(1 for x in words if x == calc)
        ext_ok = sum(1 for k in range(1, 9) if data[(k + 1) * bps - 4:(k + 1) * bps] == b"\x00\x00\x55\xaa")
        return {"readable": True, "checksum_ok": match == len(words), "computed": f"0x{calc:08x}",
                "stored": f"0x{words[0]:08x}", "matching_words": match, "words": len(words),
                "extended_signatures_ok": ext_ok}

    def _check_boot_regions(self) -> dict[str, Any]:
        bps = self.bytes_per_sector
        main = self.src.read_clamped(0, 12 * bps)
        out: dict[str, Any] = {"main": self._region_info(main, bps), "backup": None, "backup_matches_main": None}
        if out["main"]["checksum_ok"] is False:
            self._w.add("boot_checksum_mismatch", "주 부트 영역 체크섬이 섹터 11 의 값과 다릅니다(부트 영역 손상·변조).",
                        computed=out["main"]["computed"], stored=out["main"]["stored"])
        elif out["main"]["checksum_ok"] is None:
            self._w.add("boot_region_unreadable", "주 부트 영역 12 섹터를 다 읽을 수 없습니다.")
        backup = self.src.read_clamped(12 * bps, 12 * bps)
        if len(backup) == 12 * bps:
            out["backup"] = self._region_info(backup, bps)
            a = bytearray(main[:11 * bps])
            c = bytearray(backup[:11 * bps])
            for i in (106, 107, 112):
                if i < len(a) and i < len(c):
                    a[i] = c[i] = 0
            out["backup_matches_main"] = a == c
            if out["backup"]["checksum_ok"] is False:
                self._w.add("backup_boot_checksum_mismatch", "백업 부트 영역 체크섬이 맞지 않습니다.")
            if not out["backup_matches_main"]:
                self._w.add("backup_boot_differs", "백업 부트 영역이 주 부트 영역과 다릅니다(VolumeFlags·PercentInUse 제외).")
        return out

    # ------------------------------------------------------------------
    # 루트의 비트맵·up-case·레이블
    # ------------------------------------------------------------------
    def _allocation_geometry_valid(self, boot_bytes: bytes) -> bool:
        """복구용 축소·fallback을 할당 판정의 권위로 쓰지 않는다."""
        b = self.boot
        main, backup = self.boot_region["main"], self.boot_region["backup"]
        return (b["cluster_count"] == self.cluster_count
                and b["fat_offset"] >= 24
                and b["cluster_heap_offset"] >= b["fat_offset"] + b["fat_length"] * b["number_of_fats"]
                and self.volume_size <= self.src.size
                and not getattr(self.src, "truncated", False)
                and boot_bytes[:3] == b"\xeb\x76\x90" and not any(boot_bytes[11:64])
                and boot_bytes[510:512] == b"\x55\xaa"
                and b["fs_revision"] >> 8 == 1
                and main.get("checksum_ok") is True and main.get("extended_signatures_ok") == 8
                and backup is not None and backup.get("checksum_ok") is True
                and backup.get("extended_signatures_ok") == 8
                and self.boot_region["backup_matches_main"] is True)

    def _allocation_stop(self, reason: str | None) -> None:
        """공유 예산의 중단만 별도 상태로 바꾸며 취소는 전파한다."""
        reasons = {"time": "time_limit", "steps": "step_limit", "metadata_bytes": "metadata_bytes_limit"}
        if reason not in reasons:
            raise FsError("할당 메타데이터 검사가 중단됐습니다.", reason="budget_exceeded",
                          data={"limit": reason})
        self.allocation_status = "stopped"
        self.allocation_reason = reasons[reason]

    def _load_allocation_metadata(self, budget: Budget) -> None:
        """이름/시각/내용을 해석하지 않고 활성 bitmap의 실제 체인만 준비한다."""
        try:
            self._prepare_allocation_bitmap(budget)
        except FsError as exc:
            if exc.reason == "budget_exceeded":
                self._allocation_stop(exc.data.get("limit"))
            else:
                # 실제 읽기 원인은 호출자의 read latch가 전체 실패로 복원한다.
                self.allocation_status = "unknown"
            self._bitmap = None

    def _prepare_allocation_bitmap(self, budget: Budget) -> None:
        self.allocation_reason = "root_metadata_incomplete"
        if budget.expired():
            self._allocation_stop(budget.reason)
            return
        max_slots = min(self.limits.max_dir_slots, 32768)
        # 잘린 클러스터를 완전 검증 단위로 인정하지 않는다.
        full_slots = (max_slots * 32 // self.cluster_size) * (self.cluster_size // 32)
        if full_slots == 0:
            self.allocation_status, self.allocation_reason = "stopped", "root_slots_limit"
            return
        res = DirResult("root", self.limits.max_warnings)
        runs, res.chain = self._dir_runs(("root",), res.warnings, budget)
        if budget.expired() or res.chain.get("limit_reason"):
            self._allocation_stop(res.chain.get("limit_reason") or budget.reason)
            return
        # 기존 _dir_runs의 기본 full 한도를 바꾸지 않고 이 호출의 전체 단위만 남긴다.
        clipped, left = [], full_slots * 32
        for off, size in runs:
            take = min(size, left) // self.cluster_size * self.cluster_size
            if take:
                clipped.append((off, take))
                left -= take
            if take < size:
                break
        selected = None
        matched = total = 0
        pending, secondary = 0, ()
        slots = self._validated_slots(res, DirCtx("root", ("root",)), clipped,
                                      self.cluster_size, full_slots, budget)
        for slot, _, raw in slots:
            res.slots = slot + 1
            typ = raw[0]
            if pending:
                expected = (secondary[0],) if pending == secondary[2] else secondary[1]
                if typ not in expected:
                    return
                pending -= 1
            elif typ in (0x85, 0x05):
                pending = raw[1]
                secondary = ((0xC0 if typ == 0x85 else 0x40),
                             (_SECONDARY_LIVE if typ == 0x85 else _SECONDARY_DEL), pending)
            elif typ == 0:
                res.end_slot = slot
                break
            elif typ == 0x81:
                total += 1
                if raw[1] & 1 == self.active_fat:
                    matched += 1
                    selected = struct.unpack_from("<IQ", raw, 20)
        if budget.expired() or res.budget_stop:
            self._allocation_stop(res.budget_stop or budget.reason)
            return
        if res.unvalidated is not None or pending:
            return
        if res.end_slot is None:
            if res.chain.get("status") == "too_fragmented":
                self.allocation_status, self.allocation_reason = "stopped", "bitmap_runs_limit"
                return
            if res.chain.get("cut") or sum(n for _, n in runs) > full_slots * 32:
                self.allocation_status, self.allocation_reason = "stopped", "root_slots_limit"
                return
            if res.chain.get("status") != "ok" or res.scanned * 32 != sum(n for _, n in clipped):
                return
        if matched != 1:
            self.allocation_reason = ("bitmap_ambiguous" if matched > 1 else
                                      "bitmap_active_mismatch" if total else "bitmap_missing")
            return
        self.allocation_reason = "bitmap_chain_invalid"
        fc, length = selected
        if not 0 < length <= self.cluster_count * self.cluster_size or not 2 <= fc <= self.max_cluster:
            return
        needed = ceil_div(length, self.cluster_size)
        chain = self._follow(fc, needed, budget)
        if budget.expired() or chain.capped:
            self._allocation_stop(chain.capped or budget.reason)
            return
        if chain.status == "too_fragmented":
            self.allocation_status, self.allocation_reason = "stopped", "bitmap_runs_limit"
            return
        # 마지막 FAT도 EOC여야 한다. 짧거나 긴 체인을 연속 배치로 추정하지 않는다.
        if chain.status != "ok" or chain.count != needed:
            return
        extents, left = [], length
        # 이미 확인한 root 체인과의 모순만 본다. 다른 파일/디렉터리를 탐색하지 않는다.
        root_ranges = sorted((off, off + size) for off, size in clipped)
        root_starts = [off for off, _ in root_ranges]
        for start, count in zip(chain.starts, chain.lens):
            budget.tick()
            if budget.expired():
                self._allocation_stop(budget.reason)
                return
            take = min(left, count * self.cluster_size)
            off = self.cluster_offset(start)
            if off + take > self.src.size:
                return
            root_index = bisect_right(root_starts, off + take - 1) - 1
            if root_index >= 0 and root_ranges[root_index][1] > off:
                return
            extents.append((off, take))
            left -= take
        if budget.expired():
            self._allocation_stop(budget.reason)
            return
        self._bitmap = ClusterBitmap(self.src, extents, min(self.cluster_count, length * 8))
        self.allocation_status, self.allocation_reason = "ready", None

    def _object_runs(self, fc: int, length: int, w: Warnings, what: str,
                     budget: Budget | None = None) -> list[tuple[int, int]]:
        """FAT 체인으로 기록되는 메타데이터 객체(비트맵, up-case 표)의 바이트 구간. 체인이 깨졌으면 연속으로 가정."""
        cs = self.cluster_size
        n = ceil_div(length, cs)
        if n <= 0 or not 2 <= fc <= self.max_cluster:
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_reasons.add("reference_chain_incomplete")
            if what == "bitmap":
                self._cluster_metadata_allocation_complete = False
                self._cluster_metadata_reasons.add("metadata_inconsistent")
            w.add(f"{what}_cluster_invalid", f"{what} 의 시작 클러스터 {fc} 가 범위를 벗어났습니다.")
            return []
        ch = self._follow(fc, n, budget)
        if ch.status != "ok" or ch.count != n or ch.capped:
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_reasons.add("reference_chain_incomplete")
            if what == "bitmap":
                self._cluster_metadata_allocation_complete = False
                self._cluster_metadata_reasons.add("metadata_inconsistent")
        runs: list[tuple[int, int]]
        if ch.count < n:
            w.add(f"{what}_chain_short", f"{what} 의 FAT 체인이 짧습니다({ch.count}/{n}, {ch.status}) — 연속으로 가정합니다.")
            runs = [(fc, min(n, self.max_cluster - fc + 1))]
        else:
            runs = list(zip(ch.starts, ch.lens))
        out: list[tuple[int, int]] = []
        remaining = length
        for s, k in runs:
            if remaining <= 0:
                break
            take = min(k * cs, remaining)
            out.append((self.cluster_offset(s), take))
            remaining -= take
        return out

    def _load_root_metadata(self, budget: Budget) -> None:
        try:
            self._load_root_metadata_full(budget)
            if budget.expired():
                raise budget.error("루트 메타데이터 검사")
        except FsError as exc:
            if exc.reason != "budget_exceeded":
                raise
            self._cluster_metadata_reasons.add(_cluster_reason(exc.data.get("limit")))
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_allocation_complete = False

    def _load_root_metadata_full(self, budget: Budget) -> None:
        try:
            res = self._parse_dir("root", budget)
        except FsError as e:
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_allocation_complete = False
            if e.reason == "budget_exceeded":
                self._cluster_metadata_reasons.add(_cluster_reason(e.data.get("limit")))
            else:
                self._cluster_metadata_reasons.add("dir_unreadable")
            self._w.add("root_unreadable", f"루트 디렉터리를 읽을 수 없습니다: {e.message}")
            return
        if res.budget_stop:
            self._cluster_metadata_reasons.add(_cluster_reason(res.budget_stop))
        if res.unvalidated is not None:
            self._cluster_metadata_reasons.add("dir_unvalidated")
        if res.cut_hit():
            self._cluster_metadata_reasons.add("max_dir_slots")
        if res.chain.get("status") != "ok":
            self._cluster_metadata_reasons.add("reference_chain_incomplete")
        if self._cluster_metadata_reasons - {"metadata_inconsistent"}:
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_allocation_complete = False
        for it in res.warnings.items:
            if it["code"] == "dir_unvalidated":
                self._w.add(**it)
        if res.budget_stop is not None:
            self._w.add("budget_exceeded", "예산이 다 돼 루트 디렉터리를 끝까지 읽지 못했습니다(비트맵·up-case·레이블이 빠졌을 수 있음).",
                        limit=res.budget_stop)
        sp = res.extra.get("specials", {})
        self.label = sp.get("label")
        self.volume_guid = sp.get("guid")
        bitmaps = sp.get("bitmaps", [])
        active = [cand for cand in bitmaps if cand["flags"] & 1 == self.active_fat]
        if len(active) != 1 or any(cand["flags"] & 0xFE for cand in bitmaps):
            self._cluster_metadata_allocation_complete = False
            self._cluster_metadata_reasons.add("metadata_inconsistent" if bitmaps else "allocation_unreadable")
        bm = None
        for cand in bitmaps:
            if (cand["flags"] & 1) == self.active_fat:
                bm = cand
                break
        if bm is None and bitmaps:
            bm = bitmaps[0]
            self._w.add("bitmap_active_mismatch", "활성 FAT 에 맞는 할당 비트맵 항목이 없어 첫 비트맵을 씁니다.")
        if bm is None:
            self._w.add("bitmap_missing", "루트에 할당 비트맵 항목(0x81)이 없습니다 — 할당 상태를 판단할 수 없습니다.")
        else:
            need = ceil_div(self.cluster_count, 8)
            length = bm["data_length"]
            info = {"present": True, "first_cluster": bm["first_cluster"], "data_length": length,
                    "expected_length": need, "flags": bm["flags"], "slot": bm["slot"]}
            if length < need:
                self._cluster_metadata_allocation_complete = False
                self._cluster_metadata_reasons.add("metadata_inconsistent")
                self._w.add("bitmap_short", f"할당 비트맵이 짧습니다({length} < {need} 바이트).")
            length = min(length, max(need, 0))
            runs = self._object_runs(bm["first_cluster"], length, self._w, "bitmap", budget)
            if runs:
                self._bitmap = ClusterBitmap(self.src, runs, min(self.cluster_count, length * 8))
                ones, seen = self._bitmap.count_range(0, self.cluster_count)
                info["allocated_clusters"] = ones
                info["readable_bits"] = seen
                if seen < self.cluster_count:
                    self._cluster_metadata_allocation_complete = False
                    self._cluster_metadata_reasons.add("allocation_unreadable")
            self.bitmap_info = info
        up = sp.get("upcase")
        if up is None:
            self._cluster_metadata_map_complete = False
            self._cluster_metadata_reasons.add("metadata_inconsistent")
            self._w.add("upcase_missing", "루트에 up-case 표 항목(0x82)이 없습니다(이름 비교는 단순 대문자화).")
        else:
            info = {"present": True, "first_cluster": up["first_cluster"], "data_length": up["data_length"],
                    "stored_checksum": f"0x{up['checksum']:08x}", "checksum_ok": None}
            if not 0 < up["data_length"] <= UPCASE_MAX_BYTES:
                self._cluster_metadata_map_complete = False
                self._cluster_metadata_reasons.add("metadata_inconsistent")
                self._w.add("upcase_size_invalid", f"up-case 표 크기 {up['data_length']} 가 범위를 벗어났습니다(무시).")
            else:
                runs = self._object_runs(up["first_cluster"], up["data_length"], self._w, "upcase", budget)
                data = b"".join(self.src.read_clamped(o, n) for o, n in runs)
                if len(data) == up["data_length"]:
                    calc = upcase_table_checksum(data)
                    info["computed_checksum"] = f"0x{calc:08x}"
                    info["checksum_ok"] = calc == up["checksum"]
                    if not info["checksum_ok"]:
                        self._cluster_metadata_map_complete = False
                        self._cluster_metadata_reasons.add("metadata_inconsistent")
                        self._w.add("upcase_checksum_mismatch", "up-case 표 체크섬이 맞지 않습니다.")
                    self._upcase = self._decompress_upcase(data)
                else:
                    self._cluster_metadata_map_complete = False
                    self._cluster_metadata_reasons.add("metadata_inconsistent")
                    self._w.add("upcase_unreadable", "up-case 표를 다 읽을 수 없습니다.")
            self.upcase_info = info
        # 비트맵을 읽은 뒤에는 삭제 항목의 할당 상태를 다시 계산해야 하므로 캐시를 비운다
        self._dir_cache.clear()

    @staticmethod
    def _decompress_upcase(data: bytes) -> array:
        table = array("H", range(65536))
        units = struct.unpack(f"<{len(data) // 2}H", data[: len(data) // 2 * 2])
        i = 0
        k = 0
        while k < len(units) and i < 65536:
            u = units[k]
            if u == 0xFFFF and k + 1 < len(units):
                i += units[k + 1]
                k += 2
                continue
            table[i] = u
            i += 1
            k += 1
        return table

    def _upcase_units(self, raw_utf16: bytes) -> bytes:
        units = array("H")
        units.frombytes(raw_utf16[: len(raw_utf16) // 2 * 2])
        if self._upcase is not None:
            t = self._upcase
            units = array("H", (t[u] for u in units))
        else:
            units = array("H", ((u - 32) if 0x61 <= u <= 0x7A else u for u in units))
        return units.tobytes()

    def _upcase_str(self, s: str) -> str:
        raw = s.encode("utf-16-le", errors="surrogatepass")
        return self._upcase_units(raw).decode("utf-16-le", errors="replace")

    def _fold(self, s: str) -> str:
        """exFAT 이름 비교: 볼륨의 up-case 표로 글자마다 바꾼다(표는 UTF-16 단위 하나 → 하나라 글자 수가 변하지 않는다).

        표가 없으면 ASCII a-z 만 대문자로. str.translate 로 C 수준에서 바꾼다(BMP 밖 글자는 표에 없어 그대로)."""
        m = self._fold_map
        if m is None:
            if self._upcase is not None:
                t = self._upcase
                m = {i: t[i] for i in range(65536) if t[i] != i and not 0xD800 <= i <= 0xDFFF}
            else:
                m = {i: i - 32 for i in range(0x61, 0x7B)}
            self._fold_map = m
        return s.translate(m)

    def _method_names(self, e: dict[str, Any], region: str = "data") -> list[str]:
        if region not in ("data", "residual"):
            return []
        dlen = e["size"]
        vdl = min(e["valid_data_length"], dlen)
        size = vdl if region == "data" else dlen - vdl
        if ceil_div(dlen, self.cluster_size) == 0 or size == 0:
            return ["empty"]
        if not 2 <= e["first_cluster"] <= self.max_cluster:
            return ["none"]
        if not e["deleted"]:
            return ["nofatchain" if e["no_fat_chain"] else "chain"]
        if e["no_fat_chain"]:
            return ["contiguous"]
        return ["stale-chain", "contiguous"] + (["skip-allocated"] if self._bitmap is not None else [])

    # ------------------------------------------------------------------
    # dirspec
    # ------------------------------------------------------------------
    def _parse_spec(self, spec: str) -> tuple[Any, ...]:
        if not isinstance(spec, str):
            raise FsError("디렉터리 지정이 문자열이 아닙니다.", reason="bad_ref")
        m = _SPEC_RE.match(spec)
        if not m:
            raise FsError(f"디렉터리 지정 형식이 잘못됐습니다: {spec[:60]!r}", reason="bad_ref",
                          hint="root, c<클러스터>[+<바이트>], n<클러스터>+<바이트> 중 하나")
        if m.group(1):
            return ("root",)
        if m.group(2) is not None:
            c = int(m.group(2))
            length = int(m.group(3)) if m.group(3) is not None else None
            kind = "chain"
        else:
            c = int(m.group(4))
            length = int(m.group(5))
            kind = "contig"
        if not 2 <= c <= self.max_cluster:
            raise FsError(f"디렉터리 클러스터 {c} 가 범위(2..{self.max_cluster})를 벗어났습니다.", reason="bad_ref")
        if length is not None and not 1 <= length <= MAX_DIR_BYTES:
            raise FsError("디렉터리 길이가 범위(1..256 MiB)를 벗어났습니다.", reason="bad_ref")
        return (kind, c, length)

    def _spec_key(self, spec: str) -> Any:
        t = self._parse_spec(spec)
        return self.root_cluster if t[0] == "root" else t[1]

    def _dir_runs(self, spec_t: tuple[Any, ...], w: Warnings,
                  budget: Budget | None = None) -> tuple[list[tuple[int, int]], dict[str, Any]]:
        """디렉터리 바이트 구간과 체인 정보. 디렉터리가 슬롯 한도(min(max_dir_slots, 사양 최대) × 32 바이트)보다 길면 거기까지만
        돌려주고 info['cut'] 에 '잘릴 수 있음'을 남긴다 — 한도 안에 끝 표시가 없으면 잘린 디렉터리로 보고한다(_finish_dir)."""
        cs = self.cluster_size
        max_slots = min(self.limits.max_dir_slots, MAX_DIR_BYTES // 32)
        if self.metadata_mode == "allocation":
            max_slots = min(max_slots, 32768)
        max_bytes = max_slots * 32
        if spec_t[0] == "contig":
            start, length = spec_t[1], spec_t[2]
            n = min(ceil_div(min(length, max_bytes), cs), self.max_cluster - start + 1)
            info: dict[str, Any] = {"status": "contiguous", "clusters": n}
            if length > max_bytes and n * cs >= max_bytes:
                info["cut"] = {"reason": "max_dir_slots", "slots_read": max_slots, "slots_total": length // 32}
            return [(self.cluster_offset(start), min(length, max_bytes, n * cs))], info
        if spec_t[0] == "root":
            start, length = self.root_cluster, None
        else:
            start, length = spec_t[1], spec_t[2]
        if not 2 <= start <= self.max_cluster:
            w.add("dir_start_invalid", f"디렉터리 시작 클러스터 {start} 가 범위를 벗어났습니다.")
            return [], {"status": "out-of-range", "clusters": 0}
        want = min(length, max_bytes) if length is not None else max_bytes
        limit = ceil_div(want, cs)
        ch = self._follow(start, limit, budget)
        status = ch.status
        cut = None
        short = False
        covered = False
        if ch.capped:
            pass  # 예산이 다 됨 — 해석도 곧 멈춘다(budget_stop)
        elif status == "limit":
            # 체인이 읽을 길이보다 길다: DataLength 가 한도 안이면 정상(DataLength 까지만 읽음), 한도 밖이거나 길이를 모르는
            # 루트면 한도에서 잘린 디렉터리일 수 있다
            if length is None or length > max_bytes:
                cut = {"reason": "max_dir_slots", "slots_read": max_slots,
                       "slots_total": (length // 32) if length is not None else None}
            status = "ok" if length is not None else status
        elif status != "ok":
            w.add(f"dir_chain_{status}", f"디렉터리 클러스터 체인이 정상적으로 끝나지 않았습니다({status}).", start=start)
            # 읽을 길이(want = DataLength, 한도보다 길면 한도)만큼은 다 모았다 — 끝 항목만 망가졌고 그 안에서 빠진 것은 없다(_finish_dir 가
            # dir_chain_broken 으로 보지 않는다). 다만 DataLength 가 한도보다 길면 한도에서 잘린 디렉터리다(limit 상태일 때와 같다).
            covered = length is not None and ch.count * cs >= want
            if covered and length > max_bytes:
                cut = {"reason": "max_dir_slots", "slots_read": max_slots, "slots_total": length // 32}
        elif length is not None and ch.count * cs < length:
            w.add("dir_chain_short", "디렉터리 체인이 DataLength 보다 짧습니다.", start=start)
            short = True  # 끝 표시를 못 보면 끝까지 읽지 못한 디렉터리(dir_chain_broken)다 — _finish_dir
        runs: list[tuple[int, int]] = []
        remaining = want
        for s, k in zip(ch.starts, ch.lens):
            if remaining <= 0:
                break
            take = min(k * cs, remaining)
            runs.append((self.cluster_offset(s), take))
            remaining -= take
        info = {"status": status, "clusters": ch.count}
        if ch.capped:
            info["limit_reason"] = ch.capped
        if cut is not None:
            info["cut"] = cut
        if short:
            info["short"] = True
        if covered:
            info["covered"] = True
        return runs, info

    # ------------------------------------------------------------------
    # 디렉터리 검증 (클러스터 단위)
    # ------------------------------------------------------------------
    def _cluster_ok(self, fc: int, dl: int) -> bool:
        return (2 <= fc <= self.max_cluster) if dl else (fc == 0 or 2 <= fc <= self.max_cluster)

    def _slot_problem(self, raw: bytes, is_root: bool) -> str | None:
        """슬롯 하나의 문제 (없으면 None). 해석하지 않는 InUse=0 슬롯(빈 자리)은 보지 않는다."""
        t = raw[0]
        if t == 0x85 or t == 0x05:  # File
            if not 2 <= raw[1] <= 18:
                return "file_secondary_count"
            if (raw[4] | (raw[5] << 8)) & 0xFFC8:
                return "file_attributes"
            if raw[20] > 199 or raw[21] > 199:
                return "file_time_increment"
            return None
        if t == 0xC0 or t == 0x40:  # Stream Extension
            flags = raw[1]
            if flags & 0xFC:
                return "stream_flags"
            if raw[3] == 0:
                return "stream_name_length"
            fc, dl = struct.unpack_from("<IQ", raw, 20)
            if not flags & 1 and (fc or dl):
                return "stream_allocation"
            if not self._cluster_ok(fc, dl):
                return "cluster_range"
            return None
        if t == 0xC1 or t == 0x41:  # File Name
            return "name_flags" if raw[1] else None
        if t in (0xE0, 0x60):  # Vendor Extension
            return None
        if t in (0xE1, 0x61):  # Vendor Allocation
            fc, dl = struct.unpack_from("<IQ", raw, 20)
            return None if self._cluster_ok(fc, dl) else "cluster_range"
        if t == 0x81:  # Allocation Bitmap
            if not is_root:
                return "critical_outside_root"
            if raw[1] & 0xFE:
                return "bitmap_flags"
            fc, = struct.unpack_from("<I", raw, 20)
            return None if 2 <= fc <= self.max_cluster else "cluster_range"
        if t == 0x82:  # Up-case Table
            if not is_root:
                return "critical_outside_root"
            fc, = struct.unpack_from("<I", raw, 20)
            return None if 2 <= fc <= self.max_cluster else "cluster_range"
        if t == 0x83 or t == 0x03:  # Volume Label
            if not is_root:
                return "label_outside_root"
            return "label_length" if raw[1] > 11 else None
        if t == 0xA0:  # Volume GUID
            if not is_root:
                return "guid_outside_root"
            return "guid_secondary_count" if raw[1] != 0 else None
        if t in (0xA1, 0xA2):  # TexFAT 패딩 / Windows CE 접근 제어 표
            return None
        if t & 0x80:
            return "unknown_type"  # 사양이 정하지 않은 사용 중 항목 — 디렉터리 데이터가 아닐 가능성
        return None

    def _unit_problem(self, ctx: DirCtx, first: int, data: bytes, peek: Peek) -> tuple[str | None, int | None]:
        if self.metadata_mode == "allocation" and len(data) != self.cluster_size:
            return "allocation_incomplete_unit", None
        is_root = ctx.is_root
        n = len(data) // 32
        for i in range(n):
            raw = data[32 * i:32 * i + 32]
            t = raw[0]
            if t == 0x00:
                return None, i
            p = self._slot_problem(raw, is_root)
            if p is not None:
                return p, None
            if t == 0x85 or t == 0x05:
                sc = raw[1]
                deleted = t == 0x05
                nxt = [data[32 * j:32 * j + 32] for j in range(i + 1, min(n, i + 1 + sc))]
                if len(nxt) < sc:
                    nxt += peek(sc - len(nxt))
                taken: list[bytes] = []
                for k, r2 in enumerate(nxt):
                    ok = r2[0] == (0x40 if deleted else 0xC0) if k == 0 else r2[0] in (_SECONDARY_DEL if deleted else _SECONDARY_LIVE)
                    if not ok:
                        break
                    taken.append(r2)
                if len(taken) == sc:
                    stored = raw[2] | (raw[3] << 8)
                    if entry_set_checksum([raw] + taken, force_in_use=deleted) != stored:
                        return "set_checksum", None
        return None, None

    # ------------------------------------------------------------------
    # 디렉터리 해석
    # ------------------------------------------------------------------
    def _parse_dir(self, spec: str, budget: Budget | None = None, *, summaries: bool = True) -> DirResult:
        cached = self._dir_cache.get(spec)
        if cached is not None:
            self._dir_cache.move_to_end(spec)
            return cached
        budget = self._budget(None, budget)
        spec_t = self._parse_spec(spec)
        res = DirResult(spec, self.limits.max_warnings)
        w = res.warnings
        runs, res.chain = self._dir_runs(spec_t, w, budget)
        res.cut = res.chain.pop("cut", None)
        is_root = spec_t[0] == "root"
        max_slots = min(self.limits.max_dir_slots, MAX_DIR_BYTES // 32)
        pk = _Peek(self._validated_slots(res, DirCtx(spec, spec_t), runs, self.cluster_size, max_slots, budget))
        sp: dict[str, Any] = {"bitmaps": [], "upcase": None, "label": None, "guid": None, "label_deleted": None}
        unknown = 0
        while True:
            item = pk.pop()
            if item is None:
                break
            slot, off, raw = item
            res.slots = slot + 1
            t = raw[0]
            if t == 0x00:
                res.end_slot = slot
                break
            if t == 0x85 or t == 0x05:
                self._file_set(res, pk, item, deleted=(t == 0x05), budget=budget, summaries=summaries)
                continue
            if t == 0x81:
                if is_root:
                    fc, dl = struct.unpack_from("<IQ", raw, 20)
                    sp["bitmaps"].append({"flags": raw[1], "first_cluster": fc, "data_length": dl, "slot": slot})
                else:
                    w.add("critical_outside_root", "루트가 아닌 디렉터리에 할당 비트맵 항목이 있습니다.", slot=slot)
            elif t == 0x82:
                if is_root and sp["upcase"] is None:
                    cks, = struct.unpack_from("<I", raw, 4)
                    fc, dl = struct.unpack_from("<IQ", raw, 20)
                    sp["upcase"] = {"checksum": cks, "first_cluster": fc, "data_length": dl, "slot": slot}
                elif not is_root:
                    w.add("critical_outside_root", "루트가 아닌 디렉터리에 up-case 표 항목이 있습니다.", slot=slot)
            elif t == 0x83 or t == 0x03:
                n = min(raw[1], 11)
                text, _ = decode_utf16le(bytes(raw[2:2 + 2 * n]))
                if raw[1] > 11:
                    w.add("label_length_invalid", "볼륨 레이블 CharacterCount 가 11 보다 큽니다.")
                if t == 0x83:
                    if is_root and sp["label"] is None:
                        sp["label"] = text
                else:
                    sp["label_deleted"] = text
            elif t == 0xA0:
                if is_root and sp["guid"] is None:
                    g = bytes(raw[6:22])
                    sp["guid"] = "-".join([g[3::-1].hex(), g[5:3:-1].hex(), g[7:5:-1].hex(), g[8:10].hex(),
                                           g[10:16].hex()]).upper()
            elif t in (0xA1, 0xA2):
                pass  # TexFAT 패딩 / Windows CE 접근 제어 표
            elif t in (0xC0, 0xC1, 0xE0, 0xE1, 0x40, 0x41, 0x60, 0x61):
                self._orphan_secondary(res, pk, item)
            elif t & 0x80:
                unknown += 1
                if not t & 0x40:  # 알 수 없는 사용 중 primary: 딸린 secondary 를 건너뛴다
                    for _ in range(min(raw[1], 18)):
                        nxt = pk.peek(1)
                        if not nxt or (nxt[0][2][0] & 0xC0) != 0xC0:
                            break
                        pk.pop()
                w.add("unknown_entry_type", f"알 수 없는 항목 형식 0x{t:02x} (건너뜀).", slot=slot)
            # 나머지: 쓰지 않는(InUse=0) 다른 형식 — 무시
        res.label = sp["label"]
        res.extra["specials"] = sp
        res.extra["public"] = {"label_deleted": sp["label_deleted"]} if is_root else {}
        return self._finish_dir(self._dir_cache, spec, res, budget, summaries=summaries, runs=runs)

    def _orphan_secondary(self, res: DirResult, pk: _Peek, item: tuple[int, int, bytes]) -> None:
        """주 항목 없이 남은 보조 항목 조각 (스트림 + 이름 조각을 묶어 보고)."""
        slot, off, raw = item
        deleted = not raw[0] & 0x80
        group = [item]
        if (raw[0] | 0x80) == 0xC0:
            while len(group) < 18:
                nxt = pk.peek(1)
                if not nxt or nxt[0][2][0] != (0x41 if deleted else 0xC1):
                    break
                group.append(pk.pop())  # type: ignore[arg-type]
        if len(res.orphans) >= self.limits.max_orphans:
            res.warnings.add("orphan_limit", "고아 항목 보고 한도에 닿았습니다.")
            return
        o: dict[str, Any] = {"dir": res.spec, "slot": slot, "slot_count": len(group), "offset": off,
                             "image_offset": self.base_offset + off, "deleted": deleted,
                             "entry_type": f"0x{raw[0]:02x}", "reason": "no_primary"}
        names = [r for _, _, r in group if (r[0] | 0x80) == 0xC1]
        if (raw[0] | 0x80) == 0xC0:
            flags, _r, name_len, _nh, _r2, vdl, _r3, fc, dl = struct.unpack_from("<BBBHHQIIQ", raw, 1)
            o.update(first_cluster=fc, data_length=dl, valid_data_length=vdl, no_fat_chain=bool(flags & 2),
                     name_length=name_len)
            units = b"".join(bytes(r[2:32]) for r in names)[: name_len * 2]
        else:
            units = b"".join(bytes(r[2:32]) for r in names)
            while units.endswith(b"\x00\x00"):
                units = units[:-2]
        if units:
            text, lossy = decode_utf16le(units)
            o.update(partial_name=text, display_name=display_name(text), name_lossy=lossy)
        res.orphans.append(o)

    def _file_set(self, res: DirResult, pk: _Peek, item: tuple[int, int, bytes], *, deleted: bool,
                  budget: Budget | None = None, summaries: bool = True) -> None:
        slot, off, raw = item
        sc = raw[1]
        w = res.warnings
        if not 2 <= sc <= 18:
            w.add("file_set_bad_secondary_count", f"File 항목의 SecondaryCount {sc} 가 범위(2..18)를 벗어났습니다.",
                  slot=slot)
            if sc < 1 or sc > 18:
                return
        ahead = pk.peek(sc)
        if len(ahead) < sc and res.cut is not None and res.scanned >= int(res.cut["slots_read"]):
            # 슬롯 한도에서 잘린 자리에 걸친 집합: 나머지 보조 항목은 한도 뒤에 있다 — 부분 항목(잘린 이름)을 내보내지 않는다
            for _ in ahead:
                pk.pop()
            res.cut["boundary_slot"] = slot
            return
        taken: list[tuple[int, int, bytes]] = []
        for idx, (_s2, _o2, r2) in enumerate(ahead):
            t2 = r2[0]
            if idx == 0:
                ok = t2 == (0x40 if deleted else 0xC0)
            else:
                ok = t2 in (_SECONDARY_DEL if deleted else _SECONDARY_LIVE)
            if not ok:
                break
            taken.append(ahead[idx])
        for _ in taken:
            pk.pop()
        complete = len(taken) == sc
        stored, = struct.unpack_from("<H", raw, 2)
        csum_ok = None
        if complete:
            csum_ok = entry_set_checksum([raw] + [r for _, _, r in taken], force_in_use=deleted) == stored
        e = self._build_entry(res, slot, off, raw, taken, deleted=deleted, complete=complete, csum_ok=csum_ok,
                              budget=budget, summaries=summaries)
        res.entries.append(e)

    def _build_entry(self, res: DirResult, slot: int, off: int, primary: bytes, taken: list[tuple[int, int, bytes]],
                     *, deleted: bool, complete: bool, csum_ok: bool | None,
                     budget: Budget | None = None, summaries: bool = True) -> dict[str, Any]:
        (sc, _csum, attrs, _r1, cts, mts, ats, c10, m10, cutc, mutc, autc) = struct.unpack_from(
            "<BHHHIIIBBBBB", primary, 1)
        ewarn: list[dict[str, Any]] = []
        stream = taken[0][2] if taken else None
        if stream is not None:
            flags, _r, name_len, nh, _r2, vdl, _r3, fc, dlen = struct.unpack_from("<BBBHHQIIQ", stream, 1)
        else:
            flags = name_len = nh = vdl = fc = dlen = 0
            ewarn.append({"code": "stream_missing", "message": "Stream Extension 항목이 없습니다(덮어써짐) — 크기·클러스터를 모릅니다."})
        names = [r for _, _, r in taken[1:] if (r[0] | 0x80) == 0xC1]
        need = ceil_div(name_len, 15)
        units = b"".join(bytes(r[2:32]) for r in names[:need])
        raw_name = units[: name_len * 2]
        if name_len and len(raw_name) == name_len * 2:
            name_status = "ok"
        elif raw_name:
            name_status = "partial"
        else:
            name_status = "missing"
        name, lossy = decode_utf16le(raw_name)
        nh_ok = None
        if stream is not None and name_status == "ok":
            nh_ok = name_hash(self._upcase_units(raw_name)) == nh
            if not nh_ok:
                ewarn.append({"code": "name_hash_mismatch", "message": "NameHash 가 이름과 맞지 않습니다."})
        if name_len == 0 and stream is not None:
            ewarn.append({"code": "name_length_zero", "message": "NameLength 가 0 입니다."})
        is_dir = bool(attrs & 0x10)
        no_fat_chain = bool(flags & 0x02)
        alloc_possible = bool(flags & 0x01)
        vdl_eff = vdl
        if vdl > dlen:
            ewarn.append({"code": "vdl_exceeds_datalength", "message": "ValidDataLength 가 DataLength 보다 큽니다(DataLength 로 자름)."})
            vdl_eff = dlen
        if stream is not None and not alloc_possible and (fc or dlen):
            ewarn.append({"code": "allocation_not_possible", "message": "AllocationPossible=0 인데 클러스터·크기가 있습니다."})
        if dlen and not 2 <= fc <= self.max_cluster:
            ewarn.append({"code": "first_cluster_invalid", "message": f"시작 클러스터 {fc} 가 범위를 벗어났습니다."})
        if complete and csum_ok is False:
            ewarn.append({"code": "set_checksum_mismatch", "message": "항목 집합 SetChecksum 이 맞지 않습니다."})
        if not complete:
            ewarn.append({"code": "set_incomplete", "message": f"항목 집합이 불완전합니다({len(taken)}/{sc} 보조 항목)."})
        child_dir = None
        if is_dir:
            if dlen % self.cluster_size:
                ewarn.append({"code": "dir_length_unaligned", "message": "디렉터리 DataLength 가 클러스터 크기의 배수가 아닙니다."})
            if 2 <= fc <= self.max_cluster and dlen > 0:
                length = min(dlen, MAX_DIR_BYTES)
                child_dir = f"n{fc}+{length}" if no_fat_chain else f"c{fc}+{length}"
        display = display_name(name) if name else "(이름 없음)"
        entry: dict[str, Any] = {
            "ref": f"{res.spec}/{slot}",
            "fs": "exfat",
            "dir": res.spec,
            "slot": slot,
            "offset": off,
            "image_offset": self.base_offset + off,
            "secondary_count": sc,
            "slots_used": 1 + len(taken),
            "name": name,
            "display_name": display,
            "name_lossy": lossy,
            "name_raw": raw_name.hex() if lossy else None,
            "name_length": name_len,
            "name_status": name_status,
            "name_hash_ok": nh_ok,
            "set_checksum_ok": csum_ok,
            "set_complete": complete,
            "deleted": deleted,
            "is_dir": is_dir,
            "attributes": {"raw": attrs, "flags": _attr_flags(attrs)},
            "size": dlen,
            "valid_data_length": vdl_eff,
            "valid_data_length_raw": vdl,
            "residual_bytes": max(0, dlen - vdl_eff),
            "first_cluster": fc,
            "no_fat_chain": no_fat_chain,
            "allocation_possible": alloc_possible,
            "times": {
                "created": exfat_timestamp(cts, c10, cutc),
                "modified": exfat_timestamp(mts, m10, mutc),
                "accessed": exfat_timestamp(ats, None, autc),
            },
            "child_dir": child_dir,
            "warnings": ewarn,
        }
        if deleted:
            entry["allocation_now"] = (self._alloc_summary(fc, dlen, no_fat_chain, budget) if summaries
                                       else {"status": "unknown", "checked_clusters": 0, "allocated_now": 0})
        return entry

    def _alloc_summary(self, fc: int, dlen: int, no_fat_chain: bool, budget: Budget | None = None) -> dict[str, Any]:
        """삭제 항목의 클러스터가 지금 비트맵에서 비었는지 (목록용 — 항목당 대조 상한, 구간 단위로 센다, 호출의 예산 안에서)."""
        n = ceil_div(dlen, self.cluster_size)
        if n == 0 or not 2 <= fc <= self.max_cluster:
            return {"status": "none", "checked_clusters": 0, "allocated_now": 0}
        if self._bitmap is None:
            return {"status": "unknown", "checked_clusters": 0, "allocated_now": 0}
        capped = None
        if no_fat_chain:
            k = min(n, self.max_cluster - fc + 1, _DELETED_STATUS_CHECK_CONTIG)
            if budget is not None:
                budget.tick((k >> 6) + 1)
            ones, seen = self._bitmap.count_range(fc - 2, fc - 2 + k)
            checked, alloc = seen, ones
            partial = k < n
        else:
            ch = self._follow(fc, min(n, _DELETED_STATUS_CHECK), budget)
            alloc, _seen = self._count_allocated_runs(ch.starts, ch.lens)
            checked = ch.count
            partial = ch.count < n
            capped = ch.capped
        if checked == 0:
            status = "unknown"
        else:
            status = "free" if alloc == 0 else ("reused" if alloc >= checked else "partially_reused")
        out: dict[str, Any] = {"status": status, "checked_clusters": checked, "allocated_now": alloc}
        if partial:
            out["partial_check"] = True
        if capped:
            out["limit_reason"] = capped
        return out

    def _deleted_dir_ok(self, e: dict[str, Any], w: Warnings, path: str) -> bool:
        fc = e["first_cluster"]
        if self.allocated(fc):
            w.add("deleted_dir_reused", "삭제된 디렉터리의 첫 클러스터가 지금 할당돼 있어 내용을 믿을 수 없습니다(건너뜀).",
                  path=path, cluster=fc)
            return False
        head = self.src.read_clamped(self.cluster_offset(fc), 32)
        if len(head) < 32 or head[0] not in (0x00, 0x05, 0x85, 0x40, 0x41, 0xC0, 0xC1):
            w.add("deleted_dir_overwritten", "삭제된 디렉터리의 첫 슬롯이 exFAT 항목처럼 보이지 않습니다(건너뜀).",
                  path=path, cluster=fc)
            return False
        return True

    # ------------------------------------------------------------------
    # 체인·내용
    # ------------------------------------------------------------------
    def _chain_summary(self, e: dict[str, Any], budget: Budget | None = None) -> dict[str, Any]:
        fc = e["first_cluster"]
        need = ceil_div(e["size"], self.cluster_size)
        if need == 0 or fc == 0:
            return {"status": "empty", "clusters": 0, "expected_clusters": need,
                    "size_check": "ok" if need == 0 else "no_clusters"}
        if not 2 <= fc <= self.max_cluster:
            return {"status": "out-of-range", "clusters": 0, "expected_clusters": need, "size_check": "no_clusters"}
        if e["no_fat_chain"]:
            k = min(need, self.max_cluster - fc + 1)
            out = {"status": "nofatchain", "clusters": k, "expected_clusters": need,
                   "size_check": "ok" if k == need else "beyond_volume"}
            if budget is not None:
                budget.tick((k >> 6) + 1)
                if budget.expired():
                    out["limit_reason"] = budget.reason  # 비트맵 대조는 하지 않았다
                    return out
            cnt = self._count_allocated_run(fc, k)
            if cnt is not None:
                out["unallocated_in_bitmap"] = cnt[1] - cnt[0]
            return out
        ch = self._follow(fc, need + 1, budget)
        if ch.capped:  # 예산이 다 돼 끝까지 따라가지 못함 — 크기와 비교할 수 없다
            out = {"status": "limit", "clusters": ch.count, "expected_clusters": need, "size_check": "unknown",
                   "limit_reason": ch.capped}
        else:
            if ch.status == "limit" or ch.count > need:
                check = "chain_longer"
            elif ch.count < need:
                check = "chain_shorter"
            else:
                check = "ok"
            out = {"status": ch.status, "clusters": ch.count, "expected_clusters": need, "size_check": check}
        if self._bitmap is not None:
            ones, seen = self._count_allocated_runs(ch.starts, ch.lens)
            out["unallocated_in_bitmap"] = seen - ones
        return out

    def _candidate_plans(self, e: dict[str, Any], region: str = "data", budget: Budget | None = None, *,
                         want: str | None = None, skipped: set[str] | None = None) -> list[ContentPlan]:
        """내용 계획 후보. want 를 주면 그 방법의 후보만 만든다(다른 후보가 예산을 먼저 쓰지 않게). 예산이 다 돼 만들지 못한 방법은
        skipped 에 넣는다."""
        if region not in ("data", "residual"):
            raise FsError("region 은 'data' 또는 'residual' 입니다.", reason="bad_argument")
        budget = self._budget(None, budget)
        skipped = skipped if skipped is not None else set()
        cs = self.cluster_size
        dlen = e["size"]
        vdl = min(e["valid_data_length"], dlen)
        fc = e["first_cluster"]
        ref = e["ref"]
        n = ceil_div(dlen, cs)
        skip, size = (0, vdl) if region == "data" else (vdl, dlen - vdl)

        def mk(method: str) -> ContentPlan:
            p = self._new_plan(ref, method, size, region)
            p.skip = skip
            p.extra["data_length"] = dlen
            p.extra["valid_data_length"] = vdl
            return p

        def wanted(method: str) -> bool:
            return want is None or want == method

        if n == 0 or size == 0:
            p = mk("empty")
            p.note = "읽을 바이트가 없습니다." + (" (ValidDataLength 가 0 — 녹화 전 미리 할당된 파일일 수 있음, residual 참고)"
                                            if region == "data" and dlen and not vdl else "")
            return [p] if wanted("empty") else []
        if not 2 <= fc <= self.max_cluster:
            p = mk("none")
            p.status = "out-of-range"
            p.confidence = "none"
            p.note = f"시작 클러스터 {fc} 가 범위를 벗어나 읽을 수 없습니다."
            return [p] if wanted("none") else []
        if not e["deleted"]:
            live = "nofatchain" if e["no_fat_chain"] else "chain"
            return [self._live_plan(e, mk, n, budget)] if wanted(live) else []
        plans: list[ContentPlan] = []
        if e["no_fat_chain"]:
            if not wanted("contiguous"):
                return []
            p = mk("contiguous")
            k = min(n, self.max_cluster - fc + 1)
            p.add_run(fc, k)
            budget.tick((k >> 6) + 1)
            cnt = self._count_allocated_run(fc, k)
            alloc = cnt[0] if cnt else None
            p.conflicts = {"allocated": alloc if alloc is not None else -1}
            if k < n:
                p.status = "beyond_volume"
            if alloc is None:
                p.confidence = "medium"
                p.note = "NoFatChain(연속) 파일이지만 비트맵이 없어 덮어쓰기 여부를 모릅니다."
            elif alloc == 0:
                p.confidence = "high"
                p.note = "NoFatChain 파일은 정의상 연속이고 그 클러스터가 지금 모두 비어 있습니다."
            else:
                p.confidence = "low"
                p.note = f"NoFatChain(연속) 파일이지만 클러스터 {alloc} 개가 지금 다른 곳에 할당돼 있습니다(덮어써짐)."
            return [self._finish(p)]
        if wanted("stale-chain"):
            ch = self._follow(fc, n + 1, budget)
            p = mk("stale-chain")
            taken = 0
            for s, k in zip(ch.starts, ch.lens):
                kk = min(k, n - taken)
                if kk <= 0:
                    break
                p.add_run(s, kk)
                taken += kk
            conflicts = None
            if self._bitmap is not None:
                # 구간마다 비트맵 popcount — 긴 체인도 클러스터 목록을 만들지 않는다
                budget.tick((p.clusters >> 6) + p.run_count)
                conflicts = self._count_allocated_runs(p.run_start, p.run_len)[0]
            p.conflicts = {"allocated": conflicts if conflicts is not None else -1}
            # status 'limit' 는 예산 멈춤에만 쓴다 — 크기보다 긴 체인은 chain_status 로만 남긴다
            p.status = "ok" if ch.status == "limit" and not ch.capped else ch.status
            p.extra["chain_status"] = ch.status
            exact = taken == n and (ch.status == "ok" and ch.count == n)
            if exact and conflicts == 0:
                p.confidence = "high"
                p.note = ("exFAT 삭제는 FAT 항목을 지우지 않습니다 — 남은 FAT 체인이 크기와 정확히 맞고 그 클러스터가 지금 모두 "
                          "비어 있습니다.")
            elif exact and conflicts is None:
                p.confidence = "medium"
                p.note = "남은 FAT 체인이 크기와 맞지만 비트맵이 없어 덮어쓰기 여부를 모릅니다."
            elif taken == n and conflicts == 0:
                p.confidence = "medium"
                p.note = f"남은 FAT 체인이 크기보다 깁니다({ch.status}) — 크기까지만 읽습니다."
            else:
                p.confidence = "low"
                parts = []
                if taken < n:
                    parts.append(f"체인이 {taken}/{n} 클러스터에서 끊김({ch.status})")
                if conflicts:
                    parts.append(f"클러스터 {conflicts} 개가 지금 할당돼 있음(재사용되며 FAT 항목도 바뀌었을 수 있음)")
                p.note = "남은 FAT 체인을 믿기 어렵습니다: " + ", ".join(parts) + "."
            if ch.capped:
                self._mark_capped(p, ch.capped, "남은 FAT 체인")
            plans.append(self._finish(p))
        if wanted("contiguous"):
            # 대안: 연속 / 할당된 곳 건너뛰기 (비트맵 기준)
            pc = mk("contiguous")
            k = min(n, self.max_cluster - fc + 1)
            pc.add_run(fc, k)
            budget.tick((k >> 6) + 1)
            cnt = self._count_allocated_run(fc, k)
            pc.conflicts = {"allocated": cnt[0] if cnt else -1}
            pc.confidence = "low"
            pc.note = "FAT 체인 파일(NoFatChain=0)이라 연속 가정은 약합니다 — stale-chain 이 더 정확합니다."
            plans.append(self._finish(pc))
        if wanted("skip-allocated") and self._bitmap is not None:
            if budget.expired():
                skipped.add("skip-allocated")
            else:
                ps = mk("skip-allocated")
                max_scan = min(self.limits.max_scan_clusters, n * 4 + 65536, self.max_cluster - fc + 1)
                scan = self._bitmap.scan_free(fc - 2, n, max_scan, max_runs=self.limits.max_runs, budget=budget)
                for b0, k in scan["runs"]:
                    ps.add_run(b0 + 2, k)
                skipped_n = scan["skipped"]
                if scan["stop"] == "max_runs":
                    ps.warnings.add("too_fragmented", "후보의 클러스터 구간 수가 한도(max_runs)에 닿아 멈췄습니다.")
                ps.conflicts = {"skipped_allocated": skipped_n}
                if scan["got"] < n:
                    ps.status = "incomplete"
                ps.confidence = "low"
                ps.note = f"비트맵에서 할당된 클러스터 {skipped_n} 개를 건너뛰었습니다 — stale-chain 이 깨졌을 때의 대안."
                if scan["stop"] == "budget":
                    self._mark_capped(ps, budget.reason, "빈 클러스터 탐색")
                plans.append(self._finish(ps))
        order = {"contiguous": 0, "stale-chain": 0, "skip-allocated": 2}
        plans.sort(key=lambda q: (CONFIDENCE_ORDER.get(q.confidence, 9), order.get(q.method, 9)))
        return plans

    def _live_plan(self, e: dict[str, Any], mk: Any, n: int, budget: Budget | None = None) -> ContentPlan:
        fc = e["first_cluster"]
        if e["no_fat_chain"]:
            p = mk("nofatchain")
            k = min(n, self.max_cluster - fc + 1)
            p.add_run(fc, k)
            if budget is not None:
                budget.tick((k >> 6) + 1)
            if k < n:
                p.status = "beyond_volume"
                p.confidence = "low"
            cnt = self._count_allocated_run(fc, k)
            if cnt is not None and cnt[0] < cnt[1]:
                p.warnings.add("live_unallocated", f"살아 있는 파일의 클러스터 {cnt[1] - cnt[0]} 개가 비트맵에서 비어 있습니다.")
            p.note = "NoFatChain (연속 할당)"
            return self._finish(p)
        ch = self._follow(fc, n + 1, budget)
        p = mk("chain")
        taken = 0
        for s, k in zip(ch.starts, ch.lens):
            kk = min(k, n - taken)
            if kk <= 0:
                break
            p.add_run(s, kk)
            taken += kk
        p.status = ch.status if ch.status != "limit" else "ok"
        p.extra["chain_status"] = ch.status
        if taken < n:
            p.confidence = "low"
            p.note = f"FAT 체인이 크기보다 짧습니다({taken}/{n} 클러스터, 상태 {ch.status})."
            p.warnings.add("chain_short", p.note)
        else:
            p.note = "할당된 FAT 체인"
        if ch.capped:
            self._mark_capped(p, ch.capped, "FAT 체인")
        return self._finish(p)

    # ------------------------------------------------------------------
    # 공개: 볼륨 정보·점검
    # ------------------------------------------------------------------
    @guard
    def info(self, *, budget: Budget | None = None) -> dict[str, Any]:
        """볼륨 정보 (부트 영역, 비트맵·up-case, 레이블). 루트는 열 때(검증·예산 적용) 이미 읽었다 — 여기서는 더 읽지 않는다."""
        b = self.boot
        w = Warnings(self.limits.max_warnings)
        w.extend(self._w)
        flags = self.volume_flags
        serial = b["volume_serial"]
        out: dict[str, Any] = {
            "fs_type": "exfat",
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": b["sectors_per_cluster"],
            "cluster_size": self.cluster_size,
            "partition_offset_sectors": b["partition_offset"],
            "volume_length_sectors": b["volume_length"],
            "fat_offset_sectors": b["fat_offset"],
            "fat_length_sectors": b["fat_length"],
            "cluster_heap_offset_sectors": b["cluster_heap_offset"],
            "cluster_count": b["cluster_count"],
            "cluster_count_effective": self.cluster_count,
            "max_cluster": self.max_cluster,
            "root_cluster": self.root_cluster,
            "fat_offset": self.fat_offset,
            "data_offset": self.heap_offset,
            "volume_serial": f"{(serial >> 16) & 0xFFFF:04X}-{serial & 0xFFFF:04X}",
            "fs_revision": f"{b['fs_revision'] >> 8}.{b['fs_revision'] & 0xFF:02d}",
            "number_of_fats": b["number_of_fats"],
            "percent_in_use": None if b["percent_in_use"] == 0xFF else b["percent_in_use"],
            "volume_flags": {
                "raw": flags,
                "active_fat": flags & 1,
                "volume_dirty": bool(flags & 2),
                "media_failure": bool(flags & 4),
                "clear_to_zero": bool(flags & 8),
            },
            "state": {
                "dirty": bool(flags & 2),
                "media_failure": bool(flags & 4),
                "sources": {"dirty": "VolumeFlags.VolumeDirty (exFAT 사양)",
                            "media_failure": "VolumeFlags.MediaFailure (exFAT 사양)"},
            },
            "boot_region": self.boot_region,
            "volume_label": self.label,
            "volume_guid": self.volume_guid,
            "bitmap": dict(self.bitmap_info),
            "upcase": dict(self.upcase_info),
            "volume_size": self.volume_size,
            "available_size": self.src.size,
            "truncated": self.volume_size > self.src.size,
            "base_offset": self.base_offset,
        }
        out.update(w.export())
        return out

    def _live_map(self, budget: Budget | None = None) -> dict[str, Any]:
        if self._live_cache is not None:
            return self._live_cache
        lim = self.limits
        budget = self._budget(None, budget)
        nbits = self.cluster_count if self._bitmap is None else min(self.cluster_count, self._bitmap.readable_bits())
        bits = BitSet(nbits)
        cross = 0
        cross_samples: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []
        truncated = False
        inspection = _cluster_inspection()
        reasons = set(self._cluster_metadata_reasons)
        map_complete = self._cluster_metadata_map_complete

        def check() -> None:
            if budget.expired():
                raise budget.error("클러스터 참조 검사")

        def incomplete() -> None:
            nonlocal map_complete
            map_complete = False
            reasons.add("reference_chain_incomplete")

        def sample(rows: list, row: dict) -> None:
            if len(rows) < lim.max_report_items:
                rows.append(row)
            else:
                inspection["rows_complete"] = False
                reasons.add("rows_limit")

        def mark_run(start: int, count: int, ref: str, path: str) -> None:
            nonlocal cross
            for block in range(start, start + count, 4096):
                check()
                stop = min(block + 4096, start + count)
                for c in range(block, stop):
                    if not 0 <= c - 2 < bits.n:
                        incomplete()
                    if bits.set(c - 2):
                        cross += 1
                        sample(cross_samples, {"cluster": c, "ref": ref, "path": path})
                budget.tick(stop - block)
                check()

        def chain_complete(ch: Chain) -> None:
            if ch.status != "ok" or ch.capped:
                incomplete()

        cs = self.cluster_size
        try:
            check()
            for what, info in (("bitmap", self.bitmap_info), ("upcase", self.upcase_info)):
                if info.get("present") and 2 <= info.get("first_cluster", 0) <= self.max_cluster:
                    n = ceil_div(info["data_length"], cs)
                    ch = self._follow(info["first_cluster"], max(1, n), budget)
                    chain_complete(ch)
                    if ch.count < n:
                        incomplete()
                        mark_run(info["first_cluster"], min(n, self.max_cluster - info["first_cluster"] + 1), what, what)
                    else:
                        for start, count in zip(ch.starts, ch.lens):
                            mark_run(start, count, what, what)
            if 2 <= self.root_cluster <= self.max_cluster:
                ch = self._follow(self.root_cluster, ceil_div(MAX_DIR_BYTES, cs), budget)
                chain_complete(ch)
                for start, count in zip(ch.starts, ch.lens):
                    mark_run(start, count, "root", "/")
            else:
                incomplete()
            res = self.walk(include_deleted=False, check_chains=False, budget=budget)
            truncated = res["truncated"]
            inspection["entries_observed"] = len(res["entries"])
            reasons.update(_cluster_reason(r) for r in res.get("truncated_reasons", []))
            if res.get("unvalidated_dirs_live", 0):
                reasons.add("dir_unvalidated")
            inspection["reference_walk_complete"] = not res["truncated"] and not res.get("unvalidated_dirs_live", 0)
            for e in res["entries"]:
                check()
                fc = e["first_cluster"]
                n = ceil_div(e["size"], cs)
                if n == 0 or not 2 <= fc <= self.max_cluster:
                    if n:
                        sample(anomalies, {"ref": e["ref"], "path": e["path"], "status": "out-of-range",
                                           "size_check": "no_clusters"})
                        incomplete()
                    continue
                if e["no_fat_chain"]:
                    count = min(n, self.max_cluster - fc + 1)
                    if count != n:
                        incomplete()
                    mark_run(fc, count, e["ref"], e["path"])
                    continue
                ch = self._follow(fc, n + 1, budget)
                chain_complete(ch)
                if ch.capped:
                    truncated = True
                taken = 0
                for start, count in zip(ch.starts, ch.lens):
                    take = min(count, n - taken)
                    if take <= 0:
                        break
                    mark_run(start, take, e["ref"], e["path"])
                    taken += take
                size_check = "ok" if taken == n and ch.count == n else ("chain_shorter" if taken < n else "chain_longer")
                if ch.status != "ok" or size_check != "ok":
                    sample(anomalies, {"ref": e["ref"], "path": e["path"], "status": ch.status,
                                       "clusters": ch.count, "expected_clusters": n, "size_check": size_check})
                    incomplete()
        except FsError as exc:
            if exc.reason != "budget_exceeded":
                raise
            reasons.add(_cluster_reason(exc.data.get("limit")))
            map_complete = False
            truncated = True
        inspection["reference_map_complete"] = inspection["reference_walk_complete"] and map_complete
        inspection["observed_referenced_clusters"] = bits.count()
        inspection["reasons"] = [r for r in _CLUSTER_REASONS if r in reasons]
        self._live_cache = {"bits": bits, "cross_linked": cross, "cross_linked_samples": cross_samples,
                            "chain_anomalies": anomalies, "truncated": truncated, "inspection": inspection}
        return self._live_cache

    @guard
    def cluster_report(self, *, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
        """기존 할당/참조 진단에 실제로 본 비트 수와 독립 phase 완료도를 덧붙인다."""
        lim = self.limits
        budget = self._budget(limits, budget)
        w = Warnings(lim.max_warnings)
        inspection = _cluster_inspection()
        if self.cluster_count > lim.max_scan_clusters:
            w.add("scan_limit", f"클러스터 수가 점검 한도({lim.max_scan_clusters})를 넘어 점검하지 않습니다.")
            inspection["reasons"] = ["cluster_limit"]
            out = {"fs": "exfat", "scanned": False, "truncated": True, "inspection": inspection}
            out.update(w.export())
            return out
        if self._bitmap is None:
            w.add("bitmap_missing", "할당 비트맵이 없어 점검할 수 없습니다.")
            reasons = self._cluster_metadata_reasons | {"allocation_unreadable"}
            if budget.expired():
                reasons.add(_cluster_reason(budget.reason))
            inspection["reasons"] = [r for r in _CLUSTER_REASONS if r in reasons]
            out = {"fs": "exfat", "scanned": False, "truncated": False,
                   "state": self.info()["state"], "inspection": inspection}
            out.update(w.export())
            return out
        live = self._live_map(budget)
        inspection = dict(live["inspection"])
        reasons = set(inspection["reasons"])
        bits: BitSet = live["bits"]
        allocated = unref = unalloc_ref = examined = free = 0
        unref_runs: list[list[int]] = []
        unalloc_samples: list[int] = []
        refbuf = bits.buf
        cut = False

        def check() -> None:
            if budget.expired():
                raise budget.error("클러스터 할당 검사")

        try:
            check()
            for bit0, data in self._bitmap.iter_bytes(0, self.cluster_count):
                for offset in range(0, len(data), 512):
                    check()
                    part = data[offset:offset + 512]
                    for j, byte in enumerate(part, offset):
                        first_bit = bit0 + 8 * j
                        valid_count = min(8, self.cluster_count - first_bit)
                        valid = (1 << valid_count) - 1
                        byte &= valid
                        ri = (bit0 >> 3) + j
                        refbyte = (refbuf[ri] if ri < len(refbuf) else 0) & valid
                        ones = bin(byte).count("1")
                        examined += valid_count
                        allocated += ones
                        free += valid_count - ones
                        diff = byte & ~refbyte
                        miss = refbyte & ~byte
                        for b in range(valid_count):
                            c = first_bit + b + 2
                            if diff & (1 << b):
                                unref += 1
                                if unref_runs and unref_runs[-1][0] + unref_runs[-1][1] == c:
                                    unref_runs[-1][1] += 1
                                elif len(unref_runs) < lim.max_report_items:
                                    unref_runs.append([c, 1])
                                else:
                                    inspection["rows_complete"] = False
                                    reasons.add("rows_limit")
                            if miss & (1 << b):
                                unalloc_ref += 1
                                if len(unalloc_samples) < lim.max_report_items:
                                    unalloc_samples.append(c)
                                else:
                                    inspection["rows_complete"] = False
                                    reasons.add("rows_limit")
                    budget.tick((len(part) >> 3) + 1)
                    check()
        except FsError as exc:
            if exc.reason != "budget_exceeded":
                raise
            reasons.add(_cluster_reason(exc.data.get("limit")))
            cut = True
        if examined != self.cluster_count:
            reasons.add("allocation_unreadable")
        inspection.update(allocation_clusters_examined=examined, allocation_free=free,
                          allocation_complete=examined == self.boot["cluster_count"]
                          and self._cluster_metadata_allocation_complete and not cut)
        inspection["reasons"] = [r for r in _CLUSTER_REASONS if r in reasons]
        pct = self.boot["percent_in_use"]
        out = {
            "fs": "exfat", "scanned": True, "cluster_count": self.cluster_count, "allocated": allocated,
            "free": self.cluster_count - allocated, "referenced_by_live": bits.count(),
            "allocated_unreferenced": unref, "allocated_unreferenced_runs": unref_runs,
            "unallocated_referenced": unalloc_ref,
            "unallocated_referenced_samples": [{"cluster": c} for c in unalloc_samples],
            "cross_linked": live["cross_linked"], "cross_linked_samples": live["cross_linked_samples"],
            "chain_anomalies": live["chain_anomalies"],
            "percent_in_use_boot": None if pct == 0xFF else pct,
            "percent_in_use_computed": (allocated * 100) // self.cluster_count if self.cluster_count else 0,
            "state": {"dirty": bool(self.volume_flags & 2), "media_failure": bool(self.volume_flags & 4)},
            "truncated": bool(live["truncated"]) or cut, "inspection": inspection,
        }
        out.update(w.export())
        return out
