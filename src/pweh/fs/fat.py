"""FAT12/16/32 해석 (Microsoft "FAT32 File System Specification" 을 바탕으로 한 깨끗한 재구현).

다루는 것
- BPB 해석·검사, FAT 종류는 사양대로 **클러스터 수**로 정한다(BS_FilSysType 문자열은 참고만).
  예외: BPB_FATSz16 == 0 인 FAT32 배치인데 클러스터 수가 65525 미만이면 Linux 처럼 32비트 항목으로 읽고 경고한다.
- FSInfo, FAT32 백업 부트 섹터, ExtFlags(미러링 꺼짐이면 활성 FAT 사용), 볼륨 레이블(부트 섹터·루트 항목 둘 다).
- 상태 표시: FAT[1] 의 ClnShutBit/HrdErrBit(FAT16 0x8000/0x4000, FAT32 0x08000000/0x04000000 — 켜져 있으면 깨끗함/오류 없음,
  FAT12 에는 없음)와 부트 섹터 상태 바이트(FAT12/16 0x25, FAT32 0x41) 비트0(Linux FAT_STATE_DIRTY·Windows NT 가 씀, 사양상 예약).
- 디렉터리: 8.3 이름(+ NT 소문자 플래그), LFN 조립(순서·체크섬 확인, 고아 LFN 보고), 삭제 항목(0xE5).
  삭제된 SFN 의 첫 글자는 바로 앞의 삭제 LFN 체크섬을 거꾸로 풀어 얻는다(체크섬은 첫 바이트에 대해 전단사).
  체크섬을 이렇게 쓰면 검사 기능을 잃으므로, 얻은 바이트가 SFN 에 쓸 수 있는 문자이고 LFN 첫 글자와 맞을 때만 연결한다.
- 체인 따라가기: 순환·길이 한도, 상태 ok / zeroed(빈 항목에서 끊김) / broken(불량 클러스터 표시) / out-of-range / cycle /
  unreadable(FAT 이 이미지 밖) / limit(크기보다 김).
- 삭제 파일 복구 후보: contiguous(시작 클러스터부터 연속), skip-allocated(지금 할당된 클러스터 건너뛰기),
  skip-claimed(다른 삭제 항목이 차지했던 구간도 건너뛰기), fat-chain(FAT 항목이 남아 있을 때). 신뢰도와 설명을 붙인다.
- 볼륨 수준 점검(cluster_report): 할당됐지만 참조되지 않는 클러스터(잃어버린 체인), 참조되지만 빈 클러스터, 교차 연결,
  크기·체인 불일치, FSInfo 빈 클러스터 수 비교, FAT 사본 차이.

- 디렉터리 검증(base.py 설명): 클러스터(고정 루트는 섹터)마다 모든 슬롯이 엄격한 검사를 통과해야 해석한다 — 속성 예약 비트(0x40·0x80)·
  조합(볼륨 레이블+디렉터리 금지, 레이블은 루트에만·클러스터와 크기 0), 8.3 이름 바이트(" * . / : < > ? \\ | 와 제어 문자 금지,
  2바이트 코드 페이지의 둘째 바이트로는 \\ | 허용; + , ; = [ ] 는 Linux msdos 드라이버가 쓰고 fsck.fat 도 받으므로 허용), LFN 구조
  (LDIR_Type 0, LDIR_FstClusLO 0, ordinal 범위, 종결자 뒤 0xFFFF 채움), 클러스터 번호 범위, 크기(볼륨 데이터 영역보다 클 수 없음,
  살아 있는 파일이 크기가 있으면 시작 클러스터가 있어야 함), 하위 디렉터리 첫 두 슬롯의 '.'(자기 클러스터)·'..', FAT12/16/32 디렉터리의
  이어지는 클러스터를 다른 FAT 항목이나 살아 있는 항목의 시작 클러스터도 가리키면 교차 연결(cross_linked). FAT32 루트도 검사한다.
  역방향 FAT·시작 클러스터 색인은 예산·슬롯·깊이·메모리 한도 안에서 만든다. 역방향 FAT 을 다 못 보면
  cross_link_check_incomplete 로 멈추며, 시작 클러스터 색인만 일부면 앞부분을 보존하고 cross_link_check_partial 로 알린다.
  LFN 순서·체크섬이 어긋난 것은 검증 실패가 아니라 고아 LFN 으로 보고한다(예전과 같음).
- 일부러 fsck.fat 보다 엄격한 검사: 속성 예약 비트(attr_reserved), 하위 디렉터리의 볼륨 레이블(label_outside_root), LFN ordinal 의
  예약 비트·제어 문자·종결자 뒤 글자(lfn_ordinal·lfn_char·lfn_padding). 알려진 기록기가 쓰지 않는 값이고, 녹화 데이터(무작위 바이트)를
  디렉터리로 잘못 읽지 않게 거르는 주된 장치라 그대로 둔다. 이런 클러스터는 조용히 버리지 않고 unvalidated_dirs(사유 코드 포함)와
  dir_unvalidated 경고로 드러난다 — 사람이 그 디렉터리를 따로 확인할 수 있다.
- 예산: 체인 따라가기·건너뛰기 탐색·볼륨 전체 순회는 호출의 Budget 안에서 한다(base.py).

참조(ref)는 ``"<dirspec>/<slot>"`` 이다. dirspec 은 ``root``, ``c<클러스터>``(FAT 체인을 따라가는 디렉터리),
``n<클러스터>+<바이트>``(체인 없이 연속으로 읽는 디렉터리 — 삭제된 디렉터리의 첫 클러스터) 중 하나이고 slot 은 SFN 항목의 슬롯 번호다.
ref 는 에이전트를 거쳐 돌아오는 신뢰할 수 없는 입력이므로 형식과 범위를 검사하고 디렉터리를 다시 읽어(검증 포함) 그 슬롯이 SFN 인지
확인한다. 항목의 바이트 오프셋(offset/image_offset)은 정보용이다.
"""

from __future__ import annotations

import bisect
import codecs
import re
import struct
from collections import OrderedDict
from typing import Any

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
    fat_date_only,
    fat_timestamp,
    guard,
)
from .base import DirCtx, DirResult, Peek, VolumeBase
from .tables import BitSet, Chain, FatTable, follow_chain

__all__ = ["FatVolume", "parse_bpb", "probe_fat_boot_sector", "lfn_checksum"]

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LONG_NAME = 0x0F
_ATTR_NAMES = ((0x01, "readonly"), (0x02, "hidden"), (0x04, "system"), (0x08, "volume_label"),
               (0x10, "directory"), (0x20, "archive"), (0x40, "device"), (0x80, "reserved"))

DIR_MAX_SLOTS = 65536  # 사양: 디렉터리 하나에 32바이트 항목 65536 개까지
DIR_MAX_BYTES = DIR_MAX_SLOTS * 32
LFN_MAX_SLOTS = 20  # 255자 / 13
_ENTRY_LIMITS = {"fat12": 0xFF6, "fat16": 0xFFF6, "fat32": 0x0FFFFFF6}
_BAD = {"fat12": 0xFF7, "fat16": 0xFFF7, "fat32": 0x0FFFFFF7}
_EOC_MIN = {"fat12": 0xFF8, "fat16": 0xFFF8, "fat32": 0x0FFFFFF8}
_WIDTH = {"fat12": 12, "fat16": 16, "fat32": 32}

# SFN 에 쓸 수 있는 바이트 (첫 글자 기준: 공백 불가, 0xE5 는 0x05 로 저장)
_SFN_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~") | frozenset(range(0x80, 0x100))
_SFN_FIRST_OK = (_SFN_CHARS - {0xE5}) | {0x05}
_LFN_TO_SFN_REPLACED = frozenset("+,;=[] ")

_SPEC_RE = re.compile(r"^(?:(root)|c(\d{1,10})|n(\d{1,10})\+(\d{1,9}))$")

_DOT = b".          "
_DOTDOT = b"..         "
# 8.3 이름에 쓸 수 없는 바이트: 0x00~0x1F, " * . / : < > ? \ |  (소문자·0x7F·0x80 이상은 허용 — 사양 밖 구현이 쓴다).
# 사양은 + , ; = [ ] 도 금지하지만 Linux 'msdos'(LFN 없음) 마운트가 짧은 이름에 쓰고 fsck.fat 도 받으므로 허용한다.
_SFN_BAD = frozenset(range(0x20)) | frozenset(b'"*./:<>?\\|')
_SFN_ALLOWED = bytes(b for b in range(256) if b not in _SFN_BAD)
_DBCS_TRAIL_OK = frozenset(b"\\|")  # 2바이트 코드 페이지(Shift-JIS·GBK·Big5)의 둘째 바이트로는 나올 수 있다


def lfn_checksum(name11: bytes) -> int:
    """LFN 항목이 가리키는 8.3 이름의 체크섬 (사양의 회전 덧셈)."""
    s = 0
    for b in name11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _invert_first_byte(rest10: bytes, target: int) -> int:
    """name11[1:] 이 rest10 일 때 체크섬이 target 이 되는 첫 바이트 (첫 바이트에 대해 전단사라 하나뿐).

    체크섬은 s ← ror8(s) + b 를 11번 하고 처음 s 는 0 이라 첫 걸음 뒤 s = 첫 바이트다. 마지막 값에서 거꾸로
    s ← rol8(s − b) 를 10번 하면 그 첫 바이트가 나온다 — 상수 시간(예전 256번 시도 대신).
    """
    s = target & 0xFF
    for b in reversed(bytes(rest10)):
        s = (s - b) & 0xFF
        s = ((s << 1) & 0xFF) | (s >> 7)
    return s


def _sfn_name_problem(name11: bytes) -> str | None:
    """8.3 이름 11바이트의 문제 (없으면 None). 첫 바이트 0xE5(삭제)·0x05(첫 글자 0xE5)는 건너뛴다."""
    b0 = name11[0]
    if b0 == 0x20:
        return "name_first_space"
    start = 1 if b0 in (0x05, 0xE5) else 0
    rest = name11[start:]
    if not rest.translate(None, _SFN_ALLOWED):
        return None
    prev = 0xE5 if start else 0
    for c in rest:
        if c in _SFN_BAD and not (c in _DBCS_TRAIL_OK and prev >= 0x81):
            return "name_char"
        prev = c
    return None


def _lfn_problem(raw: bytes) -> str | None:
    """LFN 슬롯 하나의 구조 문제 (없으면 None). 순서·체크섬은 여기서 보지 않는다(어긋나면 고아 LFN 으로 보고)."""
    if raw[12] != 0:
        return "lfn_type"
    if raw[26] or raw[27]:
        return "lfn_cluster"
    b0 = raw[0]
    last = None
    if b0 != 0xE5:
        if b0 & 0xA0 or not 1 <= (b0 & 0x1F) <= LFN_MAX_SLOTS:
            return "lfn_ordinal"
        last = bool(b0 & 0x40)
    u = _lfn_units(raw)
    pad = False  # 종결자(0x0000) 뒤 — 사양은 0xFFFF 채움이지만 0x0000 채움·종결자 없는 0xFFFF 채움을 쓰는 구현도 받아 준다
    for i in range(0, 26, 2):
        v = u[i] | (u[i + 1] << 8)
        if pad:
            if v != 0xFFFF and v != 0:
                return "lfn_padding"
        elif v == 0 or v == 0xFFFF:
            pad = True
        elif v < 0x20:
            return "lfn_char"
    if pad and last is False:
        return "lfn_terminator"  # 마지막이 아닌 LFN 슬롯은 13글자가 다 차 있어야 한다
    return None


def _attr_flags(attr: int) -> list[str]:
    return [name for bit, name in _ATTR_NAMES if attr & bit]


def fold_1to1(s: str) -> str:
    """대소문자 무시 비교용: 글자마다 대문자로 — 대문자가 한 글자일 때만 바꾼다(ß→SS·ﬁ→FI 처럼 글자 수를 바꾸는 접기는 하지 않는다).

    str.upper() 는 글자를 줄이지 않으므로 길이가 같으면 글자마다 한 글자로 바뀐 것이다(빠른 길).
    """
    u = s.upper()
    if len(u) == len(s):
        return u
    out = []
    for c in s:
        cu = c.upper()
        out.append(cu if len(cu) == 1 else c)
    return "".join(out)


def parse_bpb(bs: bytes, w: Warnings | None = None, *, strict_jump: bool = False) -> dict[str, Any]:
    """부트 섹터(최소 512바이트)의 BPB 를 해석하고 기하를 계산한다. FAT 가 아니면 FsError(reason="not_fat")."""
    w = w if w is not None else Warnings()
    if len(bs) < 512:
        raise FsError("FAT 부트 섹터는 512바이트 이상이어야 합니다.", reason="not_fat")
    name = bytes(bs[3:11])
    if name in (b"EXFAT   ", b"NTFS    "):
        raise FsError(f"FAT 이 아닙니다({name.decode('ascii').strip()}).", reason="not_fat")
    (bps, spc, rsvd, nfats, root_ent, tot16, media, fatsz16, spt, heads, hidden, tot32) = struct.unpack_from(
        "<HBHBHHBHHHII", bs, 11)
    jump_ok = (bs[0] == 0xEB and bs[2] == 0x90) or bs[0] == 0xE9
    if not jump_ok:
        if strict_jump:
            raise FsError("부트 섹터의 점프 명령이 FAT 형식이 아닙니다.", reason="not_fat")
        w.add("bpb_bad_jump", "부트 섹터 점프 명령(EB xx 90 / E9 xx xx)이 없습니다.", value=bytes(bs[0:3]).hex())
    if bps not in (512, 1024, 2048, 4096):
        raise FsError(f"BPB_BytsPerSec 값이 잘못됐습니다: {bps}", reason="not_fat", data={"bytes_per_sector": bps})
    if spc == 0 or spc & (spc - 1):
        raise FsError(f"BPB_SecPerClus 가 2의 거듭제곱이 아닙니다: {spc}", reason="not_fat")
    if rsvd == 0:
        raise FsError("BPB_RsvdSecCnt 가 0 입니다.", reason="not_fat")
    if nfats == 0:
        raise FsError("BPB_NumFATs 가 0 입니다.", reason="not_fat")
    layout32 = fatsz16 == 0
    ext: dict[str, Any] = {}
    if layout32:
        (fatsz32, ext_flags, fs_ver, root_clus, fsinfo, bk_boot, _res, drv, state, bootsig, volid, vollab,
         fstype) = struct.unpack_from("<IHHIHH12sBBBI11s8s", bs, 36)
        fatsz = fatsz32
        ext.update(ext_flags=ext_flags, fs_version=fs_ver, root_cluster=root_clus, fsinfo_sector=fsinfo,
                   backup_boot_sector=bk_boot, state_offset=0x41)
    else:
        drv, state, bootsig, volid, vollab, fstype = struct.unpack_from("<BBBI11s8s", bs, 36)
        fatsz = fatsz16
        ext.update(state_offset=0x25)
    if fatsz == 0:
        raise FsError("FAT 크기(BPB_FATSz16/32)가 0 입니다.", reason="not_fat")
    if tot16 and tot32 and tot16 != tot32:
        w.add("bpb_both_totsec", "BPB_TotSec16 과 BPB_TotSec32 가 둘 다 0 이 아니고 다릅니다(TotSec16 사용).",
              tot16=tot16, tot32=tot32)
    totsec = tot16 if tot16 else tot32
    if totsec == 0:
        raise FsError("전체 섹터 수가 0 입니다.", reason="not_fat")
    if media not in (0xF0,) and media < 0xF8:
        w.add("bpb_media", f"BPB_Media 값이 이상합니다: 0x{media:02x}")
    if bs[510] != 0x55 or bs[511] != 0xAA:
        w.add("boot_signature_missing", "부트 섹터 끝 서명 0x55AA 가 없습니다.")
    if nfats > 2:
        w.add("bpb_many_fats", f"FAT 사본이 {nfats} 개입니다.")
    if layout32 and root_ent:
        w.add("bpb_fat32_rootent", "FAT32 배치인데 BPB_RootEntCnt 가 0 이 아닙니다.", value=root_ent)
    if not layout32 and (root_ent * 32) % bps:
        w.add("bpb_rootent_align", "루트 디렉터리 크기가 섹터 크기의 배수가 아닙니다.", value=root_ent)
    root_dir_sectors = 0 if layout32 else ((root_ent * 32) + (bps - 1)) // bps
    meta = rsvd + nfats * fatsz + root_dir_sectors
    if totsec <= meta:
        raise FsError("데이터 영역이 없습니다(예약·FAT·루트 영역이 전체보다 큼).", reason="not_fat",
                      data={"total_sectors": totsec, "metadata_sectors": meta})
    count = (totsec - meta) // spc
    if count < 1:
        raise FsError("클러스터가 하나도 없습니다.", reason="not_fat")
    by_count = "fat12" if count < 4085 else ("fat16" if count < 65525 else "fat32")
    if layout32:
        fat_type = "fat32"
        if by_count != "fat32":
            w.add("fat_type_layout_mismatch",
                  f"FAT32 배치(BPB_FATSz16=0)인데 클러스터 수 {count} 는 사양상 {by_count.upper()} 입니다. "
                  "Linux 처럼 32비트 항목으로 읽습니다.", cluster_count=count)
    else:
        fat_type = by_count if by_count != "fat32" else "fat16"
        if by_count == "fat32":
            w.add("fat_type_layout_mismatch",
                  f"FAT12/16 배치인데 클러스터 수 {count} 는 사양상 FAT32 입니다. FAT16 항목으로 읽고 범위를 줄입니다.",
                  cluster_count=count)
    width = _WIDTH[fat_type]
    capacity = (fatsz * bps * 8) // width
    max_cluster = min(count + 1, _ENTRY_LIMITS[fat_type])
    if capacity < max_cluster + 1:
        w.add("fat_too_small", f"FAT 크기가 클러스터 {count} 개를 담기에 부족합니다(항목 {capacity} 개).",
              capacity=capacity)
        max_cluster = capacity - 1
    if max_cluster < 2:
        raise FsError("사용할 수 있는 클러스터가 없습니다.", reason="not_fat")
    cluster_size = bps * spc
    if cluster_size > 64 * 1024:
        w.add("cluster_size_large", f"클러스터 크기 {cluster_size} 바이트는 사양 권장(32 KiB)보다 큽니다.")
    return {
        "fat_type": fat_type,
        "fat_type_by_count": by_count,
        "layout": "fat32" if layout32 else "fat12/16",
        "jump": bytes(bs[0:3]).hex(),
        "oem_name": bytes(bs[3:11]),
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "cluster_size": cluster_size,
        "reserved_sectors": rsvd,
        "num_fats": nfats,
        "root_entry_count": root_ent,
        "total_sectors": totsec,
        "total_sectors16": tot16,
        "total_sectors32": tot32,
        "media": media,
        "fat_size_sectors": fatsz,
        "sectors_per_track": spt,
        "heads": heads,
        "hidden_sectors": hidden,
        "drive_number": drv,
        "state_byte": state,
        "ext_boot_signature": bootsig,
        "volume_id": volid,
        "volume_label_raw": bytes(vollab),
        "fs_type_label_raw": bytes(fstype),
        "root_dir_sectors": root_dir_sectors,
        "first_data_sector": meta,
        "cluster_count": count,
        "max_cluster": max_cluster,
        **ext,
    }


def probe_fat_boot_sector(bs: bytes) -> dict[str, Any] | None:
    """부트 섹터가 FAT 로 보이면 BPB 요약, 아니면 None (분류용 — 점프 명령도 요구한다)."""
    try:
        return parse_bpb(bs, Warnings(0), strict_jump=True)
    except FsError:
        return None
    except Exception:  # noqa: BLE001 - 분류는 실패해도 None
        return None


def _lfn_units(raw: bytes) -> bytes:
    return bytes(raw[1:11]) + bytes(raw[14:26]) + bytes(raw[28:32])


def _lfn_has_terminator(raw: bytes) -> bool:
    u = _lfn_units(raw)
    return any(u[i] == 0 and u[i + 1] == 0 for i in range(0, 26, 2)) or u[0:2] == b"\xff\xff"


def _lfn_text(ordered: list[bytes]) -> tuple[str, bool, bytes]:
    """ordinal 1..n 순서의 LFN 슬롯 → (이름, lossy, 원시 UTF-16LE)."""
    units = b"".join(_lfn_units(r) for r in ordered)
    end = len(units)
    for i in range(0, len(units) - 1, 2):
        if units[i] == 0 and units[i + 1] == 0:
            end = i
            break
    raw = units[:end]
    # 종결자 없이 0xFFFF 채움만 있는 경우(손상) 대비
    while raw.endswith(b"\xff\xff"):
        raw = raw[:-2]
    text, lossy = decode_utf16le(raw)
    return text, lossy, raw


def _expected_sfn_first(long_name: str) -> tuple[set[int], bool] | None:
    """긴 이름에서 기대하는 SFN 첫 바이트 집합과 '하나로 정해지는지' 여부."""
    s = long_name.lstrip(" .")
    if not s:
        return None
    c = s[0]
    if ord(c) < 0x80:
        cu = c.upper()
        if len(cu) == 1 and ord(cu) in _SFN_CHARS:
            return {ord(cu)}, True
        if c in _LFN_TO_SFN_REPLACED or ord(c) < 0x20:
            return {ord("_")}, True
        return {ord("_")}, False
    return {ord("_")} | set(range(0x80, 0x100)), False


class _FatDirCtx(DirCtx):
    """교차 연결 색인에도 이 디렉터리를 읽는 호출의 예산을 전달한다."""

    __slots__ = ("budget", "partial_reason", "heads")

    def __init__(self, spec: str, spec_t: tuple[Any, ...], budget: Budget) -> None:
        super().__init__(spec, spec_t)
        self.budget = budget
        self.partial_reason: str | None = None
        self.heads: set[int] | None = None


class FatVolume(VolumeBase):
    """FAT12/16/32 볼륨 (읽기 전용)."""

    kind = "fat"
    max_slot = DIR_MAX_SLOTS

    @guard
    def __init__(self, src: Any, *, limits: Limits | None = None, oem_codepage: str = "cp437",
                 budget: Budget | None = None) -> None:
        self.src = src
        self.limits = limits or Limits()
        self.base_offset = int(getattr(src, "base_offset", 0))
        try:
            codecs.lookup(oem_codepage)
        except LookupError:
            raise FsError(f"알 수 없는 OEM 코드 페이지: {oem_codepage}", reason="bad_argument") from None
        self.oem_codepage = oem_codepage
        self._w = Warnings(self.limits.max_warnings)
        if src.size < 512:
            raise FsError("FAT 부트 섹터를 읽을 수 없습니다(512바이트 미만).", reason="not_fat")
        bs = src.read(0, 512)
        bpb = parse_bpb(bs, self._w)
        bps = bpb["bytes_per_sector"]
        self.boot_sector = src.read(0, bps) if src.size >= bps else bs
        self.bpb = bpb
        self.fat_type: str = bpb["fat_type"]
        self.bytes_per_sector = bps
        self.cluster_size: int = bpb["cluster_size"]
        self.max_cluster: int = bpb["max_cluster"]
        self.cluster_count: int = bpb["cluster_count"]
        self.fat_offset = bpb["reserved_sectors"] * bps
        self.fat_bytes = bpb["fat_size_sectors"] * bps
        self.root_offset = (bpb["reserved_sectors"] + bpb["num_fats"] * bpb["fat_size_sectors"]) * bps
        self.root_size = bpb["root_dir_sectors"] * bps
        self.data_offset = bpb["first_data_sector"] * bps  # 클러스터 2 의 볼륨 기준 오프셋
        self.heap_offset = self.data_offset
        self.volume_size = bpb["total_sectors"] * bps
        self.bad_value = _BAD[self.fat_type]
        self.eoc_min = _EOC_MIN[self.fat_type]
        self.active_fat = 0
        self.mirroring = True
        self.root_cluster = 0
        if self.fat_type == "fat32":
            ext_flags = bpb.get("ext_flags", 0)
            if ext_flags & 0x80:
                self.mirroring = False
                self.active_fat = ext_flags & 0x0F
                if self.active_fat >= bpb["num_fats"]:
                    self._w.add("fat32_active_fat_invalid", f"ExtFlags 의 활성 FAT 번호 {self.active_fat} 가 FAT 수보다 큽니다(0 사용).")
                    self.active_fat = 0
            if bpb.get("fs_version", 0) != 0:
                self._w.add("fat32_fsver", f"BPB_FSVer 가 0.0 이 아닙니다: 0x{bpb['fs_version']:04x}")
            self.root_cluster = bpb.get("root_cluster", 0)
            if not 2 <= self.root_cluster <= self.max_cluster:
                self._w.add("fat32_root_cluster_invalid", f"루트 디렉터리 클러스터 {self.root_cluster} 가 범위를 벗어났습니다.")
        if self.volume_size > src.size:
            self._w.add("volume_truncated", "이미지(또는 파티션)가 볼륨 크기보다 짧습니다 — 뒷부분 클러스터는 읽을 수 없습니다.",
                        volume_size=self.volume_size, available=src.size)
        if self.fat_offset + self.fat_bytes > src.size:
            self._w.add("fat_beyond_image", "FAT 영역 일부가 이미지 밖에 있습니다.")
        self._fat = FatTable(src, self.fat_offset + self.active_fat * self.fat_bytes, self.fat_bytes,
                             _WIDTH[self.fat_type], self.max_cluster, mask_top_nibble=self.fat_type == "fat32")
        self._dir_cache: "OrderedDict[str, DirResult]" = OrderedDict()
        self._live_cache: dict[str, Any] | None = None
        self._claims_cache: list[tuple[int, int, str]] | None = None
        self._claims_partial: str | None = None
        #: 디렉터리 항목 크기의 상한 = 주소를 붙일 수 있는 데이터 영역 바이트
        self._data_bytes = max(0, self.max_cluster - 1) * self.cluster_size
        #: 역방향 FAT: 하나 이상/둘 이상이 가리키는 클러스터. 표 크기와 max_scan_clusters 로 메모리를 묶는다.
        self._preds: tuple[BitSet, BitSet] | None = None
        self._preds_complete = False
        self._preds_reason: str | None = None
        #: 검증한 살아 있는 항목의 시작 클러스터. 완주한 색인만 캐시한다.
        self._heads: set[int] | None = None
        self._heads_reason: str | None = None
        self._heads_partial: tuple[Budget, set[int], str] | None = None
        self._scanning_heads = False
        if budget is not None:
            budget.raise_steps(self.step_cap())  # 호출자가 이 볼륨에 함께 쓸 예산 — 이 볼륨의 단계 상한까지 올린다

    # ------------------------------------------------------------------
    # 기본 도우미
    # ------------------------------------------------------------------
    def _bitset_size(self) -> int:
        """클러스터 비트 집합 크기: 헤더가 주장하는 클러스터 수가 아니라 이미지 안에서 실제로 읽을 수 있는 FAT 항목 수로 묶는다."""
        return min(self.max_cluster + 1, self._fat.readable + 2)

    def cluster_offset(self, c: int) -> int:
        return self.data_offset + (c - 2) * self.cluster_size

    def fat_entry(self, c: int) -> int | None:
        return self._fat.get(c)

    def _kind(self, v: int | None) -> str:
        if v is None:
            return "unreadable"
        if v == 0:
            return "free"
        if v == self.bad_value:
            return "bad"
        if v >= self.eoc_min:
            return "eoc"
        if 2 <= v <= self.max_cluster:
            return "next"
        return "invalid"

    def _follow(self, start: int, limit: int, budget: Budget | None = None) -> Chain:
        return follow_chain(self._fat.get, self._kind, start, limit, self.max_cluster, max_runs=self.limits.max_runs,
                            budget=budget)

    def _cluster_of(self, raw: bytes) -> int:
        lo = raw[26] | (raw[27] << 8)
        if self.fat_type == "fat32":
            return lo | ((raw[20] | (raw[21] << 8)) << 16)
        return lo

    def _decode_sfn(self, name11: bytes, ntres: int, first: int | None) -> str:
        base = bytearray(name11[0:8])
        ext = bytes(name11[8:11])
        if first is not None:
            base[0] = first
        if base[0] == 0x05:
            base[0] = 0xE5
        b = bytes(base).rstrip(b" ").decode(self.oem_codepage, errors="replace")
        e = ext.rstrip(b" ").decode(self.oem_codepage, errors="replace")
        if ntres & 0x08:
            b = b.lower()
        if ntres & 0x10:
            e = e.lower()
        return b + ("." + e if e else "")

    # ------------------------------------------------------------------
    # dirspec / ref
    # ------------------------------------------------------------------
    def _parse_spec(self, spec: str) -> tuple[Any, ...]:
        if not isinstance(spec, str):
            raise FsError("디렉터리 지정이 문자열이 아닙니다.", reason="bad_ref")
        m = _SPEC_RE.match(spec)
        if not m:
            raise FsError(f"디렉터리 지정 형식이 잘못됐습니다: {spec[:60]!r}", reason="bad_ref",
                          hint="root, c<클러스터>, n<클러스터>+<바이트> 중 하나")
        if m.group(1):
            return ("root",)
        if m.group(2) is not None:
            c = int(m.group(2))
            if not 2 <= c <= self.max_cluster:
                raise FsError(f"디렉터리 클러스터 {c} 가 범위(2..{self.max_cluster})를 벗어났습니다.", reason="bad_ref")
            return ("chain", c)
        c = int(m.group(3))
        length = int(m.group(4))
        if not 2 <= c <= self.max_cluster or not 1 <= length <= DIR_MAX_BYTES:
            raise FsError("디렉터리 지정의 클러스터나 길이가 범위를 벗어났습니다.", reason="bad_ref")
        return ("contig", c, length)

    def _spec_key(self, spec: str) -> Any:
        """방문 표시용 키: 디렉터리의 첫 클러스터 (FAT12/16 루트는 'root')."""
        t = self._parse_spec(spec)
        if t[0] == "root":
            return self.root_cluster if self.fat_type == "fat32" else "root"
        return t[1]

    def _fs_name(self) -> str:
        return self.fat_type

    def _fold(self, s: str) -> str:
        """FAT 이름 비교: 글자마다 한 글자 대문자 (짧은 이름은 OEM 코드 페이지로 푼 글자를 같은 규칙으로 — 대소문자 무시)."""
        return fold_1to1(s)

    def _name_keys(self, e: dict[str, Any]) -> tuple[str, ...]:
        return (e["name"], e["display_name"], e["short_name"])

    def _method_names(self, e: dict[str, Any], region: str = "data") -> list[str]:
        if region != "data":
            return []
        if not e["deleted"]:
            return ["chain"]
        n = ceil_div(self.cluster_size if e["is_dir"] else e["size"], self.cluster_size)
        if n == 0:
            return ["empty"]
        start = e["first_cluster"]
        if not 2 <= start <= self.max_cluster:
            return ["none"]
        out = ["contiguous", "skip-allocated", "skip-claimed"]
        if self._fat.get(start) not in (0, None):
            out.append("fat-chain")
        return out

    def _ensure_predecessors(self, budget: Budget) -> None:
        """FAT12/16/32 의 역방향 수를 2 에서 포화시킨다. 미완료 표는 다음 호출에서 다시 만든다."""
        if self._preds_complete:
            return
        cap = max(0, int(self.limits.max_scan_clusters))
        nbits = min(self._bitset_size(), cap + 2)
        seen, shared = BitSet(nbits), BitSet(nbits)
        self._preds = seen, shared
        self._preds_reason = None
        stop = min(self.max_cluster + 1, self._fat.readable, cap + 2)
        scanned = 2
        # 조각마다 취소·시간·단계 예산을 확인한다(다른 FAT 순회처럼 64 항목 = 1 단계).
        for start in range(2, stop, 4096):
            budget.tick(ceil_div(min(4096, stop - start), 64))
            if budget.expired():
                self._preds_reason = budget.reason
                return
            for base, values in self._fat.slices(start, min(stop, start + 4096)):
                for c in values:
                    if 2 <= c < nbits and seen.set(c):
                        shared.set(c)
                scanned = base + len(values)
        self._preds_complete = scanned >= self.max_cluster + 1
        if not self._preds_complete:
            self._preds_reason = "max_scan_clusters" if cap < self.cluster_count else "fat_unreadable"

    def _directory_heads(self, budget: Budget) -> set[int]:
        """살아 있는 디렉터리의 검증된 항목만 읽어 시작 클러스터를 모은다. 내용·파일 체인은 읽지 않는다.

        이어지는 디렉터리 클러스터가 파일의 첫 클러스터이면 역방향 FAT 이 하나뿐일 수 있다. 따라서 그 단위를 내보내기 전에
        이름 없는 시작 클러스터 색인을 만든다. 순회 도중 검증하지 못한 디렉터리·한도는 '미완료'이고, 양성 근거만 쓸 수 있다.
        """
        if self._heads is not None:
            return self._heads
        if self._heads_partial is not None and self._heads_partial[0] is budget:
            self._heads_reason = self._heads_partial[2]
            return self._heads_partial[1]
        self._heads_partial = None
        heads: set[int] = {self.root_cluster} if self.fat_type == "fat32" else set()
        visited: set[Any] = set()
        stack = [("root", 0)]
        slots = entries = 0
        reason = None
        self._scanning_heads = True
        try:
            while stack:
                if budget.expired():
                    reason = budget.reason
                    break
                if slots >= self.limits.max_total_slots:
                    reason = "max_total_slots"
                    break
                spec, depth = stack.pop()
                key = self._spec_key(spec)
                if key in visited:
                    continue
                visited.add(key)
                try:
                    res = self._parse_dir(spec, budget, summaries=False)
                except FsError as exc:
                    reason = budget.reason or exc.reason
                    continue
                slots += res.slots
                if res.unvalidated or res.incomplete or res.cut or res.budget_stop:
                    reason = res.budget_stop or res.incomplete or (res.cut or {}).get("reason") or "dir_unvalidated"
                for e in res.entries:
                    if e["deleted"]:
                        continue
                    entries += 1
                    if entries > self.limits.max_entries:
                        reason = "max_entries"
                        stack.clear()
                        break
                    fc = e["first_cluster"]
                    if 2 <= fc <= self.max_cluster:
                        heads.add(fc)
                    child = e.get("child_dir")
                    if child:
                        if depth + 1 >= self.limits.max_depth:
                            reason = "max_depth"
                        else:
                            stack.append((child, depth + 1))
        finally:
            self._scanning_heads = False
        self._heads_reason = reason
        if reason is None:
            self._heads = heads
        else:
            # 같은 호출에서 여러 디렉터리를 읽어도 같은 부분 색인을 다시 만들지 않는다. 새 예산이면 다시 확인한다.
            self._heads_partial = budget, heads, reason
        return heads

    def _check_dir(self, spec: str, key: Any, res: DirResult, w: Warnings, path: str) -> None:
        dot = res.extra.get("dot", {}).get(".")
        if spec != "root" and not spec.startswith("n") and dot and dot["cluster"] != key:
            w.add("dot_mismatch", "'.' 항목이 자기 클러스터를 가리키지 않습니다.", path=path)

    # ------------------------------------------------------------------
    # 디렉터리 검증 (클러스터·섹터 단위)
    # ------------------------------------------------------------------
    def _slot_problem(self, raw: bytes, is_root: bool) -> str | None:
        """'.'·'..' 가 아닌 슬롯 하나의 문제 (없으면 None)."""
        attr = raw[11]
        if (attr & 0x3F) == ATTR_LONG_NAME:
            return _lfn_problem(raw)
        if attr & 0xC0:
            return "attr_reserved"
        name11 = raw[0:11]
        if attr & ATTR_VOLUME_ID:
            if attr & ATTR_DIRECTORY:
                return "attr_combination"
            if not is_root:
                return "label_outside_root"
            if raw[20] or raw[21] or raw[26] or raw[27] or any(raw[28:32]):
                return "label_fields"  # 레이블 항목은 클러스터·크기가 0 이다
            if min(name11) < 0x20:
                return "label_char"
            return None
        if name11 == _DOT or name11 == _DOTDOT:
            return "dot_position"  # '.'·'..' 는 하위 디렉터리의 첫 두 슬롯에만
        p = _sfn_name_problem(name11)
        if p is not None:
            return p
        cl = self._cluster_of(raw)
        if cl == 1 or cl > self.max_cluster:
            return "cluster_range"
        live = raw[0] != 0xE5
        if attr & ATTR_DIRECTORY and live and cl == 0:
            return "dir_cluster"
        size = raw[28] | (raw[29] << 8) | (raw[30] << 16) | (raw[31] << 24)
        if size > self._data_bytes:
            return "size_range"  # 볼륨 데이터 영역보다 큰 파일은 없다 (살아 있는·삭제된 항목 모두)
        if size and cl == 0 and live and not attr & ATTR_DIRECTORY:
            return "size_without_cluster"  # 크기가 있는 살아 있는 파일은 시작 클러스터가 있어야 한다
        return None

    def _dot_problem(self, raw: bytes, idx: int, own: int) -> str | None:
        """하위 디렉터리 슬롯 0 = '.'(자기 첫 클러스터), 슬롯 1 = '..'."""
        want = _DOT if idx == 0 else _DOTDOT
        if raw[0:11] != want:
            return "missing_dot" if idx == 0 else "missing_dotdot"
        attr = raw[11]
        if not attr & ATTR_DIRECTORY or attr & (0xC0 | ATTR_VOLUME_ID):
            return "dot_attributes"
        cl = self._cluster_of(raw)
        if idx == 0 and cl != own:
            return "dot_cluster"
        if cl == 1 or cl > self.max_cluster:
            return "cluster_range"
        return None

    def _unit_problem(self, ctx: DirCtx, first: int, data: bytes, peek: Peek) -> tuple[str | None, int | None]:
        is_root = ctx.is_root
        if first and ctx.off is not None and (ctx.spec_t[0] == "chain" or (is_root and self.fat_type == "fat32")):
            # 고정 루트와 삭제된 연속 디렉터리는 FAT 체인의 교차 연결 검사 대상이 아니다.
            budget = ctx.budget
            if self._preds is None or (not self._preds_complete and not self._scanning_heads):
                self._ensure_predecessors(budget)
            c = (ctx.off - self.data_offset) // self.cluster_size + 2
            if self._preds is not None and self._preds[1].test(c):
                return "cross_linked", None
            if not self._scanning_heads:
                if ctx.heads is None:
                    ctx.heads = self._directory_heads(budget)
                    ctx.partial_reason = self._heads_reason
                if c in ctx.heads:
                    return "cross_linked", None
                if not self._preds_complete or budget.expired():
                    return "cross_link_check_incomplete", None
        for i in range(len(data) // 32):
            idx = first + i
            raw = data[32 * i:32 * i + 32]
            if raw[0] == 0x00:
                if not is_root and idx < 2:
                    return ("missing_dot" if idx == 0 else "missing_dotdot"), None
                return None, i
            if not is_root and idx < 2:
                p = self._dot_problem(raw, idx, ctx.own)
            else:
                p = self._slot_problem(raw, is_root)
            if p is not None:
                return p, None
        return None, None

    # ------------------------------------------------------------------
    # 디렉터리 읽기
    # ------------------------------------------------------------------
    def _dir_runs(self, spec_t: tuple[Any, ...], w: Warnings,
                  budget: Budget | None = None) -> tuple[list[tuple[int, int]], dict[str, Any]]:
        cs = self.cluster_size
        if spec_t[0] == "root" and self.fat_type != "fat32":
            return [(self.root_offset, self.root_size)], {"status": "fixed", "clusters": 0}
        if spec_t[0] == "contig":
            start, length = spec_t[1], spec_t[2]
            n = min(ceil_div(length, cs), self.max_cluster - start + 1)
            return [(self.cluster_offset(start), n * cs)], {"status": "contiguous", "clusters": n}
        start = self.root_cluster if spec_t[0] == "root" else spec_t[1]
        if not 2 <= start <= self.max_cluster:
            w.add("dir_start_invalid", f"디렉터리 시작 클러스터 {start} 가 범위를 벗어났습니다.")
            return [], {"status": "out-of-range", "clusters": 0}
        limit = ceil_div(DIR_MAX_BYTES, cs)
        ch = self._follow(start, limit, budget)
        info: dict[str, Any] = {"status": ch.status, "clusters": ch.count}
        if ch.capped:
            info["limit_reason"] = ch.capped  # 예산이 다 됨 — 해석도 곧 멈춘다(budget_stop)
        elif ch.status == "limit":
            # 체인이 사양 최대(65536 항목)보다 길다 — 앞부분만 읽고, 그 안에 끝 표시가 없으면 잘린 디렉터리로 보고한다(_finish_dir)
            info["cut"] = {"reason": "max_dir_slots", "slots_read": min(DIR_MAX_SLOTS, self.limits.max_dir_slots),
                           "slots_total": None}
        elif ch.status != "ok":
            w.add(f"dir_chain_{ch.status}", f"디렉터리 클러스터 체인이 정상적으로 끝나지 않았습니다({ch.status}).",
                  start=start)
        return [(self.cluster_offset(s), n * cs) for s, n in zip(ch.starts, ch.lens)], info

    def _orphan(self, res: DirResult, slots: list[tuple[int, int, bytes]], *, deleted: bool, reason: str,
                physical: bool = True) -> None:
        if not slots or len(res.orphans) >= self.limits.max_orphans:
            if slots:
                res.warnings.add("orphan_limit", "고아 LFN 보고 한도에 닿았습니다.")
            return
        ordered = [r for _, _, r in (reversed(slots) if physical else slots)]
        text, lossy, raw = _lfn_text(ordered)
        res.orphans.append({
            "dir": res.spec,
            "slot": slots[0][0],
            "slot_count": len(slots),
            "offset": slots[0][1],
            "image_offset": self.base_offset + slots[0][1],
            "deleted": deleted,
            "checksum": slots[-1][2][13],
            "partial_name": text,
            "display_name": display_name(text),
            "name_lossy": lossy,
            "name_raw": raw.hex() if lossy else None,
            "reason": reason,
        })

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
        max_slots = min(DIR_MAX_SLOTS, self.limits.max_dir_slots)
        is_root = spec_t[0] == "root"
        # 검사 단위: 클러스터 (FAT12/16 고정 루트는 섹터 — 클러스터 체인이 아니라 교차 연결될 수 없다)
        unit = self.bytes_per_sector if (is_root and self.fat_type != "fat32") else self.cluster_size
        live_lfn: list[tuple[int, int, bytes]] = []
        live_expect = 0
        live_csum = -1
        del_lfn: list[tuple[int, int, bytes]] = []

        def flush_live(reason: str) -> None:
            nonlocal live_lfn
            if live_lfn:
                self._orphan(res, live_lfn, deleted=False, reason=reason)
                live_lfn = []

        def flush_del(reason: str) -> None:
            nonlocal del_lfn
            if del_lfn:
                self._orphan(res, del_lfn, deleted=True, reason=reason)
                del_lfn = []

        ctx = _FatDirCtx(spec, spec_t, budget)
        for slot, off, raw in self._validated_slots(res, ctx, runs, unit, max_slots, budget):
            res.slots = slot + 1
            b0 = raw[0]
            attr = raw[11]
            if b0 == 0x00:
                res.end_slot = slot
                break
            lfn_attr = (attr & 0x3F) == ATTR_LONG_NAME
            if b0 == 0xE5:
                if lfn_attr:
                    flush_live("interrupted")
                    del_lfn.append((slot, off, raw))
                    if len(del_lfn) > 2 * LFN_MAX_SLOTS:
                        self._orphan(res, del_lfn[:LFN_MAX_SLOTS], deleted=True, reason="unassociated")
                        del_lfn = del_lfn[LFN_MAX_SLOTS:]
                    continue
                flush_live("interrupted")
                if attr & ATTR_VOLUME_ID and not attr & ATTR_DIRECTORY:
                    flush_del("unassociated")
                    continue  # 삭제된 볼륨 레이블
                e = self._make_entry(res, slot, off, raw, deleted=True, lfn=None, del_lfn=del_lfn)
                del_lfn = []
                if e is not None:
                    res.entries.append(e)
                continue
            if lfn_attr:
                flush_del("unassociated")
                ordv = b0
                if ordv & 0x40:
                    flush_live("interrupted")
                    n = ordv & 0x1F
                    if ordv & 0xA0 or not 1 <= n <= LFN_MAX_SLOTS:
                        self._orphan(res, [(slot, off, raw)], deleted=False, reason="bad_ordinal")
                        continue
                    live_lfn = [(slot, off, raw)]
                    live_expect = n - 1
                    live_csum = raw[13]
                else:
                    if (not live_lfn or ordv & 0xE0 or (ordv & 0x1F) != live_expect or raw[13] != live_csum
                            or live_expect < 1):
                        flush_live("sequence_broken")
                        self._orphan(res, [(slot, off, raw)], deleted=False, reason="sequence_broken")
                        continue
                    live_lfn.append((slot, off, raw))
                    live_expect -= 1
                continue
            # 살아 있는 SFN 또는 볼륨 레이블
            flush_del("unassociated")
            if attr & ATTR_VOLUME_ID and not attr & ATTR_DIRECTORY:
                flush_live("label")
                text = bytes(raw[0:11]).rstrip(b" ").decode(self.oem_codepage, errors="replace")
                if is_root and res.label is None:
                    res.label = text
                elif not is_root:
                    w.add("label_outside_root", "루트가 아닌 디렉터리에 볼륨 레이블 항목이 있습니다.", slot=slot)
                continue
            lfn_seq = None
            if live_lfn:
                if live_expect == 0:
                    lfn_seq = live_lfn
                else:
                    flush_live("incomplete")
                live_lfn = []
            e = self._make_entry(res, slot, off, raw, deleted=False, lfn=lfn_seq, del_lfn=None)
            if e is not None:
                res.entries.append(e)
        if res.cut_hit():
            # 슬롯 한도에서 잘린 자리에 걸친 LFN 조각은 SFN 이 한도 뒤에 있다 — 부분 이름을 고아로 내지 않는다
            if live_lfn or del_lfn:
                res.cut["boundary_slot"] = min(s for s, _, _ in live_lfn + del_lfn)
            live_lfn = []
            del_lfn = []
        flush_live("dangling")
        flush_del("unassociated")
        res.extra["public"] = {"dot_entries": dict(res.extra.get("dot", {}))}
        if res.unvalidated and res.unvalidated["reason"] == "cross_link_check_incomplete":
            res.extra["public"]["cross_link_check"] = {
                "status": "unknown", "reasons": list(dict.fromkeys(
                    r for r in (self._preds_reason, self._heads_reason) if r is not None)),
            }
        elif ctx.partial_reason is not None:
            res.extra["public"]["cross_link_check"] = {"status": "partial", "reasons": [ctx.partial_reason]}
            w.add("cross_link_check_partial", "시작 클러스터 색인을 끝까지 만들지 못해 디렉터리 교차 연결 검사는 일부 범위뿐입니다.",
                  reason=ctx.partial_reason)
        return self._finish_dir(self._dir_cache, spec, res, budget, summaries=summaries, runs=runs)

    def _make_entry(self, res: DirResult, slot: int, off: int, raw: bytes, *, deleted: bool,
                    lfn: list[tuple[int, int, bytes]] | None,
                    del_lfn: list[tuple[int, int, bytes]] | None) -> dict[str, Any] | None:
        name11 = bytes(raw[0:11])
        attr = raw[11]
        ntres = raw[12]
        ctenth = raw[13]
        ctime, cdate, adate, hi, wtime, wdate, lo, size = struct.unpack_from("<HHHHHHHI", raw, 14)
        ewarn: list[dict[str, Any]] = []
        fat32 = self.fat_type == "fat32"
        first_cluster = lo | ((hi << 16) if fat32 else 0)
        if not fat32 and hi:
            ewarn.append({"code": "fstclushi_ignored", "message": "FAT12/16 인데 DIR_FstClusHI 가 0 이 아닙니다(무시)."})
        is_dir = bool(attr & ATTR_DIRECTORY)
        if name11 in (b".          ", b"..         ") and not deleted:
            # . / .. 는 목록에 넣지 않고 디렉터리 검사용으로만 기록
            res.extra.setdefault("dot", {})[name11.strip().decode("ascii")] = {"slot": slot, "cluster": first_cluster}
            return None
        long_name = None
        lfn_status = "none"
        name_lossy = False
        long_raw = b""
        lfn_slots: list[int] = []
        first_info: dict[str, Any] | None = None
        recovered_first: int | None = None
        unverified = None
        if lfn is not None:  # 살아 있는 LFN (물리 순서 L_n..L_1)
            ordered = [r for _, _, r in reversed(lfn)]
            text, lossy, long_raw = _lfn_text(ordered)
            if lfn[0][2][13] == lfn_checksum(name11):
                long_name, name_lossy, lfn_status = text, lossy, "ok"
                lfn_slots = [s for s, _, _ in lfn]
            else:
                lfn_status = "checksum_mismatch"
                unverified = text
                self._orphan(res, lfn, deleted=False, reason="checksum_mismatch")
        if deleted:
            first_info = {"known": False, "source": "unknown", "confidence": "none"}
            tail: list[tuple[int, int, bytes]] = []
            if del_lfn:
                target = del_lfn[-1][2][13]
                for item in reversed(del_lfn):
                    if item[2][13] != target or len(tail) >= LFN_MAX_SLOTS:
                        break
                    tail.append(item)  # ordinal 1, 2, … 순서
                    if _lfn_has_terminator(item[2]):
                        break
            if tail:
                target = tail[0][2][13]
                b0 = _invert_first_byte(name11[1:], target)
                text, lossy, raw_name = _lfn_text([r for _, _, r in tail])
                expected = _expected_sfn_first(text)
                real = 0xE5 if b0 == 0x05 else b0
                if b0 in _SFN_FIRST_OK and expected is not None and real in expected[0]:
                    long_name, name_lossy, long_raw = text, lossy, raw_name
                    lfn_status = "recovered"
                    recovered_first = b0
                    lfn_slots = [s for s, _, _ in reversed(tail)]
                    first_info = {"known": True, "source": "lfn_checksum",
                                  "confidence": "high" if expected[1] else "medium",
                                  "value": bytes([real]).decode(self.oem_codepage, errors="replace")}
                    used = len(tail)
                    rest = del_lfn[:len(del_lfn) - used]
                    if rest:
                        self._orphan(res, rest, deleted=True, reason="unassociated")
                else:
                    lfn_status = "unassociated"
                    self._orphan(res, del_lfn, deleted=True, reason="checksum_mismatch")
            elif del_lfn:
                self._orphan(res, del_lfn, deleted=True, reason="unassociated")
            short = self._decode_sfn(name11, ntres, recovered_first if recovered_first is not None else ord("_"))
        else:
            short = self._decode_sfn(name11, ntres, None)
        name = long_name if long_name is not None else short
        if long_name is None:
            name_lossy = False
        child_dir = None
        if is_dir:
            if 2 <= first_cluster <= self.max_cluster:
                child_dir = f"n{first_cluster}+{self.cluster_size}" if deleted else f"c{first_cluster}"
            elif not deleted:
                ewarn.append({"code": "dir_bad_cluster", "message": f"디렉터리의 시작 클러스터 {first_cluster} 가 범위를 벗어났습니다."})
        entry: dict[str, Any] = {
            "ref": f"{res.spec}/{slot}",
            "fs": self.fat_type,
            "dir": res.spec,
            "slot": slot,
            "offset": off,
            "image_offset": self.base_offset + off,
            "name": name,
            "display_name": display_name(name),
            "name_lossy": name_lossy,
            "name_source": "lfn" if long_name is not None else "sfn",
            "short_name": short,
            "short_name_raw": name11.hex(),
            "long_name": long_name,
            "long_name_raw": long_raw.hex() if (long_name is not None and name_lossy) else None,
            "lfn_status": lfn_status,
            "lfn_slots": lfn_slots,
            "deleted": deleted,
            "is_dir": is_dir,
            "attributes": {"raw": attr, "flags": _attr_flags(attr)},
            "nt_case_flags": ntres & 0x18,
            "size": size,
            "first_cluster": first_cluster,
            "times": {
                "created": fat_timestamp(cdate, ctime, ctenth),
                "modified": fat_timestamp(wdate, wtime),
                "accessed": fat_date_only(adate),
            },
            "child_dir": child_dir,
            "warnings": ewarn,
        }
        if fat32:
            entry["first_cluster_hi"] = hi
        if first_info is not None:
            entry["first_char"] = first_info
        if unverified is not None:
            entry["long_name_unverified"] = unverified
        if is_dir and size:
            ewarn.append({"code": "dir_nonzero_size", "message": "디렉터리 항목의 크기가 0 이 아닙니다."})
        return entry

    # ------------------------------------------------------------------
    # 공개: 볼륨 정보
    # ------------------------------------------------------------------
    @guard
    def info(self, *, budget: Budget | None = None) -> dict[str, Any]:
        """볼륨 정보 (부트 섹터, FSInfo, 상태 비트, 레이블). 루트 디렉터리 하나만 읽는다(검증·예산 적용)."""
        b = self.bpb
        w = Warnings(self.limits.max_warnings)
        w.extend(self._w)
        label_root = None
        budget = self._budget(None, budget)
        try:
            root = self._parse_dir("root", budget)
            label_root = root.label
            for it in root.warnings.items:
                if it["code"] == "dir_unvalidated":
                    w.add(**it)
            if root.budget_stop is not None:
                w.add("budget_exceeded", "예산이 다 돼 루트 디렉터리를 끝까지 읽지 못했습니다(레이블이 빠졌을 수 있음).",
                      limit=root.budget_stop)
        except FsError as e:
            w.add("root_unreadable", f"루트 디렉터리를 읽을 수 없습니다: {e.message}")
        label_boot = None
        if b["ext_boot_signature"] in (0x28, 0x29):
            label_boot = b["volume_label_raw"].rstrip(b" ").decode(self.oem_codepage, errors="replace")
        volid = b["volume_id"]
        out: dict[str, Any] = {
            "fs_type": self.fat_type,
            "fat_type_by_count": b["fat_type_by_count"],
            "layout": b["layout"],
            "oem_name": b["oem_name"].decode("latin-1"),
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": b["sectors_per_cluster"],
            "cluster_size": self.cluster_size,
            "reserved_sectors": b["reserved_sectors"],
            "num_fats": b["num_fats"],
            "fat_size_sectors": b["fat_size_sectors"],
            "root_entry_count": b["root_entry_count"],
            "total_sectors": b["total_sectors"],
            "hidden_sectors": b["hidden_sectors"],
            "media": f"0x{b['media']:02x}",
            "sectors_per_track": b["sectors_per_track"],
            "heads": b["heads"],
            "drive_number": b["drive_number"],
            "cluster_count": self.cluster_count,
            "max_cluster": self.max_cluster,
            "fat_offset": self.fat_offset,
            "data_offset": self.data_offset,
            "root_dir_offset": self.root_offset if self.fat_type != "fat32" else None,
            "root_dir_size": self.root_size if self.fat_type != "fat32" else None,
            "root_cluster": self.root_cluster if self.fat_type == "fat32" else None,
            "ext_boot_signature": f"0x{b['ext_boot_signature']:02x}",
            "volume_id": f"{(volid >> 16) & 0xFFFF:04X}-{volid & 0xFFFF:04X}" if b["ext_boot_signature"] in (0x28, 0x29) else None,
            "volume_label": label_root if label_root is not None else label_boot,
            "volume_label_boot": label_boot,
            "volume_label_root": label_root,
            "fs_type_label": b["fs_type_label_raw"].decode("latin-1").rstrip() if b["ext_boot_signature"] == 0x29 else None,
            "volume_size": self.volume_size,
            "available_size": self.src.size,
            "truncated": self.volume_size > self.src.size,
            "base_offset": self.base_offset,
            "state": self._state(),
        }
        if self.fat_type == "fat32":
            out["fat32"] = {
                "ext_flags": f"0x{b.get('ext_flags', 0):04x}",
                "mirroring": self.mirroring,
                "active_fat": self.active_fat,
                "fs_version": f"{(b.get('fs_version', 0) >> 8) & 0xFF}.{b.get('fs_version', 0) & 0xFF}",
                "fsinfo": self._fsinfo(w),
                "backup_boot": self._backup_boot(w),
            }
        out.update(w.export())
        return out

    def _state(self) -> dict[str, Any]:
        fat1 = self._fat.get(1)
        st_byte = self.bpb["state_byte"]
        clean = hard_ok = None
        if fat1 is not None and self.fat_type == "fat16":
            clean = bool(fat1 & 0x8000)
            hard_ok = bool(fat1 & 0x4000)
        elif fat1 is not None and self.fat_type == "fat32":
            clean = bool(fat1 & 0x08000000)
            hard_ok = bool(fat1 & 0x04000000)
        boot_dirty = bool(st_byte & 0x01)
        return {
            "fat0_raw": None if self._fat.get(0) is None else f"0x{self._fat.get(0):x}",
            "fat1_raw": None if fat1 is None else f"0x{fat1:x}",
            "clean_shutdown": clean,
            "hard_error": None if hard_ok is None else not hard_ok,
            "boot_state_byte": st_byte,
            "boot_state_offset": self.bpb["state_offset"],
            "boot_dirty": boot_dirty,
            "boot_surface_scan": bool(st_byte & 0x02),
            "dirty": bool(boot_dirty or clean is False),
            "sources": {
                "clean_shutdown": "FAT[1] ClnShutBit (MS FAT 사양, 1=깨끗함; FAT12 에는 없음)",
                "hard_error": "FAT[1] HrdErrBit (MS FAT 사양, 0=입출력 오류)",
                "boot_dirty": "부트 섹터 BS_Reserved1 비트0 (Linux FAT_STATE_DIRTY / Windows NT, 사양상 예약)",
            },
        }

    def _fsinfo(self, w: Warnings) -> dict[str, Any]:
        sec = self.bpb.get("fsinfo_sector", 0)
        bps = self.bytes_per_sector
        out: dict[str, Any] = {"sector": sec, "valid": False, "free_count": None, "next_free": None}
        if not 1 <= sec < self.bpb["reserved_sectors"]:
            w.add("fsinfo_sector_invalid", f"FSInfo 섹터 번호 {sec} 가 예약 영역 밖입니다.")
            return out
        data = self.src.read_clamped(sec * bps, 512)
        if len(data) < 512:
            w.add("fsinfo_unreadable", "FSInfo 섹터를 읽을 수 없습니다.")
            return out
        lead, = struct.unpack_from("<I", data, 0)
        struc, free, nxt = struct.unpack_from("<III", data, 484)
        trail, = struct.unpack_from("<I", data, 508)
        out["lead_signature_ok"] = lead == 0x41615252
        out["struct_signature_ok"] = struc == 0x61417272
        out["trail_signature_ok"] = trail == 0xAA550000
        out["valid"] = bool(out["lead_signature_ok"] and out["struct_signature_ok"] and out["trail_signature_ok"])
        if not out["valid"]:
            w.add("fsinfo_bad_signature", "FSInfo 서명이 맞지 않습니다.")
        out["free_count"] = None if free == 0xFFFFFFFF else free
        out["next_free"] = None if nxt == 0xFFFFFFFF else nxt
        if out["free_count"] is not None and out["free_count"] > self.cluster_count:
            w.add("fsinfo_free_count_invalid", "FSInfo 빈 클러스터 수가 전체 클러스터 수보다 큽니다.")
        return out

    def _backup_boot(self, w: Warnings) -> dict[str, Any]:
        sec = self.bpb.get("backup_boot_sector", 0)
        out: dict[str, Any] = {"sector": sec, "present": False, "matches_primary": None}
        if sec == 0 or sec == 0xFFFF:
            return out
        if sec >= self.bpb["reserved_sectors"]:
            w.add("backup_boot_invalid", f"백업 부트 섹터 번호 {sec} 가 예약 영역 밖입니다.")
            return out
        bps = self.bytes_per_sector
        data = self.src.read_clamped(sec * bps, 512)
        if len(data) < 512:
            return out
        out["present"] = data[510:512] == b"\x55\xaa"
        out["matches_primary"] = data == self.boot_sector[:512]
        if out["present"] and not out["matches_primary"]:
            w.add("backup_boot_differs", "FAT32 백업 부트 섹터가 주 부트 섹터와 다릅니다.")
        return out

    def _deleted_dir_ok(self, e: dict[str, Any], w: Warnings, path: str) -> bool:
        c = e["first_cluster"]
        v = self._fat.get(c)
        if v is None:
            w.add("deleted_dir_unreadable", "삭제된 디렉터리의 클러스터를 읽을 수 없습니다.", path=path)
            return False
        if v != 0:
            w.add("deleted_dir_reused", "삭제된 디렉터리의 첫 클러스터가 지금 다른 곳에 할당돼 있어 내용을 믿을 수 없습니다(건너뜀).",
                  path=path, cluster=c)
            return False
        head = self.src.read_clamped(self.cluster_offset(c), 64)
        if len(head) < 64 or head[0:11] != b".          " or not head[11] & ATTR_DIRECTORY:
            w.add("deleted_dir_overwritten", "삭제된 디렉터리의 첫 클러스터에 '.' 항목이 없습니다(덮어써짐, 건너뜀).",
                  path=path, cluster=c)
            return False
        lo, = struct.unpack_from("<H", head, 26)
        hi, = struct.unpack_from("<H", head, 20)
        dot_c = lo | ((hi << 16) if self.fat_type == "fat32" else 0)
        if dot_c != c:
            w.add("deleted_dir_overwritten", "삭제된 디렉터리의 '.' 항목이 자기 클러스터를 가리키지 않습니다(건너뜀).",
                  path=path, cluster=c)
            return False
        return True

    def _chain_summary(self, e: dict[str, Any], budget: Budget | None = None) -> dict[str, Any]:
        size = e["size"]
        need = ceil_div(size, self.cluster_size)
        if e["first_cluster"] == 0:
            return {"status": "empty", "clusters": 0, "expected_clusters": need,
                    "size_check": "ok" if need == 0 else "no_clusters"}
        ch = self._follow(e["first_cluster"], need + 1, budget)
        if ch.capped:  # 예산이 다 돼 끝까지 따라가지 못함 — 크기와 비교할 수 없다
            return {"status": "limit", "clusters": ch.count, "expected_clusters": need, "size_check": "unknown",
                    "limit_reason": ch.capped}
        if ch.status == "limit":
            check = "chain_longer"
        elif ch.count < need:
            check = "chain_shorter"
        elif ch.count > need:
            check = "chain_longer"
        else:
            check = "ok"
        return {"status": ch.status, "clusters": ch.count, "expected_clusters": need, "size_check": check}

    def _chain_plan(self, e: dict[str, Any], budget: Budget | None = None) -> ContentPlan:
        size = e["size"]
        if e["is_dir"]:
            limit = ceil_div(DIR_MAX_BYTES, self.cluster_size)
            ch = self._follow(e["first_cluster"], limit, budget)
            p = self._new_plan(e["ref"], "chain", ch.count * self.cluster_size)
            for s, n in zip(ch.starts, ch.lens):
                p.add_run(s, n)
            p.size = p.expected_size = ch.count * self.cluster_size
            # status 'limit' 는 예산 멈춤에만 쓴다 — 사양 최대보다 긴 체인은 chain_status 로만 남긴다
            p.status = "too_long" if ch.status == "limit" and not ch.capped else ch.status
            p.extra["chain_status"] = ch.status
            p.confidence = "high" if ch.status == "ok" else "low"
            p.note = "디렉터리 클러스터 원본" + (" (체인이 사양 최대보다 길어 앞부분만)" if p.status == "too_long" else "")
            if ch.capped:
                self._mark_capped(p, ch.capped, "디렉터리 체인")
            return self._finish(p)
        need = ceil_div(size, self.cluster_size)
        p = self._new_plan(e["ref"], "chain", size)
        if need == 0:
            p.note = "크기 0"
            return p
        ch = self._follow(e["first_cluster"], need + 1, budget)
        taken = 0
        for s, n in zip(ch.starts, ch.lens):
            k = min(n, need - taken)
            if k <= 0:
                break
            p.add_run(s, k)
            taken += k
        p.status = ch.status if ch.status != "limit" else "ok"
        if ch.count < need:
            p.confidence = "low"
            p.note = f"FAT 체인이 크기보다 짧습니다({ch.count}/{need} 클러스터, 상태 {ch.status})."
            p.warnings.add("chain_short", p.note)
        elif ch.count > need or ch.status == "limit":
            p.note = "FAT 체인이 크기보다 깁니다(크기까지만 읽음)."
            p.warnings.add("chain_long", p.note)
        else:
            p.note = "할당된 FAT 체인"
        p.extra["chain_status"] = ch.status
        if ch.capped:
            self._mark_capped(p, ch.capped, "FAT 체인")
        return self._finish(p)

    def _claims(self, budget: Budget | None = None) -> list[tuple[int, int, str]]:
        """삭제 항목들이 연속 가정으로 차지했던 클러스터 구간 [start, end) — skip-claimed 후보용 (볼륨 전체를 한 번 읽음).

        각 구간은 다음 삭제 항목의 시작 클러스터에서 자른다: 다른 파일의 첫 클러스터였던 곳까지 연속으로 뻗었을 수는 없으므로
        (그 파일이 연속이라는 가정 자체가 틀린 것), 서로의 연속 가정이 상대를 깎아내리지 않게 한다.
        """
        if self._claims_cache is None:
            raw: list[tuple[int, int, str]] = []
            res = self.walk(include_deleted=True, check_chains=False, budget=budget)
            self._claims_partial = res["truncated_reason"] if res["truncated"] else None
            for e in res["entries"]:
                if not e["deleted"]:
                    continue
                fc = e["first_cluster"]
                if not 2 <= fc <= self.max_cluster:
                    continue
                n = 1 if e["is_dir"] else ceil_div(e["size"], self.cluster_size)
                if n <= 0:
                    continue
                raw.append((fc, min(fc + n, self.max_cluster + 1), e["ref"]))
            raw.sort()
            starts = sorted({s for s, _, _ in raw})
            claims: list[tuple[int, int, str]] = []
            for s, t, r in raw:
                i = bisect.bisect_right(starts, s)
                if i < len(starts):
                    t = min(t, starts[i])
                claims.append((s, t, r))
            self._claims_cache = claims
        return self._claims_cache

    def _live_map(self, budget: Budget | None = None) -> dict[str, Any]:
        """살아 있는 항목이 참조하는 클러스터 비트 집합과 이상 목록 (cluster_report·fat-chain 후보용). 예산이 다 되면 truncated."""
        if self._live_cache is not None:
            return self._live_cache
        lim = self.limits
        budget = self._budget(None, budget)
        bits = BitSet(self._bitset_size())
        cross = 0
        cross_samples: list[dict[str, Any]] = []
        unalloc_ref = 0
        unalloc_samples: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []
        truncated = False

        def mark(ch: Chain, ref: str, path: str) -> None:
            nonlocal cross
            for c in ch.clusters():
                if bits.set(c):
                    cross += 1
                    if len(cross_samples) < lim.max_report_items:
                        cross_samples.append({"cluster": c, "ref": ref, "path": path})

        if self.fat_type == "fat32" and 2 <= self.root_cluster <= self.max_cluster:
            ch = self._follow(self.root_cluster, ceil_div(DIR_MAX_BYTES, self.cluster_size), budget)
            mark(ch, "root", "/")
        res = self.walk(include_deleted=False, check_chains=False, budget=budget)
        truncated = res["truncated"]
        for e in res["entries"]:
            if budget.expired():
                truncated = True
                break
            fc = e["first_cluster"]
            if fc == 0:
                if e["size"] and not e["is_dir"]:
                    anomalies.append({"ref": e["ref"], "path": e["path"], "status": "empty",
                                      "size_check": "no_clusters"})
                continue
            if e["is_dir"]:
                ch = self._follow(fc, ceil_div(DIR_MAX_BYTES, self.cluster_size), budget)
                need = None
            else:
                need = ceil_div(e["size"], self.cluster_size)
                ch = self._follow(fc, need + 1, budget)
            if ch.capped:
                truncated = True
            if 2 <= fc <= self.max_cluster and self._fat.get(fc) == 0:
                unalloc_ref += 1
                if len(unalloc_samples) < lim.max_report_items:
                    unalloc_samples.append({"cluster": fc, "ref": e["ref"], "path": e["path"]})
            mark(ch, e["ref"], e["path"])
            check = "ok"
            if need is not None:
                if ch.count < need:
                    check = "chain_shorter"
                elif ch.count > need or ch.status == "limit":
                    check = "chain_longer"
            bad_status = ch.status not in ("ok",) and not (need is not None and ch.status == "limit")
            if (bad_status or check != "ok") and len(anomalies) < lim.max_report_items:
                anomalies.append({"ref": e["ref"], "path": e["path"], "status": ch.status, "clusters": ch.count,
                                  "expected_clusters": need, "size_check": check})
        self._live_cache = {
            "bits": bits,
            "cross_linked": cross,
            "cross_linked_samples": cross_samples,
            "unallocated_referenced": unalloc_ref,
            "unallocated_referenced_samples": unalloc_samples,
            "chain_anomalies": anomalies,
            "truncated": truncated,
        }
        return self._live_cache

    def _candidate_plans(self, e: dict[str, Any], region: str = "data", budget: Budget | None = None, *,
                         want: str | None = None, skipped: set[str] | None = None) -> list[ContentPlan]:
        """복구 후보. want 를 주면 그 방법의 후보만(그것이 기대는 것 — contiguous·skip-* 는 삭제 항목 범위, skip-* 는 contiguous —
        와 함께) 만든다. 예산이 다 돼 만들지 못한 방법은 skipped 에 넣는다."""
        if region != "data":
            raise FsError("FAT 에는 residual 영역이 없습니다(region='data' 만).", reason="bad_argument")
        budget = self._budget(None, budget)
        skipped = skipped if skipped is not None else set()
        if not e["deleted"]:
            return [self._chain_plan(e, budget)] if want in (None, "chain") else []
        cs = self.cluster_size
        start = e["first_cluster"]
        size = cs if e["is_dir"] else e["size"]
        n = ceil_div(size, cs)
        ref = e["ref"]
        if n == 0:
            p = self._new_plan(ref, "empty", 0)
            p.note = "크기 0 — 복구할 내용이 없습니다."
            return [p] if want in (None, "empty") else []
        if not 2 <= start <= self.max_cluster:
            p = self._new_plan(ref, "none", size)
            p.status = "out-of-range"
            p.confidence = "none"
            p.note = f"시작 클러스터 {start} 가 범위를 벗어나 복구할 수 없습니다."
            return [p] if want in (None, "none") else []
        hi_note = ""
        if self.fat_type == "fat32" and e.get("first_cluster_hi", 0) == 0 and self.max_cluster > 0xFFFF:
            hi_note = " (주의: Windows 는 FAT32 에서 삭제 때 DIR_FstClusHI 를 지운다 — 시작 클러스터 상위 16비트가 지워졌을 수 있음)"
        fat = self._fat
        start_alloc = fat.get(start) not in (0, None)

        def build_fat_chain() -> ContentPlan | None:
            """4) fat-chain: 삭제 때 FAT 을 지우지 않은 구현이면 체인이 남아 있다 (FAT 항목이 비었으면 없음)."""
            if fat.get(start) in (0, None):
                return None
            if budget.expired():
                skipped.add("fat-chain")
                return None
            ch = self._follow(start, n + 1, budget)
            pf = self._new_plan(ref, "fat-chain", size)
            taken = 0
            for s0, k in zip(ch.starts, ch.lens):
                kk = min(k, n - taken)
                if kk <= 0:
                    break
                pf.add_run(s0, kk)
                taken += kk
            # status 'limit' 는 예산 멈춤에만 쓴다 — 크기보다 긴 체인은 chain_status 로만 남긴다
            pf.status = "ok" if ch.status == "limit" and not ch.capped else ch.status
            pf.extra["chain_status"] = ch.status
            live = None
            live_partial = False
            if self.max_cluster - 1 <= self.limits.max_scan_clusters and not budget.expired():
                lm = self._live_map(budget)
                live = lm["bits"]
                live_partial = bool(lm["truncated"])
            owned = live.test(start) if live is not None else False
            crossed = sum(live.count_range(s0, s0 + k) for s0, k in zip(pf.run_start, pf.run_len)) if live is not None else 0
            pf.conflicts = {"live_owned": crossed}
            if live is None:
                pf.confidence = "low"
                pf.note = "클러스터 수가 점검 한도를 넘었거나 예산이 다 돼 살아 있는 파일과의 겹침을 확인하지 못했습니다."
            elif owned:
                pf.confidence = "none"
                pf.note = "시작 클러스터가 살아 있는 파일의 체인에 속합니다 — 이 체인은 다른 파일의 것입니다."
            elif crossed:
                pf.confidence = "low"
                pf.note = f"남은 FAT 체인의 클러스터 {crossed} 개가 살아 있는 파일의 체인과 겹칩니다(교차 연결 — 중간부터 다른 파일)."
            elif ch.status == "ok" and ch.count == n and not live_partial:
                pf.confidence = "medium"
                pf.note = ("삭제 항목의 시작 클러스터에 FAT 체인이 남아 있고 길이가 크기와 맞으며 살아 있는 파일이 참조하지 않습니다 "
                           "(삭제 때 FAT 을 지우지 않는 구현이거나 잃어버린 체인).")
            elif ch.status == "ok" and ch.count == n:
                pf.confidence = "low"
                pf.note = "남은 FAT 체인이 크기와 맞지만 살아 있는 파일 목록이 한도에서 잘려 겹침을 다 확인하지 못했습니다."
            elif (ch.count > n or ch.status == "limit") and not ch.capped:
                pf.confidence = "low"
                pf.note = "남은 FAT 체인이 크기보다 깁니다(크기까지만 읽음)."
            else:
                pf.confidence = "low"
                pf.note = f"남은 FAT 체인이 크기와 맞지 않습니다({ch.count}/{n} 클러스터, 상태 {ch.status})."
            if ch.capped:
                self._mark_capped(pf, ch.capped, "남은 FAT 체인")
            return self._finish(pf)

        if want == "fat-chain":
            pf = build_fat_chain()
            return [pf] if pf is not None else []
        if want is not None and want not in ("contiguous", "skip-allocated", "skip-claimed"):
            return []

        # 다른 삭제 항목이 차지했던 구간 (같은 시작 클러스터는 제외)
        all_claims = self._claims(budget)
        claims_partial = self._claims_partial
        window_end = min(self.max_cluster + 1, start + n * 4 + 65536)
        claims = [(s0, t, r) for s0, t, r in all_claims if s0 != start and t > start and s0 < window_end]
        same_start = sum(1 for s0, _, r in all_claims if s0 == start and r != ref)
        merged: list[list[int]] = []
        for s0, t, _ in sorted(claims):
            if merged and s0 <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], t)
            else:
                merged.append([s0, t])

        def note_partial(p: ContentPlan) -> None:
            if claims_partial:
                p.extra["claims_partial"] = claims_partial
                p.warnings.add("claims_partial", f"다른 삭제 항목 목록이 한도({claims_partial})에서 잘려 겹침 판단이 부분적입니다.")

        plans: list[ContentPlan] = []

        # 1) contiguous — 할당·겹침은 구간 단위로 센다 (클러스터마다 파이썬을 돌지 않는다)
        pc = self._new_plan(ref, "contiguous", size)
        end = min(start + n, self.max_cluster + 1)
        pc.add_run(start, end - start)
        budget.tick(((end - start) >> 6) + 1)
        free_in = sum(sl.count(0) for _, sl in fat.slices(start, end))
        alloc = (end - start) - free_in
        claimed = sum(max(0, min(t, end) - max(s0, start)) for s0, t in merged)
        pc.conflicts = {"allocated": alloc, "claimed": claimed}
        if end - start < n:
            pc.status = "beyond_volume"
            pc.warnings.add("beyond_volume", "연속 가정 구간이 볼륨 끝을 넘습니다.")
        if start_alloc:
            pc.confidence = "low"
            pc.note = "시작 클러스터가 지금 다른 파일에 할당돼 있습니다 — 내용이 덮어써졌을 가능성이 큽니다."
        elif alloc:
            pc.confidence = "low"
            pc.note = (f"연속 구간 중 {alloc} 클러스터가 지금 할당돼 있습니다 — 덮어써졌거나 파일이 그 클러스터를 피해 "
                       "단편화돼 있었습니다(skip-allocated 후보 참고).")
        elif claimed:
            pc.confidence = "low"
            pc.note = (f"연속 구간 중 {claimed} 클러스터가 다른 삭제 항목의 범위와 겹칩니다 — 파일이 그 항목을 피해 "
                       "단편화돼 있었을 수 있습니다(skip-claimed 후보 참고).")
        elif n == 1:
            pc.confidence = "high"
            pc.note = "클러스터 하나짜리 파일이고 그 클러스터가 비어 있습니다."
        else:
            pc.confidence = "medium"
            pc.note = ("구간이 모두 비어 있고 다른 삭제 항목과 겹치지 않습니다. FAT 체인이 지워져 단편화 여부는 알 수 없으므로 "
                       "연속을 가정합니다.")
        if same_start:
            pc.warnings.add("same_start_cluster", f"다른 삭제 항목 {same_start} 개가 같은 시작 클러스터를 가리킵니다(재사용 흔적).")
        pc.note += hi_note
        note_partial(pc)
        if want == "contiguous":
            return [self._finish(pc)]
        plans.append(self._finish(pc))

        # 2) skip-allocated (+ 3) skip-claimed) — FAT 조각(array)을 훑는다: 할당된 구간은 array.index 로 C 수준에서 넘긴다
        max_runs = self.limits.max_runs

        def build_skip(method: str, skip_claimed: bool) -> ContentPlan:
            p = self._new_plan(ref, method, size)
            got = skipped_alloc = skipped_claim = got_claimed = 0
            max_scan = min(self.limits.max_scan_clusters, n * 4 + 65536)
            scan_end = min(self.max_cluster + 1, start + max_scan)
            pos = start
            stop: str | None = None
            mi = 0
            for base, sl in fat.slices(start, scan_end):
                if got >= n or stop:
                    break
                budget.tick((len(sl) >> 6) + 1)
                if budget.expired():
                    stop = "budget"
                    break
                if base != pos:
                    break  # 읽을 수 없는 구간 (조각이 이어지지 않음)
                i = 0
                ln = len(sl)
                while i < ln and got < n and stop is None:
                    c = base + i
                    while mi < len(merged) and merged[mi][1] <= c:
                        mi += 1
                    in_claim = mi < len(merged) and merged[mi][0] <= c
                    if in_claim:
                        j_end = min(ln, merged[mi][1] - base)
                    elif mi < len(merged):
                        j_end = min(ln, merged[mi][0] - base)
                    else:
                        j_end = ln
                    if in_claim and skip_claimed:
                        z = sl[i:j_end].count(0)
                        skipped_claim += z
                        skipped_alloc += (j_end - i) - z
                        i = j_end
                        continue
                    while i < j_end and got < n:
                        try:
                            z = sl.index(0, i, j_end)
                        except ValueError:
                            skipped_alloc += j_end - i
                            i = j_end
                            break
                        skipped_alloc += z - i
                        k = z
                        lim_k = min(j_end, z + (n - got))
                        while k < lim_k and sl[k] == 0:
                            k += 1
                        if (p.run_count >= max_runs
                                and not (p.run_count and p.run_start[-1] + p.run_len[-1] == base + z)):
                            p.warnings.add("too_fragmented", "후보의 클러스터 구간 수가 한도(max_runs)에 닿아 멈췄습니다.")
                            stop = "max_runs"
                            i = z
                            break
                        p.add_run(base + z, k - z)
                        budget.tick(k - z)
                        got += k - z
                        if in_claim:
                            got_claimed += k - z
                        i = k
                pos = base + i
            p.conflicts = {"skipped_allocated": skipped_alloc, "skipped_claimed": skipped_claim,
                           "claimed_included": got_claimed}
            if stop is None and got < n and pos < scan_end:
                p.warnings.add("fat_unreadable", "FAT 을 더 읽을 수 없어 멈췄습니다.")
            if got < n:
                p.status = "incomplete"
                p.warnings.add("incomplete", f"빈 클러스터를 {got}/{n} 개만 찾았습니다.")
            if stop == "budget":
                self._mark_capped(p, budget.reason, "빈 클러스터 탐색")
            return p

        ps = build_skip("skip-allocated", False)
        same_as_contig = ps.run_start == pc.run_start and ps.run_len == pc.run_len
        if ps.status == "limit":
            pass  # 예산 때문에 덜 만든 후보 — _mark_capped 가 신뢰도를 낮췄다
        elif same_as_contig:
            ps.confidence = pc.confidence
            ps.note = "연속 구간에 할당된 클러스터가 없어 contiguous 와 같습니다."
            ps.extra["same_as"] = "contiguous"
        elif start_alloc:
            ps.confidence = "low"
            ps.note = "시작 클러스터가 지금 할당돼 있습니다 — 내용이 덮어써졌을 가능성이 큽니다."
        elif ps.conflicts["claimed_included"]:
            ps.confidence = "low"
            ps.note = (f"할당된 클러스터 {ps.conflicts['skipped_allocated']} 개를 건너뛰었지만 고른 클러스터 중 "
                       f"{ps.conflicts['claimed_included']} 개가 다른 삭제 항목의 범위입니다.")
        else:
            ps.confidence = "medium"
            ps.note = (f"지금 할당된 클러스터 {ps.conflicts['skipped_allocated']} 개를 건너뛰었습니다 — 쓸 때 이미 할당돼 있던 "
                       "파일을 피해 단편화됐다는 가정(그 파일이 아직 남아 있을 때 맞음).")
        ps.note += hi_note
        note_partial(ps)
        if want == "skip-allocated":
            return [self._finish(ps)]
        plans.append(self._finish(ps))

        if want == "skip-claimed" or merged:
            if budget.expired():
                skipped.add("skip-claimed")
            else:
                pk = build_skip("skip-claimed", True)
                same = pk.run_start == ps.run_start and pk.run_len == ps.run_len
                if not same or want == "skip-claimed":
                    if pk.status == "limit":
                        pass
                    elif same:
                        pk.confidence = ps.confidence
                        pk.note = "다른 삭제 항목이 차지했던 구간과 겹치지 않아 skip-allocated 와 같습니다."
                        pk.extra["same_as"] = "skip-allocated"
                    elif start_alloc:
                        pk.confidence = "low"
                        pk.note = "시작 클러스터가 지금 할당돼 있습니다."
                    else:
                        pk.confidence = "medium"
                        pk.note = (f"할당된 클러스터 {pk.conflicts['skipped_allocated']} 개와 다른 삭제 항목이 연속 가정으로 "
                                   f"차지했던 클러스터 {pk.conflicts['skipped_claimed']} 개를 건너뛰었습니다 — 그 항목들이 연속이었다는 가정.")
                    pk.note += hi_note
                    note_partial(pk)
                    if want == "skip-claimed":
                        return [self._finish(pk)]
                    plans.append(self._finish(pk))
        if want == "skip-claimed":
            return []

        pf = build_fat_chain()
        if pf is not None:
            plans.append(pf)

        order = {"contiguous": 0, "skip-allocated": 1, "skip-claimed": 2, "fat-chain": 3}
        plans.sort(key=lambda p: (CONFIDENCE_ORDER.get(p.confidence, 9), order.get(p.method, 9)))
        return plans

    # ------------------------------------------------------------------
    # 공개: 볼륨 점검
    # ------------------------------------------------------------------
    @guard
    def cluster_report(self, *, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
        """깨끗하지 않게 뽑은 카드 점검: 잃어버린 체인, 참조되지만 빈 클러스터, 교차 연결, 체인 이상, FSInfo·FAT 사본 비교."""
        lim = self.limits
        budget = self._budget(limits, budget)
        w = Warnings(lim.max_warnings)
        if self.max_cluster - 1 > lim.max_scan_clusters:
            w.add("scan_limit", f"클러스터 수가 점검 한도({lim.max_scan_clusters})를 넘어 점검하지 않습니다.")
            out = {"fs": self.fat_type, "scanned": False, "truncated": True}
            out.update(w.export())
            return out
        live = self._live_map(budget)
        bits: BitSet = live["bits"]
        fat = self._fat
        free = bad = invalid = allocated = unref = 0
        cut = False
        unref_runs: list[list[int]] = []
        unref_set = BitSet(self._bitset_size())
        for base, sl in fat.slices(2, self.max_cluster + 1):
            budget.tick((len(sl) >> 6) + 1)
            if budget.expired():
                cut = True
                break
            c = base
            for v in sl:
                if v == 0:
                    free += 1
                elif v == self.bad_value:
                    bad += 1
                else:
                    allocated += 1
                    if not (v >= self.eoc_min or 2 <= v <= self.max_cluster):
                        invalid += 1
                    if not bits.test(c):
                        unref += 1
                        unref_set.set(c)
                        if unref_runs and unref_runs[-1][0] + unref_runs[-1][1] == c:
                            unref_runs[-1][1] += 1
                        elif len(unref_runs) < lim.max_report_items:
                            unref_runs.append([c, 1])
                c += 1
        readable = fat.readable if fat._whole is None else len(fat._whole)
        if readable < self.max_cluster + 1:
            w.add("fat_partially_unreadable", "FAT 일부를 읽을 수 없어 그 부분은 세지 않았습니다.")
        # 잃어버린 체인의 머리: 참조되지 않은 할당 클러스터 중 다른 참조되지 않은 클러스터가 가리키지 않는 것
        lost: list[dict[str, Any]] = []
        lost_total = 0
        if unref and not cut:
            has_pred = BitSet(self._bitset_size())
            for base, sl in fat.slices(2, self.max_cluster + 1):
                c = base
                for v in sl:
                    if v and unref_set.test(c) and 2 <= v <= self.max_cluster and unref_set.test(v):
                        has_pred.set(v)
                    c += 1
            follow_budget = 4 * unref + 1024  # 머리들이 한 체인으로 모이는 손상 FAT 대비 총 걸음 수 상한
            for base, sl in fat.slices(2, self.max_cluster + 1):
                c = base
                for _v in sl:
                    if unref_set.test(c) and not has_pred.test(c):
                        lost_total += 1
                        if len(lost) < lim.max_report_items and follow_budget > 0:
                            ch = self._follow(c, follow_budget, budget)
                            follow_budget -= ch.count
                            lost.append({"head": c, "clusters": ch.count, "status": ch.status,
                                         "bytes": ch.count * self.cluster_size})
                    c += 1
        fsinfo = self._fsinfo(Warnings(0)) if self.fat_type == "fat32" else None
        copies = self._compare_fat_copies(w)
        out = {
            "fs": self.fat_type,
            "scanned": True,
            "cluster_count": self.cluster_count,
            "free": free,
            "allocated": allocated,
            "bad": bad,
            "invalid_values": invalid,
            "referenced_by_live": bits.count(),
            "allocated_unreferenced": unref,
            "allocated_unreferenced_runs": unref_runs,
            "lost_chains": lost,
            "lost_chains_total": lost_total,
            "unallocated_referenced": live["unallocated_referenced"],
            "unallocated_referenced_samples": live["unallocated_referenced_samples"],
            "cross_linked": live["cross_linked"],
            "cross_linked_samples": live["cross_linked_samples"],
            "chain_anomalies": live["chain_anomalies"],
            "fsinfo_free_count": fsinfo["free_count"] if fsinfo else None,
            "fsinfo_free_matches": (fsinfo["free_count"] == free) if fsinfo and fsinfo["free_count"] is not None else None,
            "fat_copies": copies,
            "state": self._state(),
            "truncated": bool(live["truncated"]) or cut or budget.expired(),
        }
        if cut or budget.expired():
            out["truncated_reason"] = budget.reason
        out.update(w.export())
        return out

    def _compare_fat_copies(self, w: Warnings) -> dict[str, Any]:
        nf = self.bpb["num_fats"]
        if nf < 2:
            return {"copies": nf, "compared": False}
        need = min(self.fat_bytes, (self._fat.entries * _WIDTH[self.fat_type] + 7) // 8)
        diff_bytes = 0
        first_diff = None
        pos = 0
        step = 1 << 20
        compared = 0
        while pos < need:
            n = min(step, need - pos)
            a = self.src.read_clamped(self.fat_offset + pos, n)
            b = self.src.read_clamped(self.fat_offset + self.fat_bytes + pos, n)
            m = min(len(a), len(b))
            if m == 0:
                break
            if a[:m] != b[:m]:
                for i in range(m):
                    if a[i] != b[i]:
                        diff_bytes += 1
                        if first_diff is None:
                            first_diff = pos + i
            compared += m
            if m < n:
                break
            pos += n
        if diff_bytes:
            w.add("fat_copies_differ", f"FAT 사본 1 과 2 가 {diff_bytes} 바이트 다릅니다(쓰는 중 중단 흔적일 수 있음).")
        return {"copies": nf, "compared": True, "bytes_compared": compared, "differing_bytes": diff_bytes,
                "first_difference_offset": first_diff, "mirroring": self.mirroring, "active_fat": self.active_fat}
