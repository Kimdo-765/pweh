"""pweh.fs 시험용 카드 이미지 빌더 (순수 파이썬, 외부 도구·다운로드 없음).

- MBR(주 파티션 4개) + 확장 파티션의 EBR 사슬, GPT(보호 MBR, 헤더·항목 배열 CRC32, 백업 헤더) — 512/4096 바이트 섹터
- FAT12/16/32 포맷터: BPB, FSInfo, 백업 부트 섹터, FAT 사본, 루트 볼륨 레이블, 디렉터리·파일(LFN + 8.3, 단편화 체인, 시각),
  "Linux 처럼 삭제"(SFN·LFN 슬롯 첫 바이트 0xE5, FAT 체인 0 으로, 항목의 시작 클러스터·크기는 남김), 상태 비트(FAT[1], 부트 상태 바이트)
- exFAT 포맷터: 주/백업 부트 영역과 부트 체크섬, FAT, 할당 비트맵, 최소 up-case 표(+체크섬), 루트의 레이블·비트맵·up-case 항목,
  파일(NoFatChain 연속 / FAT 체인 단편화, ValidDataLength < DataLength), "Linux 처럼 삭제"(InUse 비트만 지우고 비트맵 해제, FAT 은 그대로)

오라클 독립성: 체크섬·이름 해시·배치 계산은 라이브러리(pweh.fs)를 쓰지 않고 여기서 따로 구현한다.
값은 모두 합성이다.
"""

from __future__ import annotations

import datetime as dt
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# 공통
# ---------------------------------------------------------------------------

def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def dos_datetime(t: dt.datetime) -> tuple[int, int, int]:
    """(date, time, 10ms 단위 보충값 0~199)."""
    date = ((t.year - 1980) << 9) | (t.month << 5) | t.day
    time_ = (t.hour << 11) | (t.minute << 5) | (t.second // 2)
    extra = (t.second % 2) * 100 + t.microsecond // 10_000
    return date, time_, extra


def iso_local(t: dt.datetime, with_cs: bool) -> str:
    s = t.strftime("%Y-%m-%dT%H:%M:%S")
    if with_cs:
        s += f".{t.microsecond // 10_000:02d}"
    return s


def pattern(n: int, seed: int) -> bytes:
    """결정적인 의사 난수 바이트 (내용 비교용)."""
    out = bytearray()
    x = (seed * 2654435761 + 12345) & 0xFFFFFFFF
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


# ---------------------------------------------------------------------------
# MBR / EBR / GPT
# ---------------------------------------------------------------------------

def mbr_entry(ptype: int, start_lba: int, nsect: int, *, bootable: bool = False) -> bytes:
    return struct.pack("<B3sB3sII", 0x80 if bootable else 0x00, b"\xfe\xff\xff", ptype, b"\xfe\xff\xff", start_lba, nsect)


def put_mbr(img: bytearray, entries: list[tuple], *, disk_signature: int = 0x5EED1234, offset: int = 0) -> None:
    """entries: (type, start_lba, nsect[, bootable]) 최대 4개. 서명 0x55AA."""
    sec = bytearray(512)
    struct.pack_into("<I", sec, 440, disk_signature)
    for i, e in enumerate(entries[:4]):
        sec[446 + 16 * i:446 + 16 * (i + 1)] = mbr_entry(e[0], e[1], e[2], bootable=bool(e[3]) if len(e) > 3 else False)
    sec[510:512] = b"\x55\xaa"
    img[offset:offset + 512] = sec


def put_ebr(img: bytearray, ebr_lba: int, logical: tuple[int, int, int] | None, next_link: tuple[int, int] | None,
            *, sector: int = 512) -> None:
    """EBR 하나. logical=(type, 이 EBR 기준 상대 시작, 섹터 수), next_link=(확장 파티션 시작 기준 상대 LBA, 섹터 수)."""
    sec = bytearray(512)
    if logical:
        sec[446:462] = mbr_entry(logical[0], logical[1], logical[2])
    if next_link:
        sec[462:478] = mbr_entry(0x05, next_link[0], next_link[1])
    sec[510:512] = b"\x55\xaa"
    img[ebr_lba * sector:ebr_lba * sector + 512] = sec


GUID_BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
GUID_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
GUID_LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


@dataclass
class GptPart:
    first_lba: int
    last_lba: int
    type_guid: str = GUID_BASIC_DATA
    unique_guid: str = "11111111-2222-3333-4444-555555555555"
    name: str = "SDDATA"
    attributes: int = 0


def put_gpt(img: bytearray, parts: list[GptPart], *, sector: int = 512, num_entries: int = 128, entry_size: int = 128,
            disk_guid: str = "A1B2C3D4-0000-4000-8000-000000000001", write_backup: bool = True,
            protective: bool = True) -> dict:
    """보호 MBR + 주 GPT(LBA1) + 항목 배열(LBA2~) + 백업 항목·헤더(마지막 LBA). 배치 정보를 돌려준다."""
    total = len(img) // sector
    arr = bytearray(num_entries * entry_size)
    for i, p in enumerate(parts):
        name = p.name.encode("utf-16-le")[:72]
        e = struct.pack("<16s16sQQQ72s", uuid.UUID(p.type_guid).bytes_le, uuid.UUID(p.unique_guid).bytes_le,
                        p.first_lba, p.last_lba, p.attributes, name)
        arr[i * entry_size:i * entry_size + len(e)] = e
    arr_sectors = ceil_div(len(arr), sector)
    first_usable = 2 + arr_sectors
    last_usable = total - 2 - arr_sectors
    entries_crc = zlib.crc32(bytes(arr)) & 0xFFFFFFFF

    def header(my_lba: int, alt_lba: int, entries_lba: int) -> bytes:
        h = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0, my_lba, alt_lba, first_usable,
                                  last_usable, uuid.UUID(disk_guid).bytes_le, entries_lba, num_entries, entry_size,
                                  entries_crc))
        struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)) & 0xFFFFFFFF)
        return bytes(h) + bytes(sector - len(h))

    if protective:
        put_mbr(img, [(0xEE, 1, min(total - 1, 0xFFFFFFFF))], disk_signature=0)
    img[sector:2 * sector] = header(1, total - 1, 2)
    img[2 * sector:2 * sector + len(arr)] = arr
    if write_backup:
        b_entries = total - 1 - arr_sectors
        img[b_entries * sector:b_entries * sector + len(arr)] = arr
        img[(total - 1) * sector:total * sector] = header(total - 1, 1, b_entries)
    return {"first_usable": first_usable, "last_usable": last_usable, "arr_sectors": arr_sectors, "total": total}


# ---------------------------------------------------------------------------
# FAT12/16/32
# ---------------------------------------------------------------------------

def lfn_checksum(name11: bytes) -> int:
    s = 0
    for b in name11:
        s = ((s >> 1) | ((s & 1) << 7)) + b
        s &= 0xFF
    return s


def sfn11(short: str) -> bytes:
    """'CLIP0001.MP4' → b'CLIP0001MP4' (이미 대문자·유효 문자라고 가정)."""
    if short in (".", ".."):
        return short.encode().ljust(11, b" ")
    if "." in short:
        base, ext = short.rsplit(".", 1)
    else:
        base, ext = short, ""
    raw = base.encode("ascii").ljust(8, b" ")[:8] + ext.encode("ascii").ljust(3, b" ")[:3]
    if raw[0] == 0xE5:
        raw = b"\x05" + raw[1:]
    return raw


def lfn_slots(name: str, csum: int) -> list[bytes]:
    """긴 이름 → LFN 슬롯 (물리 순서: 가장 큰 ordinal 먼저)."""
    units = list(struct.unpack(f"<{len(name.encode('utf-16-le')) // 2}H", name.encode("utf-16-le")))
    if len(units) % 13:
        units.append(0)
        while len(units) % 13:
            units.append(0xFFFF)
    n = len(units) // 13
    slots = []
    for i in range(n):
        c = units[i * 13:(i + 1) * 13]
        ordv = (i + 1) | (0x40 if i == n - 1 else 0)
        raw = (bytes([ordv]) + struct.pack("<5H", *c[0:5]) + bytes([0x0F, 0x00, csum]) + struct.pack("<6H", *c[5:11])
               + b"\x00\x00" + struct.pack("<2H", *c[11:13]))
        assert len(raw) == 32
        slots.append(raw)
    return list(reversed(slots))


def auto_short(name: str, used: set[bytes]) -> str:
    base, _, ext = name.rpartition(".") if "." in name.lstrip(".") else (name, "", "")
    ok = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")

    def clean(s: str) -> str:
        return "".join(ch if ch in ok else "_" for ch in s.upper().replace(" ", "").replace(".", ""))

    b = clean(base.lstrip(" .")) or "_"
    e = clean(ext)[:3]
    for i in range(1, 100):
        tail = f"~{i}"
        cand = b[: 8 - len(tail)] + tail
        full = cand + ("." + e if e else "")
        if sfn11(full) not in used:
            return full
    raise ValueError("short name space exhausted")


@dataclass
class FatRec:
    path: str
    dir_path: str
    slots: list[int]  # LFN.. + SFN (SFN 마지막)
    clusters: list[int]
    data: bytes
    is_dir: bool
    short: str
    sfn: bytes
    size: int


@dataclass
class FatDir:
    path: str
    clusters: list[int]  # 빈 목록 = FAT12/16 고정 루트
    slots: list[bytes] = field(default_factory=list)
    capacity: int = 0


DEFAULT_TIME = dt.datetime(2026, 3, 14, 15, 9, 26, 530000)


class FatBuilder:
    """FAT12/16/32 이미지를 만든다 (사양 계산을 라이브러리와 독립적으로 한다)."""

    def __init__(self, fat_type: int, *, total_sectors: int, bytes_per_sector: int = 512, sectors_per_cluster: int = 1,
                 reserved_sectors: int | None = None, num_fats: int = 2, root_entries: int = 512, media: int = 0xF8,
                 volume_id: int = 0x1234ABCD, label: str = "PWEHTEST", oem: bytes = b"PWEHFS  ", hidden_sectors: int = 0,
                 ext_flags: int = 0) -> None:
        assert fat_type in (12, 16, 32)
        self.fat_type = fat_type
        self.bps = bytes_per_sector
        self.spc = sectors_per_cluster
        self.cs = bytes_per_sector * sectors_per_cluster
        self.nfats = num_fats
        self.total = total_sectors
        self.rsvd = reserved_sectors if reserved_sectors is not None else (32 if fat_type == 32 else 1)
        self.root_entries = 0 if fat_type == 32 else root_entries
        self.root_secs = ceil_div(self.root_entries * 32, self.bps)
        width = {12: 1.5, 16: 2, 32: 4}[fat_type]
        fatsz = 1
        for _ in range(64):
            data = self.total - self.rsvd - self.nfats * fatsz - self.root_secs
            count = data // self.spc
            need = ceil_div(int((count + 2) * width + 0.5), self.bps)
            if need <= fatsz:
                break
            fatsz = need
        self.fatsz = fatsz
        self.count = (self.total - self.rsvd - self.nfats * fatsz - self.root_secs) // self.spc
        lo, hi = {12: (1, 4084), 16: (4085, 65524), 32: (65525, 0x0FFFFFF5)}[fat_type]
        if not lo <= self.count <= hi:
            raise ValueError(f"geometry gives {self.count} clusters, not FAT{fat_type}")
        self.max_cluster = self.count + 1
        self.media = media
        self.volume_id = volume_id
        self.label = label
        self.fat_off = self.rsvd * self.bps
        self.root_off = (self.rsvd + self.nfats * fatsz) * self.bps
        self.data_off = (self.rsvd + self.nfats * fatsz + self.root_secs) * self.bps
        self.buf = bytearray(self.total * self.bps)
        self.used: set[int] = set()
        self.next_hint = 2
        self.state_byte = 0
        self.ext_flags = ext_flags
        self.fat1_clean = True
        self.fat1_no_error = True
        self.files: dict[str, FatRec] = {}
        self.dirs: dict[str, FatDir] = {}
        self.eoc = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[fat_type]
        self.set_fat(0, {12: 0xF00, 16: 0xFF00, 32: 0x0FFFFF00}[fat_type] | media)
        self._write_fat1()
        if fat_type == 32:
            root = [self._take_free()]
            self.set_fat(root[0], self.eoc)
            self.dirs["/"] = FatDir("/", root, capacity=self.cs // 32)
        else:
            self.dirs["/"] = FatDir("/", [], capacity=self.root_entries)
        if label:
            self.dirs["/"].slots.append(struct.pack("<11sB20s", label.encode("ascii").ljust(11, b" ")[:11], 0x08, bytes(20)))

    # -- FAT --
    def set_fat(self, n: int, v: int) -> None:
        for k in range(self.nfats):
            base = self.fat_off + k * self.fatsz * self.bps
            if self.fat_type == 12:
                o = base + n + n // 2
                if n & 1:
                    self.buf[o] = (self.buf[o] & 0x0F) | ((v << 4) & 0xF0)
                    self.buf[o + 1] = (v >> 4) & 0xFF
                else:
                    self.buf[o] = v & 0xFF
                    self.buf[o + 1] = (self.buf[o + 1] & 0xF0) | ((v >> 8) & 0x0F)
            elif self.fat_type == 16:
                struct.pack_into("<H", self.buf, base + 2 * n, v)
            else:
                old, = struct.unpack_from("<I", self.buf, base + 4 * n)
                struct.pack_into("<I", self.buf, base + 4 * n, (old & 0xF0000000) | (v & 0x0FFFFFFF))

    def set_fat_copy(self, copy: int, n: int, v: int) -> None:
        """사본 하나만 바꾼다 (사본 차이 시험용, FAT16/32)."""
        base = self.fat_off + copy * self.fatsz * self.bps
        if self.fat_type == 16:
            struct.pack_into("<H", self.buf, base + 2 * n, v)
        elif self.fat_type == 32:
            struct.pack_into("<I", self.buf, base + 4 * n, v)
        else:
            raise NotImplementedError

    def _write_fat1(self) -> None:
        if self.fat_type == 12:
            self.set_fat(1, 0xFFF)
            return
        if self.fat_type == 16:
            v = 0x3FFF | (0x8000 if self.fat1_clean else 0) | (0x4000 if self.fat1_no_error else 0)
        else:
            v = 0x03FFFFFF | (0x08000000 if self.fat1_clean else 0) | (0x04000000 if self.fat1_no_error else 0)
        self.set_fat(1, v)

    def set_dirty(self, *, fat1_clean: bool = True, fat1_no_error: bool = True, boot_state: int = 0) -> None:
        self.fat1_clean = fat1_clean
        self.fat1_no_error = fat1_no_error
        self.state_byte = boot_state
        self._write_fat1()

    def _take_free(self) -> int:
        c = self.next_hint
        while c in self.used:
            c += 1
        if c > self.max_cluster:
            raise ValueError("volume full")
        self.used.add(c)
        self.next_hint = c + 1
        return c

    def alloc(self, n: int) -> list[int]:
        return [self._take_free() for _ in range(n)]

    def reserve(self, clusters: Iterable[int]) -> None:
        for c in clusters:
            if c in self.used:
                raise ValueError(f"cluster {c} already used")
            if not 2 <= c <= self.max_cluster:
                raise ValueError(f"cluster {c} out of range")
            self.used.add(c)

    def write_chain(self, clusters: list[int]) -> None:
        for a, b in zip(clusters, clusters[1:]):
            self.set_fat(a, b)
        if clusters:
            self.set_fat(clusters[-1], self.eoc)

    def coff(self, c: int) -> int:
        return self.data_off + (c - 2) * self.cs

    def write_clusters(self, clusters: list[int], data: bytes) -> None:
        for i, c in enumerate(clusters):
            chunk = data[i * self.cs:(i + 1) * self.cs]
            o = self.coff(c)
            self.buf[o:o + self.cs] = chunk.ljust(self.cs, b"\x00")

    # -- 디렉터리 항목 --
    def _sfn_entry(self, name11: bytes, attr: int, cluster: int, size: int, *, ctime: dt.datetime, mtime: dt.datetime,
                   adate: dt.date | None, nt_case: int = 0) -> bytes:
        cd, ct, cx = dos_datetime(ctime)
        md, mt, _ = dos_datetime(mtime)
        ad = dos_datetime(dt.datetime(adate.year, adate.month, adate.day))[0] if adate else 0
        hi = (cluster >> 16) & 0xFFFF if self.fat_type == 32 else 0
        return struct.pack("<11sBBBHHHHHHHI", name11, attr, nt_case, cx, ct, cd, ad, hi, mt, md, cluster & 0xFFFF, size)

    def _place(self, d: FatDir, raws: list[bytes]) -> list[int]:
        start = len(d.slots)
        while start + len(raws) > (len(d.clusters) * (self.cs // 32) if d.clusters else d.capacity):
            if not d.clusters:
                raise ValueError("fixed root directory full")
            c = self._take_free()
            self.set_fat(d.clusters[-1], c)
            self.set_fat(c, self.eoc)
            d.clusters.append(c)
            self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
        d.slots.extend(raws)
        return list(range(start, start + len(raws)))

    def _used_names(self, d: FatDir) -> set[bytes]:
        return {s[0:11] for s in d.slots}

    def _add(self, path: str, data: bytes, *, is_dir: bool, short: str | None, lfn: bool | None,
             clusters: list[int] | None, attr: int | None, ctime: dt.datetime, mtime: dt.datetime,
             adate: dt.date | None, nt_case: int, size: int | None, pad_slots: int = 0) -> FatRec:
        parent, _, name = path.rpartition("/")
        parent = parent or "/"
        d = self.dirs[parent]
        if short is None:
            up = name.upper()
            simple = (len(name.rsplit(".", 1)[0]) <= 8 and ("." not in name or len(name.rsplit(".", 1)[1]) <= 3)
                      and name == up and all(ch.isalnum() or ch in "_-." for ch in name) and name.count(".") <= 1)
            short = name if simple else auto_short(name, self._used_names(d))
        name11 = sfn11(short)
        use_lfn = lfn if lfn is not None else (name != short)
        if is_dir:
            if clusters is None:
                clusters = self.alloc(1)
            else:
                self.reserve(clusters)
            payload = b""
        else:
            n = ceil_div(len(data), self.cs)
            if clusters is None:
                clusters = self.alloc(n)
            else:
                self.reserve(clusters)
            payload = data
        self.write_chain(clusters)
        if payload:
            self.write_clusters(clusters, payload)
        first = clusters[0] if clusters else 0
        a = (0x10 if is_dir else 0x20) if attr is None else attr
        raws = []
        if use_lfn:
            raws.extend(lfn_slots(name, lfn_checksum(name11)))
        sz = 0 if is_dir else (len(data) if size is None else size)
        raws.append(self._sfn_entry(name11, a, first, sz, ctime=ctime, mtime=mtime, adate=adate, nt_case=nt_case))
        if pad_slots:
            self._place(d, [b"\xe5" + bytes(31)] * pad_slots)
        slots = self._place(d, raws)
        rec = FatRec(path, parent, slots, list(clusters), data, is_dir, short, name11, sz)
        self.files[path] = rec
        if is_dir:
            nd = FatDir(path, list(clusters))
            for c in clusters:
                self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
            parent_cluster = 0 if parent == "/" else self.dirs[parent].clusters[0]
            nd.slots.append(self._sfn_entry(sfn11("."), 0x10, clusters[0], 0, ctime=ctime, mtime=mtime, adate=adate))
            nd.slots.append(self._sfn_entry(sfn11(".."), 0x10, parent_cluster, 0, ctime=ctime, mtime=mtime, adate=adate))
            self.dirs[path] = nd
        return rec

    def add_file(self, path: str, data: bytes = b"", *, short: str | None = None, lfn: bool | None = None,
                 clusters: list[int] | None = None, attr: int | None = None, ctime: dt.datetime = DEFAULT_TIME,
                 mtime: dt.datetime = DEFAULT_TIME, adate: dt.date | None = DEFAULT_TIME.date(), nt_case: int = 0,
                 size: int | None = None, pad_slots: int = 0) -> FatRec:
        return self._add(path, data, is_dir=False, short=short, lfn=lfn, clusters=clusters, attr=attr, ctime=ctime,
                         mtime=mtime, adate=adate, nt_case=nt_case, size=size, pad_slots=pad_slots)

    def mkdir(self, path: str, *, short: str | None = None, lfn: bool | None = None, clusters: list[int] | None = None,
              ctime: dt.datetime = DEFAULT_TIME, mtime: dt.datetime = DEFAULT_TIME,
              adate: dt.date | None = DEFAULT_TIME.date()) -> FatRec:
        rec = self._add(path, b"", is_dir=True, short=short, lfn=lfn, clusters=clusters[:1] if clusters else None,
                        attr=None, ctime=ctime, mtime=mtime, adate=adate, nt_case=0, size=None)
        if clusters and len(clusters) > 1:  # 미리 정한 추가 디렉터리 클러스터 (비인접 시험용)
            self.reserve(clusters[1:])
            d = self.dirs[path]
            d.clusters = list(clusters)
            rec.clusters = list(clusters)
            self.write_chain(clusters)
            for c in clusters[1:]:
                self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
        return rec

    def delete(self, path: str) -> FatRec:
        """Linux vfat 처럼 삭제: 모든 슬롯 첫 바이트 0xE5, FAT 체인 0, 항목의 시작 클러스터·크기 유지.

        디렉터리는 안의 항목을 먼저 지운 뒤 지운다(rmdir 처럼). 디렉터리 클러스터의 내용은 디스크에 남는다.
        """
        rec = self.files.pop(path)
        if rec.is_dir:
            d = self.dirs.pop(path)
            self._flush_dir_obj(d)
        pd = self.dirs[rec.dir_path]
        for s in rec.slots:
            pd.slots[s] = b"\xe5" + pd.slots[s][1:]
        for c in rec.clusters:
            self.set_fat(c, 0)
            self.used.discard(c)
        return rec

    def put_slot(self, dir_path: str, slot: int, raw: bytes) -> None:
        d = self.dirs[dir_path]
        while len(d.slots) <= slot:
            self._place(d, [bytes(32)])
        d.slots[slot] = raw

    # -- 마무리 --
    def _flush_dir_obj(self, d: FatDir) -> None:
        per = self.cs // 32
        if not d.clusters:
            area = bytearray(self.root_secs * self.bps)
            for i, s in enumerate(d.slots):
                area[i * 32:(i + 1) * 32] = s
            self.buf[self.root_off:self.root_off + len(area)] = area
            return
        for i, s in enumerate(d.slots):
            c = d.clusters[i // per]
            o = self.coff(c) + (i % per) * 32
            self.buf[o:o + 32] = s

    def _boot_sector(self) -> bytes:
        bs = bytearray(self.bps)
        bs[0:3] = b"\xeb\x58\x90" if self.fat_type == 32 else b"\xeb\x3c\x90"
        bs[3:11] = b"PWEHFS  "
        tot16 = self.total if (self.total < 0x10000 and self.fat_type != 32) else 0
        tot32 = 0 if tot16 else self.total
        struct.pack_into("<HBHBHHBHHHII", bs, 11, self.bps, self.spc, self.rsvd, self.nfats, self.root_entries, tot16,
                         self.media, 0 if self.fat_type == 32 else self.fatsz, 63, 255, 0, tot32)
        label = self.label.encode("ascii").ljust(11, b" ")[:11] if self.label else b"NO NAME    "
        if self.fat_type == 32:
            struct.pack_into("<IHHIHH12sBBBI11s8s", bs, 36, self.fatsz, self.ext_flags, 0, self.dirs["/"].clusters[0],
                             1, 6, bytes(12), 0x80, self.state_byte, 0x29, self.volume_id, label, b"FAT32   ")
        else:
            struct.pack_into("<BBBI11s8s", bs, 36, 0x80, self.state_byte, 0x29, self.volume_id, label,
                             b"FAT12   " if self.fat_type == 12 else b"FAT16   ")
        bs[510:512] = b"\x55\xaa"
        return bytes(bs)

    def free_count(self) -> int:
        return self.count - len(self.used)

    def image(self) -> bytes:
        for d in self.dirs.values():
            self._flush_dir_obj(d)
        bs = self._boot_sector()
        self.buf[0:self.bps] = bs
        if self.fat_type == 32:
            fsi = bytearray(self.bps)
            struct.pack_into("<I", fsi, 0, 0x41615252)
            struct.pack_into("<III", fsi, 484, 0x61417272, self.free_count(), self.next_hint)
            struct.pack_into("<I", fsi, 508, 0xAA550000)
            self.buf[self.bps:2 * self.bps] = fsi
            self.buf[6 * self.bps:7 * self.bps] = bs
            self.buf[7 * self.bps:8 * self.bps] = fsi
        return bytes(self.buf)


def fat12_small(**kw) -> FatBuilder:
    """FAT12: 4 MiB, 2 KiB 클러스터 (약 2000 클러스터)."""
    return FatBuilder(12, total_sectors=8192, sectors_per_cluster=4, root_entries=224, **kw)


def fat16_small(**kw) -> FatBuilder:
    """FAT16: 16 MiB, 1 KiB 클러스터 (약 16000 클러스터)."""
    return FatBuilder(16, total_sectors=32768, sectors_per_cluster=2, root_entries=512, **kw)


def fat32_small(**kw) -> FatBuilder:
    """FAT32: 34 MiB, 512 바이트 클러스터 (약 68000 클러스터)."""
    return FatBuilder(32, total_sectors=69632, sectors_per_cluster=1, **kw)


# ---------------------------------------------------------------------------
# exFAT
# ---------------------------------------------------------------------------

def exfat_boot_checksum(sectors: bytes, bps: int) -> int:
    s = 0
    for i in range(11 * bps):
        if i in (106, 107, 112):
            continue
        s = ((s >> 1) | ((s & 1) << 31)) + sectors[i]
        s &= 0xFFFFFFFF
    return s


def exfat_set_checksum(entries: list[bytes]) -> int:
    s = 0
    data = b"".join(entries)
    for i, b in enumerate(data):
        if i in (2, 3):
            continue
        s = ((s >> 1) | ((s & 1) << 15)) + b
        s &= 0xFFFF
    return s


def exfat_name_hash(name: str) -> int:
    up = "".join(ch.upper() if "a" <= ch <= "z" else ch for ch in name)
    h = 0
    for b in up.encode("utf-16-le"):
        h = ((h >> 1) | ((h & 1) << 15)) + b
        h &= 0xFFFF
    return h


def minimal_upcase_table() -> bytes:
    """압축 up-case 표: 0..0x60 그대로, a..z → A..Z, 나머지 그대로."""
    units = [0xFFFF, 0x61] + list(range(0x41, 0x5B)) + [0xFFFF, 0x10000 - 0x7B]
    return struct.pack(f"<{len(units)}H", *units)


def upcase_checksum(data: bytes) -> int:
    s = 0
    for b in data:
        s = ((s >> 1) | ((s & 1) << 31)) + b
        s &= 0xFFFFFFFF
    return s


def exfat_ts(t: dt.datetime) -> tuple[int, int]:
    """(32비트 시각, 10ms 증분)."""
    date, time_, extra = dos_datetime(t)
    return (date << 16) | time_, extra


def utc_offset_byte(minutes: int | None) -> int:
    if minutes is None:
        return 0
    q = minutes // 15
    return 0x80 | (q & 0x7F)


@dataclass
class ExRec:
    path: str
    dir_path: str
    slots: list[int]
    clusters: list[int]
    no_fat_chain: bool
    is_dir: bool
    data_length: int
    valid_data_length: int


@dataclass
class ExDir:
    path: str
    clusters: list[int]
    no_fat_chain: bool
    slots: list[bytes] = field(default_factory=list)


class ExfatBuilder:
    """exFAT 이미지를 만든다 (체크섬·이름 해시·배치를 라이브러리와 독립적으로 계산)."""

    def __init__(self, *, total_sectors: int, bytes_per_sector: int = 512, sectors_per_cluster: int = 8,
                 label: str = "PWEHEXFAT", serial: int = 0xC0FFEE11, fat_offset: int = 32, number_of_fats: int = 1,
                 volume_flags: int = 0, percent_in_use: int = 0xFF, root_clusters: int = 1) -> None:
        self.bps = bytes_per_sector
        self.spc = sectors_per_cluster
        self.cs = self.bps * self.spc
        self.bps_shift = self.bps.bit_length() - 1
        self.spc_shift = self.spc.bit_length() - 1
        assert 1 << self.bps_shift == self.bps and 1 << self.spc_shift == self.spc
        self.total = total_sectors
        self.nfats = number_of_fats
        self.fat_off = fat_offset
        fat_len = 1
        for _ in range(64):
            heap = self.fat_off + fat_len * self.nfats
            heap = ceil_div(heap, self.spc) * self.spc
            count = (self.total - heap) // self.spc
            need = ceil_div((count + 2) * 4, self.bps)
            if need <= fat_len:
                break
            fat_len = need
        self.fat_len = fat_len
        self.heap = heap
        self.count = count
        self.max_cluster = count + 1
        self.serial = serial
        self.flags = volume_flags
        self.pct = percent_in_use
        self.buf = bytearray(self.total * self.bps)
        self.used: set[int] = set()
        self.next_hint = 2
        self.files: dict[str, ExRec] = {}
        self.dirs: dict[str, ExDir] = {}
        self.set_fat(0, 0xFFFFFFF8)
        self.set_fat(1, 0xFFFFFFFF)
        # 할당 비트맵
        self.bitmap_len = ceil_div(self.count, 8)
        self.bitmap_clusters = self.alloc(ceil_div(self.bitmap_len, self.cs))
        self.write_chain(self.bitmap_clusters)
        # up-case 표
        self.upcase = minimal_upcase_table()
        self.upcase_clusters = self.alloc(ceil_div(len(self.upcase), self.cs))
        self.write_chain(self.upcase_clusters)
        self.write_clusters(self.upcase_clusters, self.upcase)
        # 루트
        self.root_clusters = self.alloc(root_clusters)
        self.write_chain(self.root_clusters)
        for c in self.root_clusters:
            self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
        root = ExDir("/", list(self.root_clusters), False)
        self.dirs["/"] = root
        lab = bytearray(32)
        lab[0] = 0x83
        lab[1] = len(label)
        enc = label.encode("utf-16-le")
        lab[2:2 + len(enc)] = enc
        root.slots.append(bytes(lab))
        bme = bytearray(32)
        bme[0] = 0x81
        struct.pack_into("<IQ", bme, 20, self.bitmap_clusters[0], self.bitmap_len)
        root.slots.append(bytes(bme))
        upe = bytearray(32)
        upe[0] = 0x82
        struct.pack_into("<I", upe, 4, upcase_checksum(self.upcase))
        struct.pack_into("<IQ", upe, 20, self.upcase_clusters[0], len(self.upcase))
        root.slots.append(bytes(upe))

    # -- FAT·비트맵 --
    def set_fat(self, n: int, v: int) -> None:
        for k in range(self.nfats):
            struct.pack_into("<I", self.buf, (self.fat_off + k * self.fat_len) * self.bps + 4 * n, v)

    def fat(self, n: int) -> int:
        return struct.unpack_from("<I", self.buf, self.fat_off * self.bps + 4 * n)[0]

    def coff(self, c: int) -> int:
        return self.heap * self.bps + (c - 2) * self.cs

    def _take_free(self) -> int:
        c = self.next_hint
        while c in self.used:
            c += 1
        if c > self.max_cluster:
            raise ValueError("volume full")
        self.used.add(c)
        self.next_hint = c + 1
        return c

    def alloc(self, n: int) -> list[int]:
        return [self._take_free() for _ in range(n)]

    def reserve(self, clusters: Iterable[int]) -> None:
        for c in clusters:
            if c in self.used or not 2 <= c <= self.max_cluster:
                raise ValueError(f"cluster {c} not available")
            self.used.add(c)

    def alloc_run(self, n: int) -> list[int]:
        """처음 나오는 빈 연속 구간 n 개."""
        c = 2
        while c + n - 1 <= self.max_cluster:
            if all(x not in self.used for x in range(c, c + n)):
                run = list(range(c, c + n))
                self.used.update(run)
                self.next_hint = max(self.next_hint, c + n)
                return run
            c += 1
        raise ValueError("no contiguous run")

    def write_chain(self, clusters: list[int]) -> None:
        for a, b in zip(clusters, clusters[1:]):
            self.set_fat(a, b)
        if clusters:
            self.set_fat(clusters[-1], 0xFFFFFFFF)

    def write_clusters(self, clusters: list[int], data: bytes) -> None:
        for i, c in enumerate(clusters):
            chunk = data[i * self.cs:(i + 1) * self.cs]
            o = self.coff(c)
            self.buf[o:o + self.cs] = chunk.ljust(self.cs, b"\x00")

    def _bitmap_bytes(self) -> bytearray:
        bm = bytearray(self.bitmap_len)
        for c in self.used:
            bm[(c - 2) >> 3] |= 1 << ((c - 2) & 7)
        return bm

    # -- 항목 집합 --
    def file_set(self, name: str, *, attrs: int, first_cluster: int, data_length: int, valid_data_length: int,
                 no_fat_chain: bool, ctime: dt.datetime, mtime: dt.datetime, atime: dt.datetime,
                 offsets: tuple[int | None, int | None, int | None] = (None, None, None)) -> list[bytes]:
        enc = name.encode("utf-16-le")
        nl = len(enc) // 2
        n_names = ceil_div(nl, 15)
        f = bytearray(32)
        f[0] = 0x85
        f[1] = 1 + n_names
        struct.pack_into("<H", f, 4, attrs)
        cts, c10 = exfat_ts(ctime)
        mts, m10 = exfat_ts(mtime)
        ats, _ = exfat_ts(atime)
        struct.pack_into("<IIIBBBBB", f, 8, cts, mts, ats, c10, m10, utc_offset_byte(offsets[0]),
                         utc_offset_byte(offsets[1]), utc_offset_byte(offsets[2]))
        s = bytearray(32)
        s[0] = 0xC0
        s[1] = 0x01 | (0x02 if no_fat_chain else 0)
        s[3] = nl
        struct.pack_into("<H", s, 4, exfat_name_hash(name))
        struct.pack_into("<Q", s, 8, valid_data_length)
        struct.pack_into("<I", s, 20, first_cluster)
        struct.pack_into("<Q", s, 24, data_length)
        out = [f, s]
        for i in range(n_names):
            ne = bytearray(32)
            ne[0] = 0xC1
            chunk = enc[i * 30:(i + 1) * 30]
            ne[2:2 + len(chunk)] = chunk
            out.append(ne)
        struct.pack_into("<H", f, 2, exfat_set_checksum([bytes(x) for x in out]))
        return [bytes(x) for x in out]

    def _place(self, d: ExDir, raws: list[bytes]) -> list[int]:
        start = len(d.slots)
        per = self.cs // 32
        while start + len(raws) > len(d.clusters) * per:
            if d.path != "/":
                raise ValueError("subdirectory full (pre-size it with clusters=...)")
            c = self._take_free()
            self.set_fat(d.clusters[-1], c)
            self.set_fat(c, 0xFFFFFFFF)
            d.clusters.append(c)
            self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
        d.slots.extend(raws)
        return list(range(start, start + len(raws)))

    def add_file(self, path: str, data: bytes = b"", *, contiguous: bool = True, clusters: list[int] | None = None,
                 data_length: int | None = None, valid_data_length: int | None = None, residual: bytes = b"",
                 attrs: int = 0x20, ctime: dt.datetime = DEFAULT_TIME, mtime: dt.datetime = DEFAULT_TIME,
                 atime: dt.datetime = DEFAULT_TIME, offsets: tuple = (None, None, None)) -> ExRec:
        """data = ValidDataLength 까지의 내용, residual = 그 뒤 DataLength 까지 남은(이전) 바이트."""
        parent, _, name = path.rpartition("/")
        parent = parent or "/"
        d = self.dirs[parent]
        payload = data + residual
        dlen = len(payload) if data_length is None else data_length
        vdl = len(data) if valid_data_length is None else valid_data_length
        n = ceil_div(dlen, self.cs)
        if clusters is None:
            clusters = self.alloc_run(n) if contiguous else self.alloc(n)
        else:
            self.reserve(clusters)
        nfc = contiguous and clusters == list(range(clusters[0], clusters[0] + len(clusters))) if clusters else contiguous
        if not nfc:
            self.write_chain(clusters)
        if payload:
            self.write_clusters(clusters, payload)
        raws = self.file_set(name, attrs=attrs, first_cluster=clusters[0] if clusters else 0, data_length=dlen,
                             valid_data_length=vdl, no_fat_chain=nfc, ctime=ctime, mtime=mtime, atime=atime,
                             offsets=offsets)
        slots = self._place(d, raws)
        rec = ExRec(path, parent, slots, list(clusters), nfc, False, dlen, vdl)
        self.files[path] = rec
        return rec

    def mkdir(self, path: str, *, clusters: list[int] | None = None, contiguous: bool = True, nclusters: int = 1,
              ctime: dt.datetime = DEFAULT_TIME, mtime: dt.datetime = DEFAULT_TIME, atime: dt.datetime = DEFAULT_TIME,
              offsets: tuple = (None, None, None)) -> ExRec:
        parent, _, name = path.rpartition("/")
        parent = parent or "/"
        d = self.dirs[parent]
        if clusters is None:
            clusters = self.alloc(nclusters)
        else:
            self.reserve(clusters)
        nfc = contiguous and clusters == list(range(clusters[0], clusters[0] + len(clusters)))
        if not nfc:
            self.write_chain(clusters)
        for c in clusters:
            self.buf[self.coff(c):self.coff(c) + self.cs] = bytes(self.cs)
        dlen = len(clusters) * self.cs
        raws = self.file_set(name, attrs=0x10, first_cluster=clusters[0], data_length=dlen, valid_data_length=dlen,
                             no_fat_chain=nfc, ctime=ctime, mtime=mtime, atime=atime, offsets=offsets)
        slots = self._place(d, raws)
        rec = ExRec(path, parent, slots, list(clusters), nfc, True, dlen, dlen)
        self.files[path] = rec
        self.dirs[path] = ExDir(path, list(clusters), nfc)
        return rec

    def delete(self, path: str) -> ExRec:
        """Linux exFAT 처럼 삭제: 항목 집합의 InUse 비트만 지우고 비트맵에서 클러스터를 해제한다. FAT 항목은 그대로 둔다."""
        rec = self.files.pop(path)
        if rec.is_dir:
            d = self.dirs.pop(path)
            self._flush_dir(d)
        pd = self.dirs[rec.dir_path]
        for s in rec.slots:
            raw = pd.slots[s]
            pd.slots[s] = bytes([raw[0] & 0x7F]) + raw[1:]
        for c in rec.clusters:
            self.used.discard(c)
        return rec

    def put_slot(self, dir_path: str, slot: int, raw: bytes) -> None:
        d = self.dirs[dir_path]
        while len(d.slots) <= slot:
            self._place(d, [b"\x01" + bytes(31)])
        d.slots[slot] = raw

    # -- 마무리 --
    def _flush_dir(self, d: ExDir) -> None:
        per = self.cs // 32
        for i, s in enumerate(d.slots):
            c = d.clusters[i // per]
            o = self.coff(c) + (i % per) * 32
            self.buf[o:o + 32] = s

    def boot_region(self) -> bytes:
        bps = self.bps
        reg = bytearray(12 * bps)
        bs = memoryview(reg)[0:bps]
        bs[0:3] = b"\xeb\x76\x90"
        bs[3:11] = b"EXFAT   "
        struct.pack_into("<QQIIIIIIHHBBBBB", reg, 64, 0, self.total, self.fat_off, self.fat_len, self.heap,
                         self.count, self.root_clusters[0], self.serial, 0x0100, self.flags, self.bps_shift,
                         self.spc_shift, self.nfats, 0x80, self.pct)
        reg[510:512] = b"\x55\xaa"
        for k in range(1, 9):
            reg[(k + 1) * bps - 4:(k + 1) * bps] = b"\x00\x00\x55\xaa"
        cks = exfat_boot_checksum(bytes(reg), bps)
        for i in range(bps // 4):
            struct.pack_into("<I", reg, 11 * bps + 4 * i, cks)
        return bytes(reg)

    def image(self) -> bytes:
        for d in self.dirs.values():
            self._flush_dir(d)
        bm = self._bitmap_bytes()
        self.write_clusters(self.bitmap_clusters, bytes(bm))
        reg = self.boot_region()
        self.buf[0:len(reg)] = reg
        self.buf[len(reg):2 * len(reg)] = reg
        return bytes(self.buf)


def exfat_small(**kw) -> ExfatBuilder:
    """exFAT: 8 MiB, 4 KiB 클러스터."""
    kw.setdefault("sectors_per_cluster", 8)
    return ExfatBuilder(total_sectors=16384, **kw)
