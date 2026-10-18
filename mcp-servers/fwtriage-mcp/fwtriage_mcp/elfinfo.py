"""순수 Python ELF 분석기 (fw_elf_info).

- 헤더: class/endianness/type/e_machine 이름/e_flags 해석(MIPS ABI·ISA·ASE, ARM EABI·float ABI)
- 프로그램 헤더 기반 동적 정보: PT_INTERP, DT_NEEDED/SONAME/RPATH/RUNPATH, 임포트 심볼
  (섹션 헤더가 없는 sstrip 바이너리도 PT_DYNAMIC → DT_SYMTAB/DT_STRTAB, 심볼 수는 DT_HASH nchain /
  DT_GNU_HASH 순회 / DT_MIPS_SYMTABNO 로 구한다)
- 보호 기법: NX(PT_GNU_STACK), RELRO(+BIND_NOW), PIE, 스택 카나리(__stack_chk_fail), FORTIFY(*_chk)
- MIPS .MIPS.abiflags (PT_MIPS_ABIFLAGS) — FP ABI(soft/hard float) 등
- 위험 임포트: 내장 목록 + cctv-hunt-patterns.yaml 의 function_heuristics

상수 출처: glibc elf/elf.h (EM_*, EF_MIPS_*, EF_ARM_*, DT_*, PT_*, Elf_MIPS_ABIFlags_v0, Val_GNU_MIPS_ABI_FP_*).
모든 오프셋/개수는 파일 크기로 제한한다 (손상·악의적 입력 대비). 바이너리를 실행하지 않는다.
"""

from __future__ import annotations

import re
import struct
from typing import Any

EM_NAMES: dict[int, str] = {
    0: "none", 2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 10: "mips-rs3-le", 15: "parisc", 18: "sparc32plus",
    20: "powerpc", 21: "powerpc64", 22: "s390", 40: "arm", 42: "superh", 43: "sparcv9", 50: "ia64", 62: "x86-64",
    76: "cris", 83: "avr", 87: "v850", 88: "m32r", 92: "openrisc", 93: "arc-compact", 94: "xtensa", 106: "blackfin",
    113: "nios2", 164: "hexagon", 167: "nds32", 183: "aarch64", 185: "avr32", 189: "microblaze", 195: "arc-v2",
    243: "riscv", 247: "bpf", 252: "csky", 258: "loongarch",
}
ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
OSABI = {0: "SYSV", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 97: "ARM", 255: "standalone"}

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PT_MIPS_ABIFLAGS = 0x70000003
SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM = 2, 3, 11
SHT_MIPS_ABIFLAGS = 0x7000002A
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 10, 11
DT_SONAME, DT_RPATH, DT_TEXTREL, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS = 14, 15, 22, 24, 29, 30
DT_GNU_HASH, DT_FLAGS_1 = 0x6FFFFEF5, 0x6FFFFFFB
DT_MIPS_SYMTABNO = 0x70000011
DF_TEXTREL, DF_BIND_NOW = 0x4, 0x8
DF_1_NOW, DF_1_PIE = 0x1, 0x08000000
PF_X, PF_W, PF_R = 1, 2, 4

MIPS_ARCH = {
    0x00000000: "mips1", 0x10000000: "mips2", 0x20000000: "mips3", 0x30000000: "mips4", 0x40000000: "mips5",
    0x50000000: "mips32", 0x60000000: "mips64", 0x70000000: "mips32r2", 0x80000000: "mips64r2",
    0x90000000: "mips32r6", 0xA0000000: "mips64r6",
}
MIPS_ABI = {0x1000: "o32", 0x2000: "o64", 0x3000: "eabi32", 0x4000: "eabi64"}
MIPS_FLAG_BITS = {0x1: "noreorder", 0x2: "pic", 0x4: "cpic", 0x8: "xgot", 0x10: "ucode", 0x20: "abi2", 0x40: "abi_on32",
                  0x100: "32bitmode", 0x200: "fp64", 0x400: "nan2008"}
MIPS_ASE_BITS = {0x08000000: "mdmx", 0x04000000: "mips16", 0x02000000: "micromips"}
MIPS_FP_ABI = {0: "any", 1: "hard-double", 2: "hard-single", 3: "soft-float", 4: "old-64", 5: "fpxx", 6: "fp64", 7: "fp64a"}
MIPS_AFL_ASE = {0x1: "dsp", 0x2: "dspr2", 0x4: "eva", 0x8: "mcu", 0x10: "mdmx", 0x20: "mips3d", 0x40: "mt", 0x80: "smartmips",
                0x100: "virt", 0x200: "msa", 0x400: "mips16", 0x800: "micromips", 0x1000: "xpa"}
MIPS_AFL_REG = {0: 0, 1: 32, 2: 64, 3: 128}

# 내장 위험 함수 분류 (YAML function_heuristics 가 있으면 그 결과가 함께 보고된다)
BUILTIN_RISKY: dict[str, dict[str, Any]] = {
    "command-exec": {"severity": "high", "functions": ["system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fexecve", "posix_spawn", "posix_spawnp", "wordexp"]},
    "unsafe-copy": {"severity": "medium", "functions": ["strcpy", "stpcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat", "getwd"]},
    "unbounded-scanf": {"severity": "medium", "functions": ["scanf", "sscanf", "fscanf", "vscanf", "vsscanf", "vfscanf"]},
    "weak-random": {"severity": "low", "functions": ["rand", "srand", "random", "srandom", "rand_r"]},
    "temp-file": {"severity": "low", "functions": ["tmpnam", "tempnam", "mktemp"]},
    "privilege": {"severity": "info", "functions": ["setuid", "setgid", "seteuid", "setegid", "setreuid", "setresuid", "chroot"]},
    "dynamic-loading": {"severity": "info", "functions": ["dlopen"]},
    "network-server": {"severity": "info", "functions": ["bind", "listen", "accept", "accept4"]},
}


def _norm_sym(name: str) -> str:
    """심볼 이름 정규화: 버전 접미사 제거, glibc __isoc99_ 접두사 제거."""
    n = name.split("@", 1)[0]
    if n.startswith("__isoc99_"):
        n = n[len("__isoc99_"):]
    return n


def machine_name(em: int) -> str:
    return EM_NAMES.get(em, f"EM_{em}")


def decode_flags(em: int, flags: int, cls: int) -> dict[str, Any]:
    out: dict[str, Any] = {"raw": f"0x{flags:08x}"}
    if em in (8, 10):  # MIPS
        arch = MIPS_ARCH.get(flags & 0xF0000000, f"arch-0x{flags & 0xF0000000:x}")
        abi_field = flags & 0x0000F000
        if cls == 64:
            abi = MIPS_ABI.get(abi_field, "n64")
        elif flags & 0x20:
            abi = "n32"
        else:
            abi = MIPS_ABI.get(abi_field, "o32" if abi_field == 0 else f"abi-0x{abi_field:x}")
        names = [n for b, n in MIPS_FLAG_BITS.items() if flags & b]
        names += [n for b, n in MIPS_ASE_BITS.items() if flags & b]
        mach = flags & 0x00FF0000
        out.update({"isa": arch, "abi": abi, "flags": names})
        if mach:
            out["mach"] = f"0x{mach:08x}"
        out["summary"] = ", ".join([arch, abi] + names)
    elif em == 40:  # ARM
        eabi = (flags & 0xFF000000) >> 24
        names = []
        if eabi >= 5:
            if flags & 0x200:
                names.append("soft-float")
            if flags & 0x400:
                names.append("hard-float")
        if flags & 0x00800000:
            names.append("be8")
        out.update({"eabi_version": eabi, "flags": names})
        out["summary"] = ", ".join([f"EABI{eabi}" if eabi else "old-ABI"] + names)
    else:
        out["summary"] = out["raw"]
    return out


def describe_elf_header(h: bytes) -> dict[str, Any] | None:
    """ELF 헤더 검증 + 요약. 유효하지 않으면 None (fw_identify 에서도 사용)."""
    if len(h) < 52 or h[:4] != b"\x7fELF":
        return None
    cls_b, data_b, ver_b = h[4], h[5], h[6]
    if cls_b not in (1, 2) or data_b not in (1, 2) or ver_b != 1:
        return None
    if h[9:16] != b"\0" * 7:
        return None
    e = "<" if data_b == 1 else ">"
    if cls_b == 1:
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack(e + "HHIIIIIHHHHHH", h[16:52])
        ehsize, phent, shent = 52, 32, 40
    else:
        if len(h) < 64:
            return None
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack(e + "HHIQQQIHHHHHH", h[16:64])
        ehsize, phent, shent = 64, 56, 64
    if e_type not in ET_NAMES or e_type == 0 or e_version != 1 or e_ehsize != ehsize:
        return None
    if e_phnum and e_phentsize != phent:
        return None
    if e_shnum and e_shentsize != shent:
        return None
    if e_phoff > (1 << 32) or e_shoff > (1 << 32):
        return None
    cls = 32 if cls_b == 1 else 64
    fl = decode_flags(e_machine, e_flags, cls)
    endian = "little" if data_b == 1 else "big"
    summary = f"{cls}-bit {'LSB' if data_b == 1 else 'MSB'} {ET_NAMES[e_type]}, {machine_name(e_machine)}"
    if e_machine in (8, 10, 40):
        summary += f" ({fl['summary']})"
    return {
        "class": cls,
        "endianness": endian,
        "osabi": OSABI.get(h[7], str(h[7])),
        "type": ET_NAMES[e_type],
        "machine": machine_name(e_machine),
        "machine_code": e_machine,
        "machine_known": e_machine in EM_NAMES,
        "flags": fl,
        "entry": f"0x{e_entry:x}",
        "phoff": e_phoff,
        "phnum": e_phnum,
        "phentsize": e_phentsize,
        "shoff": e_shoff,
        "shnum": e_shnum,
        "shentsize": e_shentsize,
        "shstrndx": e_shstrndx,
        "summary": summary,
    }


class ElfError(Exception):
    pass


class _Elf:
    def __init__(self, buf: Any, size: int) -> None:
        self.buf = buf
        self.size = size
        h = bytes(buf[:64])
        hdr = describe_elf_header(h)
        if hdr is None:
            raise ElfError("유효한 ELF 헤더가 아닙니다")
        self.hdr = hdr
        self.e = "<" if hdr["endianness"] == "little" else ">"
        self.c32 = hdr["class"] == 32
        self.warnings: list[str] = []

    def rd(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            raise ElfError(f"파일 범위 밖 읽기 (offset 0x{off:x}, {n} bytes)")
        return bytes(self.buf[off : off + n])

    def u32(self, off: int) -> int:
        return struct.unpack(self.e + "I", self.rd(off, 4))[0]

    def cstr(self, off: int, limit: int, maxlen: int = 4096) -> str:
        end = self.buf.find(b"\0", off, min(limit, self.size, off + maxlen))
        if end < 0:
            raise ElfError("문자열이 끝나지 않음")
        return bytes(self.buf[off:end]).decode("latin-1")

    # -- 헤더 테이블 --------------------------------------------------------
    def phdrs(self) -> list[dict[str, int]]:
        out = []
        h = self.hdr
        for i in range(min(h["phnum"], 512)):
            off = h["phoff"] + i * h["phentsize"]
            if off + h["phentsize"] > self.size:
                self.warnings.append("프로그램 헤더 테이블이 파일 끝에서 잘림")
                break
            raw = self.rd(off, h["phentsize"])
            if self.c32:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(self.e + "8I", raw[:32])
            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(self.e + "IIQQQQQQ", raw[:56])
            out.append({"type": p_type, "offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz, "flags": p_flags})
        return out

    def shdrs(self) -> list[dict[str, Any]]:
        h = self.hdr
        if not h["shoff"] or not h["shnum"]:
            return []
        if h["shoff"] + h["shnum"] * h["shentsize"] > self.size:
            self.warnings.append("섹션 헤더 테이블이 파일 밖 (sstrip 또는 손상) — 프로그램 헤더만 사용")
            return []
        out = []
        for i in range(min(h["shnum"], 8192)):
            raw = self.rd(h["shoff"] + i * h["shentsize"], h["shentsize"])
            if self.c32:
                vals = struct.unpack(self.e + "10I", raw[:40])
            else:
                vals = struct.unpack(self.e + "IIQQQQIIQQ", raw[:64])
            name, typ, flags, addr, off, size, link, info, align, entsize = vals
            out.append({"name_off": name, "type": typ, "addr": addr, "offset": off, "size": size, "link": link, "entsize": entsize})
        idx = h["shstrndx"]
        if 0 < idx < len(out):
            st = out[idx]
            if st["offset"] + st["size"] <= self.size:
                for s in out:
                    try:
                        s["name"] = self.cstr(st["offset"] + s["name_off"], st["offset"] + st["size"], 256)
                    except ElfError:
                        s["name"] = ""
        return out

    def v2o(self, vaddr: int, loads: list[dict[str, int]]) -> int | None:
        for ph in loads:
            if ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                off = vaddr - ph["vaddr"] + ph["offset"]
                return off if off < self.size else None
        return None


def _sym_entries(elf: _Elf, off: int, count: int, entsize: int, strtab_off: int, strtab_end: int, max_symbols: int) -> list[dict[str, Any]]:
    out = []
    e = elf.e
    count = min(count, max_symbols)
    for i in range(count):
        p = off + i * entsize
        if p + entsize > elf.size:
            elf.warnings.append("심볼 테이블이 파일 끝에서 잘림")
            break
        raw = elf.rd(p, 16 if elf.c32 else 24)
        if elf.c32:
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(e + "IIIBBH", raw)
        else:
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(e + "IBBHQQ", raw)
        name = ""
        if st_name:
            try:
                name = elf.cstr(strtab_off + st_name, strtab_end, 512)
            except ElfError:
                name = ""
        out.append({"name": name, "value": st_value, "size": st_size, "bind": st_info >> 4, "type": st_info & 0xF, "shndx": st_shndx})
    return out


def _gnu_hash_count(elf: _Elf, off: int) -> int | None:
    nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack(elf.e + "4I", elf.rd(off, 16))
    if nbuckets == 0 or nbuckets > (1 << 20) or bloom_size > (1 << 20):
        return None
    buckets_off = off + 16 + bloom_size * (4 if elf.c32 else 8)
    raw = elf.rd(buckets_off, 4 * nbuckets)
    buckets = struct.unpack(elf.e + f"{nbuckets}I", raw)
    max_sym = max(buckets)
    if max_sym < symoffset:
        return symoffset
    chains_off = buckets_off + 4 * nbuckets
    idx = max_sym
    for _ in range(1 << 20):
        hv = elf.u32(chains_off + 4 * (idx - symoffset))
        idx += 1
        if hv & 1:
            return idx
    return None


def _notes(elf: _Elf, off: int, size: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    p = off
    end = min(off + size, elf.size)
    while p + 12 <= end:
        namesz, descsz, ntype = struct.unpack(elf.e + "III", elf.rd(p, 12))
        p += 12
        name = elf.rd(p, namesz) if namesz and p + namesz <= end else b""
        p += (namesz + 3) & ~3
        if p + descsz > end:
            break
        desc = elf.rd(p, descsz)
        p += (descsz + 3) & ~3
        if name.rstrip(b"\0") == b"GNU" and ntype == 3:
            out["build_id"] = desc.hex()
        elif name.rstrip(b"\0") == b"GNU" and ntype == 1 and len(desc) >= 16:
            os_id, major, minor, patch = struct.unpack(elf.e + "4I", desc[:16])
            out["abi_tag"] = f"{['Linux', 'GNU', 'Solaris', 'FreeBSD'][os_id] if os_id < 4 else os_id} {major}.{minor}.{patch}"
    return out


def _mips_abiflags(elf: _Elf, off: int) -> dict[str, Any] | None:
    raw = elf.rd(off, 24)
    version = struct.unpack(elf.e + "H", raw[:2])[0]
    isa_level, isa_rev, gpr, cpr1, cpr2, fp_abi = raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]
    isa_ext, ases, flags1, flags2 = struct.unpack(elf.e + "4I", raw[8:24])
    return {
        "version": version,
        "isa": f"mips{isa_level}" + (f"r{isa_rev}" if isa_rev else ""),
        "gpr_size": MIPS_AFL_REG.get(gpr, gpr),
        "cpr1_size": MIPS_AFL_REG.get(cpr1, cpr1),
        "cpr2_size": MIPS_AFL_REG.get(cpr2, cpr2),
        "fp_abi": MIPS_FP_ABI.get(fp_abi, str(fp_abi)),
        "isa_ext": isa_ext,
        "ases": [n for b, n in MIPS_AFL_ASE.items() if ases & b],
        "flags1": flags1,
    }


def parse_elf(buf: Any, size: int, *, max_symbols: int = 50000, collect_exports: int = 300) -> dict[str, Any]:
    """ELF 전체 분석. 오류가 나도 가능한 부분까지 채우고 warnings 에 기록한다."""
    elf = _Elf(buf, size)
    hdr = elf.hdr
    out: dict[str, Any] = {k: hdr[k] for k in ("class", "endianness", "osabi", "type", "machine", "machine_code", "flags", "entry")}
    out["summary"] = hdr["summary"]
    phdrs = elf.phdrs()
    loads = [p for p in phdrs if p["type"] == PT_LOAD]
    shdrs = elf.shdrs()
    out["segments"] = {"count": len(phdrs), "loads": len(loads)}
    out["sections"] = {"count": len(shdrs), "names": [s.get("name", "") for s in shdrs if s.get("name")][:80]}

    # -- interp ------------------------------------------------------------
    interp = None
    for p in phdrs:
        if p["type"] == PT_INTERP and 0 < p["filesz"] <= 4096:
            try:
                interp = elf.cstr(p["offset"], p["offset"] + p["filesz"])
            except ElfError as exc:
                elf.warnings.append(f"PT_INTERP 읽기 실패: {exc}")
    out["interpreter"] = interp

    # -- dynamic -----------------------------------------------------------
    dyn: dict[int, list[int]] = {}
    dyn_seg = next((p for p in phdrs if p["type"] == PT_DYNAMIC), None)
    if dyn_seg is not None:
        entsz = 8 if elf.c32 else 16
        n = min(dyn_seg["filesz"] // entsz, 8192)
        for i in range(n):
            try:
                raw = elf.rd(dyn_seg["offset"] + i * entsz, entsz)
            except ElfError:
                elf.warnings.append("PT_DYNAMIC 이 파일 끝에서 잘림")
                break
            tag, val = struct.unpack(elf.e + ("iI" if elf.c32 else "qQ"), raw)
            if tag == DT_NULL:
                break
            dyn.setdefault(tag & 0xFFFFFFFFFFFFFFFF if tag >= 0 else tag & 0xFFFFFFFF, []).append(val)
    out["static"] = dyn_seg is None and interp is None
    needed: list[str] = []
    soname = rpath = runpath = None
    strtab_off = strtab_end = None
    if dyn:
        st_v = (dyn.get(DT_STRTAB) or [None])[0]
        st_sz = (dyn.get(DT_STRSZ) or [0])[0]
        if st_v is not None:
            strtab_off = elf.v2o(st_v, loads)
            if strtab_off is not None:
                strtab_end = min(elf.size, strtab_off + (st_sz or 1 << 20))
        if strtab_off is not None and strtab_end is not None:
            def dstr(v: int) -> str | None:
                try:
                    return elf.cstr(strtab_off + v, strtab_end)  # type: ignore[operator]
                except ElfError:
                    return None
            needed = [s for s in (dstr(v) for v in dyn.get(DT_NEEDED, [])) if s]
            soname = dstr(dyn[DT_SONAME][0]) if DT_SONAME in dyn else None
            rpath = dstr(dyn[DT_RPATH][0]) if DT_RPATH in dyn else None
            runpath = dstr(dyn[DT_RUNPATH][0]) if DT_RUNPATH in dyn else None
        else:
            elf.warnings.append("DT_STRTAB 을 파일 오프셋으로 변환하지 못함")
    out["needed"] = needed
    out["soname"] = soname
    out["rpath"] = rpath
    out["runpath"] = runpath

    # -- 동적 심볼 ----------------------------------------------------------
    dynsyms: list[dict[str, Any]] = []
    sym_source = None
    dynsym_sec = next((s for s in shdrs if s["type"] == SHT_DYNSYM), None)
    if dynsym_sec is not None and 0 <= dynsym_sec["link"] < len(shdrs):
        strsec = shdrs[dynsym_sec["link"]]
        ent = dynsym_sec["entsize"] or (16 if elf.c32 else 24)
        if ent in (16, 24) and dynsym_sec["offset"] + dynsym_sec["size"] <= elf.size and strsec["offset"] + strsec["size"] <= elf.size:
            dynsyms = _sym_entries(elf, dynsym_sec["offset"], dynsym_sec["size"] // ent, ent, strsec["offset"], strsec["offset"] + strsec["size"], max_symbols)
            sym_source = "section(.dynsym)"
    if not dynsyms and dyn and strtab_off is not None:
        sym_v = (dyn.get(DT_SYMTAB) or [None])[0]
        syment = (dyn.get(DT_SYMENT) or [16 if elf.c32 else 24])[0]
        symtab_off = elf.v2o(sym_v, loads) if sym_v is not None else None
        count = None
        try:
            if DT_MIPS_SYMTABNO in dyn:
                count = dyn[DT_MIPS_SYMTABNO][0]
            if count is None and DT_HASH in dyn:
                ho = elf.v2o(dyn[DT_HASH][0], loads)
                if ho is not None:
                    count = elf.u32(ho + 4)
            if count is None and DT_GNU_HASH in dyn:
                go = elf.v2o(dyn[DT_GNU_HASH][0], loads)
                if go is not None:
                    count = _gnu_hash_count(elf, go)
        except (ElfError, struct.error) as exc:
            elf.warnings.append(f"심볼 수 계산 실패: {exc}")
        if count is None and symtab_off is not None and strtab_off > symtab_off:
            count = (strtab_off - symtab_off) // max(syment, 1)
            elf.warnings.append("심볼 수를 DT_SYMTAB~DT_STRTAB 간격으로 추정")
        if symtab_off is not None and count and syment in (16, 24):
            dynsyms = _sym_entries(elf, symtab_off, count, syment, strtab_off, strtab_end or elf.size, max_symbols)
            sym_source = "dynamic(DT_SYMTAB)"
    imports = sorted({s["name"] for s in dynsyms if s["shndx"] == 0 and s["name"] and s["bind"] in (1, 2)})
    exports = sorted({s["name"] for s in dynsyms if s["shndx"] != 0 and s["name"] and s["bind"] in (1, 2) and s["type"] in (1, 2)})
    out["symbol_source"] = sym_source
    out["imports"] = imports
    out["import_count"] = len(imports)
    out["export_count"] = len(exports)
    if exports and collect_exports:
        out["exports_sample"] = exports[:collect_exports]

    # -- 정적 심볼(.symtab, strip 안 된 경우) -------------------------------
    symtab_funcs: list[str] = []
    symtab_sec = next((s for s in shdrs if s["type"] == SHT_SYMTAB), None)
    if symtab_sec is not None and 0 <= symtab_sec["link"] < len(shdrs):
        strsec = shdrs[symtab_sec["link"]]
        ent = symtab_sec["entsize"] or (16 if elf.c32 else 24)
        if ent in (16, 24) and symtab_sec["offset"] + symtab_sec["size"] <= elf.size and strsec["offset"] + strsec["size"] <= elf.size:
            syms = _sym_entries(elf, symtab_sec["offset"], symtab_sec["size"] // ent, ent, strsec["offset"], strsec["offset"] + strsec["size"], max_symbols)
            symtab_funcs = sorted({s["name"] for s in syms if s["type"] == 2 and s["shndx"] != 0 and s["name"]})
    out["stripped"] = symtab_sec is None
    out["defined_function_count"] = len(symtab_funcs)

    # -- 보호 기법 ----------------------------------------------------------
    gnu_stack = next((p for p in phdrs if p["type"] == PT_GNU_STACK), None)
    relro = any(p["type"] == PT_GNU_RELRO for p in phdrs)
    flags_v = (dyn.get(DT_FLAGS) or [0])[0]
    flags1_v = (dyn.get(DT_FLAGS_1) or [0])[0]
    bind_now = DT_BIND_NOW in dyn or bool(flags_v & DF_BIND_NOW) or bool(flags1_v & DF_1_NOW)
    norm_imports = {_norm_sym(n) for n in imports}
    all_funcs = norm_imports | set(symtab_funcs)
    hardening = {
        "nx": None if gnu_stack is None else not (gnu_stack["flags"] & PF_X),
        "nx_note": "PT_GNU_STACK 없음: 아키텍처/커널 기본값에 따라 스택이 실행 가능할 수 있음" if gnu_stack is None else None,
        "relro": "full" if relro and bind_now else ("partial" if relro else "none"),
        "pie": hdr["type"] == "DYN" and (interp is not None or bool(flags1_v & DF_1_PIE)),
        "shared_library": hdr["type"] == "DYN" and interp is None and not (flags1_v & DF_1_PIE),
        "stack_canary": bool({"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"} & all_funcs),
        "fortify": sorted(n for n in all_funcs if n.startswith("__") and n.endswith("_chk") and n not in ("__stack_chk_fail",))[:20],
        "textrel": DT_TEXTREL in dyn or bool(flags_v & DF_TEXTREL),
        "rpath": rpath,
        "runpath": runpath,
    }
    out["hardening"] = hardening

    # -- 노트 / MIPS abiflags ----------------------------------------------
    for p in phdrs:
        if p["type"] == PT_NOTE and p["filesz"] <= 65536:
            try:
                out.update(_notes(elf, p["offset"], p["filesz"]))
            except (ElfError, struct.error):
                pass
    if hdr["machine_code"] in (8, 10):
        ab_off = next((p["offset"] for p in phdrs if p["type"] == PT_MIPS_ABIFLAGS), None)
        if ab_off is None:
            ab_off = next((s["offset"] for s in shdrs if s["type"] == SHT_MIPS_ABIFLAGS), None)
        if ab_off is not None:
            try:
                out["mips_abiflags"] = _mips_abiflags(elf, ab_off)
            except (ElfError, struct.error):
                elf.warnings.append("MIPS abiflags 읽기 실패")
    # libc 추정
    libc = None
    for cand in [interp or ""] + needed:
        if "uClibc" in cand:
            libc = "uClibc"
        elif "musl" in cand:
            libc = "musl"
        elif cand.startswith("libc.so.6") or "ld-linux" in cand or cand.endswith("ld.so.1"):
            libc = libc or "glibc"
    out["libc_guess"] = libc
    out["_all_funcs"] = sorted(all_funcs)  # 위험 함수 분석용 (응답에는 넣지 않음)
    out["_symtab_funcs_sample"] = symtab_funcs[:collect_exports]
    out["warnings"] = elf.warnings
    return out


def risky_analysis(info: dict[str, Any], function_heuristics: list[dict[str, Any]] | None = None, strings: list[str] | None = None) -> dict[str, Any]:
    """임포트(또는 정적 심볼) 기준 위험 함수 분석 + 간단한 순위 점수."""
    funcs = set(info.get("_all_funcs") or [])
    static_only = info.get("static") and not info.get("imports")
    builtin = {}
    for cat, spec in BUILTIN_RISKY.items():
        hit = sorted(f for f in spec["functions"] if f in funcs)
        if hit:
            builtin[cat] = {"severity": spec["severity"], "functions": hit}
    heur = {}
    wrappers: dict[str, list[str]] = {}
    for h in function_heuristics or []:
        names = [str(f) for f in (h.get("functions") or []) if "::" not in str(f)]
        hit = sorted(f for f in names if f in funcs)
        rx = h.get("_wrapper_rx")
        if rx is not None:
            wl = sorted(f for f in funcs if rx.search(f) and f not in names)[:20]
            if wl:
                wrappers[h["id"]] = wl
        if hit:
            heur[h["id"]] = {"category": h.get("category"), "severity_hint": h.get("severity_hint"), "pattern_class": h.get("pattern_class"), "functions": hit}
    fmt_hits: list[str] = []
    if strings is not None and ({"sscanf", "fscanf", "scanf", "vsscanf", "vfscanf"} & funcs):
        rx = None
        for h in function_heuristics or []:
            if h.get("_format_rx") is not None:
                rx = h["_format_rx"]
                break
        rx = rx or re.compile(r"%(?![0-9*])(?:s|\[)")
        # scanf 포맷은 대개 짧고 공백이 적다 (긴 문장형 printf 포맷 오탐 감소)
        fmt_hits = [s for s in strings if "%" in s and len(s) <= 64 and s.count(" ") <= 3 and rx.search(s)][:20]
    score = 0.0
    score += 3 * len(builtin.get("command-exec", {}).get("functions", []))
    score += 1 * len(builtin.get("unsafe-copy", {}).get("functions", []))
    score += 1 * len(builtin.get("unbounded-scanf", {}).get("functions", []))
    score += 2 * len(fmt_hits[:3])
    if "network-server" in builtin:
        score *= 1.5
        score += 1
    hd = info.get("hardening") or {}
    if hd.get("nx") is False:
        score += 1
    if not hd.get("stack_canary"):
        score += 0.5
    return {
        "builtin": builtin,
        "heuristics": heur,
        "wrapper_name_matches": wrappers,
        "unbounded_scanf_formats": fmt_hits,
        "network_facing_hint": "network-server" in builtin,
        "score": round(score, 1),
        "basis": "static-symbols" if static_only else "imports",
    }
