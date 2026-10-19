"""fwtriage 테스트용 합성 입력 (실제 기기/펌웨어 없이).

- 외부 도구 찾기 (환경변수 → ~/pweh-tools/bin → PATH)
- 취약점을 심어 둔 가짜 rootfs 트리
- 손으로 만든 최소 동적 ELF (zig 가 없을 때의 대체)
- zig 로 ARM/MIPS ELF 빌드 (있으면)
- mksquashfs 로 squashfs 만들기 (있으면)
- U-Boot env + uImage(gzip) + squashfs + 0xFF 패딩으로 된 플래시 이미지
"""

from __future__ import annotations

import gzip
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

from pweh.toolsdir import tools_dir
from typing import Any

from pweh.formats import build_uboot_env, build_uimage_header

TOOLS_BIN = tools_dir() / "bin"
EXTRACTORS_BIN = tools_dir() / "extractors" / "bin"


def find_tool(env: str, name: str) -> str | None:
    v = os.environ.get(env)
    if v and Path(v).is_file() and os.access(v, os.X_OK):
        return v
    for base in (Path(os.environ.get("PWEH_TOOLS_DIR", "")) / "bin" if os.environ.get("PWEH_TOOLS_DIR") else None, TOOLS_BIN, Path.home() / "pweh-tools" / "bin"):
        if base is None:
            continue
        p = base / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which(name)


# ---------------------------------------------------------------------------
# 최소 동적 ELF (손으로 구성)
# ---------------------------------------------------------------------------


def build_min_elf(*, machine: int = 40, little: bool = True, flags: int = 0x05000200, imports: tuple[str, ...] = ("system", "strcpy", "popen", "sprintf"),
                  needed: tuple[str, ...] = ("libc.so.0",), interp: str = "/lib/ld-uClibc.so.0", with_sections: bool = True, gnu_stack_exec: bool = False) -> bytes:
    """32비트 동적 ELF: PT_LOAD/PT_INTERP/PT_DYNAMIC/PT_GNU_STACK, DT_NEEDED/HASH/STRTAB/SYMTAB, 임포트(UND) 심볼."""
    e = "<" if little else ">"
    base_v = 0x10000
    phnum = 4
    ph_off = 52
    off = ph_off + 32 * phnum
    interp_b = interp.encode() + b"\0"
    interp_off = off
    off += len(interp_b)
    off = (off + 3) & ~3
    strtab = bytearray(b"\0")
    name_off = {}
    for n in list(needed) + list(imports):
        name_off[n] = len(strtab)
        strtab += n.encode() + b"\0"
    strtab_off = off
    off += len(strtab)
    off = (off + 3) & ~3
    nsyms = 1 + len(imports)
    symtab_off = off
    syms = bytearray(16)  # 0번 null 심볼
    for n in imports:
        syms += struct.pack(e + "IIIBBH", name_off[n], 0, 0, (1 << 4) | 2, 0, 0)  # GLOBAL FUNC UND
    off += len(syms)
    hash_off = off
    hashtab = struct.pack(e + "II", 1, nsyms) + struct.pack(e + "I", 0) + b"\0" * (4 * nsyms)
    off += len(hashtab)
    dyn_off = off
    dyn_entries = [(1, name_off[n]) for n in needed] + [(4, base_v + hash_off), (5, base_v + strtab_off), (6, base_v + symtab_off), (10, len(strtab)), (11, 16), (0, 0)]
    dyn = b"".join(struct.pack(e + "iI", t, v) for t, v in dyn_entries)
    off += len(dyn)
    body_end = off
    shstr = b"\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0"
    sections = b""
    sh_off = 0
    shnum = 0
    shstrndx = 0
    if with_sections:
        shstr_off = body_end
        off = body_end + len(shstr)
        off = (off + 3) & ~3
        sh_off = off

        def sh(name: int, typ: int, flags_: int, addr: int, offset: int, size: int, link: int, info: int, align: int, entsize: int) -> bytes:
            return struct.pack(e + "10I", name, typ, flags_, addr, offset, size, link, info, align, entsize)

        sections = (
            sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            + sh(1, 11, 2, base_v + symtab_off, symtab_off, len(syms), 2, 1, 4, 16)
            + sh(9, 3, 2, base_v + strtab_off, strtab_off, len(strtab), 0, 0, 1, 0)
            + sh(17, 6, 3, base_v + dyn_off, dyn_off, len(dyn), 2, 0, 4, 8)
            + sh(26, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
        )
        shnum = 5
        shstrndx = 4
    total = (sh_off + len(sections)) if with_sections else body_end
    ehdr = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 0]) + b"\0" * 8
    ehdr += struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, base_v + 0x100, ph_off, sh_off, flags, 52, 32, phnum, 40 if with_sections else 0, shnum, shstrndx)
    phdrs = (
        struct.pack(e + "8I", 1, 0, base_v, base_v, total, total, 5, 0x1000)
        + struct.pack(e + "8I", 3, interp_off, base_v + interp_off, base_v + interp_off, len(interp_b), len(interp_b), 4, 1)
        + struct.pack(e + "8I", 2, dyn_off, base_v + dyn_off, base_v + dyn_off, len(dyn), len(dyn), 6, 4)
        + struct.pack(e + "8I", 0x6474E551, 0, 0, 0, 0, 0, 7 if gnu_stack_exec else 6, 16)
    )
    out = bytearray(total)
    out[0:52] = ehdr
    out[ph_off : ph_off + len(phdrs)] = phdrs
    out[interp_off : interp_off + len(interp_b)] = interp_b
    out[strtab_off : strtab_off + len(strtab)] = strtab
    out[symtab_off : symtab_off + len(syms)] = syms
    out[hash_off : hash_off + len(hashtab)] = hashtab
    out[dyn_off : dyn_off + len(dyn)] = dyn
    if with_sections:
        out[body_end : body_end + len(shstr)] = shstr
        out[sh_off : sh_off + len(sections)] = sections
    return bytes(out)


def strip_section_headers(elf: bytes) -> bytes:
    """e_shoff/e_shnum/e_shstrndx 를 0 으로 (sstrip 과 같은 효과 — PT_DYNAMIC 경로 시험용)."""
    b = bytearray(elf)
    little = b[5] == 1
    e = "<" if little else ">"
    if b[4] == 1:
        struct.pack_into(e + "I", b, 32, 0)
        struct.pack_into(e + "HHH", b, 46, 0, 0, 0)
    else:
        struct.pack_into(e + "Q", b, 40, 0)
        struct.pack_into(e + "HHH", b, 58, 0, 0, 0)
    return bytes(b)


ZIG_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
    char buf[64]; char user[32];
    if (argc > 1) { strcpy(buf, argv[1]); }
    if (argc > 2) { sscanf(argv[2], "%[^:]:%s", user, buf); }
    FILE *p = popen("id", "r"); if (p) pclose(p);
    int s = socket(2, 1, 0); bind(s, 0, 0); listen(s, 1);
    printf("uc-httpd 1.0.0 OpenTelnet:OpenOnce ping -c 1 %s\n", buf);
    return system(buf);
}
"""


def zig_build(out_dir: Path, target: str, *, dynamic: bool = True) -> Path | None:
    zig = find_tool("PWEH_ZIG", "zig")
    if not zig:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "prog.c"
    src.write_text(ZIG_SRC)
    out = out_dir / f"prog-{target}{'-dyn' if dynamic else '-static'}"
    env = dict(os.environ)
    env["ZIG_GLOBAL_CACHE_DIR"] = str(Path(tempfile.gettempdir()) / f"pweh-zig-cache-{os.getuid()}")
    env["ZIG_LOCAL_CACHE_DIR"] = env["ZIG_GLOBAL_CACHE_DIR"]
    cmd = [zig, "cc", "-target", target, "-Os", "-o", str(out), str(src)]
    if dynamic:
        cmd.insert(5, "-dynamic")
    try:
        subprocess.run(cmd, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, env=env, cwd=str(out_dir))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return out if out.exists() else None


# ---------------------------------------------------------------------------
# 가짜 rootfs
# ---------------------------------------------------------------------------

# 가짜 키 (실제 키 아님). 저장소의 비밀값 스캐너 오탐을 피하려고 PEM 머리글을 실행 시 이어 붙인다.
_PEM_TAG = "RSA PRIVATE" + " KEY"
FAKE_PEM_KEY = f"-----BEGIN {_PEM_TAG}-----\nTUlJQk9nSUJBQUpCQUtqLWZha2UtdGVzdC1rZXktbm90LXJlYWwtLS0tLS0tLS0tLS0tLQ==\n-----END {_PEM_TAG}-----\n"
FAKE_PEM_CERT = "-----BEGIN CERTIFICATE-----\nTUlJQmZha2UtY2VydGlmaWNhdGUtbm90LXJlYWw=\n-----END CERTIFICATE-----\n"


def make_rootfs_tree(root: Path, *, md5crypt_support: str | None = None) -> dict[str, Any]:
    """취약 구성을 심은 rootfs. md5crypt_support 는 'support' 계정에 넣을 $1$ 해시."""
    root.mkdir(parents=True, exist_ok=True)

    def w(rel: str, data: str | bytes, mode: int | None = None) -> Path:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    busybox = build_min_elf(imports=("system", "execve", "strcpy")) + b"\0BusyBox v1.20.2 (2020-01-01 00:00:00 CST) multi-call binary\0"
    w("bin/busybox", busybox, 0o4755)
    os.symlink("busybox", root / "bin" / "sh")
    os.symlink("/bin/busybox", root / "bin" / "telnetd")
    passwd = (
        "root:absxcfbgXtb3o:0:0:root:/root:/bin/sh\n"
        "admin::0:0:admin:/:/bin/sh\n"
        "user:$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0:1000:1000::/home/user:/bin/sh\n"
        "daemon:x:2:2:daemon:/:/bin/false\n"
        "support:x:1001:1001::/:/bin/sh\n"
    )
    w("etc/passwd", passwd)
    if md5crypt_support:
        w("etc/shadow", f"support:{md5crypt_support}:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\n", 0o600)
    w("etc/inittab", "::sysinit:/etc/init.d/rcS\n::respawn:-/bin/sh\nttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100 -n -l /bin/sh\n::restart:/sbin/init\n")
    w(
        "etc/init.d/rcS",
        "#!/bin/sh\n"
        "mount -t proc proc /proc\n"
        "mount -t jffs2 /dev/mtdblock4 /mnt/mtd\n"
        "telnetd -l /bin/sh &\n"
        "/usr/bin/dropbear -B -p 22 &\n"
        "remserial -p 5150 -s 9600 raw /dev/ttyAMA1 &\n"
        "# telnetd -p 2323 (주석: 무시되어야 함)\n"
        "/usr/sbin/boa -f /etc/boa/boa.conf &\n"
        "echo \"root:secret123\" | chpasswd\n"
        "sh /mnt/mtd/start.sh &\n"
        "/etc/init.d/S50app start\n",
        0o755,
    )
    w("etc/init.d/S50app", "#!/bin/sh\n/usr/bin/Sofia &\n", 0o755)
    w("etc/init.d/S99custom", "#!/bin/sh\necho custom\n", 0o777)
    w("etc/inetd.conf", "telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n")
    w("etc/fstab", "proc /proc proc defaults 0 0\n/dev/mtdblock5 /mnt/config jffs2 defaults 0 0\n")
    w("etc/boa/boa.conf", "Port 80\nUser root\nDocumentRoot /var/www\nScriptAlias /cgi-bin/ /var/www/cgi-bin/\n")
    w("etc/httpd.conf", "A:*\n/cgi-bin:admin:admin123\n")
    w("etc/config/system.conf", "# 설정\nadmin_password=SuperSecret1\nwifi_psk=\"hunter22\"\nntp_server=pool.ntp.org\nftp_url=ftp://backup:Backup2020@10.0.0.5/cfg\n")
    w("etc/ssl/private/server.key", FAKE_PEM_KEY)
    w("etc/ssl/certs/server.crt", FAKE_PEM_CERT)
    w("etc/dropbear/dropbear_rsa_host_key", os.urandom(64))
    w("usr/sbin/boa", build_min_elf(imports=("system", "sprintf", "bind", "listen", "accept")) + b"\0GoAhead-Webs\0")
    sofia = build_min_elf(machine=40, imports=("popen", "strcpy", "sscanf")) + b"\0uc-httpd 1.0.0\0OpenTelnet:OpenOnce\0TelnetOEMPasswd\0I0TO5Wv9\0ping -c 1 %s\0%[^:]:%s\0\0\0" + "macGuarder".encode("utf-16-le") + b"\0\0"
    w("usr/bin/Sofia", sofia)
    w("var/www/cgi-bin/login.cgi", build_min_elf(imports=("system", "getenv", "strcpy")))
    w("var/www/index.html", "<html><body>login</body></html>\n")
    w("var/www/js/login.js", "var u = 'anonymous:\\177\\177\\177\\177\\177\\177';\n")
    w("mnt/mtd/.keep", "")
    w("etc/hostname", "should-not-be-read-through-link\n")
    os.remove(root / "etc" / "hostname")
    os.symlink("/etc/hostname", root / "etc" / "hostname")  # 자기 자신을 가리키는 절대 링크 (루프)
    os.symlink("/etc/os-release", root / "etc" / "issue")  # 호스트 파일을 가리키는 절대 링크 (이미지 안에 없음)
    os.symlink("loop2", root / "etc" / "loop1")
    os.symlink("loop1", root / "etc" / "loop2")
    try:
        os.mkfifo(root / "etc" / "fifo_test")
    except (OSError, AttributeError):
        pass
    return {"root": root}


def mksquashfs(tree: Path, out: Path, *, comp: str = "xz", extra: list[str] | None = None) -> Path | None:
    tool = find_tool("PWEH_MKSQUASHFS", "mksquashfs")
    if not tool:
        return None
    cmd = [tool, str(tree), str(out), "-noappend", "-all-root", "-comp", comp, "-quiet", "-no-progress"]
    cmd += extra or ["-p", "dev d 755 0 0", "-p", "dev/console c 600 0 0 5 1"]
    try:
        subprocess.run(cmd, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return out


# ---------------------------------------------------------------------------
# 플래시 이미지
# ---------------------------------------------------------------------------

LAYOUT_TEXT = "mtdparts=hi_sfc:256k(boot),64k(env),1M(kernel),2M(rootfs),-(config)"
FLASH_SIZE = 0x400000  # 4MiB


def build_flash(squashfs: bytes | None, *, env_redundant: bool = False, marker: bool = True) -> tuple[bytes, dict[str, Any]]:
    """boot(0) | env(0x40000) | kernel uImage+gzip(0x50000) | rootfs squashfs(0x150000) | config(0x350000, 0xFF)."""
    img = bytearray(b"\xff" * FLASH_SIZE)
    boot = bytearray(b"\x00" * 0x1000)
    boot[0x100:0x100 + 64] = b"U-Boot 2016.11 (Mar 03 2020 - 15:04:22 +0800) hi3518ev300\0".ljust(64, b"\0")
    default_env = b"bootcmd=sf probe 0;sf read 0x82000000 0x50000 0x100000;bootm 0x82000000\0bootdelay=1\0baudrate=115200\0bootargs=mem=64M console=ttyAMA0,115200 " + LAYOUT_TEXT.encode() + b"\0\0"
    boot[0x400:0x400 + len(default_env)] = default_env
    if marker:
        mk = b"PWEH SYNTHETIC FIRMWARE - test image, not a real device\0"
        boot[0x800:0x800 + len(mk)] = mk
    img[0:len(boot)] = boot
    env = {
        "bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x100000; bootm 0x82000000",
        "bootdelay": "1",
        "baudrate": "115200",
        "bootargs": "mem=64M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs " + LAYOUT_TEXT,
        "ethaddr": "00:11:22:33:44:55",
    }
    envb = build_uboot_env(env, size=0x10000, redundant=env_redundant)
    img[0x40000:0x40000 + len(envb)] = envb
    kernel_payload = gzip.compress(b"Linux kernel image placeholder " * 4000, mtime=0)
    hdr = build_uimage_header(kernel_payload, name="Linux-3.18.20", load=0x80008000, entry=0x80008000, arch="arm", comp="gzip")
    k = hdr + kernel_payload
    img[0x50000:0x50000 + len(k)] = k
    if squashfs is not None:
        assert len(squashfs) <= 0x200000
        img[0x150000:0x150000 + len(squashfs)] = squashfs
    layout = {"env": 0x40000, "uimage": 0x50000, "uimage_size": len(k), "squashfs": 0x150000, "config": 0x350000, "mtdparts": LAYOUT_TEXT}
    return bytes(img), layout


# ---------------------------------------------------------------------------
# JFFS2 / UBI 합성 구조 (형식 검증용)
# ---------------------------------------------------------------------------


def jffs2_crc(data: bytes) -> int:
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def jffs2_node(ntype: int, payload: bytes, *, big: bool = False) -> bytes:
    e = ">" if big else "<"
    totlen = 12 + len(payload)
    hdr8 = struct.pack(e + "HHI", 0x1985, ntype, totlen)
    node = hdr8 + struct.pack(e + "I", jffs2_crc(hdr8)) + payload
    pad = (-len(node)) % 4
    return node + b"\xff" * pad


def jffs2_image(n_nodes: int = 6, *, big: bool = False, erase: int = 0x2000) -> bytes:
    out = bytearray()
    out += jffs2_node(0x2003, b"", big=big)  # cleanmarker
    for i in range(n_nodes):
        out += jffs2_node(0xE001 if i % 2 else 0xE002, os.urandom(40 + i), big=big)
    out += b"\xff" * (erase - len(out) % erase)
    out += jffs2_node(0x2003, b"", big=big)
    out += jffs2_node(0xE002, os.urandom(50), big=big)
    return bytes(out)


def ubi_crc(data: bytes) -> int:
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def ubi_image(pebs: int = 4, peb: int = 0x4000, *, volume_name: str = "rootfs") -> bytes:
    out = bytearray()
    vid_off, data_off = 64, 128
    for i in range(pebs):
        blk = bytearray(b"\xff" * peb)
        ec = b"UBI#" + bytes([1, 0, 0, 0]) + struct.pack(">QIII", 1, vid_off, data_off, 0x1234) + b"\0" * 32
        ec += struct.pack(">I", ubi_crc(ec))
        blk[0:64] = ec
        vol_id = 0x7FFFEFFF if i < 2 else 0
        lnum = i if i < 2 else i - 2
        vid = b"UBI!" + bytes([1, 1, 0, 0]) + struct.pack(">II", vol_id, lnum) + b"\0" * 4 + struct.pack(">IIII", 0, 0, 0, 0) + b"\0" * 4 + struct.pack(">Q", i) + b"\0" * 12
        vid += struct.pack(">I", ubi_crc(vid))
        blk[vid_off:vid_off + 64] = vid
        if vol_id == 0x7FFFEFFF:
            recs = bytearray()
            for r in range(4):
                if r == 0:
                    name = volume_name.encode()
                    rec = struct.pack(">IIIBBH", 10, 1, 0, 1, 0, len(name)) + name.ljust(128, b"\0") + bytes([0]) + b"\0" * 23
                else:
                    rec = b"\0" * 168
                recs += rec + struct.pack(">I", ubi_crc(rec))
            blk[data_off:data_off + len(recs)] = recs
        out += blk
    return bytes(out)
