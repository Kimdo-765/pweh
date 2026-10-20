"""fw_sd_surface 테스트용 합성 벤더 펌웨어 (실제 기기·카드 없이).

펌웨어 쪽 파일만 만든다: 시작·핫플러그 스크립트, mdev.conf/udev 규칙, fstab, 서버 설정, 카드 경로 문자열이 든 바이너리,
U-Boot env 가 든 플래시 이미지. 카드에 들어갈 파일(boot.scr·uEnv.txt·업데이트 이미지·트리거 파일)은 만들지 않는다 — 펌웨어가 그 경로를
'참조'하는 줄만 있다.
"""

from __future__ import annotations

import os
from pathlib import Path

from pweh.formats import build_uboot_env

from fwtriage.builders import build_min_elf

BASE_FILES: dict[str, str] = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
    "etc/inittab": "::sysinit:/etc/init.d/rcS\n::restart:/sbin/init\n",
}


def write_tree(root: Path, files: dict[str, str | bytes], *, symlinks: dict[str, str] | None = None, base: bool = True) -> Path:
    """rootfs 트리 만들기. 문자열은 UTF-8, '#!' 로 시작하면 실행 권한. symlinks 는 {링크 경로: 대상 문자열}."""
    root.mkdir(parents=True, exist_ok=True)
    allf: dict[str, str | bytes] = {}
    if base:
        allf["bin/busybox"] = build_min_elf(imports=("system", "execve")) + b"\0BusyBox v1.24.1 multi-call binary\0"
        allf.update(BASE_FILES)
    allf.update(files)
    for rel, data in allf.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        raw = data.encode() if isinstance(data, str) else data
        p.write_bytes(raw)
        if raw.startswith(b"#!"):
            os.chmod(p, 0o755)
    for rel, target in (symlinks or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)
    if base and not (root / "bin" / "sh").exists():
        os.symlink("busybox", root / "bin" / "sh")
    return root


def app_binary(*strings: str) -> bytes:
    """카드 경로 문자열을 심은 가짜 ELF (데몬이 system() 으로 실행할 명령 문자열 흉내)."""
    return build_min_elf(imports=("system", "popen", "mount")) + b"\0" + b"\0".join(s.encode() for s in strings) + b"\0\0"


#: 모든 점검(SD-01~SD-09)이 found 가 되도록 심은 벤더 트리 (MCP 수준 시험용)
VENDOR_FILES: dict[str, str | bytes] = {
    "etc/init.d/rcS": (
        "#!/bin/sh\n"
        "mount -t proc proc /proc\n"
        "echo /sbin/mdev > /proc/sys/kernel/hotplug\n"
        "mount -t vfat -o rw /dev/mmcblk0p1 /mnt/sdcard\n"
        "SD_DIR=/mnt/sdcard\n"
        "if [ -f $SD_DIR/autorun.sh ]; then\n"
        "    sh $SD_DIR/autorun.sh &\n"
        "fi\n"
        "[ -f /mnt/sdcard/enable_telnetd.dat ] && telnetd &\n"
        "[ -f /mnt/sdcard/wpa_supplicant.conf ] && cp /mnt/sdcard/wpa_supplicant.conf /etc/wpa_supplicant.conf\n"
        "syslogd -O /mnt/sdcard/log/messages -s 200\n"
        "echo \"psk=Hunter22x\" >> /mnt/sdcard/debug.txt\n"
        "fw_setenv bootcmd 'fatload mmc 0:1 0x82000000 uImage; bootm 0x82000000'\n"
        "/usr/bin/appd &\n"
    ),
    "etc/init.d/S80update": (
        "#!/bin/sh\n"
        "if [ -f /mnt/sdcard/update.bin ]; then\n"
        "    flashcp -v /mnt/sdcard/update.bin /dev/mtd2\n"
        "fi\n"
    ),
    "etc/mdev.conf": (
        "# 장치 노드\n"
        "null 0:0 666\n"
        "mmcblk[0-9]p[0-9] 0:0 660 */etc/hotplug/sdcard.sh\n"
        "mmcblk[0-9] 0:0 660 $/usr/sbin/sd_remove.sh\n"
    ),
    "etc/hotplug/sdcard.sh": (
        "#!/bin/sh\n"
        "if [ \"$ACTION\" = \"add\" ]; then\n"
        "    mount -t vfat /dev/$MDEV /media/$MDEV\n"
        "    /media/$MDEV/hotplug_run.sh &\n"
        "fi\n"
    ),
    "usr/sbin/sd_remove.sh": "#!/bin/sh\numount -l /media/$MDEV\n",
    "etc/boa/boa.conf": "Port 80\nDocumentRoot /var/www\nAlias /record /mnt/sdcard/record\nErrorLog /mnt/sdcard/log/boa_error.log\n",
    "var/www/index.html": "<html>cam</html>\n",
    "var/www/cgi-bin/list.cgi": "#!/bin/sh\necho Content-type: text/plain\necho\nls /mnt/sdcard/record\n",
    "etc/app/record.conf": "record_path=/mnt/sdcard/record\nrecord_encrypt=1\n",
    "etc/fw_env.config": "# 장치 오프셋 크기\n/dev/mtd1 0x0 0x10000 0x10000\n",
    "usr/sbin/fw_setenv": build_min_elf(imports=("open", "write")),
    "usr/bin/appd": app_binary("sh /mnt/sdcard/autorun_app.sh &", "/mnt/sdcard/wifi.ini", "/dev/mmcblk0p1",
                               "mount -t vfat -o rw,umask=0000 /dev/mmcblk0p1 /mnt/sdcard"),
}
VENDOR_SYMLINKS = {"var/www/sd": "/mnt/sdcard", "usr/sbin/fw_printenv": "fw_setenv"}


def make_sd_vendor_rootfs(root: Path) -> Path:
    return write_tree(root, VENDOR_FILES, symlinks=VENDOR_SYMLINKS)


def make_plain_rootfs(root: Path) -> Path:
    """SD 를 전혀 다루지 않는 펌웨어 (설정 파티션 jffs2 만)."""
    files: dict[str, str | bytes] = {
        "etc/init.d/rcS": "#!/bin/sh\nmount -t proc proc /proc\nmount -t jffs2 /dev/mtdblock4 /mnt/mtd\nsh /mnt/mtd/start.sh &\n/usr/bin/app &\n",
        "etc/fstab": "proc /proc proc defaults 0 0\n/dev/mtdblock5 /mnt/config jffs2 defaults 0 0\n",
        "usr/bin/app": build_min_elf(imports=("socket", "bind")) + b"\0/mnt/mtd/Config/app.cfg\0/var/log/app.log\0",
        "mnt/mtd/.keep": "",
    }
    return write_tree(root, files)


# ---------------------------------------------------------------------------
# 플래시 이미지 (U-Boot 문자열 + 내장 기본 env + CRC env)
# ---------------------------------------------------------------------------

FLASH_SIZE = 0x80000


def build_sd_flash(*, env: dict[str, str] | None = None, default_env: dict[str, str] | None = None, markers: tuple[str, ...] = (),
                   env_offset: int = 0x40000) -> bytes:
    """boot(0x0: U-Boot 버전 문자열, 0x1000: 내장 기본 env, 0x3000: 표지 문자열) | env(0x40000, CRC) | 0xFF."""
    img = bytearray(b"\xff" * FLASH_SIZE)
    boot = bytearray(b"\x00" * 0x8000)
    ver = b"U-Boot 2016.11 (Jan 01 2020 - 00:00:00 +0000) synthetic\0"
    boot[0x100:0x100 + len(ver)] = ver
    if default_env:
        d = b"".join(f"{k}={v}".encode() + b"\0" for k, v in default_env.items()) + b"\0"
        boot[0x1000:0x1000 + len(d)] = d
    if markers:
        mk = b"\0".join(m.encode() for m in markers) + b"\0"
        boot[0x3000:0x3000 + len(mk)] = mk
    img[0:len(boot)] = boot
    if env:
        blk = build_uboot_env(env, size=0x10000)
        img[env_offset:env_offset + len(blk)] = blk
    return bytes(img)
