"""합성 펌웨어 빌더 테스트.

전체 빌드(zig + mksquashfs)는 외부 도구가 필요하므로 ``@pytest.mark.external`` — 없으면 skip.
빠른 빌드(외부 도구 없음)는 항상 실행한다.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

from pweh.formats import UIMAGE_MAGIC, find_uboot_env, parse_mtdparts, parse_uboot_env, parse_uimage_header
from pweh.mocktarget import SYNTHETIC_MARKER, build_image, load_profile
from pweh.mocktarget.firmware import build_image_bytes
from pweh.mocktarget.rootfs import BACKDOOR_TOKEN, md5crypt

from .helpers import make_device, tool_path

PLANTED = ["PWEH-PLANT-01", "PWEH-PLANT-02", "PWEH-PLANT-03", "PWEH-PLANT-04", "PWEH-PLANT-05", "PWEH-PLANT-06"]


def _check_common(image: bytes, manifest: dict, profile_name: str) -> None:
    prof = load_profile(profile_name)
    assert len(image) == 16 * 1024 * 1024 == manifest["image"]["size"]
    assert manifest["marker"] == SYNTHETIC_MARKER and SYNTHETIC_MARKER.encode() in image
    parts = {p["name"]: p for p in parse_mtdparts(prof["flash"]["mtdparts"], total_size=len(image))}
    # env: CRC 가 맞고 bootargs 안에 같은 mtdparts
    env_p = parts["env"]
    res = parse_uboot_env(image[env_p["offset"] : env_p["offset"] + prof["uboot"]["env_size"]])
    assert res is not None and res["redundant"] is False
    for key in ("bootargs", "bootcmd", "bootdelay", "ipaddr", "serverip", "ethaddr"):
        assert key in res["env"], key
    assert "mtdparts=" + prof["flash"]["mtdparts"] in res["env"]["bootargs"]
    assert find_uboot_env(image)[0]["offset"] == env_p["offset"]
    # kernel: legacy uImage 헤더/데이터 CRC
    k = image[parts["kernel"]["offset"] : parts["kernel"]["offset"] + parts["kernel"]["size"]]
    assert struct.unpack(">I", k[:4])[0] == UIMAGE_MAGIC
    info = parse_uimage_header(k)
    assert info["header_crc_ok"] and info["data_crc_ok"]
    assert info["arch"] == prof["arch"] and info["name"] == prof["kernel"]["image_name"]
    assert info["compression"] == prof["kernel"]["compression"]
    # boot: 버전 문자열
    boot = image[: parts["boot"]["size"]]
    assert prof["uboot"]["version"].encode() in boot
    # 매니페스트: 정답 목록
    assert [p["id"] for p in manifest["planted_issues"]] == PLANTED
    cats = {p["category"] for p in manifest["planted_issues"]}
    assert {"backdoor", "auth-bypass", "command-injection", "hardcoded-credential", "debug-interface"} <= cats
    shadow_issue = manifest["planted_issues"][5]
    pw = prof["linux"]["login"]["password"]
    salt = shadow_issue["hash"].split("$")[2]
    assert md5crypt(pw, salt) == shadow_issue["hash"]
    files = {f["path"]: f for f in manifest["rootfs"]["files"]}
    for path in ("/etc/passwd", "/etc/shadow", "/etc/inittab", "/etc/init.d/rcS", "/usr/sbin/httpd", "/mnt/mtd",
                 "/bin/busybox", "/var/www/cgi-bin/status.cgi"):
        assert path in files, path


def test_fast_image_without_external_tools(profile_name):
    image, manifest = build_image_bytes(profile_name, fast=True, use_cache=False)
    _check_common(image, manifest, profile_name)
    assert manifest["rootfs"]["type"] == "cpio.gz"
    assert manifest["httpd"]["kind"] == "script"
    assert any(f["component"] == "rootfs" for f in manifest["fallbacks"])
    files = {f["path"] for f in manifest["rootfs"]["files"]}
    assert "/var/www/cgi-bin/ping.cgi" in files  # 셸 CGI 대체 경로에 같은 취약점 클래스
    # 같은 입력 → 같은 바이트 (결정적)
    again, _ = build_image_bytes(profile_name, fast=True, use_cache=False)
    assert again == image


@pytest.fixture(scope="session")
def full_images(tmp_path_factory) -> dict[str, tuple[Path, dict]]:
    zig = tool_path("PWEH_ZIG", "zig")
    sq = tool_path("PWEH_MKSQUASHFS", "mksquashfs")
    if not zig or not sq:
        pytest.skip("zig/mksquashfs 가 없어 전체 펌웨어 빌드를 건너뜀")
    out = tmp_path_factory.mktemp("fw")
    images = {}
    for name in ("hisilicon-like", "ingenic-like"):
        path = out / f"{name}.bin"
        manifest = build_image(name, path, zig=zig, mksquashfs=sq)
        images[name] = (path, manifest)
    return images


@pytest.mark.external
def test_full_image_squashfs_and_zig_httpd(full_images, profile_name):
    path, manifest = full_images[profile_name]
    image = path.read_bytes()
    _check_common(image, manifest, profile_name)
    saved = json.loads(Path(str(path) + ".manifest.json").read_text(encoding="utf-8"))
    assert saved["image"]["sha256"] == manifest["image"]["sha256"]
    assert manifest["fallbacks"] == []
    prof = load_profile(profile_name)
    rootfs_part = next(p for p in prof["partitions"] if p["name"] == "rootfs")
    assert image[rootfs_part["offset"] : rootfs_part["offset"] + 4] == b"hsqs"
    assert manifest["rootfs"]["type"] == "squashfs" and manifest["rootfs"]["compression"] == "xz"
    httpd = manifest["httpd"]
    assert httpd["kind"] == "elf"
    assert httpd["elf_machine"] == ("ARM" if prof["arch"] == "arm" else "MIPS")
    target = manifest["tools"]["zig"]["target"]
    assert target == ("arm-linux-musleabi" if prof["arch"] == "arm" else "mipsel-linux-musleabi")


@pytest.mark.external
def test_unsquashfs_lists_planted_files(full_images, tmp_path, profile_name):
    unsq = tool_path("PWEH_UNSQUASHFS", "unsquashfs")
    if not unsq:
        pytest.skip("unsquashfs 없음")
    path, manifest = full_images[profile_name]
    prof = load_profile(profile_name)
    part = next(p for p in prof["partitions"] if p["name"] == "rootfs")
    blob = path.read_bytes()[part["offset"] : part["offset"] + part["size"]]
    sq = tmp_path / "rootfs.sqfs"
    sq.write_bytes(blob)
    res = subprocess.run([unsq, "-l", str(sq)], capture_output=True, timeout=60)
    assert res.returncode == 0, res.stderr
    listing = res.stdout.decode()
    for f in ("squashfs-root/usr/sbin/httpd", "squashfs-root/etc/shadow", "squashfs-root/etc/init.d/rcS",
              "squashfs-root/bin/busybox", "squashfs-root/var/www/cgi-bin/status.cgi", "squashfs-root/mnt/mtd"):
        assert f in listing, f
    dest = tmp_path / "x"
    res = subprocess.run([unsq, "-d", str(dest), str(sq), "usr/sbin/httpd", "etc/init.d/rcS", "etc/shadow"],
                         capture_output=True, timeout=60)
    assert res.returncode == 0, res.stderr
    httpd = (dest / "usr/sbin/httpd").read_bytes()
    assert httpd[:4] == b"\x7fELF"
    machine = int.from_bytes(httpd[18:20], "little")
    assert machine == (40 if prof["arch"] == "arm" else 8)
    for needle in (BACKDOOR_TOKEN.encode(), b"ping -c 1 %s", b"/static/", SYNTHETIC_MARKER.encode(), b"check_auth",
                   b"handle_ping_cgi"):
        assert needle in httpd, needle
    assert "/usr/sbin/telnetd &" in (dest / "etc/init.d/rcS").read_text()
    shadow = (dest / "etc/shadow").read_text()
    assert shadow.startswith("root:$1$")
    os.chmod(dest / "etc/shadow", 0o644)


@pytest.mark.external
def test_device_boots_from_full_image(full_images):
    path, manifest = full_images["ingenic-like"]
    dev = make_device("ingenic-like", flash_image=path)
    try:
        assert dev.firmware_manifest["image"]["sha256"] == manifest["image"]["sha256"]
        dev.start_pty()
        dev.power_on()
        assert dev.wait_for_state("linux-login", 20)
        assert dev.crashed is None
        assert "Uncompressing Kernel Image ... OK" in dev.console_text()  # lzma uImage 를 실제로 풀어 검증
    finally:
        dev.stop()
