"""fwtriage 의 펌웨어 쪽 SD 카드 공격 표면 (I3a) 테스트.

- rootfs.py 빈틈 수정: iter_mount_commands(exfat/msdos/fat/auto/ntfs3/sdcardfs, '-t' 없는 /dev/mmcblk*, -o ro 제외), fstab 의 mmcblk 장치,
  STARTUP_GLOBS 의 mdev.conf·udev 규칙·hotplug, mdev @/$/* 와 udev RUN+=(상대 이름은 /lib/udev) 처리기 따라가기
- sdsurface.py: SD-01~09 각각 found / not-found, 입력이 없으면 unknown, 예산 초과면 unknown(not-found 아님), 심볼릭 링크 탈출 거부,
  verify=n·CRC 유효 env(쓰기 가능)·mmc 우선 부팅, 버튼 전용 업데이트 심각도, eMMC 마운트 구분, 마스킹, SD 없는 펌웨어
- YAML sd-* 휴리스틱: 로드·컴파일·사전 필터·예시 일치·오탐 회귀·참조 CVE 가 설계 표에 있는지
- MCP(in-memory Client): fw_sd_surface, fw_rootfs_audit(sd_surface=...), fw_uboot_env 의 sd_boot, background·짧은 예산
합성 벤더 펌웨어만 쓴다 (카드 쪽 파일·실제 기기 없음).
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from mcp import Client

from fwtriage.builders import build_flash, build_min_elf, make_rootfs_tree
from fwtriage.sd_builders import build_sd_flash, make_plain_rootfs, make_sd_vendor_rootfs, write_tree
from mcp_helpers import call

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp.common import Ctl  # noqa: E402
from fwtriage_mcp.hunt import hunt  # noqa: E402
from fwtriage_mcp.patterns import FINDING_CATEGORIES, load_patterns, matches_empty  # noqa: E402
from fwtriage_mcp.rootfs import (  # noqa: E402
    STARTUP_GLOBS,
    Auditor,
    command_program,
    iter_mount_commands,
    parse_mdev_conf,
    parse_udev_rules,
)
from fwtriage_mcp.sdsurface import (  # noqa: E402
    CHECK_IDS,
    CHECKS,
    SdSurface,
    attach_sd_boot,
    compact_result,
    parse_mount_command,
    sd_boot_analysis,
)
from fwtriage_mcp.uboot import env_scan  # noqa: E402

pytestmark = pytest.mark.anyio

CCTV_YAML = REPO / "src" / "pweh" / "data" / "cctv-hunt-patterns.yaml"
#: docs/design/sd-forensics.md 5.1 표에 적힌 CVE (이 밖의 CVE 를 SD 점검·sd-* 휴리스틱에 붙이지 않는다)
DESIGN_CVES = {"CVE-2023-30356", "CVE-2023-41612", "CVE-2019-16398", "CVE-2024-13893", "CVE-2018-12258", "CVE-2018-10988", "CVE-2025-65397",
               "CVE-2020-27540", "CVE-2020-19642", "CVE-2025-30124", "CVE-2025-64305", "CVE-2019-12919"}
YAML_CATEGORIES = {"auth-bypass", "backdoor", "hardcoded-credential", "command-injection", "debug-interface", "crypto", "info-leak"}

VENDOR_ENV = {
    "bootcmd": "run sdboot; sf probe 0; sf read 0x82000000 0x50000 0x100000; bootm 0x82000000",
    "sdboot": "mmc rescan; fatload mmc 0:1 0x82000000 boot.scr && source 0x82000000",
    "verify": "n",
    "bootdelay": "1",
}
VENDOR_DEFAULT_ENV = {
    "bootcmd": "run distro_bootcmd",
    "boot_targets": "mmc0 sf0",
    "distro_bootcmd": "for target in ${boot_targets}; do run bootcmd_${target}; done",
    "bootcmd_mmc0": "setenv devnum 0; run mmc_boot",
    "bootdelay": "2",
}
VENDOR_MARKERS = ("do_auto_update", "au_check_cksum_valid", "demo.bin", "key-name-hint")


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _vendor_flash() -> bytes:
    return build_sd_flash(env=VENDOR_ENV, default_env=VENDOR_DEFAULT_ENV, markers=VENDOR_MARKERS)


def _plain_flash() -> bytes:
    img, _ = build_flash(None)
    return img


def _audit(root: Path, ctl: Ctl | None = None, persistent: tuple[str, ...] = ()) -> Auditor:
    aud = Auditor(root, ctl or Ctl(max_seconds=120), load_patterns(), persistent_paths=list(persistent), profile={}, max_file_size=16 << 20,
                  crack=False, crack_seconds=1, words=[], max_entries=20000)
    aud.walk()
    return aud


def _surface(root: Path | None = None, image: bytes | None = None, ctl: Ctl | None = None) -> dict:
    ctl = ctl or Ctl(max_seconds=120)
    sd = SdSurface(ctl, load_patterns())
    if root is not None:
        aud = _audit(root, ctl)
        sd.scan_rootfs(aud, aud.audit_startup(), aud.audit_web())
    if image is not None:
        sd.scan_image(image, len(image), "dumps/flash.bin", env_scan(image, len(image), ctl, include_default=True))
    return sd.result(rootfs_given=root is not None, image_given=image is not None)


def _checks(res: dict) -> dict[str, dict]:
    return {c["id"]: c for c in res["checks"]}


def _rules(c: dict) -> set[str]:
    return {e["rule"] for e in c["evidence"]}


# ---------------------------------------------------------------------------
# rootfs.py 빈틈 수정
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cmd, fs, dev, mp, ro", [
    ("mount -t jffs2 /dev/mtdblock4 /mnt/mtd", "jffs2", None, "/mnt/mtd", False),  # 기존 동작
    ("mount /dev/mmcblk0p1 /mnt/sd", None, "/dev/mmcblk0p1", "/mnt/sd", False),  # '-t' 없는 mmcblk
    ("mount -o rw,umask=000 /dev/mmcblk0 /mnt/mmc", None, "/dev/mmcblk0", "/mnt/mmc", False),
    ("mount -t vfat -o ro /dev/mmcblk0p1 /mnt/sd", "vfat", "/dev/mmcblk0p1", "/mnt/sd", True),  # -o ro 는 건너뛴다
    ("mount -r /dev/mmcblk0p1 /mnt/sd", None, "/dev/mmcblk0p1", "/mnt/sd", True),
    ("mount -oro /dev/mmcblk0p1 /mnt/sd", None, "/dev/mmcblk0p1", "/mnt/sd", True),
    ("mount -t exfat /dev/mmcblk0p1 /mnt/sdcard 2>/dev/null", "exfat", "/dev/mmcblk0p1", "/mnt/sdcard", False),
    ("mount -t msdos /dev/sda1 /mnt/usb", "msdos", None, "/mnt/usb", False),
    ("mount -t fat /dev/sda1 /mnt/usb", "fat", None, "/mnt/usb", False),
    ("mount -t auto /dev/mmcblk0p1 /mnt/disc1; ls", "auto", "/dev/mmcblk0p1", "/mnt/disc1", False),
    ("mount -t ntfs3 /dev/sda1 /mnt/usb && echo ok", "ntfs3", None, "/mnt/usb", False),
    ("mount -t sdcardfs /data/media /mnt/runtime", "sdcardfs", None, "/mnt/runtime", False),
    ("mount -tvfat /dev/mmcblk1p1 /mnt/tf", "vfat", "/dev/mmcblk1p1", "/mnt/tf", False),
    ("mount -t vfat /dev/$MDEV /media/$MDEV", "vfat", None, "/media/$MDEV", False),
    ("mount /dev/mmcblk0p1 -t vfat /mnt/sd >/dev/null 2>&1", "vfat", "/dev/mmcblk0p1", "/mnt/sd", False),
    ("busybox mount -t ext4,ext3 /dev/mmcblk0p3 \"/data\"", "ext4", "/dev/mmcblk0p3", "/data", False),
])
def test_mount_scanner_recognises_removable_fs_and_tless_mmcblk(cmd, fs, dev, mp, ro):
    got = iter_mount_commands(cmd)
    if ro:
        assert got == [], cmd  # 읽기 전용 마운트는 쓰기 저장소가 아니다
        assert iter_mount_commands(re.sub(r" (?:-o ?ro|-r)(?= )", "", cmd)) != [], cmd  # 읽기 전용 표시만 빼면 잡힌다
        return
    assert [(m["fs"], m["device"], m["mount_point"]) for m in got] == [(fs, dev, mp)], cmd


@pytest.mark.parametrize("cmd", ["mount -t proc proc /proc", "mount -o remount,rw /", "mount --bind /tmp /var", "mount -t ext4dev /dev/x /y",
                                 "mount /dev/mtdblock3 /mnt/x", "mount -t squashfs /dev/mmcblk0p2 /rom", "umount -t vfat /mnt/sd"])
def test_mount_scanner_ignores_unrelated_mounts(cmd):
    assert iter_mount_commands(cmd) == []


def test_rootfs_audit_mount_gap_fix_makes_sd_mounts_writable(tmp_path):
    root = write_tree(tmp_path / "r", {
        "etc/fstab": "/dev/mmcblk0p1 /mnt/sd vfat noauto,rw 0 0\n/dev/mmcblk1p1 /mnt/ro vfat ro 0 0\nLABEL=usb /mnt/usb auto rw 0 0\n/dev/mmcblk0p5 /data ext4 defaults 0 0\n",
        "etc/init.d/rcS": (
            "#!/bin/sh\n"
            "mount -t exfat /dev/mmcblk0p2 /mnt/exf\n"
            "mount /dev/mmcblk0p3 /mnt/mmc\n"
            "mount -o rw,umask=000 /dev/mmcblk0 /mnt/mmc2\n"
            "mount -t vfat -o ro /dev/mmcblk1p1 /mnt/tf\n"
            "mount -r /dev/mmcblk1p2 /mnt/tf2\n"
            "mount -t msdos /dev/sda1 /mnt/msd\n"
            "mount -t ntfs3 /dev/sdb1 /mnt/nt\n"
            "mount -t sdcardfs /data/media /mnt/sdfs\n"
            "sh /mnt/mmc/run.sh &\n"
        ),
    })
    aud = _audit(root)
    st = aud.audit_startup()
    mps = {m["mount_point"] for m in st["mounts"]}
    assert {"/mnt/sd", "/mnt/usb", "/data", "/mnt/exf", "/mnt/mmc", "/mnt/mmc2", "/mnt/msd", "/mnt/nt", "/mnt/sdfs"} <= mps, mps
    assert not mps & {"/mnt/ro", "/mnt/tf", "/mnt/tf2"}
    tless = [m for m in st["mounts"] if m["mount_point"] == "/mnt/mmc"][0]
    assert tless["fs"] is None and tless["device"] == "/dev/mmcblk0p3"
    # SD 마운트가 쓰기 가능 접두가 되어 기본 감사에도 카드 스크립트 실행이 뜬다 (persistent_paths 없이)
    assert any(i["id"] == "builtin-exec-from-writable-storage" and i.get("target") == "/mnt/mmc/run.sh" for i in aud.items)


def test_parse_mdev_conf_and_udev_rules():
    rules = parse_mdev_conf(
        "# 주석\nnull 0:0 666\nmmcblk[0-9]p[0-9] 0:0 660 */etc/hotplug/sd.sh\n-SUBSYSTEM=block;mmcblk.* 0:0 660 @/sbin/automount.sh $MDEV\n"
        "sd[a-z][0-9]* root:disk 660 =disk/ $/lib/mdev/usbremove\nbad line\n"
    )
    assert [(r["line"], r["action"], r["command"]) for r in rules] == [
        (2, None, None), (3, "both", "/etc/hotplug/sd.sh"), (4, "add", "/sbin/automount.sh $MDEV"), (5, "remove", "/lib/mdev/usbremove")]
    assert rules[2]["device_regex"] == "mmcblk.*" and rules[2]["env"] == ["SUBSYSTEM=block"]
    ud = parse_udev_rules('KERNEL=="mmcblk[0-9]p[0-9]", SUBSYSTEM=="block", ACTION=="add", \\\n  RUN+="sd_mount.sh %k"\n# x\nACTION=="remove", KERNEL!="sd*", RUN+="/bin/umount /mnt/usb"\n')
    assert ud[0]["line"] == 1 and ud[0]["match"]["KERNEL"] == "mmcblk[0-9]p[0-9]" and ud[0]["run"] == ["sd_mount.sh %k"]
    assert ud[1]["match"]["KERNEL"] == "!sd*"
    assert command_program("/bin/sh /etc/x.sh arg") == "/etc/x.sh" and command_program("busybox sh /x.sh") == "/x.sh"
    assert command_program("FOO=1 /usr/bin/z") == "/usr/bin/z"


def test_startup_globs_follow_mdev_udev_and_hotplug_handlers(tmp_path):
    assert {"etc/mdev.conf", "etc/udev/rules.d/*", "lib/udev/rules.d/*", "usr/lib/udev/rules.d/*", "etc/hotplug/**", "etc/hotplug.d/**",
            "sbin/hotplug", "usr/sbin/hotplug"} <= set(STARTUP_GLOBS)
    root = write_tree(tmp_path / "r", {
        "etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 *sd_handler.sh\nmmcblk[0-9] 0:0 660 $/usr/sbin/sd_remove.sh\nsd[a-z][0-9] 0:0 660 @/bin/sh /usr/sbin/usb_add.sh $MDEV\n",
        "lib/mdev/sd_handler.sh": "#!/bin/sh\nmount /dev/$MDEV /mnt/sd\n",
        "usr/sbin/sd_remove.sh": "#!/bin/sh\numount /mnt/sd\n",
        "usr/sbin/usb_add.sh": "#!/bin/sh\necho usb\n",
        "lib/udev/rules.d/80-sd.rules": 'KERNEL=="mmcblk*", RUN+="sd_udev.sh"\n',
        "lib/udev/sd_udev.sh": "#!/bin/sh\necho udev\n",
        "etc/hotplug.d/block/10-sd": "#!/bin/sh\n[ \"$ACTION\" = add ] && mount /dev/$DEVNAME /mnt/mmc\n",
        "sbin/hotplug": "#!/bin/sh\nexec /sbin/mdev\n",
        "usr/sbin/hotplug": build_min_elf(),  # 바이너리 hotplug 는 텍스트 검사에서 건너뛴다
    })
    st = _audit(root).audit_startup()
    assert {"/etc/mdev.conf", "/lib/mdev/sd_handler.sh", "/usr/sbin/sd_remove.sh", "/usr/sbin/usb_add.sh", "/lib/udev/rules.d/80-sd.rules",
            "/lib/udev/sd_udev.sh", "/etc/hotplug.d/block/10-sd", "/sbin/hotplug"} <= set(st["startup_files"]), st["startup_files"]


# ---------------------------------------------------------------------------
# sdsurface: 전체 벤더 트리 (SD-01~SD-09 모두 found)
# ---------------------------------------------------------------------------


def test_vendor_tree_every_check_found_with_expected_rules(tmp_path):
    res = _surface(make_sd_vendor_rootfs(tmp_path / "v"), _vendor_flash())
    c = _checks(res)
    assert [x["id"] for x in res["checks"]] == list(CHECK_IDS)
    assert res["counts"] == {"found": 9, "not-found": 0, "unknown": 0}
    assert res["risk_found"] == [i for i in CHECK_IDS if i != "SD-07"]
    assert {"sh", "direct-exec", "trigger-service", "binary-exec-string"} <= _rules(c["SD-01"])
    assert {"flash-write", "trigger-flash", "uboot-auto-update", "update-image-name"} <= _rules(c["SD-02"])
    assert {"env-boot-script", "env-distro-boot", "fw_setenv-mmc"} <= _rules(c["SD-03"])
    assert {"mdev-rule", "hotplug-script", "daemon-mmcblk"} <= _rules(c["SD-04"])
    assert "uevent-helper" not in _rules(c["SD-04"])  # 'echo /sbin/mdev > /proc/sys/kernel/hotplug' 는 카드 처리기 근거가 아니다 (모든 BusyBox rcS 에 있다)
    assert {"config-import", "binary-config-path"} <= _rules(c["SD-05"])
    assert {"syslogd-to-card", "write-to-card", "log-path-config"} <= _rules(c["SD-06"])
    assert _rules(c["SD-07"]) == {"encryption-flag"} and c["SD-07"]["found_means"] == "protection" and c["SD-07"]["severity_hint"] == "info"
    assert {"weak-mount-options", "umask-zero"} <= _rules(c["SD-08"])
    assert {"web-config-root", "web-symlink", "cgi-sd-listing"} <= _rules(c["SD-09"])
    # 변수 펼침: SD_DIR=/mnt/sdcard → sh $SD_DIR/autorun.sh
    sh = [e for e in c["SD-01"]["evidence"] if e["rule"] == "sh"][0]
    assert (sh["file"], sh["line"], sh["sd_path"], sh["context"], sh["severity"]) == ("/etc/init.d/rcS", 7, "/mnt/sdcard/autorun.sh", "boot", "high")
    assert sh["expanded"].startswith("sh /mnt/sdcard/autorun.sh")
    hot = [e for e in c["SD-01"]["evidence"] if e["rule"] == "direct-exec"][0]
    assert hot["context"] == "hotplug" and hot["sd_path"] == "/media/$MDEV/hotplug_run.sh"
    # U-Boot: verify=n + mmc 우선 + CRC 유효 env(saveenv 가능), 사용자 공간 fw_setenv
    ctx3 = c["SD-03"]["context"]
    assert ctx3["env_persistent"] is True and ctx3["env_userspace"]["userspace_writable"] is True
    crc = [x for x in ctx3["envs"] if x["storage"] == "flash-crc"][0]
    assert crc["verify_off"] is True and crc["mmc_first"] is True and c["SD-03"]["severity_hint"] == "high"
    assert c["SD-02"]["context"]["fit_signature_keys"] is True and c["SD-02"]["severity_hint"] == "high"
    au = [e for e in c["SD-02"]["evidence"] if e["rule"] == "uboot-auto-update" and "au_check" in e["excerpt"]][0]
    assert au["source"] == "image-strings" and au["image"] == "dumps/flash.bin" and au["offset_hex"] and "CRC" in au["note"]
    # 증거 형식·어휘
    for cc in res["checks"]:
        assert cc["category"] in FINDING_CATEGORIES and set(cc["references"]) <= DESIGN_CVES
        assert re.search("[가-힣]", cc["rationale"]) and cc["title"] and cc["next_steps"]
        for e in cc["evidence"]:
            assert e["source"] in ("rootfs", "uboot-env", "image-strings") and e["rule"] and isinstance(e["excerpt"], str) and len(e["excerpt"]) <= 200
            assert ("file" in e) or ("image" in e)
    # 카드 경로 목록 (나중에 카드 내용과 대조)
    refs = {r["path"]: r for r in res["sd_paths_referenced"]}
    assert refs["/mnt/sdcard/autorun.sh"]["card_relative"] == "autorun.sh" and "exec" in refs["/mnt/sdcard/autorun.sh"]["actions"]
    assert "flash" in refs["/mnt/sdcard/update.bin"]["actions"] and "SD-02" in refs["/mnt/sdcard/update.bin"]["checks"]
    assert "read-config" in refs["/mnt/sdcard/wpa_supplicant.conf"]["actions"]
    mps = {m["path"]: m for m in res["mount_points"]}
    assert {"script", "binary-string"} <= {s["source"] for s in mps["/mnt/sdcard"]["sources"]} and "/media/$MDEV" in mps
    assert {h["kind"] for h in res["hotplug_handlers"]} >= {"mdev", "hotplug-script", "daemon"}
    # 마스킹: 카드에 쓰는 줄의 PSK
    assert "Hunter22x" not in json.dumps(res, ensure_ascii=False)


def test_check_definitions_follow_design_table():
    assert tuple(CHECKS) == CHECK_IDS == tuple(f"SD-0{i}" for i in range(1, 10))
    for cid, meta in CHECKS.items():
        assert meta["category"] in FINDING_CATEGORIES and set(meta["references"]) <= DESIGN_CVES, cid
        assert meta["found_means"] == ("protection" if cid == "SD-07" else "risk"), cid
        assert re.search("[가-힣]", meta["title"]) and re.search("[가-힣]", meta["rationale"]) and meta["next_steps"], cid
        assert not any(_ARTIFACT_ADVICE.search(s) for s in meta["next_steps"]), cid
    # 동적 확인 안내는 사람이 동의한 새 빈 시험 카드의 수동 부팅 로그 관찰(sd_events)까지만
    dyn = [s for m in CHECKS.values() for s in m["next_steps"] if "sd_events" in s]
    assert dyn and all("새 빈 시험 카드" in s for s in dyn)


def test_no_sd_firmware_reports_nothing_found(tmp_path):
    for root in (make_plain_rootfs(tmp_path / "plain"), make_rootfs_tree(tmp_path / "vuln")["root"]):
        res = _surface(root, _plain_flash())
        c = _checks(res)
        assert res["counts"]["found"] == 0, [(x["id"], x["evidence"][:1]) for x in res["checks"] if x["status"] == "found"]
        for cid in ("SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-09"):
            assert c[cid]["status"] == "not-found", (root, cid, c[cid].get("unknown_reason"))
        assert c["SD-07"]["status"] == "unknown" and c["SD-08"]["status"] == "unknown"
        assert res["mount_points"] == [] and res["sd_paths_referenced"] == []


#: 점검 하나만 심은 최소 트리 → 그 점검만 found, 나머지는 not-found (점검 사이 오탐 없음)
PER_CHECK = {
    "SD-01": ({"etc/init.d/rcS": "#!/bin/sh\nmount -t vfat -o noexec,nosuid,nodev /dev/mmcblk0p1 /mnt/sd\nsh /mnt/sd/autorun.sh &\n"}, None),
    "SD-02": ({"etc/init.d/S80update": "#!/bin/sh\nif [ -f /mnt/sd/update.bin ]; then\n    flashcp -v /mnt/sd/update.bin /dev/mtd2\nfi\n"}, None),
    "SD-03": ({}, {"bootcmd": "run sdboot; sf probe 0; bootm 0x82000000", "sdboot": "fatload mmc 0:1 0x82000000 uEnv.txt; env import -t 0x82000000 ${filesize}"}),
    "SD-04": ({"etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 @/sbin/automount.sh\n",
               "sbin/automount.sh": "#!/bin/sh\nmount -t vfat -o noexec,nosuid,nodev /dev/$MDEV /mnt/sd\n"}, None),
    "SD-05": ({"etc/init.d/rcS": "#!/bin/sh\ncp /mnt/sd/wifi.conf /etc/wifi.conf\n"}, None),
    "SD-06": ({"etc/init.d/rcS": "#!/bin/sh\nsyslogd -O /mnt/sd/messages\n"}, None),
    "SD-07": ({"etc/app.conf": "sd_encrypt_enable=1\n"}, None),
    "SD-08": ({"etc/fstab": "/dev/mmcblk0p1 /mnt/sd vfat rw,umask=000 0 0\n"}, None),
    "SD-09": ({"etc/samba/smb.conf": "[global]\n workgroup = WG\n[sd]\n path = /mnt/sd\n writable = yes\n"}, None),
}


@pytest.mark.parametrize("target", list(PER_CHECK))
def test_each_check_found_alone_and_others_not_found(tmp_path, target):
    files, env = PER_CHECK[target]
    image = build_sd_flash(env=env) if env else _plain_flash()
    res = _surface(write_tree(tmp_path / target, files), image)
    c = _checks(res)
    assert c[target]["status"] == "found", (target, c[target])
    others = {"SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-09"} - {target}
    assert {i for i in others if c[i]["status"] != "not-found"} == set(), [(i, c[i]["status"], c[i]["evidence"][:1]) for i in others if c[i]["status"] != "not-found"]
    if target not in ("SD-07",):
        assert c["SD-07"]["status"] == "unknown"
    if target == "SD-04":
        assert c["SD-08"]["status"] == "not-found"  # noexec 가 있는 vfat 핫플러그 마운트
    if target == "SD-09":
        assert c["SD-09"]["evidence"][0]["remote_write"] is True and c["SD-09"]["evidence"][0]["rule"] == "samba-share"


def test_exec_shapes_copy_decrypt_loop_module_inittab_cron_mdev(tmp_path):
    root = write_tree(tmp_path / "x", {
        "etc/init.d/rcS": (
            "#!/bin/sh\n"
            "cp /mnt/sd/tool.bin /tmp/tool\n"
            "chmod +x /tmp/tool\n"
            "/tmp/tool &\n"
            "openssl enc -d -aes-128-cbc -k S3cretKey99 -in /mnt/sd/pkg.enc | sh\n"
            "for f in /mnt/sd/init/*.sh; do sh $f; done\n"
            "insmod /mnt/sd/drv.ko\n"
            "LD_PRELOAD=/mnt/sd/hook.so /usr/bin/app &\n"
            ". /mnt/sd/env.conf\n"
        ),
        "etc/inittab": "::sysinit:/etc/init.d/rcS\n::respawn:/mnt/sd/daemon\n",
        "etc/crontabs/root": "*/5 * * * * /mnt/sd/cron.sh\n",
        "etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 */mnt/sd/hot.sh\n",
    })
    c = _checks(_surface(root))
    assert {"copy-then-exec", "decrypt-then-exec", "sh", "kernel-module", "ld-preload", "source", "inittab-exec", "cron-exec", "mdev-exec"} <= _rules(c["SD-01"]), _rules(c["SD-01"])
    assert all(e["severity"] == "high" for e in c["SD-01"]["evidence"])
    cte = [e for e in c["SD-01"]["evidence"] if e["rule"] == "copy-then-exec"][0]
    assert cte["sd_path"] == "/mnt/sd/tool.bin" and cte["copied_to"] == "/tmp/tool" and cte["copy_line"] == 2 and cte["line"] == 4
    dec = [e for e in c["SD-01"]["evidence"] if e["rule"] == "decrypt-then-exec"][0]
    assert "S3cretKey99" not in json.dumps(c, ensure_ascii=False) and "-k S3" in dec["excerpt"]  # 키 값은 앞 2글자만
    loop = [e for e in c["SD-01"]["evidence"] if e["rule"] == "sh"][0]
    assert loop["sd_path"] == "/mnt/sd/init/*.sh"
    # . (source) 로 읽는 카드 파일은 설정이 아니라 실행 (SD-05 아님)
    assert c["SD-05"]["status"] == "not-found"


def test_trigger_file_starts_service_and_non_sd_paths_ignored(tmp_path):
    root = write_tree(tmp_path / "t", {
        "etc/init.d/rcS": (
            "#!/bin/sh\n"
            "if [ -e /mnt/sd/debug_on ]; then\n"
            "    /usr/sbin/telnetd -l /bin/sh &\n"
            "fi\n"
            "[ -d /mnt/sd ] && mkdir -p /mnt/sd/record\n"
            "sh /mnt/mtd/start.sh &\n"
            "echo /mnt/sd/x.sh\n"
        ),
    })
    c = _checks(_surface(root))
    trig = [e for e in c["SD-01"]["evidence"] if e["rule"] == "trigger-service"]
    assert len(trig) == 1 and trig[0]["sd_path"] == "/mnt/sd/debug_on" and "telnetd" in trig[0]["triggered"]
    assert {e["rule"] for e in c["SD-01"]["evidence"]} == {"trigger-service"}  # echo·mkdir·[ -d 마운트지점 ] 은 실행이 아님


def test_symlink_escape_refused(tmp_path):
    host = tmp_path / "host"
    host.mkdir()
    (host / "evil.sh").write_text("#!/bin/sh\nsh /mnt/sd/HOSTONLY_exec.sh\n")
    (host / "mdev.conf").write_text("mmcblk0 0:0 660 */mnt/sd/HOSTONLY_mdev.sh\n")
    (host / "smb.conf").write_text("[x]\n path = /mnt/sd/HOSTONLY_share\n")
    (host / "www").mkdir()
    root = write_tree(tmp_path / "root", {"etc/init.d/rcS": "#!/bin/sh\necho ok\n", "var/www/index.html": "x\n"}, symlinks={
        "etc/init.d/S90abs": str(host / "evil.sh"),
        "etc/init.d/S91rel": "../" * 12 + str(host / "evil.sh").lstrip("/"),
        "etc/mdev.conf": str(host / "mdev.conf"),
        "etc/samba/smb.conf": "../../../../../../../../" + str(host / "smb.conf").lstrip("/"),
        "var/www/escape": str(host / "www"),
        "mnt/sd": "/",
    })
    res = _surface(root)
    assert "HOSTONLY" not in json.dumps(res, ensure_ascii=False)
    c = _checks(res)
    for cid in ("SD-01", "SD-04", "SD-09"):
        assert c[cid]["status"] == "not-found", (cid, c[cid]["evidence"][:1])


def test_emmc_mounts_are_not_sd_and_readonly_sd_mount_is_not_weak(tmp_path):
    root = write_tree(tmp_path / "e", {
        "etc/fstab": "/dev/mmcblk0p5 /data ext4 defaults 0 0\n/dev/mmcblk1p1 /mnt/sd vfat ro 0 0\n",
        "etc/init.d/rcS": "#!/bin/sh\nmount /dev/mmcblk0p6 /userdata\nsh /data/start.sh &\nsh /userdata/run.sh &\nmount -t vfat -o ro,noexec /dev/mmcblk1p1 /mnt/tf\n",
    })
    res = _surface(root)
    c = _checks(res)
    assert c["SD-01"]["status"] == "not-found"
    notes = {m["mount_point"]: m["note"] for m in res["other_mmc_mounts"]}
    assert set(notes) == {"/data", "/userdata"} and all("eMMC" in n for n in notes.values())
    assert {m["path"] for m in res["mount_points"]} == {"/mnt/sd", "/mnt/tf"}
    # 읽기 전용 SD 마운트뿐 → 약한 옵션 근거 없음, 쓰기 가능 마운트의 옵션은 보지 못함 → unknown
    assert c["SD-08"]["status"] == "unknown" and c["SD-08"]["evidence"] == []


def test_parse_mount_command():
    assert parse_mount_command("mount -t vfat -o rw,umask=000 /dev/mmcblk0p1 /mnt/sd") == {
        "fs": "vfat", "options": ["rw", "umask=000"], "device": "/dev/mmcblk0p1", "mount_point": "/mnt/sd", "readonly": False}
    assert parse_mount_command("if ! busybox mount -r /dev/mmcblk0p1 /mnt/sd")["readonly"] is True
    assert parse_mount_command("mount /mnt/sd")["device"] is None
    for bad in ("mount -o remount,rw /", "mount --bind /a /b", "umount /mnt/sd", "mount -a", "echo mount /x"):
        assert parse_mount_command(bad) is None, bad


# ---------------------------------------------------------------------------
# U-Boot env (sd_boot)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, off", [("n", True), ("no", True), ("N", True), ("0", True), ("false", True), ("y", False), ("yes", False), ("1", False), (None, False)])
def test_sd_boot_verify_values(raw, off):
    env = {"bootcmd": "fatload mmc 0:1 0x82000000 uImage; bootm 0x82000000"}
    if raw is not None:
        env["verify"] = raw
    b = sd_boot_analysis(env, storage="flash-crc")
    assert b["verify"] == raw and b["verify_off"] is off
    assert b["severity_hint"] == "high"  # mmc 먼저(유일한 부팅 경로)이므로 verify 와 상관없이 high
    if raw is None:
        assert any("verify 변수 없음" in n for n in b["notes"])


def test_sd_boot_mmc_first_raw_mmc_distro_update_and_storage():
    flash_first = sd_boot_analysis({"bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x100000; bootm 0x82000000 || run sdboot",
                                    "sdboot": "fatload mmc 0:1 0x82000000 uImage; bootm 0x82000000"}, storage="flash-crc")
    assert flash_first["fs_load"] and flash_first["mmc_first"] is False and flash_first["severity_hint"] == "medium"
    assert flash_first["persistent_writable"] is True and any("eMMC" in n for n in flash_first["notes"])
    raw = sd_boot_analysis({"bootcmd": "mmc dev 1; mmc read 0x82000000 0x800 0x2000; bootm 0x82000000"}, storage="embedded-default")
    assert raw["raw_mmc_only"] and raw["severity_hint"] == "low" and raw["persistent_writable"] is None
    distro = sd_boot_analysis(VENDOR_DEFAULT_ENV, storage="embedded-default")
    assert distro["distro_boot"] and distro["mmc_first"] is True and distro["severity_hint"] == "high"
    upd = sd_boot_analysis({"bootcmd": "run sdupdate; bootm", "sdupdate": "if gpio input 51; then fatload mmc 0 0x82000000 demo.bin; sf probe 0; "
                            "sf erase 0x0 0x800000; sf write 0x82000000 0x0 ${filesize}; fi"}, storage="flash-crc")
    assert upd["update_from_card"] and upd["update_gpio_gated"] is True
    none = sd_boot_analysis({"bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x100000; bootm 0x82000000", "bootdelay": "1"}, storage="flash-crc")
    assert not none["mmc_boot"] and none["severity_hint"] is None and none["signals"] == [] and none["mmc_first"] is False
    scan = {"envs": [{"env": VENDOR_ENV}], "embedded_default_envs": [{"env": VENDOR_DEFAULT_ENV}]}
    summ = attach_sd_boot(scan)
    assert summ == {"envs_with_mmc_boot": 2, "envs_with_boot_script": 1, "verify_off": 1, "update_from_card": 0, "env_persistent": True}
    assert scan["envs"][0]["sd_boot"]["storage"] == "flash-crc" and scan["embedded_default_envs"][0]["sd_boot"]["storage"] == "embedded-default"


def test_image_only_env_and_strings(tmp_path):
    c = _checks(_surface(image=_vendor_flash()))
    assert c["SD-03"]["status"] == "found" and c["SD-02"]["status"] == "found"
    for cid in ("SD-01", "SD-04", "SD-05", "SD-06", "SD-08", "SD-09"):
        assert c[cid]["status"] == "unknown" and "rootfs_dir" in c[cid]["unknown_reason"], cid
    # env 가 없는 이미지 → SD-03 unknown (not-found 가 아님)
    blank = _checks(_surface(image=b"\xff" * 0x20000))
    assert blank["SD-03"]["status"] == "unknown" and "env" in blank["SD-03"]["unknown_reason"]


def test_rootfs_only_leaves_uboot_checks_unknown(tmp_path):
    c = _checks(_surface(make_plain_rootfs(tmp_path / "p")))
    for cid in ("SD-02", "SD-03"):
        assert c[cid]["status"] == "unknown" and "image_path" in c[cid]["unknown_reason"]
        assert any("image_path" in s for s in c[cid]["next_steps"])


# ---------------------------------------------------------------------------
# SD-02 버튼 전용 업데이트의 심각도
# ---------------------------------------------------------------------------

_BUTTON_UPDATE = {"etc/init.d/S80update": "#!/bin/sh\nif [ \"$(cat /sys/class/gpio/gpio12/value)\" = \"0\" ] && [ -f /mnt/sd/update.bin ]; then\n"
                                          "    flashcp -v /mnt/sd/update.bin /dev/mtd2\nfi\n"}


def test_button_only_update_lowered_only_without_remote_write(tmp_path):
    lowered = _checks(_surface(write_tree(tmp_path / "b1", _BUTTON_UPDATE), _plain_flash()))["SD-02"]
    assert lowered["status"] == "found" and lowered["severity_hint"] == "medium"
    assert lowered["context"]["button_only"] is True and lowered["context"]["remote_write_evident"] is False and lowered["context"]["severity_adjusted"] is True
    assert all(e.get("gated_by") == "button/gpio" for e in lowered["evidence"])
    # 같은 카드가 FTP 로 쓰기 가능하게 노출 → 원격 쓰기 경로 → high 유지
    remote = dict(_BUTTON_UPDATE, **{"etc/init.d/rcS": "#!/bin/sh\ntcpsvd -vE 0.0.0.0 21 ftpd -w /mnt/sd &\n"})
    kept = _checks(_surface(write_tree(tmp_path / "b2", remote), _plain_flash()))
    assert kept["SD-02"]["severity_hint"] == "high" and kept["SD-02"]["context"]["remote_write_evident"] is True
    assert kept["SD-09"]["status"] == "found" and kept["SD-09"]["evidence"][0]["remote_write"] is True
    # 웹 파일이 같은 업데이트 파일 이름을 참조 → 원격 쓰기 경로로 본다
    web = dict(_BUTTON_UPDATE, **{"var/www/upgrade.html": "<form action=/cgi-bin/up.cgi>update.bin</form>\n"})
    assert _checks(_surface(write_tree(tmp_path / "b3", web), _plain_flash()))["SD-02"]["severity_hint"] == "high"
    # 버튼 조건이 없으면 high, 이유를 적는다
    plain = {"etc/init.d/S80update": "#!/bin/sh\nflashcp -v /mnt/sd/update.bin /dev/mtd2\n"}
    hi = _checks(_surface(write_tree(tmp_path / "b4", plain), _plain_flash()))["SD-02"]
    assert hi["severity_hint"] == "high" and hi["context"]["button_only"] is False and "유지" in hi["context"]["reason"]
    # U-Boot 문자열 표지(조건을 알 수 없음)가 섞이면 낮추지 않는다
    mixed = _checks(_surface(write_tree(tmp_path / "b5", _BUTTON_UPDATE), build_sd_flash(markers=("au_check_cksum_valid",))))["SD-02"]
    assert mixed["severity_hint"] == "high" and mixed["context"]["button_only"] is False


# ---------------------------------------------------------------------------
# 예산
# ---------------------------------------------------------------------------


def test_expired_budget_never_reports_not_found(tmp_path):
    res = _surface(make_sd_vendor_rootfs(tmp_path / "v"), _vendor_flash(), ctl=Ctl(max_seconds=1e-9))
    statuses = {c["id"]: c["status"] for c in res["checks"]}
    assert "not-found" not in statuses.values(), statuses
    assert res["phases"]["rootfs_text"] == "truncated" and res["phases"]["rootfs_binary"] == "truncated" and res["phases"]["image_strings"] == "truncated"
    assert any("시간 예산" in x for x in res["limitations"])
    assert any(c.get("unknown_reason", "").startswith("시간") for c in res["checks"])


def test_sd_paths_cap_keeps_check_paths_and_long_lines_are_bounded(tmp_path, monkeypatch):
    """회귀: 단순 참조(녹화 파일 이름 수천 개)가 sd_paths 상한을 채워, 뒤에 보는 바이너리의 실행 경로가 빠졌다."""
    from fwtriage_mcp import sdsurface

    monkeypatch.setattr(sdsurface, "MAX_PLAIN_REFS", 5)
    records = "".join(f"rec{i}=/mnt/sdcard/record/{i}.mp4\n" for i in range(3000))  # 녹화 파일 이름 3000개 (단순 참조)
    long_js = ";".join(f"var a{i}='/mnt/sdcard/x{i}.sh'" for i in range(3000))  # 한 줄짜리 압축 JS — 웹 콘텐츠는 분류하지 않는다
    root = write_tree(tmp_path / "cap", {"etc/app/records.conf": records, "var/www/js/app.min.js": long_js,
                                         "usr/bin/appd": build_min_elf() + b"\0sh /mnt/sdcard/autorun_app.sh &\0"})
    res = _surface(root)
    refs = {r["path"]: r for r in res["sd_paths_referenced"]}
    assert res["sd_paths_truncated"] is True and sum(1 for r in refs.values() if not r["checks"]) == 5
    assert "exec" in refs["/mnt/sdcard/autorun_app.sh"]["actions"]
    assert _checks(res)["SD-01"]["status"] == "found" and not any(p.startswith("/mnt/sdcard/x") for p in refs)


def test_compact_result_limits_lists(tmp_path):
    res = _surface(make_sd_vendor_rootfs(tmp_path / "v"), _vendor_flash())
    comp = compact_result(res, 2)
    assert len(comp["sd_paths_referenced"]) == 2 and comp["truncated"] is True and comp["sd_paths_total"] == res["sd_paths_total"]
    assert all(len(c["evidence"]) <= 3 for c in comp["checks"]) and comp["counts"] == res["counts"]


# ---------------------------------------------------------------------------
# YAML sd-* 휴리스틱
# ---------------------------------------------------------------------------

SD_POSITIVE = {
    "sd-autorun-known-names": ["snx_autorun.sh", "/mnt/sd/enable_telnetd.dat"],
    "sd-card-script-path": ["sh /mnt/sdcard/iu.sh", "/mnt/mmc/autoexec.sh", "/media/mmcblk0p1/run/start.sh", "/tmp/sd/x.sh", "/system/sdcard/run.sh"],
    "sd-uboot-auto-update": ["do_auto_update", "au_check_cksum_valid", "sdupdate", "hiupdate", "sdupgrade"],
    "sd-update-image-names": ["demo.bin", "/mnt/sd/ezviz.dav"],
    "sd-card-update-file": ["/mnt/sd/upgrade.sh", "/mnt/sdcard/firmware_v2.bin", "/media/sdcard/update.img", "/mnt/sdhc/update.img", "/mnt/sd0/upgrade.bin"],
    "sd-uboot-card-boot-script": ["fatload mmc 0:1 ${scriptaddr} boot.scr", "load mmc ${devnum}:${distro_bootpart} ${scriptaddr} uEnv.txt"],
    "sd-log-to-card": ["syslogd -O /mnt/sd/messages", "echo /mnt/sdcard/core.%e > /proc/sys/kernel/core_pattern"],
}
SD_NEGATIVE = ["sh /mnt/mtd/start.sh", "menu.sh", "demo.binary", "update.bin", "syslogd -O /var/log/messages", "load mmc 0:1 ${kernel_addr_r} zImage",
               "/opt/upgrade.sh", "kernel.core_pattern=/tmp/core", "/mnt/config/iu.sh", "auto_update=1",
               # SCSI 디스크 이름(SATA·USB 디스크)은 카드가 아니다 (fw_sd_surface 와 같은 규칙)
               "/media/sda1/update.img", "/mnt/sda1/maint/cleanup.sh", "syslogd -O /mnt/sda1/log/messages -s 1024", "/media/sdb1/upgrade.sh",
               "/mnt/sdb/update.bin", "/mnt/sdaa1/firmware.bin"]


def test_sd_yaml_entries_follow_conventions_and_match_samples():
    raw = yaml.safe_load(CCTV_YAML.read_text(encoding="utf-8"))
    entries = [e for e in raw["string_heuristics"] if e["id"].startswith("sd-")]
    assert [i for i, n in collections.Counter(e["id"] for e in raw["string_heuristics"]).items() if n > 1] == []
    assert {e["id"] for e in entries} == set(SD_POSITIVE)
    for e in entries:
        assert set(e) == {"id", "pattern", "category", "severity_hint", "scope", "vendor", "rationale", "references"}, e["id"]
        assert e["category"] in YAML_CATEGORIES and e["severity_hint"] in ("critical", "high", "medium", "low", "info"), e["id"]
        assert set(e["references"]) <= DESIGN_CVES, e["id"]
        assert re.search("[가-힣]", e["rationale"]) and len(e["rationale"]) <= 160, e["id"]
    ps = load_patterns()
    assert ps.errors == []
    hs = {h.id: h for h in ps.string_heuristics if h.id.startswith("sd-")}
    for hid, samples in SD_POSITIVE.items():
        h = hs[hid]
        assert h.rx is not None and not matches_empty(h) and h.literals and all(len(x) >= 3 for x in h.literals), hid
        for s in samples:
            assert h.rx.search(s), (hid, s)
            assert h.prefilter(s, lambda s=s: s.lower()), (hid, s)
    for s in SD_NEGATIVE:
        assert not [h.id for h in hs.values() if h.rx.search(s)], s


def test_sd_heuristics_hit_in_strings_hunt(tmp_path):
    case = tmp_path / "case"
    f = case / "dumps" / "uboot.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x00\x01U-Boot\x00do_auto_update\x00au_check_cksum_valid\x00\xff\xfesh /mnt/sd/autorun.sh &\x00demo.bin\x00")
    sel, _ = load_patterns().select(["sd-*"])
    assert sel and all(h.id.startswith("sd-") for h in sel)
    res = hunt(f, False, case, Ctl(max_seconds=60), sel, max_hits=50, per_pattern_cap=10, max_file_size=1 << 20)
    assert {"sd-uboot-auto-update", "sd-card-script-path", "sd-update-image-names"} <= {h["pattern_id"] for h in res["hits"]}


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


@pytest.fixture
def sd_case(workspace, auth):
    from pweh.case import CaseStore

    store = CaseStore(workspace["cases_dir"])
    case = store.create(title="SD 공격 표면", authorization=auth, case_id="sdcase")
    make_sd_vendor_rootfs(case.dir / "extract" / "rootfs-001")
    make_plain_rootfs(case.dir / "extract" / "plain-001")
    (case.subdir("dumps") / "flash.bin").write_bytes(_vendor_flash())
    (case.subdir("dumps") / "plain.bin").write_bytes(_plain_flash())
    return case


_ARTIFACT_ADVICE = re.compile(r"(?:boot\.scr|uEnv|update\.bin|demo\.bin|autorun|트리거 파일|업데이트 이미지)[^.]{0,40}(?:만들|작성|생성|넣어)")


async def test_fw_sd_surface_mcp_full(sd_case):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        r = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="extract/rootfs-001", image_path="dumps/flash.bin", max_results=5)
    assert r["ok"], r
    assert r["tool"] == "fw_sd_surface" and r["result_path"] == "analysis/sd-surface-001.json"
    assert r["counts"] == {"found": 9, "not-found": 0, "unknown": 0} and r["risk_found"] == [i for i in CHECK_IDS if i != "SD-07"]
    assert [x["id"] for x in r["checks"]] == list(CHECK_IDS)
    for x in r["checks"]:
        assert set(x) >= {"id", "title", "status", "severity_hint", "category", "found_means", "evidence_total", "evidence"} and len(x["evidence"]) <= 3
    assert len(r["sd_paths_referenced"]) == 5 and r["truncated"] is True and r["sd_paths_total"] > 5
    assert r["uboot"]["env_count"] == 1 and r["uboot"]["sd_boot_summary"]["verify_off"] == 1
    assert r["input"]["rootfs_dir"]["path"] == "extract/rootfs-001" and r["input"]["image"]["path"] == "dumps/flash.bin"
    steps = " ".join(r["next_steps"])
    assert "sd_events" in steps and "AH-04" in steps and not _ARTIFACT_ADVICE.search(steps)
    full = json.loads((sd_case.dir / r["result_path"]).read_text(encoding="utf-8"))
    assert full["schema"] == "pweh.fwtriage.sd-surface/v1" and full["tool"] == "fw_sd_surface" and full["inputs_analyzed"] == {"rootfs": True, "image": True}
    assert full["uboot"]["envs"][0]["sd_boot"]["signals"] and full["uboot"]["embedded_default_envs"][0]["sd_boot"]["storage"] == "embedded-default"
    for x in full["checks"]:
        assert set(x) >= {"id", "title", "status", "severity_hint", "category", "evidence", "rationale", "references", "next_steps"}
        assert not any(_ARTIFACT_ADVICE.search(s) for s in x["next_steps"])
    assert "Hunter22x" not in json.dumps(full, ensure_ascii=False)
    arts = {a["path"]: a for a in sd_case.load().get("artifacts", [])}
    assert arts[r["result_path"]]["kind"] == "triage-report"


async def test_secrets_masked_in_every_field_of_result_files(sd_case):
    """evidence.expanded, 마운트 명령의 발췌·옵션, 핫플러그 처리기 명령, 기본 감사의 mounts/services 에도 자격증명 원문이 남지 않는다."""
    from fwtriage_mcp.server import server

    from fwtriage.sd_builders import app_binary

    write_tree(sd_case.dir / "extract" / "mask-001", {
        "etc/init.d/rcS": (
            "#!/bin/sh\n"
            "SD_DIR=/mnt/sdcard\n"
            "echo \"psk=Hunter22x\" >> $SD_DIR/debug.txt\n"
            "mount -t cifs -o username=u,password=Hunter33y //nas/x /mnt/sdcard\n"
            "mount -t vfat -o rw,password=Hunter66v /dev/mmcblk0p1 /mnt/sd2\n"
            "telnetd -l /bin/sh -p 2323 --pass=Hunter77u &\n"
        ),
        "etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 @/sbin/sdmount.sh --password=Hunter44z\n",
        "sbin/sdmount.sh": "#!/bin/sh\nmount -t vfat /dev/$MDEV /mnt/sd\n",
        "usr/bin/appd": app_binary("mount -t vfat -o rw,password=Hunter55w /dev/mmcblk0p1 /mnt/sdcard"),
    })
    secrets = ("Hunter22x", "Hunter33y", "Hunter44z", "Hunter55w", "Hunter66v", "Hunter77u")
    async with Client(server) as c:
        r = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="extract/mask-001")
        a = await call(c, "fw_rootfs_audit", case_id=sd_case.id, rootfs_dir="extract/mask-001", sd_surface=True)
    for res in (r, a):
        assert res["ok"], res
        blob = json.dumps(res, ensure_ascii=False) + (sd_case.dir / res["result_path"]).read_text(encoding="utf-8")
        assert not [x for x in secrets if x in blob]
    # 그 필드들이 실제로 결과에 있었는지 확인 (시험이 헛돌지 않게)
    full = json.loads((sd_case.dir / r["result_path"]).read_text(encoding="utf-8"))
    assert any("psk=Hu" in (e.get("expanded") or "") for x in full["checks"] for e in x["evidence"])
    assert any(o.startswith("password=Hu") for m in full["mount_points"] for mc in m["mount_commands"] for o in mc["options"])
    assert any(h["kind"] == "mdev" and "--password=Hu" in (h["command"] or "") for h in full["hotplug_handlers"])
    af = json.loads((sd_case.dir / a["result_path"]).read_text(encoding="utf-8"))
    assert any("password=Hu" in (m.get("command") or "") for m in af["mounts"]) and any(s["service"] == "telnetd" for s in af["services"])


async def test_fw_sd_surface_validation_and_partial_inputs(sd_case):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        neither = await call(c, "fw_sd_surface", case_id=sd_case.id)
        assert "_error" in neither and "validation_failed" in neither["_error"]
        blank = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="  ", image_path="")
        assert "_error" in blank and "validation_failed" in blank["_error"]
        notdir = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="dumps/flash.bin")
        assert "_error" in notdir and "디렉터리" in notdir["_error"]
        isdir = await call(c, "fw_sd_surface", case_id=sd_case.id, image_path="extract/rootfs-001")
        assert "_error" in isdir
        img = await call(c, "fw_sd_surface", case_id=sd_case.id, image_path="dumps/flash.bin")
        root = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="extract/plain-001")
    st = {x["id"]: x for x in img["checks"]}
    assert img["ok"] and st["SD-02"]["status"] == "found" and st["SD-03"]["status"] == "found" and img["input"]["rootfs_dir"] is None
    assert all(st[i]["status"] == "unknown" for i in ("SD-01", "SD-04", "SD-05", "SD-06", "SD-08", "SD-09"))
    assert any("rootfs_dir" in s for s in img["next_steps"])
    rt_ = {x["id"]: x for x in root["checks"]}
    assert root["ok"] and rt_["SD-02"]["status"] == "unknown" and rt_["SD-03"]["status"] == "unknown" and root["counts"]["found"] == 0
    assert any("image_path" in s for s in root["next_steps"]) and "uboot" not in root


async def test_fw_rootfs_audit_sd_surface_flag(sd_case):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        plain = await call(c, "fw_rootfs_audit", case_id=sd_case.id, rootfs_dir="extract/plain-001")
        with_sd = await call(c, "fw_rootfs_audit", case_id=sd_case.id, rootfs_dir="extract/rootfs-001", sd_surface=True, max_results=5)
        plain_sd = await call(c, "fw_rootfs_audit", case_id=sd_case.id, rootfs_dir="extract/plain-001", sd_surface=True)
    # 기본값(false)이면 응답·결과 파일·params 어디에도 sd_surface 가 없다
    assert plain["ok"] and "sd_surface" not in plain
    pf = json.loads((sd_case.dir / plain["result_path"]).read_text(encoding="utf-8"))
    assert "sd_surface" not in pf and "sd_surface" not in pf["params"]
    assert with_sd["ok"] and with_sd["sd_surface"]["counts"]["found"] >= 7
    assert {x["id"]: x["status"] for x in with_sd["sd_surface"]["checks"]}["SD-01"] == "found"
    wf = json.loads((sd_case.dir / with_sd["result_path"]).read_text(encoding="utf-8"))
    assert wf["params"]["sd_surface"] is True and wf["sd_surface"]["inputs_analyzed"] == {"rootfs": True, "image": False}
    assert any("fw_sd_surface" in s for s in with_sd["next_steps"])
    # SD 없는 펌웨어 + rootfs 만: U-Boot 쪽 unknown, 나머지 found 없음
    ps = {x["id"]: x["status"] for x in plain_sd["sd_surface"]["checks"]}
    assert ps["SD-02"] == "unknown" and ps["SD-03"] == "unknown" and "found" not in ps.values()
    # 기본 감사에도 SD 마운트 지점의 카드 스크립트·YAML sd-* 히트가 뜬다 (빈틈 수정)
    ids = {i["id"] for i in with_sd["items"]} | {i["id"] for i in wf["items"]}
    assert {"sd-autorun-known-names", "sd-log-to-card"} <= ids


async def test_fw_uboot_env_sd_boot(sd_case):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        u = await call(c, "fw_uboot_env", case_id=sd_case.id, path="dumps/flash.bin")
        p = await call(c, "fw_uboot_env", case_id=sd_case.id, path="dumps/plain.bin")
    assert u["ok"] and u["sd_boot_summary"]["verify_off"] == 1 and u["sd_boot_summary"]["env_persistent"] is True
    e0 = u["envs"][0]["sd_boot"]
    assert e0["verify"] == "n" and e0["verify_off"] and e0["boot_script"] and e0["mmc_first"] and e0["persistent_writable"] is True
    assert e0["signal_vars"] == ["sdboot"] and "signals" not in e0
    d0 = u["embedded_default_envs"][0]["sd_boot"]
    assert d0["persistent_writable"] is None and d0["mmc_boot"] and d0["mmc_first"] is True
    assert any("fw_sd_surface" in s for s in u["next_steps"])
    full = json.loads((sd_case.dir / u["result_path"]).read_text(encoding="utf-8"))
    assert full["envs"][0]["sd_boot"]["signals"][0]["var"] == "sdboot" and full["embedded_default_envs"][0]["sd_boot"]["storage"] == "embedded-default"
    assert full["sd_boot_summary"] == u["sd_boot_summary"]
    # SD 신호가 없는 env: sd_boot 는 있지만 mmc 없음, fw_sd_surface 안내 없음
    assert p["ok"] and p["envs"][0]["sd_boot"]["mmc_boot"] is False and not any("fw_sd_surface" in s for s in p["next_steps"])


async def test_fw_uboot_env_verify_off_alone_is_not_an_sd_signal(sd_case):
    """4차 #18: mmc 가 전혀 없는 SPI-NOR env 에 verify=n 만 있으면 SD 안내(fw_sd_surface)가 아니라 일반 검증 끔 안내만 준다."""
    from fwtriage_mcp.server import server

    from fwtriage.sd_builders import build_sd_flash

    (sd_case.dir / "dumps" / "nor_verify_n.bin").write_bytes(build_sd_flash(env={
        "bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x300000; bootm 0x82000000", "bootdelay": "1", "verify": "n"}))
    async with Client(server) as c:
        r = await call(c, "fw_uboot_env", case_id=sd_case.id, path="dumps/nor_verify_n.bin")
    assert r["ok"] and r["sd_boot_summary"]["verify_off"] >= 1 and r["sd_boot_summary"]["envs_with_mmc_boot"] == 0
    assert not any("fw_sd_surface" in s for s in r["next_steps"])
    assert any("verify" in s and "검증" in s for s in r["next_steps"])


async def test_fw_sd_surface_short_budget_and_background(sd_case):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        quick = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="extract/rootfs-001", image_path="dumps/flash.bin", max_seconds=1)
        assert quick["ok"], quick
        job = await call(c, "fw_sd_surface", case_id=sd_case.id, rootfs_dir="extract/rootfs-001", background=True)
        assert job["ok"] and job["background"] and job["job_id"].startswith("job-")
        st = await call(c, "fwtriage_job_status", job_id=job["job_id"], wait_seconds=30)
    assert st["status"] == "succeeded", st
    assert st["result"]["tool"] == "fw_sd_surface" and st["result"]["result_path"].startswith("analysis/sd-surface-")


async def test_fw_sd_surface_listed_with_local_write_annotation(workspace):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    t = tools["fw_sd_surface"]
    assert t.annotations.read_only_hint is False and not t.annotations.destructive_hint and t.annotations.open_world_hint is False
    props = t.input_schema["properties"]
    assert {"case_id", "rootfs_dir", "image_path", "max_results", "max_seconds"} <= set(props)
    assert "sd_surface" in tools["fw_rootfs_audit"].input_schema["properties"]
    assert re.search("[가-힣]", t.description) and "SD-01" in t.description
