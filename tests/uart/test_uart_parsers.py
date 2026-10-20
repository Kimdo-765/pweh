"""uart-mcp 파서 단위 테스트 (시뮬레이터 녹화 로그 + 레퍼런스 문서의 형식 예)."""

from __future__ import annotations

import base64
import re
import zlib
from pathlib import Path

import pytest

from pweh.formats import format_md_b
from uart_mcp import parsers as P
from uart_mcp.profile import build_profile

REC = Path(__file__).resolve().parents[1] / "mock-targets" / "recorded"


def _session(profile: str) -> str:
    return (REC / f"{profile}-uboot-session.log").read_bytes().decode("utf-8", "replace")


def _between(text: str, cmd: str, prompt: str) -> str:
    """녹화 세션에서 `prompt + cmd` 다음부터 다음 프롬프트 전까지의 출력."""
    t = text.replace("\r\n", "\n")
    i = t.index(prompt + cmd + "\n") + len(prompt + cmd + "\n")
    j = t.index(prompt, i)
    return t[i:j]


PROMPTS = {"hisilicon-like": "hisilicon # ", "ingenic-like": "isvp_t31# ", "hisilicon-legacy": "hisilicon # "}


@pytest.mark.parametrize("profile", list(PROMPTS))
def test_printenv_from_recorded(profile):
    out = _between(_session(profile), "printenv", PROMPTS[profile])
    r = P.parse_printenv(out)
    assert r["complete"] is True
    env = r["env"]
    assert "bootcmd" in env and "bootargs" in env and env["baudrate"] == "115200"
    assert r["size_total"] in (65532, 262140)
    mtd = P.env_mtdparts(env)
    parts = P.partitions_from_mtdparts(mtd, 16 * 1024 * 1024)
    assert parts[0]["name"] == "boot" and parts[0]["offset"] == 0
    assert sum(p["size"] for p in parts) == 16 * 1024 * 1024
    loads = P.env_load_addresses(env)
    assert loads, env["bootcmd"]
    if profile == "hisilicon-legacy":
        assert r["order"][0] == "bootargs"  # 2010.06: 저장 순서
        assert env["bootfile"] == '"uImage"'


def test_printenv_multiline_value_and_errors():
    text = "a=1\nlong=first part\nsecond part\nb=2\n## Error: \"x\" not defined\n\nEnvironment size: 30/65532 bytes\n"
    r = P.parse_printenv(text)
    assert r["env"]["long"] == "first part\nsecond part"
    assert r["env"]["b"] == "2" and r["errors"] and r["complete"]
    assert P.parse_printenv("a=1\nb=2\n")["complete"] is False


@pytest.mark.parametrize("profile", list(PROMPTS))
def test_bdinfo_version_from_recorded(profile):
    text = _session(profile)
    bd = P.parse_bdinfo(_between(text, "bdinfo", PROMPTS[profile]))
    ver = P.parse_version(_between(text, "version", PROMPTS[profile]))
    assert ver["version"].startswith("U-Boot 20")
    if profile == "hisilicon-like":
        assert bd["dram_start"] == 0x40000000 and bd["dram_size"] == 0x04000000
        assert bd["relocaddr"] == 0x43F9E000 and bd["sp_start"] == 0x43F5DED0
        assert ver["base_version"] == "2016.11" and ver["tag"] == "hi3516ev300"
        assert len(ver["toolchain"]) == 2
    elif profile == "ingenic-like":
        assert bd["dram_start"] == 0x80000000 and bd["dram_size"] == 0x04000000
        assert "relocaddr" not in bd and bd["boot_params"] == 0x81F6BF60
    else:
        assert bd["dram_start"] == 0x80000000 and "relocaddr" not in bd
        assert ver["base_version"] == "2010.06"


def test_help_and_sf_probe_variants():
    help_text = "?       - alias for 'help'\nbase    - print or set address offset\nsf      - SPI flash sub-system\ncrc32   - checksum calculation\n"
    h = P.parse_help(help_text)
    assert h["commands"] == ["?", "base", "crc32", "sf"]
    a = P.parse_sf_probe("SF: Detected W25Q128(B/F)V with page size 256 Bytes, erase size 64 KiB, total 16 MiB\n")
    assert a["ok"] and a["model"] == "W25Q128(B/F)V" and a["size_bytes"] == 16 * 1024 * 1024
    b = P.parse_sf_probe("the manufacturer 68\nSF: Detected BY25Q128AS\n\n--->probe spend 4 ms\n")
    assert b["ok"] and b["model"] == "BY25Q128AS" and b.get("size_bytes") is None and b["manufacturer_id"] == "68"
    c = P.parse_sf_probe("16384 KiB hi_fmc at 0:0 is now current device\n")
    assert c["ok"] and c["size_bytes"] == 16 * 1024 * 1024 and c["device"] == "hi_fmc"
    d = P.parse_sf_probe("SF: Detected gd25q64, manufacturer id: c8\n")
    assert d["model"] == "gd25q64" and d["manufacturer_id"] == "c8"
    e = P.parse_sf_probe("Failed to initialize SPI flash at 0:0\n")
    assert not e["ok"] and e["errors"]


def test_print_size():
    assert P.parse_print_size("16 MiB") == 16 << 20
    assert P.parse_print_size("64 KiB") == 64 << 10
    assert P.parse_print_size("256 Bytes") == 256
    assert P.parse_print_size("16MB") == 16 << 20
    assert P.parse_print_size("64K") == 64 << 10
    assert P.parse_print_size("1.5 MiB") == 3 << 19
    assert P.parse_print_size("garbage") is None


def test_crc32_case_insensitive():
    up = P.parse_crc32("CRC32 for 42000000 ... 4200ffff ==> bf0ad0d4\n")
    lo = P.parse_crc32("crc32 for 42000000 ... 4200ffff ==> bf0ad0d4")
    assert up == lo == {"start": 0x42000000, "end": 0x4200FFFF, "crc32": 0xBF0AD0D4}
    assert P.parse_crc32("Unknown command 'crc32' - try 'help'") is None


def test_md_b_parse_and_corruption():
    data = bytes(range(256)) * 2
    text = format_md_b(0x42000000, data).replace("\n", "\r\n")
    got, problems = P.parse_md_b(text, 0x42000000, len(data))
    assert got == data and problems == []
    lines = text.split("\r\n")
    lines[5] = lines[5].replace(lines[5][10:12], "zz", 1)
    got, problems = P.parse_md_b("\r\n".join(lines), 0x42000000, len(data))
    assert problems and len(got) < len(data)
    # 2010.06 형식 (마지막 짧은 줄 패딩 없음)
    short = "82000000: 00 11 22    .\"\n"
    got, problems = P.parse_md_b(short, 0x82000000, 3)
    assert got == b"\x00\x11\x22" and not problems


def _bb_hexdump(data: bytes, squeeze: bool = True) -> str:
    """BusyBox dump.c 의 -C 출력 흉내 (시뮬레이터 구현 사용)."""
    from pweh.mocktarget.fmt import hexdump_canonical

    return hexdump_canonical(data, start=0, squeeze=squeeze)


def test_hexdump_c_squeeze_and_quirk():
    data = b"\xff" * 4096 + bytes(range(256)) + b"\x00" * 100
    got, problems = P.parse_hexdump_c(_bb_hexdump(data), len(data))
    assert got == data and not problems
    got, problems = P.parse_hexdump_c(_bb_hexdump(data, squeeze=False), len(data))
    assert got == data and not problems
    # BusyBox 버그: 마지막 짧은 블록이 앞 블록의 앞부분과 같으면 '*' 로 접히고 끝 주소가 블록 시작이 된다
    quirk = b"A" * 48 + b"A" * 5
    out = _bb_hexdump(quirk)
    got, problems = P.parse_hexdump_c(out, len(quirk))
    assert got == quirk and not problems, (out, problems)
    # 잘린 출력
    got, problems = P.parse_hexdump_c("00000000  41 42  |AB|\n", 2)
    assert problems  # 끝 주소 없음
    bad = "00000000  41 4g 43  |A?C|\n00000003\n"
    assert P.parse_hexdump_c(bad, 3)[1]


def test_base64_parse():
    data = bytes(range(200)) * 3
    enc = base64.encodebytes(data).decode().replace("\n", "\r\n")  # 76자 줄
    got, problems = P.parse_base64(enc, len(data))
    assert got == data and not problems
    lines = enc.split("\r\n")
    lines.insert(2, "random: crng init done")
    assert P.parse_base64("\r\n".join(lines), len(data))[1]
    lines = enc.split("\r\n")
    lines[1] = lines[1][:-1]
    assert P.parse_base64("\r\n".join(lines), len(data))[1]


def test_linux_parsers():
    mtd = 'dev:    size   erasesize  name\nmtd0: 00040000 00010000 "boot"\nmtd1: 00010000 00010000 "env"\n'
    rows = P.proc_mtd(mtd)
    assert rows[1]["dev"] == "mtd1" and rows[1]["size"] == 0x10000 and rows[1]["offset_estimate"] == 0x40000
    ps = "  PID USER       VSZ STAT COMMAND\n    1 root      1600 S    init\n  533 root      2448 S    /usr/sbin/httpd -p 80 -h /var/www\n"
    procs = P.parse_ps(ps)
    assert procs[1]["pid"] == 533 and procs[1]["command"] == "/usr/sbin/httpd -p 80 -h /var/www"
    ns = ("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       \n"
          "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      \n"
          "udp        0      0 0.0.0.0:3702            0.0.0.0:*                           \n")
    lst = P.parse_netstat(ns)
    assert {(x["proto"], x["port"]) for x in lst} == {("tcp", 80), ("udp", 3702)}
    mounts = P.parse_mounts("/dev/root / squashfs ro,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n")
    assert mounts[0]["type"] == "squashfs" and mounts[1]["rw"] is True
    mounts2 = P.parse_mounts("/dev/mtdblock4 on /app type squashfs (ro,relatime)\n")
    assert mounts2[0]["mountpoint"] == "/app" and mounts2[0]["rw"] is False
    u = P.parse_uname("Linux (none) 4.9.37 #1 Mon Mar 23 15:03:32 CST 2020 armv7l GNU/Linux\n")
    assert u["release"] == "4.9.37" and u["machine"] == "armv7l"
    assert P.parse_id("uid=0(root) gid=0(root) groups=0(root)") == {"uid": 0, "user": "root", "gid": 0, "group": "root"}
    bb = P.parse_busybox_list("BusyBox v1.26.2 (2020-03-23) multi-call binary.\n\nCurrently defined functions:\n\t[, [[, ash, base64,\n\tcat, dd\n\n")
    assert bb["version"].startswith("BusyBox v1.26.2") and "base64" in bb["applets"] and "dd" in bb["applets"]
    assert P.parse_md5sum("89cc71671db53c315b9345d11ce21018  -\n") == "89cc71671db53c315b9345d11ce21018"
    assert P.is_not_found("-sh: base64: not found\n", "base64")
    cpu = P.parse_cpuinfo("processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nHardware\t: Generic DT based system\n")
    assert cpu["model"].startswith("ARMv7") and cpu["processors"] == 1


def test_propose_safe_ram_dialects():
    his = P.propose_safe_ram({"dram_start": 0x40000000, "dram_size": 0x4000000, "relocaddr": 0x43F9E000, "sp_start": 0x43F5DED0,
                              "irq_sp": 0x43F5DEE0, "boot_params": 0x40000100},
                             {"bootcmd": "sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000"}, {})
    assert his["safe_ram_addr"] == "0x42000000" and his["confidence"] == "high"
    assert int(his["ram_window"]["end"], 16) == 0x43F5DED0 - P.STACK_MARGIN
    # Ingenic: relocaddr 없음, boot_params 가 위쪽(U-Boot 영역) — 부팅 로그의 스택 포인터가 있으면 그것을 상한으로
    ing = P.propose_safe_ram({"dram_start": 0x80000000, "dram_size": 0x4000000, "boot_params": 0x81F6BF60},
                             {"bootcmd": "sf probe;sf read 0x80600000 0x50000 0x200000; bootm 0x80600000"},
                             {"sp_addr": "81f6bf48", "malloc_addr": "81f8c000"})
    assert ing["safe_ram_addr"] == "0x80600000"
    assert int(ing["ram_window"]["end"], 16) == 0x81F6BF48 - P.STACK_MARGIN
    # U-Boot 영역 정보가 없으면 DRAM 위쪽 절반을 피하되, 벤더 bootcmd 적재 영역(sf read 주소+길이)은 증거로 쓴다
    leg = P.propose_safe_ram({"dram_start": 0x80000000, "dram_size": 0x4000000, "boot_params": 0x80000100},
                             {"bootcmd": "sf probe 0;sf read 0x82000000 0xc0000 0x300000;bootm 0x82000000"}, {})
    assert leg["safe_ram_addr"] == "0x82000000" and leg["confidence"] == "low"
    assert int(leg["ram_window"]["end"], 16) == 0x82300000
    noenv = P.propose_safe_ram({"dram_start": 0x80000000, "dram_size": 0x4000000}, {}, {})
    assert noenv["safe_ram_addr"] == "0x80600000" and int(noenv["ram_window"]["end"], 16) == 0x82000000
    assert P.propose_safe_ram({}, {}, {})["safe_ram_addr"] is None


@pytest.mark.parametrize("profile,kernel", [("hisilicon-like", "4.9.37"), ("ingenic-like", "3.10.14"), ("hisilicon-legacy", "3.4.35")])
def test_summarize_boot_log(profile, kernel):
    text = (REC / f"{profile}-boot.log").read_bytes().decode("utf-8", "replace")
    prof = build_profile("generic-ipcam", {})
    s = P.summarize_boot_text(text, prof)
    assert s["kernel_version"].startswith(kernel)
    assert s["uboot_version"].startswith("U-Boot 20")
    assert s["autoboot_message"].startswith("Hit any key to stop autoboot")
    assert s["bootdelay"] == (2 if profile == "hisilicon-like" else 1)
    assert s["autoboot_message"].rstrip().endswith(str(s["bootdelay"]))
    assert s["mtdparts"] and len(s["partitions"]) >= 4
    assert "kernel" in s["stages"] and "userspace" in s["stages"]
    assert s["console"].startswith("tty")


SD_BOOT_LOG = """[    2.345678] mmc0: new high speed SDHC card at address aaaa
[    2.350000] mmcblk0: mmc0:aaaa SC16G 14.8 GiB
[    2.351000]  mmcblk0: p1
[    3.100000] FAT-fs (mmcblk0p1): Volume was not properly unmounted. Some data may be corrupt. Please run fsck.
mount /dev/mmcblk0p1 /mnt/sd ok
sd card insert, start check update
found /mnt/sd/autorun.sh
[    5.000000] mmc1: new SDIO card at address 0001
[    5.100000] mmc2: new high speed MMC card at address 0001
[    5.200000] mmcblk2boot0: mmc2:0001 8GTF4R partition 1 4.00 MiB
"""

UBOOT_MMC_LOG = """MMC:   msc: 0
switch to partitions #0, OK
mmc0 is current device
reading boot.scr
** Unable to read file boot.scr **
Card did not respond to voltage select!
"""


def test_sd_events_linux_card_lines():
    r = P.sd_events(P._lines(SD_BOOT_LOG))
    kinds = [(e["line"], e["kind"]) for e in r["events"]]
    assert kinds == [(1, "card-detected"), (2, "block-device"), (3, "partition"), (4, "fs-error"), (5, "fs-mount"), (6, "update"), (7, "script")]
    assert r["events"][3]["also"] == ["fs-mount"] and r["events"][5]["also"] == ["card-detected"]
    sm = r["summary"]
    assert sm["card_detected"] is True and sm["card_absent"] is False
    # SDIO(Wi-Fi 모듈)·eMMC 줄은 카드 이벤트가 아니다 — counts 에만 남는다
    assert sm["counts"]["sdio"] == 1 and sm["counts"]["emmc"] == 2 and sm["events_total"] == 7
    assert sm["devices"] == ["mmcblk0", "mmcblk0p1"] and sm["filesystems"] == [{"device": "mmcblk0p1", "fs": "fat"}]
    assert sm["truncated"] is False


def test_sd_events_uboot_mmc_and_absent():
    r = P.sd_events(P._lines(UBOOT_MMC_LOG))
    assert [e["kind"] for e in r["events"]] == ["uboot-mmc", "uboot-mmc", "uboot-script", "uboot-script", "card-absent"]
    assert r["events"][0]["line"] == 2, "U-Boot 의 'MMC: msc: 0'(컨트롤러 목록)은 이벤트가 아니다"
    assert r["summary"]["card_absent"] is True and r["summary"]["card_detected"] is False


def test_sd_events_cap_and_long_lines():
    lines = [f"sd card status {i}" for i in range(100)] + ["x" * 5000 + " sd card insert"]
    r = P.sd_events(lines)
    assert len(r["events"]) == P.SD_EVENT_MAX and r["summary"]["events_total"] == 100 and r["summary"]["truncated"]
    assert all(e["kind"] == "card-other" for e in r["events"])
    assert r["summary"]["long_lines_skipped"] == 1, "분류하지 않은 긴 줄은 센다"
    assert P.sd_events(["sd card inserted"])["summary"]["long_lines_skipped"] == 0
    long = P.sd_events(["sd card inserted " + "y" * 500])
    assert long["events"][0]["text"].endswith("…") and len(long["events"][0]["text"]) == P.SD_EVENT_TEXT_MAX + 1


@pytest.mark.parametrize("name", ["hisilicon-like-boot.log", "ingenic-like-boot.log", "hisilicon-legacy-boot.log"])
def test_sd_events_no_false_positive_on_recorded_boot(name):
    text = (REC / name).read_bytes().decode("utf-8", "replace")
    s = P.summarize_boot_text(text, build_profile("generic-ipcam", {}))
    assert s["sd_events"] == [] and s["sd_summary"]["counts"] == {}


@pytest.mark.parametrize("line", [
    "No SD card found", "SD card not present", "sd card not detected, skip record", "TF card not found!",
    "[sdcard] no sdcard, sd card not exist", "MMC: no card present", "Card did not respond to voltage select!",
])
def test_sd_events_card_absent_is_not_detected(line):
    r = P.sd_events([line])
    assert P.classify_sd_line(line) == ["card-absent"]
    assert r["summary"]["card_detected"] is False and r["summary"]["card_absent"] is True


@pytest.mark.parametrize("line", [
    "[    0.912000] sdcard detect gpio 51, active low", "jzmmc_v1.2: tf card detect pin = PB27", "SD card insert detect irq registered",
])
def test_sd_events_card_detect_pin_config_is_not_an_event(line):
    assert P.classify_sd_line(line) == ["card-other"]
    assert P.sd_events([line])["summary"]["card_detected"] is False


def test_sd_events_emmc_host_block_lines_are_not_card_events():
    log = [
        "U-Boot 2017.09", "Loading Environment from MMC... OK", "Booting from eMMC",
        "[    1.204512] mmc0: new HS200 MMC card at address 0001",
        "[    1.205301] mmcblk0: mmc0:0001 8GTF4R 7.28 GiB",
        "[    1.207210] mmcblk0: p1 p2 p3 p4 p5 p6",
        "[    2.880112] EXT4-fs (mmcblk0p6): mounted filesystem with ordered data mode. Opts: (null)",
        "[    3.100000] OTA: auto upgrade check: no new firmware on server",
        # SD 카드가 따로 있으면(mmc1) 그 장치 줄은 후보로 남는다
        "[    4.000000] mmc1: new high speed SDHC card at address aaaa",
        "[    4.000100] mmcblk1: mmc1:aaaa SC16G 14.8 GiB",
        "[    4.000200]  mmcblk1: p1",
    ]
    r = P.sd_events(log)
    kinds = [(e["line"], e["kind"]) for e in r["events"]]
    assert kinds == [(9, "card-detected"), (10, "block-device"), (11, "partition")], kinds
    assert r["summary"]["counts"]["emmc"] == 5 and r["summary"]["devices"] == ["mmcblk1"]
    assert not any(r["summary"]["counts"].get(k) for k in P.SD_NOTE_KINDS), "eMMC 환경 변수·OTA 줄로 sd_note 를 내지 않는다"


def test_sd_events_paths_and_update_need_card_context():
    assert P.classify_sd_line("mount -t nfs 10.0.0.1:/srv /mnt/tftpboot") == []
    assert P.classify_sd_line("auto upgrade: downloading firmware from cloud") == []
    assert P.classify_sd_line("auto update from sd card start")[0] == "update"
    assert P.classify_sd_line("upgrade file /mnt/sd/update.bin found")[0] == "update"
    assert P.classify_sd_line("run /mnt/sdcard/hook.sh")[0] == "script"
    assert set(P.SD_NOTE_KINDS) == {"update", "script", "uboot-script"}


def test_sd_events_overlong_line_is_skipped_cheaply():
    import time

    line = "sd card " + "x" * (P.SD_LINE_MAX + 10)
    t0 = time.monotonic()
    assert P.classify_sd_line(line) == []
    worst = "sd card " + "not " * 1000 + "present " * 50
    P.classify_sd_line(worst[: P.SD_LINE_MAX])
    assert time.monotonic() - t0 < 1.0
