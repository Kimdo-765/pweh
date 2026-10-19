"""안전 분류기 테스트 — 정상 명령 오탐 최소화 + 알려진 우회 경로 차단."""

from __future__ import annotations

from pathlib import Path

import pytest

from pweh.safety import (
    LineAssembler,
    Risk,
    UBootContext,
    classify_console_line,
    classify_linux,
    classify_openocd,
    classify_uboot,
    uboot_setenv_effect,
)

PERSIST = ["/mnt/mtd", "/etc/config"]


@pytest.mark.parametrize(
    "line,risk",
    [
        ("printenv", Risk.INTERACT),
        ("help", Risk.INTERACT),
        ("version", Risk.INTERACT),
        ("md.b 0x82000000 0x100", Risk.INTERACT),
        ("crc32 0x82000000 0x10000", Risk.INTERACT),
        ("sf probe 0", Risk.INTERACT),
        ("sf read 0x82000000 0x0 0x1000000", Risk.INTERACT),
        ("nand read 0x82000000 0x0 0x100000", Risk.INTERACT),
        ("mmc info", Risk.INTERACT),
        ("tftpput 0x82000000 0x1000 dump.bin", Risk.INTERACT),
        ("setenv bootargs mem=64M console=ttyAMA0,115200 init=/bin/sh", Risk.MODIFY),
        ("boot", Risk.MODIFY),
        ("reset", Risk.MODIFY),
        ("saveenv", Risk.DESTRUCTIVE),
        ("env save", Risk.DESTRUCTIVE),
        ("sf erase 0x0 0x10000", Risk.DESTRUCTIVE),
        ("sf write 0x82000000 0x0 0x1000", Risk.DESTRUCTIVE),
        ("sf update 0x82000000 0x0 0x1000", Risk.DESTRUCTIVE),
        ("nand erase.chip", Risk.DESTRUCTIVE),
        ("nand write.raw 0x82000000 0 0x800", Risk.DESTRUCTIVE),
        ("mmc write 0x82000000 0 10", Risk.DESTRUCTIVE),
        ("mw.l 0x12000000 0x1", Risk.DESTRUCTIVE),
        ("cp.b 0x82000000 0x58000000 0x1000", Risk.DESTRUCTIVE),
        ("fuse prog 0 1 0x1", Risk.DESTRUCTIVE),
        ("printenv; saveenv", Risk.DESTRUCTIVE),
        ("version && sf erase 0 1000", Risk.DESTRUCTIVE),
        ("sav", Risk.DESTRUCTIVE),  # 약어 → saveenv
        ("s", Risk.DESTRUCTIVE),  # 모호한 약어 → 최댓값
        ("nan erase 0 100", Risk.DESTRUCTIVE),  # 서브커맨드 명령 약어
        ("sf er 0 100", Risk.DESTRUCTIVE),  # 서브커맨드 약어
        ("source 0x82000000", Risk.DESTRUCTIVE),
        ("vendor_magic_cmd 1 2", Risk.MODIFY),  # 미상 → unknown_risk
    ],
)
def test_uboot_basic(line, risk):
    assert classify_uboot(line).risk == risk, classify_uboot(line)


def test_uboot_run_and_boot_resolution():
    ctx = UBootContext(env={"bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x300000; bootm 0x82000000", "evil": "sf erase 0 0x1000000"})
    assert classify_uboot("boot", ctx=ctx).risk == Risk.MODIFY
    assert classify_uboot("run bootcmd", ctx=ctx).risk == Risk.MODIFY
    c = classify_uboot("run evil", ctx=ctx)
    assert c.risk == Risk.DESTRUCTIVE
    unk = classify_uboot("run mystery", ctx=ctx)
    assert unk.risk == Risk.DESTRUCTIVE and unk.uncertain
    ctx2 = UBootContext(env={"bootcmd": "nand erase.chip"})
    assert classify_uboot("boot", ctx=ctx2).risk == Risk.DESTRUCTIVE
    # 명령 위치 변수
    assert classify_uboot("$evil", ctx=ctx).risk == Risk.DESTRUCTIVE
    assert classify_uboot("${unknownvar} 0 0").risk == Risk.DESTRUCTIVE


def test_uboot_empty_enter_repeats_last():
    ctx = UBootContext(last_command="md.b 0x82000000 0x100")
    assert classify_uboot("", ctx=ctx).risk == Risk.INTERACT
    ctx = UBootContext(last_command="nand erase 0 0x20000")
    c = classify_uboot("", ctx=ctx)
    assert c.risk == Risk.DESTRUCTIVE and "반복" in c.reason


def test_setenv_effect():
    assert uboot_setenv_effect("setenv x 'sf erase 0 100'") == {"x": "sf erase 0 100"}
    assert uboot_setenv_effect("env set bootcmd 'run evil'; env delete foo") == {"bootcmd": "run evil", "foo": None}
    assert uboot_setenv_effect("setenv foo") == {"foo": None}


@pytest.mark.parametrize(
    "line,risk",
    [
        ("cat /proc/mtd", Risk.INTERACT),
        ("ls -la /etc", Risk.INTERACT),
        ("uname -a; cat /proc/cpuinfo", Risk.INTERACT),
        ("dd if=/dev/mtd0 bs=64k | hexdump -C", Risk.INTERACT),
        ("dd if=/dev/mtdblock2 2>/dev/null | base64", Risk.INTERACT),
        ("ps | grep httpd", Risk.INTERACT),
        ("ifconfig", Risk.INTERACT),
        ("ifconfig eth0 192.168.1.10", Risk.MODIFY),
        ("telnetd -l /bin/sh", Risk.MODIFY),
        ("dd if=/dev/mtd0 of=/tmp/a.bin", Risk.MODIFY),
        ("echo 1 > /tmp/x", Risk.MODIFY),
        ("echo 0 > /proc/sys/kernel/printk", Risk.MODIFY),
        ("reboot", Risk.MODIFY),
        ("flash_erase /dev/mtd3 0 0", Risk.DESTRUCTIVE),
        ("/usr/sbin/flash_eraseall /dev/mtd3", Risk.DESTRUCTIVE),
        ("busybox flash_erase /dev/mtd3 0 0", Risk.DESTRUCTIVE),
        ("nandwrite -p /dev/mtd2 /tmp/x", Risk.DESTRUCTIVE),
        ("dd if=/tmp/x of=/dev/mtdblock2", Risk.DESTRUCTIVE),
        ("cat /tmp/x > /dev/mtd2", Risk.DESTRUCTIVE),
        ("cat /tmp/x >> /dev/mtdblock2", Risk.DESTRUCTIVE),
        ("fw_setenv bootdelay 0", Risk.DESTRUCTIVE),
        ("echo x > /mnt/mtd/Config/passwd", Risk.DESTRUCTIVE),
        ("rm -rf /mnt/mtd/Config", Risk.DESTRUCTIVE),
        ("rm -rf /", Risk.DESTRUCTIVE),
        ("rm /tmp/a.bin", Risk.MODIFY),
        ("mtd_debug erase /dev/mtd1 0 65536", Risk.DESTRUCTIVE),
        ("mtd_debug read /dev/mtd1 0 65536 /tmp/x", Risk.INTERACT),
        ("devmem 0x12020000 32 0x1", Risk.DESTRUCTIVE),
        ("devmem 0x12020000", Risk.INTERACT),
        ("himm 0x12020000 0x1", Risk.DESTRUCTIVE),
        ("passwd root", Risk.DESTRUCTIVE),
        ("sed -i s/a/b/ /mnt/mtd/Config/x", Risk.DESTRUCTIVE),
        ("sed s/a/b/ /etc/passwd", Risk.INTERACT),
        ("cp /tmp/evil /mnt/mtd/Config/", Risk.DESTRUCTIVE),
        ("tftp -p -l /tmp/dump.bin -r dump.bin 192.168.1.2", Risk.INTERACT),
        ("tftp -g -l /tmp/x -r x 192.168.1.2", Risk.MODIFY),
        ("weird_vendor_tool --foo", Risk.MODIFY),
    ],
)
def test_linux_basic(line, risk):
    c = classify_linux(line, persistent_paths=PERSIST)
    assert c.risk == risk, c


@pytest.mark.parametrize(
    "line",
    [
        "X=flash_erase; $X /dev/mtd0 0 0",
        "$(echo flash_erase) /dev/mtd0 0 0",
        "`echo flash_erase` /dev/mtd0 0 0",
        "echo Zmxhc2hfZXJhc2UK | base64 -d | sh",
        "sh -c 'flash_erase /dev/mtd0 0 0'",
        "eval flash_erase /dev/mtd0 0 0",
        "sh /tmp/script.sh",
        ". /tmp/script.sh",
        "/usr/sbin/flash_er* /dev/mtd0 0 0",
        "alias x=flash_erase",
        "f() { flash_erase /dev/mtd0 0 0; }",
        "find /mnt -name '*.cfg' -delete",
        "find / -name x | xargs rm",
        "awk 'BEGIN{system(\"flash_erase /dev/mtd0 0 0\")}'",
        "'fla''sh_erase' /dev/mtd0 0 0",
        "fl\\ash_erase /dev/mtd0 0 0",
        "dd if=/tmp/x of=$TARGET",
    ],
)
def test_linux_bypass_attempts_are_destructive(line):
    c = classify_linux(line, persistent_paths=PERSIST)
    assert c.risk == Risk.DESTRUCTIVE, (line, c)


@pytest.mark.parametrize(
    "cmd,risk",
    [
        ("version", Risk.INTERACT),
        ("scan_chain", Risk.INTERACT),
        ("targets", Risk.INTERACT),
        ("reg", Risk.INTERACT),
        ("reg pc", Risk.INTERACT),
        ("mdw 0x20000000 16", Risk.INTERACT),
        ("read_memory 0x0 32 16", Risk.INTERACT),
        ("flash banks", Risk.INTERACT),
        ("flash info 0", Risk.INTERACT),
        ("capture \"mdw 0 4\"", Risk.INTERACT),
        ("halt", Risk.MODIFY),
        ("reset halt", Risk.MODIFY),
        ("reg pc 0x0", Risk.MODIFY),
        ("mww 0x40021000 0x1", Risk.DESTRUCTIVE),
        ("write_memory 0x20000000 32 {1 2}", Risk.DESTRUCTIVE),
        ("flash write_image erase fw.bin 0x08000000", Risk.DESTRUCTIVE),
        ("flash erase_sector 0 0 last", Risk.DESTRUCTIVE),
        ("flash read_bank 0 /etc/passwd 0 4", Risk.DESTRUCTIVE),
        ("program fw.elf verify reset", Risk.DESTRUCTIVE),
        ("stm32f1x unlock 0", Risk.DESTRUCTIVE),
        ("stm32f1x mass_erase 0", Risk.DESTRUCTIVE),
        ("dump_image /tmp/x 0 4", Risk.DESTRUCTIVE),
        ("eval mww 0 0", Risk.DESTRUCTIVE),
        ("if {1} {flash erase_sector 0 0 last}", Risk.DESTRUCTIVE),
        ("set x [mdw 0 1]", Risk.INTERACT),
        ("$cmd 0 0", Risk.DESTRUCTIVE),
        ("stm32f1x.cpu mww 0 0", Risk.DESTRUCTIVE),
        ("source evil.tcl", Risk.DESTRUCTIVE),
    ],
)
def test_openocd(cmd, risk):
    c = classify_openocd(cmd)
    assert c.risk == risk, (cmd, c)


def test_line_assembler_split_and_editing():
    la = LineAssembler()
    assert la.feed("sf er") == []
    lines = la.feed("ase 0 100\r")
    assert len(lines) == 1 and lines[0].text == "sf erase 0 100" and not lines[0].uncertain
    # backspace 편집
    lines = la.feed("printenX\x08v\n")
    assert lines[0].text == "printenv"
    # Ctrl-C 로 줄 버림
    lines = la.feed("sf erase\x03version\r")
    assert lines[0].text == "version"
    # CRLF 는 한 줄
    lines = la.feed("help\r\n")
    assert [l.text for l in lines] == ["help"]
    # 방향키(히스토리) → uncertain
    lines = la.feed("\x1b[A\r")
    assert lines[0].uncertain
    # 탭 → uncertain
    lines = la.feed("sf er\t0 100\r")
    assert lines[0].uncertain
    # Ctrl-W 단어 삭제
    lines = la.feed("sf erase\x17probe 0\r")
    assert lines[0].text == "sf probe 0"


def test_console_unknown_context_takes_max():
    c = classify_console_line("saveenv", "unknown")
    assert c.risk == Risk.DESTRUCTIVE
    c = classify_console_line("root", "login")
    assert c.risk == Risk.INTERACT
    c = classify_console_line("cat /proc/mtd", "linux-shell")
    assert c.risk == Risk.INTERACT


@pytest.mark.parametrize(
    "cmd,risk",
    [
        ("flash mdw 0x08000000 4", Risk.INTERACT),
        ("flash read_memory 0x08000000 32 4", Risk.INTERACT),
        ("adapter speed", Risk.INTERACT),
        ("transport select", Risk.INTERACT),
        ("adapter speed 1000", Risk.MODIFY),
        ("transport select swd", Risk.MODIFY),
    ],
)
def test_openocd_readonly_queries(cmd, risk):
    assert classify_openocd(cmd).risk == risk, classify_openocd(cmd)


# ---------------------------------------------------------------------------
# OpenOCD: 플래시 프로그래밍 proc (업스트림 program, Espressif 포크 program_esp*) 과 Espressif/Xtensa 명령
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd,rule",
    [
        # Espressif 포크 tcl/target/esp_common.cfg: reset init → flash write_image erase → verify/reset/shutdown
        ("program_esp build/app.bin 0x10000 verify reset exit", "openocd.flash.program_esp"),
        ("program_esp_bins build flasher_args.json reset", "openocd.flash.program_esp"),
        ("program_esp {fw.bin} 0x0 encrypt force", "openocd.flash.program_esp"),
        ("ocd_program_esp fw.bin 0x0", "openocd.flash.program_esp"),
        ("program_esp32 fw.bin 0x1000 verify", "openocd.flash.program_esp"),  # 예전 포크 이름
        ("esp32s3.cpu0 program_esp fw.bin 0x0", "openocd.flash.program_esp"),
        ("if {1} {program_esp fw.bin 0x0}", "openocd.flash.program_esp"),
        ("program_flash fw.bin", "openocd.flash.program_proc"),  # 그 밖의 program_* proc
        # 업스트림 program (flash/startup.tcl) 도 그대로 DESTRUCTIVE
        ("program fw.elf verify reset exit", "openocd.program"),
        ("program {fw.bin} 0x08000000 preverify verify", "openocd.program"),
        ("ocd_program fw.elf", "openocd.program"),
        ("stm32f1x.cpu program fw.elf", "openocd.program"),
    ],
)
def test_openocd_flash_programming_procs_are_destructive(cmd, rule):
    c = classify_openocd(cmd)
    assert c.risk == Risk.DESTRUCTIVE and c.rule_id == rule, (cmd, c)


@pytest.mark.parametrize(
    "cmd,risk,rule",
    [
        # 호스트 파일/네트워크로 쓰는 트레이스·gcov (gcov 는 타깃 펌웨어가 호스트 경로와 모드를 정한다)
        ("esp gcov", Risk.DESTRUCTIVE, "openocd.esp.gcov"),
        ("esp gcov dump /tmp/prefix", Risk.DESTRUCTIVE, "openocd.esp.gcov"),
        ("esp32s3.cpu0 esp gcov", Risk.DESTRUCTIVE, "openocd.esp.gcov"),
        ("esp apptrace start file://trace.log", Risk.DESTRUCTIVE, "openocd.esp.apptrace"),
        ("esp apptrace start tcp://10.0.0.1:53535", Risk.DESTRUCTIVE, "openocd.esp.apptrace"),
        ("esp apptrace dump file://dump.bin", Risk.DESTRUCTIVE, "openocd.esp.apptrace"),
        ("esp sysview start file://a.svdat file://b.svdat", Risk.DESTRUCTIVE, "openocd.esp.sysview"),
        ("esp sysview_mcore start file://m.svdat", Risk.DESTRUCTIVE, "openocd.esp.sysview_mcore"),
        ("esp apptrace status", Risk.INTERACT, "openocd.esp.apptrace.status"),
        ("esp sysview stop", Risk.MODIFY, "openocd.esp.sysview.stop"),
        # 읽기/비교·설정 (타깃에서 스텁을 돌리는 것은 MODIFY)
        ("esp verify_bank_hash 0 fw.bin 0x1000", Risk.MODIFY, "openocd.esp.verify_bank_hash"),
        ("esp flash_stub_clock_boost on", Risk.MODIFY, "openocd.esp.flash_stub_clock_boost"),
        ("esp compression off", Risk.MODIFY, "openocd.esp.compression"),
        ("esp encrypt_binary yes", Risk.MODIFY, "openocd.esp.encrypt_binary"),
        ("esp appimage_offset 0x10000", Risk.MODIFY, "openocd.esp.appimage_offset"),
        ("esp", Risk.INTERACT, "openocd.esp"),
        ("esp efuse_burn 1", Risk.DESTRUCTIVE, "openocd.esp.efuse_burn"),  # 쓰기/퓨즈 꼴 이름
        ("esp32s3.cpu0 esp write_flash 0 fw.bin", Risk.DESTRUCTIVE, "openocd.esp.write_flash"),
        # Xtensa
        ("xtensa tracedump core0.bin core1.bin", Risk.DESTRUCTIVE, "openocd.xtensa.tracedump"),
        ("esp32s3.cpu0 xtensa exe 0x0020f0", Risk.DESTRUCTIVE, "openocd.xtensa.exe"),
        ("xtensa perfmon_dump", Risk.INTERACT, "openocd.xtensa.perfmon_dump"),
        # ESP32 플래시 전압 스트랩 (잘못 고르면 1.8V 플래시에 3.3V)
        ("esp32 flashbootstrap 3.3", Risk.DESTRUCTIVE, "openocd.esp.flashbootstrap"),
        ("esp32.cpu0 esp32 flashbootstrap 1.8", Risk.DESTRUCTIVE, "openocd.esp.flashbootstrap"),
        ("esp32s3 flashbootstrap none", Risk.DESTRUCTIVE, "openocd.esp.flashbootstrap"),
        # 조회 형태는 스트랩 규칙(INTERACT)과 일반 규칙(알 수 없는 명령 = unknown_command_risk)의 worst — 기본 설정이면 MODIFY
        ("esp32 flashbootstrap", Risk.MODIFY, "openocd.unknown"),
        # semihosting 을 켜는 표준 ESP proc (esp_common.cfg: examine-end 핸들러를 감싸지 않은 채 다시 설치) / 이름에 semihost
        ("configure_event_examine_end", Risk.DESTRUCTIVE, "openocd.esp.semihosting-proc"),
        ("configure_openocd_events", Risk.DESTRUCTIVE, "openocd.esp.semihosting-proc"),
        ("create_esp_target xtensa", Risk.DESTRUCTIVE, "openocd.esp.semihosting-proc"),
        ("esp32s3.cpu0 configure -event reset-init {configure_event_examine_end}", Risk.DESTRUCTIVE, "openocd.esp.semihosting-proc"),
        ("pweh_semihosting_guard check", Risk.DESTRUCTIVE, "openocd.semihosting-proc"),
        ("enable_semihosting_now", Risk.DESTRUCTIVE, "openocd.semihosting-proc"),
    ],
)
def test_openocd_espressif_commands(cmd, risk, rule):
    c = classify_openocd(cmd)
    assert c.risk == risk and c.rule_id == rule, (cmd, c)


def test_openocd_flashbootstrap_query_rule_still_applies_when_unknown_is_interact():
    # 스트랩 조회 규칙이 먼저 들어가므로 unknown_command_risk=interact 이면 동률 → 조회 규칙
    c = classify_openocd("esp32 flashbootstrap", unknown_risk="interact")
    assert c.risk == Risk.INTERACT and c.rule_id == "openocd.esp.flashbootstrap.query", c


_HEAD_CACHE: dict[str, object] = {}


def _head_classify_openocd():
    """수정 전(HEAD) 코어 분류기 — 이 작업이 DESTRUCTIVE 를 낮추지 않았는지 비교한다 (git 이 없으면 skip)."""
    import importlib.util
    import subprocess
    import sys

    if "fn" in _HEAD_CACHE:
        return _HEAD_CACHE["fn"]
    repo = Path(__file__).resolve().parents[2]
    try:
        src = subprocess.run(["git", "-C", str(repo), "show", "HEAD:src/pweh/safety/classifiers.py"], capture_output=True, text=True,
                             timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git HEAD 의 classifiers.py 를 읽을 수 없습니다")
    name = "pweh.safety._head_classifiers"
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    mod.__package__ = "pweh.safety"  # 'from .risk import …'
    sys.modules[name] = mod  # dataclass 가 모듈을 찾는다
    try:
        exec(compile(src, "HEAD:classifiers.py", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(name, None)
    _HEAD_CACHE["fn"] = mod.classify_openocd
    return mod.classify_openocd


# 검토(critical): 'flashbootstrap' 규칙이 두/세 번째 단어만 보고 continue 해서 아래가 INTERACT 로 떨어졌다 (HEAD 는 DESTRUCTIVE)
FLASHBOOTSTRAP_BYPASS = [
    "program flashbootstrap", "flash write_image flashbootstrap", "load_image flashbootstrap", 'program "flashbootstrap"',
    "catch {program flashbootstrap}", "flash write_image erase flashbootstrap", "program esp32 flashbootstrap",
    "load_image esp32 flashbootstrap", "flash esp32 flashbootstrap",
]  # 따옴표 본문(capture "…")은 코어가 원래 보지 않는다 — 서버 guard 테스트(test_openocd_guard.py)가 본다


@pytest.mark.parametrize("cmd", FLASHBOOTSTRAP_BYPASS)
def test_openocd_flashbootstrap_does_not_downgrade_programming(cmd):
    head = _head_classify_openocd()(cmd)
    now = classify_openocd(cmd)
    assert head.risk == Risk.DESTRUCTIVE, (cmd, head)
    assert now.risk == Risk.DESTRUCTIVE and "flashbootstrap" not in now.rule_id, (cmd, now)


@pytest.mark.parametrize(
    "cmd,rule",
    [
        # 호스트 임의 경로 파일 쓰기 (dump_image 와 같은 부류)
        ("profile 1 /home/user/.bashrc", "openocd.profile"),
        ("profile 5 gmon.out 0x80000000 0x80100000", "openocd.profile"),
        ("tpiu0 configure -output /home/user/.profile", "openocd.trace.output"),
        ("tpiu create cam.tpiu -dap cam.dap -ap-num 0 -output :4000", "openocd.trace.output"),
        ("swo create cam.swo -dap cam.dap -output swo.bin", "openocd.trace.output"),
        ("tpiu config internal /tmp/trace.bin uart off 24000000", "openocd.tpiu.config.internal"),
    ],
)
def test_openocd_host_file_writers_are_destructive(cmd, rule):
    c = classify_openocd(cmd)
    assert c.risk == Risk.DESTRUCTIVE and c.rule_id == rule, (cmd, c)


def test_openocd_trace_without_host_output_is_not_destructive():
    assert classify_openocd("tpiu config external uart off 24000000").risk == Risk.MODIFY
    assert classify_openocd("tpiu0 enable").risk == Risk.MODIFY
    assert classify_openocd("echo -output").risk == Risk.INTERACT  # -output 뒤 값이 없으면 해당 없음


def test_openocd_single_core_esp_target_name_is_not_a_command_group():
    # 단일 코어 ESP cfg 의 타깃 이름은 칩 이름(esp32, esp32s3)이다 — 칩 그룹을 하위 명령 표로 만들지 않아 기존 분류(알 수 없는 명령) 그대로
    assert classify_openocd("esp32 read_memory 0x3ff00000 32 1").rule_id == "openocd.unknown"
    assert classify_openocd("esp32s3 smp on").risk == Risk.MODIFY


# ---------------------------------------------------------------------------
# 경로 실행·실행 환경 바꿔치기 (써 넣은 파일을 시스템 명령 이름으로 실행하는 우회)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "/tmp/cat /etc/passwd",          # 이름은 cat 이지만 /tmp 의 파일
        "./ls",
        "/tmp/sh -c ls",                 # 셸 이름 분기보다 경로 검사가 먼저
        "/bin/../tmp/cat x",             # 정규화 후 /tmp
        "./busybox ls",
        "/tmp/nohup cat /etc/passwd",    # 시스템 밖의 래퍼 이름은 믿지 않음
        "nohup /tmp/x &",
        "timeout 5 ./x",
        "cd /tmp && ./x",
        "/mnt/mtd/app/sonia -v",
        "/etc/init.d/S99app restart",
        "exec /tmp/x",
        "alias cat=/tmp/x",
        "cat() { /tmp/x; }",
        "find / -name x -exec /tmp/y {} ;",
    ],
)
def test_exec_outside_system_dirs_is_destructive(line):
    c = classify_linux(line, persistent_paths=PERSIST)
    assert c.risk == Risk.DESTRUCTIVE, c


@pytest.mark.parametrize(
    "line",
    [
        "PATH=/tmp ls",
        "PATH=/tmp:$PATH",
        "PATH+=:/tmp",
        "export PATH=/tmp:$PATH",
        "env PATH=/tmp ls",
        "LD_PRELOAD=/tmp/x.so ls",
        "env -i LD_LIBRARY_PATH=/tmp cat /proc/mtd",
    ],
)
def test_path_and_loader_hijack_is_destructive(line):
    c = classify_linux(line)
    assert c.risk == Risk.DESTRUCTIVE and c.rule_id == "linux.env-hijack", c


@pytest.mark.parametrize(
    "line",
    [
        "cp /tmp/x /bin/cat",
        "ln -s /tmp/x /usr/bin/cat",
        "echo x > /etc/resolv.conf",
        "mount --bind /tmp/x /bin/cat",
        "mount -o ro,bind /a /b",
        "mount -t overlay overlay -o lowerdir=/a /b",
        "chroot /tmp/r /bin/sh",
        "sh -s </tmp/x",
    ],
)
def test_replacing_what_system_commands_run_is_destructive(line):
    assert classify_linux(line).risk == Risk.DESTRUCTIVE


@pytest.mark.parametrize(
    "line,risk",
    [
        ("/bin/cat /etc/passwd", Risk.INTERACT),
        ("/usr/bin/../bin/cat /etc/passwd", Risk.INTERACT),
        ("/bin/busybox cat /proc/mtd", Risk.INTERACT),
        ("busybox cat /proc/mtd", Risk.INTERACT),
        ("/usr/sbin/httpd -v", Risk.MODIFY),
        ("TERM=vt100 ls", Risk.INTERACT),
        ("export TERM=vt100", Risk.MODIFY),
        ("exec ls", Risk.MODIFY),                 # 셸이 ls 로 바뀌므로 최소 MODIFY
        ("exec 3>/dev/null", Risk.MODIFY),
        ("mount -o remount,rw /", Risk.MODIFY),
        ("mount -t tmpfs tmpfs /tmp/x", Risk.MODIFY),
        ("cp /etc/passwd /tmp/", Risk.MODIFY),
        ("dd if=/dev/mtdblock0 bs=64k skip=0 count=1 2>/dev/null | base64", Risk.INTERACT),
        ("dd if=/dev/mtdblock2 bs=4096 skip=3 count=8 2>/dev/null | hexdump -C", Risk.INTERACT),
    ],
)
def test_system_paths_and_ordinary_recon_keep_their_risk(line, risk):
    assert classify_linux(line).risk == risk, classify_linux(line)


@pytest.mark.parametrize(
    "cmd",
    [
        "set q 1\x1c# ; mww 0 0",     # \x1c 는 Jim 의 줄 끝이 아니다
        "catch {\v# } ; mww 0 0",      # \v 도 마찬가지
        "set f 1\x85# ; mww 0 0",
    ],
)
def test_openocd_comment_stripping_splits_only_on_newline(cmd):
    assert classify_openocd(cmd).risk == Risk.DESTRUCTIVE


def test_openocd_real_comments_are_still_ignored():
    assert classify_openocd("# Erase the flash\nversion").risk == Risk.INTERACT
    assert classify_openocd("# comment\r\nmdw 0x0 4").risk == Risk.INTERACT


# ---------------------------------------------------------------------------
# 다른 명령을 실행하는 U-Boot 명령 (env run, time) / 결과를 메모리에 저장하는 체크섬
# ---------------------------------------------------------------------------
_ENV = {"x": "sf erase 0x0 0x10000", "rd": "md.b 0x42000000 0x10", "y": "env run x"}


@pytest.mark.parametrize(
    "line",
    ["env run x", "en r x", "env run nosuch", "run y", "time sf erase 0 100", "ti saveenv", "t saveenv", "time run x"],
)
def test_uboot_command_runners_are_classified_by_what_they_run(line):
    c = classify_uboot(line, ctx=UBootContext(env=dict(_ENV)))
    assert c.risk == Risk.DESTRUCTIVE, c


def test_uboot_runner_repeat_and_reads():
    assert classify_uboot("", ctx=UBootContext(env=dict(_ENV), last_command="env run x")).risk == Risk.DESTRUCTIVE
    assert classify_uboot("env run rd", ctx=UBootContext(env=dict(_ENV))).risk == Risk.MODIFY
    assert classify_uboot("time md.b 0x42000000 0x10").risk == Risk.INTERACT
    assert classify_uboot("tftpboot 0x42000000 a.bin").risk == Risk.INTERACT
    assert classify_uboot("time").risk == Risk.INTERACT


@pytest.mark.parametrize(
    "line,risk",
    [
        ("crc32 0x42000000 0x10000", Risk.INTERACT),
        ("crc32 -v 0x42000000 0x100 0x1234abcd", Risk.INTERACT),
        ("crc32 0x42000000 0x10000 0x43000000", Risk.MODIFY),
        ("md5sum 0x42000000 0x100", Risk.INTERACT),
        ("md5sum 0x42000000 0x100 *0x43000000", Risk.MODIFY),
        ("sha1sum 0x42000000 0x100 sumvar", Risk.MODIFY),
        ("hash sha256 0x42000000 0x100 *0x43000000", Risk.MODIFY),
    ],
)
def test_uboot_checksum_store_forms(line, risk):
    assert classify_uboot(line).risk == risk


@pytest.mark.parametrize(
    "line,risk",
    [
        ("dd if=/dev/watchdog bs=1 count=1", Risk.MODIFY),
        ("cat /dev/watchdog0", Risk.MODIFY),
        ("hexdump -C /dev/mem", Risk.MODIFY),
        ("head -c 16 < /dev/port", Risk.MODIFY),
        ("ls -l /dev/watchdog", Risk.INTERACT),      # 열지 않음
        ("cat /dev/mtdblock0 | md5sum", Risk.INTERACT),
    ],
)
def test_linux_side_effect_device_reads(line, risk):
    assert classify_linux(line).risk == risk, classify_linux(line)


def test_line_assembler_mark_uncertain_public_api():
    a = LineAssembler()
    a.feed("sav")
    assert a.mark_uncertain("기기가 입력 일부를 버렸을 수 있음") is True
    assert a.mark_uncertain("다시") is False
    (line,) = a.feed("eenv\r")
    assert line.uncertain and line.text == "saveenv"
    a.feed("x\x03")  # Ctrl-C 로 비우면 풀림
    (line,) = a.feed("printenv\r")
    assert not line.uncertain


@pytest.mark.parametrize(
    "line,risk",
    [
        ("lsof /dev/watchdog", Risk.INTERACT),                      # stat 만 한다
        ("du /dev/watchdog", Risk.INTERACT),
        ("find /dev/watchdog", Risk.INTERACT),
        ("find /dev/watchdog -exec cat {} ;", Risk.MODIFY),         # -exec 로 열면 부작용
        ("[ -e /dev/mtd0 ]", Risk.INTERACT),                        # '[' 단독은 test
        ("[ -c /dev/watchdog ] && echo yes", Risk.INTERACT),
        ("[abc] x", Risk.DESTRUCTIVE),                              # 명령 위치의 글롭은 그대로 확정 불가
        ("fdisk -l", Risk.INTERACT),
        ("fdisk -l /dev/mmcblk0", Risk.INTERACT),
        ("fdisk /dev/mmcblk0", Risk.DESTRUCTIVE),
    ],
)
def test_linux_false_positive_fixes(line, risk):
    assert classify_linux(line).risk == risk, classify_linux(line)


def test_uboot_question_mark_is_help_and_store_rule_needs_uboot_form():
    assert classify_uboot("?").risk == Risk.INTERACT
    assert classify_uboot("? sf").risk == Risk.INTERACT
    # 리눅스 형태(파일 여러 개)는 U-Boot 저장 형태로 보지 않는다 — 문맥 미확정에서도 INTERACT
    assert classify_console_line("md5sum /dev/mtd1 /dev/mtd2 /dev/mtd3", "unknown").risk == Risk.INTERACT
    assert classify_uboot("md5sum $loadaddr $filesize sumvar").risk == Risk.MODIFY
    assert classify_uboot("hash sha256 0x42000000 0x100 *0x43000000").risk == Risk.MODIFY
    assert classify_uboot("hash sha256 0x42000000 0x100").risk == Risk.INTERACT


# ---------------------------------------------------------------------------
# 현재 디렉터리(cwd)를 반영한 상대 경로 쓰기 (cd /usr/bin && cp /tmp/x md5sum)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line,cwd,risk",
    [
        ("cd /usr/bin && cp /tmp/x md5sum", None, Risk.DESTRUCTIVE),   # 같은 줄의 cd 를 반영
        ("cd /bin; echo x > y", None, Risk.DESTRUCTIVE),
        ("cd /etc; echo x > passwd", None, Risk.DESTRUCTIVE),
        ("cd /dev && cat x > mtd0", None, Risk.DESTRUCTIVE),
        ("cp /tmp/x md5sum", "/usr/bin", Risk.DESTRUCTIVE),            # 세션이 추적한 cwd
        ("echo x > y", "/bin", Risk.DESTRUCTIVE),
        ("cd ../bin && touch z", "/usr/lib", Risk.DESTRUCTIVE),
        ("rm -rf *", "/", Risk.DESTRUCTIVE),
        ("rm -f md5sum", "/usr/bin", Risk.DESTRUCTIVE),
        ("echo x > y", "/tmp", Risk.MODIFY),
        ("cd /tmp && echo x > y", None, Risk.MODIFY),
        ("echo x > y", None, Risk.MODIFY),                              # cwd 를 모르면 그대로 (uncertain)
        ("cd; echo x > y", "/bin", Risk.MODIFY),                        # cd 만 하면 홈 → 모름
        ("ls -la", "/usr/bin", Risk.INTERACT),
        ("cat passwd", "/etc", Risk.INTERACT),
    ],
)
def test_relative_write_targets_follow_cwd(line, cwd, risk):
    c = classify_linux(line, cwd=cwd)
    assert c.risk == risk, c


def test_linux_cwd_effect_tracks_cd():
    from pweh.safety import linux_cwd_effect

    assert linux_cwd_effect("cd /usr/bin", None) == "/usr/bin"
    assert linux_cwd_effect("cd ..", "/usr/bin") == "/usr"
    assert linux_cwd_effect("cd /tmp; cd ../bin", None) == "/bin"
    assert linux_cwd_effect("cd /a && cd b", None) == "/a/b"
    assert linux_cwd_effect("ls -la", "/x") == "/x"
    for line in ("cd", "cd -", "cd ~/a", "cd $HOME", "popd"):
        assert linux_cwd_effect(line, "/tmp") is None, line
    assert linux_cwd_effect("cd rel", None) is None
    assert classify_linux("echo x > y").uncertain is True
