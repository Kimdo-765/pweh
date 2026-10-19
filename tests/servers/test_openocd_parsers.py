"""openocd-mcp 파서/봉투/분류 단위 테스트.

입력 문자열은 가능한 한 실제 OpenOCD 에서 받은 바이트를 그대로 쓴다:
- xPack 0.12.0+dev-02228 실측: ~/pweh-tools/INSTALL_REPORT.md, verify/results/openocd_*.jsonl, 이 작업의 추가 실측
- master / 0.12.0 실측: docs/references/openocd-tcl-rpc.md (remote_bitbang 시뮬레이터)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from openocd_mcp import guard, parsers, process, semihosting, tcl
from pweh.errors import SafetyDenied
from pweh.safety import Risk

# ---------------------------------------------------------------------------
# 실측 응답 (0x1a 제거)
# ---------------------------------------------------------------------------

XPACK_VERSION = "xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)"
XPACK_SCAN = (
    "   TapName             Enabled  IdCode     Expected   IrLen IrCap IrMask\n"
    "-- ------------------- -------- ---------- ---------- ----- ----- ------\n"
    " 0 dummy.cpu              Y     0x00000000 0x00000000     4 0x01  0x01"
)
XPACK_TARGETS = (
    "    TargetName         Type       Endian TapName            State       \n"
    "--  ------------------ ---------- ------ ------------------ ------------\n"
    " 0* dummy.cpu          testee     little dummy.cpu          unknown"
)
MASTER_SCAN2 = (
    "   TapName             Enabled  IdCode     Expected   IrLen IrCap IrMask\n"
    "-- ------------------- -------- ---------- ---------- ----- ----- ------\n"
    " 0 sim.cpu                Y     0x5ba00477 0x5ba00477     4 0x01  0x0f\n"
    " 1 sim.bs                 Y     0x0792603f 0x0792603f     5 0x01  0x03"
)
MASTER_MDW = (
    "0x08000000: 56190527 6f422d55 3220746f 2e363130 28203131 296d6973 02010000 06050403 \n"
    "0x08000020: 0a090807 0e0d0c0b "
)
MASTER_MDB = (
    "0x08000000: 27 05 19 56 55 2d 42 6f 6f 74 20 32 30 31 36 2e 31 31 20 28 73 69 6d 29 00 00 01 02 03 04 05 06 \n"
    "0x08000020: 07 08 09 0a 0b 0c 0d 0e "
)
MASTER_FLASH_INFO = (
    "#0 : faux at 0x08000000, size 0x00040000, buswidth 0, chipwidth 0\n"
    "\t#  0: 0x00000000 (0x10000 64kB) not protected\n"
    "\t#  1: 0x00010000 (0x10000 64kB) not protected\n"
    "\t#  2: 0x00020000 (0x10000 64kB) not protected\n"
    "\t#  3: 0x00030000 (0x10000 64kB) not protected\n"
    "faux flash driver"
)
XPACK_STARTUP_LOG = """xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)
Licensed under GNU GPL v2
For bug reports, read
\thttp://openocd.org/doc/doxygen/bugs.html
Warn : dummy.cpu: nonstandard IR mask
adapter speed: 1000 kHz
Info : clock speed 1000 kHz
Info : JTAG tap: dummy.cpu tap/device found: 0x00000000 (mfg: 0x000 (<invalid>), part: 0x0000, ver: 0x0)
Info : [dummy.cpu] Examination succeed
Info : Listening on port 39453 for tcl connections
Info : telnet server disabled
"""


# ---------------------------------------------------------------------------
# Tcl 리스트 / 봉투
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "frame,expected",
    [
        # xPack 실측 (원시 봉투 list [catch {capture {CMD}} r] $r)
        ("0 {" + XPACK_VERSION + "}", ["0", XPACK_VERSION]),
        ("1 {}", ["1", ""]),
        ('1 {invalid command name "this_command_does_not_exist"}', ["1", 'invalid command name "this_command_does_not_exist"']),
        ("1 {Target dummy.cpu doesn't support read_memory\n}", ["1", "Target dummy.cpu doesn't support read_memory\n"]),
        ("0 halted", ["0", "halted"]),
        # Jim 인용 규칙 실측 (이 작업에서 실제 OpenOCD 로 확인)
        ("1 a\\{b", ["1", "a{b"]),
        ("0 q\\{", ["0", "q{"]),
        ("0 q\\}", ["0", "q}"]),
        ("0 a\\\\", ["0", "a\\"]),
        ("0 {tab\there}", ["0", "tab\there"]),
        ("0 {$dollar}", ["0", "$dollar"]),
        ("0 {[br]}", ["0", "[br]"]),
        ("0 a\\]b", ["0", "a]b"]),
        ("0 #hash", ["0", "#hash"]),
        ("0 {semi;colon}", ["0", "semi;colon"]),
        ("0 {line1\nline2}", ["0", "line1\nline2"]),
        # 데이터 봉투 실측
        ("0 q\\{\\ z {}", ["0", "q{ z", ""]),
        ("0 {} {hello\n}", ["0", "", "hello\n"]),
        ("1 {} {Target dummy.cpu doesn't support read_memory\n\nfailed to read memory}", ["1", "", "Target dummy.cpu doesn't support read_memory\n\nfailed to read memory"]),
        ("-306 {}", ["-306", ""]),
        ('a "b c" d', ["a", "b c", "d"]),
    ],
)
def test_split_list_real_frames(frame, expected):
    assert tcl.split_list(frame) == expected


def test_list_complete_and_errors():
    assert tcl.list_complete("0 {a b}")
    assert not tcl.list_complete("0 {a b")
    assert not tcl.list_complete('0 "abc')
    with pytest.raises(tcl.TclParseError):
        tcl.split_list("{a}b")


def test_parse_replies():
    r = tcl.parse_raw_reply("0 {" + XPACK_VERSION + "}")
    assert r.ok and r.output == XPACK_VERSION
    r = tcl.parse_raw_reply("1 {failed to read memory}")
    assert not r.ok and r.code == 1 and "failed" in r.error_text
    r = tcl.parse_raw_reply("-4 {flash bank 7 does not exist\n}")  # 0.12.0 음수 코드 + 끝 개행
    assert r.code == -4 and not r.ok and r.output == "flash bank 7 does not exist"
    r = tcl.parse_raw_reply("")
    assert r.closed and r.code is None
    r = tcl.parse_raw_reply("garbage {")
    assert r.code is None and r.notes
    d = tcl.parse_data_reply("0 {" + XPACK_TARGETS + "} {}")
    assert d.ok and "dummy.cpu" in d.output and d.log == ""
    d = tcl.parse_data_reply("1 {} {Target dummy.cpu doesn't support read_memory\n\nfailed to read memory}")
    assert not d.ok and "doesn't support" in d.error_text
    reset = tcl.parse_raw_reply(
        "0 {JTAG scan chain interrogation failed: all ones\nCheck JTAG interface, timings, target power, etc.\n"
        "Trying to use configured scan chain anyway...\nBypassing JTAG setup events due to errors\n}"
    )
    assert reset.ok and reset.output.endswith("errors")


def test_wrappers_and_validation():
    assert tcl.wrap_raw("scan_chain") == "list [catch {capture {scan_chain}} _pweh_r] $_pweh_r"
    assert tcl.wrap_raw("capture {echo hi}") == "list [catch {capture {echo hi}} _pweh_r] $_pweh_r"
    assert tcl.wrap_raw('capture "reset init"') == 'list [catch {capture "reset init"} _pweh_r] $_pweh_r'
    assert tcl.wrap_data("targets") == "set _pweh_d {}; list [catch {capture {set _pweh_d [targets]; list}} _pweh_l] $_pweh_d $_pweh_l"
    assert tcl.braces_balanced("if {1} {echo {a}}")
    assert tcl.braces_balanced("echo \\{")
    assert not tcl.braces_balanced("echo }} ; mww 0 0 ; list {{")
    assert not tcl.braces_balanced("echo {a")
    assert not tcl.braces_balanced("echo a\\")
    assert tcl.brace_quote_path("/a b/$x[1].bin") == "{/a b/$x[1].bin}"
    for bad in ("/a{b", "/a}b", "/a\\b", "/a\nb", ""):
        with pytest.raises(ValueError):
            tcl.brace_quote_path(bad)
    with pytest.raises(ValueError):
        tcl.validate_request("version\x1a")
    assert tcl.is_notification("type target_event event halted\r\n")
    assert not tcl.is_notification("0 {}")


# ---------------------------------------------------------------------------
# 파서
# ---------------------------------------------------------------------------


def test_parse_version():
    v = parsers.parse_version(XPACK_VERSION)
    assert v["parsed"] and v["vendor"] == "xPack" and v["version"] == "0.12.0" and v["dev"] and v["dev_count"] == 2228
    assert v["build_date"] == "2025-10-04-22:42"
    v = parsers.parse_version("Open On-Chip Debugger 0.11.0\n")
    assert v["minor"] == 11 and not v["dev"] and v["vendor"] is None
    assert parsers.parse_version("hello")["parsed"] is False


def test_parse_scan_chain_xpack_dummy():
    taps = parsers.parse_scan_chain(XPACK_SCAN)
    assert len(taps) == 1
    t = taps[0]
    assert t["tap_name"] == "dummy.cpu" and t["enabled"] and t["idcode"] == "0x00000000" and t["irlen"] == 4
    assert t["ircap"] == "0x01" and t["irmask"] == "0x01" and not t["decoded"]["valid"] and not t["mismatch"]


def test_parse_scan_chain_multi_and_extras():
    taps = parsers.parse_scan_chain(MASTER_SCAN2)
    assert [t["tap_name"] for t in taps] == ["sim.cpu", "sim.bs"]
    assert taps[0]["decoded"]["manufacturer"] == "ARM Ltd" and taps[0]["decoded"]["part"] == "0xba00" and taps[0]["decoded"]["version"] == 5
    assert taps[1]["decoded"]["manufacturer"] == "Atmel" and taps[1]["irlen"] == 5
    # 추가 expected 줄 + ignore-version 와일드카드 + 긴 이름 + 불일치 (소스 포맷 문자열로 생성)
    text = MASTER_SCAN2.split("\n")[0] + "\n" + MASTER_SCAN2.split("\n")[1] + "\n"
    text += f"{0:2d} {'very.long.chip.name.tap':<18s}     Y     0x4ba00477 0x*ba00477 {4:5d} 0x01  0x0f\n"
    text += " " * 43 + "0x6ba00477\n"
    text += f"{1:2d} {'other.tap':<18s}     n     0x12345679 0x0792603f {5:5d} 0x01  0x03\n"
    taps = parsers.parse_scan_chain(text)
    assert taps[0]["tap_name"] == "very.long.chip.name.tap" and taps[0]["expected_ids"] == ["0x*ba00477", "0x6ba00477"]
    assert taps[0]["mismatch"] is False  # 버전 니블 무시
    assert taps[1]["enabled"] is False and taps[1]["mismatch"] is True


def test_decode_idcode():
    d = parsers.decode_idcode(0x5BA00477)
    assert d["valid"] and d["manufacturer_code"] == "0x23b" and d["jep106_bank"] == 4 and d["manufacturer"] == "ARM Ltd"
    assert not parsers.decode_idcode(0xFFFFFFFF)["valid"]
    assert "BYPASS" in parsers.decode_idcode(0x12345678)["note"]


def test_parse_targets():
    rows = parsers.parse_targets(XPACK_TARGETS)
    assert rows == [{"index": 0, "current": True, "name": "dummy.cpu", "type": "testee", "endian": "little", "tap_name": "dummy.cpu", "state": "unknown"}]
    text = XPACK_TARGETS.split("\n")[0] + "\n" + XPACK_TARGETS.split("\n")[1] + "\n"
    text += f"{0:2d}  {'cam.ahb':<18s} {'mem_ap':<10s} {'little':<6s} {'cam.dap':<18s} running\n"
    text += f"{1:2d}* {'cam.cpu':<18s} {'cortex_a':<10s} {'little':<6s} {'cam.dap':<18s} examine deferred\n"
    rows = parsers.parse_targets("Info : some captured log line\n" + text)
    assert [r["name"] for r in rows] == ["cam.ahb", "cam.cpu"]
    assert rows[1]["state"] == "examine deferred" and rows[1]["current"] and not rows[0]["current"]
    assert parsers.current_target(rows)["name"] == "cam.cpu"
    assert parsers.current_target(rows, "cam.ahb")["type"] == "mem_ap"


def test_parse_reg():
    text = "===== arm v4/5 registers\n(0) r0 (/32): 0x00000000\n(1) r1 (/32)\n(16) cpsr (/32): 0x600001d3 (dirty)\n===== cp15\n(40) c1 (/32)"
    regs = parsers.parse_reg_list(text)
    assert [r["name"] for r in regs] == ["r0", "r1", "cpsr", "c1"]
    assert regs[0]["value"] == "0x00000000" and regs[1]["value"] is None and regs[2]["dirty"] and regs[3]["cache"] == "cp15"
    assert parsers.parse_reg_single("pc (/32): 0x80008000") == {"name": "pc", "bits": 32, "value": "0x80008000"}
    assert parsers.parse_reg_single("register pc not found in current target") is None


def test_parse_md_and_read_memory():
    pairs = parsers.parse_md(MASTER_MDW)
    assert len(pairs) == 10 and pairs[0] == (0x08000000, 0x56190527) and pairs[8] == (0x08000020, 0x0A090807)
    data = parsers.values_to_bytes([v for _, v in pairs[:2]], 4, "little")
    assert data == bytes([0x27, 0x05, 0x19, 0x56, 0x55, 0x2D, 0x42, 0x6F])
    bpairs = parsers.parse_md(MASTER_MDB)
    assert len(bpairs) == 40 and bytes(v for _, v in bpairs[:8]) == data
    vals, err = parsers.parse_read_memory("0x56190527 0x6f422d55 0x3220746f 0x2e363130")
    assert err is None and vals[0] == 0x56190527
    vals, err = parsers.parse_read_memory("0x27 0x5 0x19 0x56 0x55 0x2d")
    assert vals == [0x27, 0x5, 0x19, 0x56, 0x55, 0x2D]
    # 실패 시 공백 없이 붙는 오류 표지 ('fa' 가 16진수로 읽히면 안 됨)
    vals, err = parsers.parse_read_memory("0x1 0x2failed to read memory")
    assert vals == [1, 2] and err == "failed to read memory"
    vals, err = parsers.parse_read_memory("read_memory: failed to read memory")
    assert vals == [] and err
    assert parsers.values_to_bytes([0x11223344], 4, "big") == bytes([0x11, 0x22, 0x33, 0x44])


def test_parse_flash():
    banks = parsers.parse_flash_banks("#0 : sim.flash (faux) at 0x08000000, size 0x00040000, buswidth 0, chipwidth 0")
    assert banks == [{"bank": 0, "name": "sim.flash", "driver": "faux", "base": "0x08000000", "base_int": 0x08000000, "size": 0x40000,
                      "size_hex": "0x40000", "bus_width": 0, "chip_width": 0}]
    info = parsers.parse_flash_info(MASTER_FLASH_INFO)
    assert info["driver"] == "faux" and info["size"] == 0x40000 and len(info["sectors"]) == 4
    assert info["sectors"][1] == {"index": 1, "offset": 0x10000, "size": 0x10000, "protection": "not protected"}
    assert info["driver_info"] == "faux flash driver"
    master = "{\n    name       {sim.flash}\n    driver     faux\n    base       0x08000000\n    size       0x40000\n    bus_width  0\n    chip_width 0\n    target     sim.mem\n}"
    xpack = master.replace("{sim.flash}", "sim.flash")
    v012 = "{name sim.flash driver faux base 134217728 size 262144 bus_width 0 chip_width 0 target sim.mem}"
    for text in (master, xpack, v012):
        lst = parsers.parse_flash_list(text)
        assert lst == [{"name": "sim.flash", "driver": "faux", "target": "sim.mem", "base": 0x08000000, "size": 0x40000, "bus_width": 0, "chip_width": 0}], text
    assert parsers.parse_read_bank_bytes("wrote 64 bytes to file /tmp/rb.bin from flash bank 0 at offset 0x00000000 in 0.003000s (20.833 KiB/s)") == 64
    assert parsers.parse_dumped_bytes("dumped 256 bytes in 0.011000s (22.727 KiB/s)") == 256
    assert parsers.parse_verify_bank("read 64 bytes from file /tmp/rb.bin and flash bank 0 at offset 0x00000000 in 0.003000s (20.833 KiB/s)\ncontents match") is True
    assert parsers.parse_verify_bank("...\ncontents differ\ndiff 0 address 0x00000000. Was 0x27 instead of 0x00") is False


def test_log_summary_and_diagnosis():
    s = parsers.parse_log_summary(XPACK_STARTUP_LOG)
    assert s["listening"] == {"tcl": 39453}
    assert s["taps"][0]["tap_name"] == "dummy.cpu" and s["taps"][0]["manufacturer"] == "<invalid>"
    assert s["examination"] == [{"target": "dummy.cpu", "result": "succeed"}]
    assert s["warnings"] == ["dummy.cpu: nonstandard IR mask"] and s["errors"] == []
    log2 = (
        'Warn : AUTO auto0.tap - use "jtag newtap auto0 tap -irlen 4 -expected-id 0x5ba00477"\n'
        "Info : JTAG tap: sim.cpu tap/device found: 0x5ba00477 (mfg: 0x23b (ARM Ltd), part: 0xba00, ver: 0x5)\n"
        "Error: JTAG scan chain interrogation failed: all ones\nError: Check JTAG interface, timings, target power, etc.\n"
        "Error: auto0.tap: IR capture error; saw 0x0f not 0x01\n"
        "Error: unable to open ftdi device with description '*', serial '*' at bus location '*'\n"
        "Error: couldn't bind tcl to socket on port 6666: Address already in use\n"
    )
    s = parsers.parse_log_summary(log2)
    assert s["auto_newtap_suggestions"][0]["command"] == "jtag newtap auto0 tap -irlen 4 -expected-id 0x5ba00477"
    assert s["taps"][0]["manufacturer"] == "ARM Ltd"
    codes = {d["code"] for d in parsers.diagnose(log2)}
    assert {"jtag_all_ones", "ir_capture_error", "usb_open_failed", "port_in_use"} <= codes
    assert parsers.diagnose("Error: [cam.cpu] not halted")[0]["code"] == "target_not_halted"


# ---------------------------------------------------------------------------
# 위험도 분류 (코어 + 로컬 엄격 규칙)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd,risk",
    [
        ("version", Risk.INTERACT),
        ("scan_chain", Risk.INTERACT),
        ("targets", Risk.INTERACT),
        ("reg pc", Risk.INTERACT),
        ("read_memory 0x80000000 32 4", Risk.INTERACT),
        ("cam.ahb read_memory 0x80000000 32 4", Risk.INTERACT),
        ("flash banks", Risk.INTERACT),
        ('capture "mdw 0 4"', Risk.INTERACT),
        ("capture {flash info 0}", Risk.INTERACT),
        ("halt", Risk.MODIFY),
        ("targets cam.cpu; halt", Risk.MODIFY),
        ("reset halt", Risk.MODIFY),
        ("capture {reset halt}", Risk.MODIFY),
        ("mww 0x0 0", Risk.DESTRUCTIVE),
        ("write_memory 0x80000000 32 {0x1 0x2}", Risk.DESTRUCTIVE),
        ("flash write_image erase /tmp/x.bin 0x0 bin", Risk.DESTRUCTIVE),
        ("dump_image /tmp/x.bin 0x0 0x10", Risk.DESTRUCTIVE),
        ("flash read_bank 0 /etc/passwd 0 16", Risk.DESTRUCTIVE),
        # 코어 분류기가 놓치는 우회 형태 (실제 OpenOCD 에서 mww 가 실행됨을 확인)
        ("::mww 0x0 0", Risk.DESTRUCTIVE),
        ("m\\ww 0x0 0", Risk.DESTRUCTIVE),
        ("[string cat m ww] 0 0", Risk.DESTRUCTIVE),
        ("{*}[list mww 0 0]", Risk.DESTRUCTIVE),
        ('capture "flash erase_sector 0 0 last"', Risk.DESTRUCTIVE),
        ('catch "mww 0 0"', Risk.DESTRUCTIVE),
        ('if 1 "mww 0 0"', Risk.DESTRUCTIVE),
        ('foreach x {1} "mww 0 0"', Risk.DESTRUCTIVE),
        ("set x [popen ls]", Risk.DESTRUCTIVE),
        # 코어 표에 없어 MODIFY 로 떨어지던 호스트 탈출/영구 변경
        ("popen {rm -rf ~}", Risk.DESTRUCTIVE),
        ("socket stream 10.0.0.1:80", Risk.DESTRUCTIVE),
        ("load /tmp/evil.so", Risk.DESTRUCTIVE),
        ("script /tmp/evil.tcl", Risk.DESTRUCTIVE),
        ("log_output /home/user/.bashrc", Risk.DESTRUCTIVE),
        ("irscan cam.cpu 0x0", Risk.DESTRUCTIVE),
        ("svf /tmp/cpld.svf", Risk.DESTRUCTIVE),
        ("mmw 0x20000000 0x1 0x0", Risk.DESTRUCTIVE),
        ("memwrite32 0x20000000 1", Risk.DESTRUCTIVE),
        ("cam.dap apreg 0 0x0c 0x12345678", Risk.DESTRUCTIVE),
        ("arm semihosting enable", Risk.DESTRUCTIVE),
        ("alias foo mww", Risk.DESTRUCTIVE),
    ],
)
def test_classify_command(cmd, risk):
    c = guard.classify_command(cmd)
    assert c.risk == risk, (cmd, c)


def test_classify_minor_writes_are_at_least_modify():
    assert guard.classify_command("mips32 cp0 12 0 0x1").risk >= Risk.MODIFY
    assert guard.classify_command("cam.dap dpreg 0x4 0x50000000").risk >= Risk.MODIFY
    assert guard.classify_command("set_reg {pc 0}").risk >= Risk.MODIFY
    assert guard.classify_command("cam.dap apreg 0 0x0c").risk < Risk.DESTRUCTIVE  # 읽기


def test_classify_managed(tmp_path):
    jtag = tmp_path / "case" / "jtag"
    jtag.mkdir(parents=True)
    p = jtag / ".mem.chunk"
    ok = guard.classify_managed(f"dump_image {{{p}}} 0x80000000 0x10000", allowed_dirs=[jtag])
    assert ok.risk == Risk.INTERACT and ok.rule_id == "openocd.managed.dump_image"
    ok2 = guard.classify_managed(f"targets cam.cpu; dump_image {{{p}}} 0x80000000 0x10000", allowed_dirs=[jtag])
    assert ok2.risk == Risk.INTERACT
    fr = guard.classify_managed(f"flash read_bank 0 {{{p}}} 0x0 0x100", allowed_dirs=[jtag])
    assert fr.risk == Risk.INTERACT
    assert guard.classify_managed(f"flash verify_bank 0 {{{p}}} 0x0", allowed_dirs=[jtag]).risk == Risk.INTERACT
    assert guard.classify_managed(f"verify_image {{{p}}} 0x0 bin", allowed_dirs=[jtag]).risk == Risk.INTERACT
    assert guard.classify_managed("flash verify_bank 0 {/etc/shadow} 0x0", allowed_dirs=[jtag]).risk >= Risk.MODIFY
    # 케이스 밖 / .. 탈출 / 형식 위반 / 추가 명령은 코어 분류(DESTRUCTIVE) 그대로
    for bad in (
        "dump_image {/etc/passwd} 0x0 0x10",
        f"dump_image {{{jtag}/../../evil}} 0x0 0x10",
        f"dump_image {p} 0x0 0x10",
        f"dump_image {{{p}}} 0x0 0x10; mww 0 0",
        f"flash read_bank 0 {{{tmp_path}/x}} 0x0 0x10",
    ):
        assert guard.classify_managed(bad, allowed_dirs=[jtag]).risk == Risk.DESTRUCTIVE, bad
    with pytest.raises(SafetyDenied):
        guard.ensure_job_commands_safe(["read_memory 0x0 32 4", "mww 0 0"], allowed_dirs=[jtag])
    assert len(guard.ensure_job_commands_safe(["read_memory 0x0 32 4", f"dump_image {{{p}}} 0x0 0x10"], allowed_dirs=[jtag])) == 2


# ---------------------------------------------------------------------------
# 프로세스 명령행
# ---------------------------------------------------------------------------


def test_build_argv_order(tmp_path):
    iface = process.CfgRef("interface/ftdi/tigard.cfg", "standard")
    tgt = process.CfgRef("target/at91sam9.cfg", "standard")
    argv = process.build_argv(
        "/opt/openocd", scripts_dir=Path("/opt/scripts"), interface=iface, transport="jtag", targets=[tgt], extra_cfgs=[],
        adapter_speed_khz=500, extra_commands=["jtag newtap cam cpu -irlen 4"], tcl_port=0,
    )
    s = " | ".join(argv)
    assert argv[0] == "/opt/openocd" and argv[1:3] == ["-s", "/opt/scripts"]
    # 끝: semihosting 핸들러 감싸기 → init → init 직후 semihosting 확인·끄기 (semihosting.py)
    assert argv[-6:] == ["-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT]
    i_port = argv.index("if {[catch {tcl port 0}]} {tcl_port 0}")
    i_iface = argv.index("interface/ftdi/tigard.cfg")
    i_tr = argv.index("transport select jtag")
    i_tgt = argv.index("target/at91sam9.cfg")
    i_speed = argv.index("if {[catch {adapter speed 500}]} {adapter_khz 500}")
    i_extra = argv.index("jtag newtap cam cpu -irlen 4")
    assert i_port < i_iface < i_tr < i_tgt < i_speed < i_extra, s
    assert "if {[catch {telnet port disabled}]} {telnet_port disabled}" in argv
    assert "if {[catch {gdb port disabled}]} {gdb_port disabled}" in argv


def test_resolve_cfg(tmp_path):
    scripts = tmp_path / "scripts"
    (scripts / "interface").mkdir(parents=True)
    (scripts / "interface" / "dummy.cfg").write_text("adapter driver dummy\n")
    custom = tmp_path / "my.cfg"
    custom.write_text("adapter driver dummy\n")
    std = process.resolve_cfg("interface/dummy.cfg", [scripts])
    assert std.kind == "standard" and std.arg == str((scripts / "interface" / "dummy.cfg").resolve())  # 절대경로로 넘김
    assert process.resolve_cfg("interface/unknown.cfg", [scripts]).kind == "unresolved"
    c = process.resolve_cfg(str(custom), [scripts])
    assert c.kind == "custom" and c.path == custom.resolve()
    from pweh.errors import NotFound

    with pytest.raises(NotFound):
        process.resolve_cfg(str(tmp_path / "nope.cfg"), [scripts])
    with pytest.raises(NotFound):
        process.resolve_cfg("interface/../../nope.cfg", [scripts])


def test_resolve_cfg_cwd_relative_is_custom(tmp_path, monkeypatch):
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "mine.cfg").write_text("jtag newtap x y -irlen 4\n")
    monkeypatch.chdir(tmp_path)
    ref = process.resolve_cfg("target/mine.cfg", [])
    assert ref.kind == "custom" and ref.arg == str((tmp_path / "target" / "mine.cfg").resolve())
