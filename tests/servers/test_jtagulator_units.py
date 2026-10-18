"""jtagulator-mcp 순수 단위 테스트: 프로토콜 판별, 안전 분류기, 출력 파서, JEP106 해석.

파서 테스트의 입력은 docs/references/jtagulator-protocol.md 의 예시 바이트열(펌웨어 소스로 합성)을
그대로 옮긴 것이다 — 시뮬레이터와 독립적으로 형식을 검증한다.
"""

from __future__ import annotations

import pytest

from pweh.errors import ValidationFailed
from pweh.safety import Risk

from jtagulator_mcp import protocol as P
from jtagulator_mcp.classify import classify_jtagulator, classify_uart_probe
from jtagulator_mcp.driver import KeyPlan, PlannedStep, ScanSpec, build_scan_plan, build_voltage_plan
from jtagulator_mcp.jep106 import decode_idcode, openocd_target_hints
from jtagulator_mcp.parsers import (
    count_progress,
    parse_bypass_test,
    parse_device_id_listing,
    parse_gpio_reads,
    parse_jtag_blocks,
    parse_status,
    parse_txd_hits,
    parse_uart_hits,
    summarize_gpio,
    summarize_jtag,
    summarize_txd,
    summarize_uart,
)

# --- 레퍼런스 문서 예시 (§8.1, §8.2, §8.5, §8.6, §9.1, §9.2, §7) -------------------------
DOC_IDCODE = (
    "\r\nJTAGulating! Press any key to abort...\r\n"
    "\r\nTDI: N/A\r\nTDO: 2\r\nTCK: 0\r\nTMS: 1\r\nDevice ID #1: 0100 1011101000000000 01000111011 1 (0x4BA00477)\r\n\r\n---\r\nIDCODE scan complete."
    "\r\n\nJTAG> "
)
DOC_BYPASS = (
    "\r\nTDI: 3\r\nTDO: 2\r\nTCK: 0\r\nTMS: 1\r\nNumber of devices detected: 1\r\n\r\nBYPASS scan complete."
    "\r\n\nJTAG> "
)
DOC_UART = "---\r\nTXD: 1\r\nRXD: 0\r\nBaud: 115200\r\nData: ..#  [ 0D 0A 23 20 ]\r\n---------\r\nUART scan complete.\r\n\nUART> "
DOC_TXD = "\r\nTXD: 1\r\nBaud (Measured): 115273\r\nBaud (Best Fit): 115200\r\n"
DOC_D = (
    "\r\n\nDevice ID #1: 0100 1011101000000000 01000111011 1 (0x4BA00477)\r\n-> Manufacturer ID: 0x23B\r\n"
    "-> Part Number: 0xBA00\r\n-> Version: 0x4\r\n\r\nIDCODE listing complete.\r\n\nJTAG> "
)
DOC_T = (
    "\r\nNumber of devices detected: 1\r\nPattern in to TDI:    01011010001111001001011011100001"
    "\r\nPattern out from TDO: 01011010001111001001011011100001\r\nMatch!\r\n\nJTAG> "
)
DOC_VOLTAGE = (
    "V\r\r\nCurrent target I/O voltage: Undefined\r\nEnter new target I/O voltage (1.4 - 3.3, 0 for off): "
)


# ---------------------------------------------------------------------------
# 상태 판별
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tail,state,extra",
    [
        ("...\r\n\nJTAG> ", "menu", {"menu": "jtag"}),
        ("Welcome...!\r\n\n> ", "menu", {"menu": "main"}),
        ("x\r\n\nUART> ", "menu", {"menu": "uart"}),
        ("I\r\r\nEnter starting channel [0]: ", "value", {"kind": "start_channel", "default": "0"}),
        ("\r\n\nBring channels LOW between each permutation? [y/N]: ", "value", {"kind": "pins_low", "default": "y/N"}),
        ("\r\n\nBring channels LOW before each permutation? [Y/n]: ", "value", {"kind": "pins_low"}),
        ("\r\nEnter text string to output (prefix with \\x for hex) [\\x0D]: ", "value", {"kind": "uart_text", "default": "\\x0D"}),
        ("\r\nEnter text string to output (prefix with \\x for hex) [a]b]: ", "value", {"kind": "uart_text", "default": "a]b"}),
        ("\r\nEnter TDI pin [0]: ", "value", {"kind": "pin_tdi"}),
        (DOC_VOLTAGE, "voltage", {"vmin": 1.4, "vmax": 3.3}),
        ("\r\nPress spacebar to begin (any other key besides Enter to abort)...", "space", {}),
        ("\r\nPress spacebar to begin (any other key to abort)...", "space", {}),
        ("n\r\r\nJTAGulating! Press any key to abort...\r\n---", "scanning", {}),
        (DOC_IDCODE, "menu", {"menu": "jtag"}),
        ("\r\nEnter favorite color [red]: ", "value", {"kind": None, "label": "Enter favorite color"}),
        ("random noise", "unknown", {}),
        ("\r\n\nJTAG> extra", "unknown", {}),
    ],
)
def test_detect_context(tail, state, extra):
    ctx = P.detect_context(tail)
    assert ctx.state == state, ctx
    for k, v in extra.items():
        assert getattr(ctx, k) == v, (k, ctx)


def test_firmware_input_semantics():
    assert P.effective_line("I\r") == ("I", True)
    assert P.effective_line("VX\x08\r") == ("V", True)
    assert P.effective_line("V\n\r") == ("V", True)
    assert P.effective_line("V") == ("V", False)
    assert P.effective_line("0123456789ABCDEF\r") == ("0123456789AB", True)  # 12자 초과분 버림
    assert P.dec_pin("") == -1 and P.dec_pin("3.3") == 33 and P.dec_pin("115,200") == 115200 and P.dec_pin("3V") == -3
    assert P.get_pin("x") == -2 and P.get_pin("xx") == -3 and P.get_pin("7") == 7 and P.get_pin("") == -1
    assert P.voltage_tenths("2") == 20 and P.voltage_tenths("3") == 30 and P.voltage_tenths("1.8") == 18
    assert P.voltage_tenths("3.30") == 330 and P.voltage_tenths("") == -1


def test_normalize_volts():
    assert P.normalize_volts(3.3) == "3.3"
    assert P.normalize_volts("1.8") == "1.8"
    assert P.normalize_volts(2) == "2.0"
    assert P.normalize_volts("3.3V") == "3.3"
    assert P.normalize_volts(0) == "0"
    for bad in (1.85, 3.4, 1.3, 5, "abc", float("nan"), -1):
        with pytest.raises(ValidationFailed):
            P.normalize_volts(bad)


def test_permutations_and_specs():
    assert P.permutations(8, 3) == 336
    assert P.permutations(8, 4) == 1680
    assert P.permutations(24, 3) == 12144
    assert P.permutations(24, 4) == 255024
    assert P.permutations(8, 2) == 56
    assert ScanSpec(kind="bypass", start=0, end=7, known_pins={"tdo": 2, "tck": 0, "tms": 1}).expected_permutations() == 5
    assert ScanSpec(kind="uart", start=0, end=3, uart_answer="\\x0D", uart_probe=b"\r").expected_permutations() == 12
    assert ScanSpec(kind="uart_txd", start=0, end=3).expected_permutations() is None
    # 하한 추정: BYPASS 24채널은 몇 시간 단위
    lb = ScanSpec(kind="bypass", start=0, end=23).lower_bound_seconds()
    assert lb and lb > 3 * 3600
    assert ScanSpec(kind="idcode", start=0, end=23).lower_bound_seconds() < 60


def test_validation_helpers():
    assert P.validate_channels("idcode", 0, 2) == (0, 2)
    with pytest.raises(ValidationFailed):
        P.validate_channels("idcode", 0, 1)  # 최소 3채널
    with pytest.raises(ValidationFailed):
        P.validate_channels("uart", 0, 24)
    with pytest.raises(ValidationFailed):
        P.validate_channels("uart", -1, 3)
    assert P.validate_known_pins({"TDO": 2, "tck": 0}, ("tdi", "tdo", "tck", "tms"), 0, 7, 4) == {"tdo": 2, "tck": 0}
    with pytest.raises(ValidationFailed):
        P.validate_known_pins({"tdo": 2, "tck": 2}, ("tdi", "tdo", "tck", "tms"), 0, 7, 4)
    with pytest.raises(ValidationFailed):
        P.validate_known_pins({"tdo": 9}, ("tdi", "tdo", "tck", "tms"), 0, 7, 4)
    with pytest.raises(ValidationFailed):
        P.validate_known_pins({"foo": 1}, ("txd", "rxd"), 0, 7, 2)
    with pytest.raises(ValidationFailed):
        P.validate_known_pins({"txd": 1, "rxd": 2}, ("txd", "rxd"), 0, 7, 2)


def test_text_escape_decoding():
    assert P.decode_text_escapes("\r") == "\r"
    assert P.decode_text_escapes("\\r") == "\r"  # 이중 이스케이프 흡수
    assert P.decode_text_escapes("help\\r\\n") == "help\r\n"
    assert P.decode_text_escapes("\\x03") == "\x03"
    assert P.decode_text_escapes("a\\\\b") == "a\\b"
    with pytest.raises(ValidationFailed):
        P.decode_text_escapes("bad\\")


def test_uart_probe_answer():
    assert P.uart_probe_answer("\r") == ("\\x0D", b"\r")
    assert P.uart_probe_answer("help\r") == ("\\x68656C700D", b"help\r")
    for bad in ("", "x" * 17, "한글"):
        with pytest.raises(ValidationFailed):
            P.uart_probe_answer(bad)
    assert P.decode_uart_text_answer("\\x0D") == b"\r"
    assert P.decode_uart_text_answer("help") == b"help\r"
    assert P.decode_uart_text_answer("") is None
    assert P.decode_uart_text_answer("\\x0") is None


# ---------------------------------------------------------------------------
# 안전 분류기
# ---------------------------------------------------------------------------

MENU = {m: P.DeviceContext("menu", menu=m) for m in ("main", "jtag", "uart", "gpio", "swd")}
VOLT = P.DeviceContext("voltage", vmin=1.4, vmax=3.3)
SPACE = P.DeviceContext("space")
SCANNING = P.DeviceContext("scanning")
UNKNOWN = P.DeviceContext("unknown")


def val(label: str) -> P.DeviceContext:
    return P.DeviceContext("value", label=label, kind=P.VALUE_PROMPT_KINDS.get(label))


@pytest.mark.parametrize(
    "keys,ctx,risk",
    [
        ("V\r", MENU["main"], Risk.DESTRUCTIVE),
        ("v\r", MENU["jtag"], Risk.DESTRUCTIVE),
        ("I\r", MENU["main"], Risk.OBSERVE),
        ("I\r", MENU["jtag"], Risk.MODIFY),
        ("I\r", MENU["swd"], Risk.MODIFY),
        ("J\r", MENU["main"], Risk.OBSERVE),
        ("J\r", MENU["jtag"], Risk.MODIFY),
        ("Y\r", MENU["jtag"], Risk.DESTRUCTIVE),
        ("P\r", MENU["jtag"], Risk.DESTRUCTIVE),
        ("O\r", MENU["jtag"], Risk.DESTRUCTIVE),
        ("P\r", MENU["uart"], Risk.DESTRUCTIVE),
        ("W\r", MENU["gpio"], Risk.DESTRUCTIVE),
        ("L\r", MENU["gpio"], Risk.DESTRUCTIVE),
        ("A\r", MENU["main"], Risk.DESTRUCTIVE),
        ("M\r", MENU["uart"], Risk.OBSERVE),
        ("M\r", MENU["main"], Risk.MODIFY),  # 메인 메뉴에 없는 글자 → 알 수 없는 명령(보수적)
        ("VV\r", MENU["main"], Risk.OBSERVE),  # 두 글자 → 펌웨어가 무효 명령 처리
        ("V", MENU["main"], Risk.DESTRUCTIVE),  # 줄 끝 없음 → 확정 불가
        ("V\x08V\r", MENU["main"], Risk.DESTRUCTIVE),  # 제어 문자
        ("\x18", UNKNOWN, Risk.INTERACT),
        ("\x18\r", VOLT, Risk.INTERACT),
        ("\x18\r", SPACE, Risk.INTERACT),
        ("3.3\r", VOLT, Risk.DESTRUCTIVE),
        ("2\r", VOLT, Risk.DESTRUCTIVE),
        ("0\r", VOLT, Risk.DESTRUCTIVE),  # 끄기도 전압 변경 (타깃 전원이 켜져 있으면 위험)
        ("\r", VOLT, Risk.INTERACT),  # 빈 줄 → 범위 밖 거부, 변경 없음
        ("3.30\r", VOLT, Risk.INTERACT),  # 330 → 거부
        ("abc\r", VOLT, Risk.INTERACT),
        ("0\r", val("Enter starting channel"), Risk.INTERACT),
        ("y\r", val("Bring channels LOW before each permutation?"), Risk.INTERACT),
        ("3\r", val("Enter favorite color"), Risk.DESTRUCTIVE),  # 알 수 없는 프롬프트 + 숫자
        ("FF\r", val("Enter value to output (in hex)"), Risk.DESTRUCTIVE),  # GPIO W
        ("115200\r", val("Enter baud rate"), Risk.DESTRUCTIVE),  # 패스스루 대화
        ("\\x0D\r", val("Enter text string to output (prefix with \\x for hex)"), Risk.INTERACT),
        (" ", SPACE, Risk.DESTRUCTIVE),  # scan_kind 를 모르면 확정 불가
        ("x", SPACE, Risk.OBSERVE),
        ("\n", SCANNING, Risk.INTERACT),
        ("\n", MENU["jtag"], Risk.INTERACT),
        ("\n", UNKNOWN, Risk.DESTRUCTIVE),  # 패스스루일 수도 있음
        ("ab", SCANNING, Risk.DESTRUCTIVE),
        ("I\r", UNKNOWN, Risk.DESTRUCTIVE),
    ],
)
def test_classifier(keys, ctx, risk):
    c = classify_jtagulator(keys, ctx)
    assert c.risk == risk, c


def test_scan_start_classification_depends_on_scan_kind():
    assert classify_jtagulator(" ", SPACE, scan_kind="idcode").risk == Risk.MODIFY
    assert classify_jtagulator(" ", SPACE, scan_kind="uart_txd").risk == Risk.MODIFY


def test_uart_probe_classification():
    assert classify_uart_probe(b"\r").risk == Risk.INTERACT
    assert classify_uart_probe(b"help\r").risk == Risk.INTERACT
    assert classify_uart_probe(b"sf erase 0 100000\r").risk == Risk.DESTRUCTIVE
    assert classify_uart_probe(b"saveenv").risk == Risk.DESTRUCTIVE  # 줄 끝 없어도(누적) 보수적으로
    assert classify_uart_probe(b"\x04").risk >= Risk.MODIFY  # Ctrl-D (셸 종료)
    assert classify_uart_probe(None).risk == Risk.DESTRUCTIVE
    hex_answer = "\\x" + b"sf erase 0 100000\r".hex().upper() + "\r"
    c = classify_jtagulator(hex_answer, val("Enter text string to output (prefix with \\x for hex)"))
    assert c.risk == Risk.DESTRUCTIVE


def test_plans_and_consumption():
    vp = build_voltage_plan("3.3")
    assert vp.worst().risk == Risk.DESTRUCTIVE
    # 승인 전에는 아무것도 소비할 수 없다
    cls_v = classify_jtagulator("V\r", MENU["uart"])
    assert not vp.consume("menu", "uart", "V\r", cls_v)
    vp.authorize(Risk.DESTRUCTIVE)
    assert vp.consume("menu", "uart", "V\r", cls_v)  # where='*'
    assert not vp.consume("menu", "uart", "V\r", cls_v)  # 1회용
    cls_a = classify_jtagulator("1.8\r", VOLT)
    assert not vp.consume("voltage", "", "1.8\r", cls_a)  # 다른 전압은 계획에 없음
    cls_b = classify_jtagulator("3.3\r", VOLT)
    assert vp.consume("voltage", "", "3.3\r", cls_b)

    sp = build_scan_plan(ScanSpec(kind="idcode", start=0, end=7))
    assert sp.worst().risk == Risk.MODIFY
    sp.authorize(Risk.MODIFY)
    # 스캔 계획(MODIFY)으로는 전압 프롬프트의 숫자를 절대 보낼 수 없다
    assert not sp.consume("voltage", "", "0\r", classify_jtagulator("0\r", VOLT))
    assert sp.consume("menu", "jtag", "I\r", classify_jtagulator("I\r", MENU["jtag"]))
    assert not sp.consume("menu", "swd", "I\r", classify_jtagulator("I\r", MENU["swd"]))
    assert sp.consume("space", "idcode", " ", classify_jtagulator(" ", SPACE, scan_kind="idcode"))

    probe_ans, probe = P.uart_probe_answer("reboot\r")
    up = build_scan_plan(ScanSpec(kind="uart", start=0, end=3, uart_text="reboot\r", uart_answer=probe_ans, uart_probe=probe))
    assert up.worst().risk >= Risk.MODIFY
    custom = KeyPlan([PlannedStep("menu", "jtag", "B\r", classify_jtagulator("B\r", MENU["jtag"]))], name="t")
    custom.authorize(Risk.INTERACT)
    assert not custom.consume("menu", "jtag", "B\r", classify_jtagulator("B\r", MENU["jtag"]))  # 상한 초과


# ---------------------------------------------------------------------------
# 파서
# ---------------------------------------------------------------------------


def test_parse_idcode_doc_example():
    blocks = parse_jtag_blocks(DOC_IDCODE)
    assert len(blocks) == 1
    b = blocks[0]
    assert (b["tdi"], b["tdo"], b["tck"], b["tms"]) == (None, 2, 0, 1)
    assert b["devices"][0]["idcode"] == "0x4BA00477"
    assert b["devices"][0]["manufacturer"] == "ARM Ltd"
    st = parse_status(DOC_IDCODE, "idcode")
    assert st["completed"] and not st["aborted"] and not st["no_device_found"]
    assert count_progress(DOC_IDCODE) == 3
    summ = summarize_jtag(blocks, "idcode")
    assert summ["best"]["tdo"] == 2 and summ["best"]["known_manufacturer"]
    assert any("TDI" in n for n in summ["notes"])


def test_parse_bypass_doc_example():
    blocks = parse_jtag_blocks(DOC_BYPASS)
    assert blocks and blocks[0]["tdi"] == 3 and blocks[0]["device_count"] == 1
    summ = summarize_jtag(blocks, "bypass")
    assert summ["best"]["tdi"] == 3
    assert parse_status(DOC_BYPASS, "bypass")["completed"]


def test_parse_uart_doc_example():
    hits = parse_uart_hits(DOC_UART)
    assert len(hits) == 1
    h = hits[0]
    assert (h["txd"], h["rxd"], h["baud"]) == (1, 0, 115200)
    assert h["data_hex"] == "0D0A2320" and h["data_ascii"] == "..# "
    assert count_progress(DOC_UART) == 12
    summ = summarize_uart(hits)
    assert summ["best"]["txd"] == 1 and summ["best"]["confidence"] == "high"


def test_uart_data_with_brackets_and_garbage_ranking():
    text = (
        "\r\nTXD: 2\r\nRXD: 3\r\nBaud: 19200\r\nData: .... [ 80 FF 81 92 ]\r\n"
        "\r\nTXD: 2\r\nRXD: 3\r\nBaud: 57600\r\nData: x [ 41 ] [ 78 20 5B 20 34 31 20 5D ]\r\n"
        "\r\nTXD: 2\r\nRXD: 3\r\nBaud: 115200\r\nData: ..root@cam:~#  [ 0D 0A 72 6F 6F 74 40 63 61 6D 3A 7E 23 20 ]\r\n"
    )
    hits = parse_uart_hits(text)
    assert [h["baud"] for h in hits] == [19200, 57600, 115200]
    assert hits[1]["data_hex"] == "78205B20343120 5D".replace(" ", "")
    summ = summarize_uart(hits)
    assert summ["best"]["baud"] == 115200 and summ["best"]["confidence"] == "high"
    assert summ["candidates"][0]["bauds_seen"] == [19200, 57600, 115200]


def test_parse_txd_and_device_listing_and_bypass_test():
    hits = parse_txd_hits(DOC_TXD * 3 + "\r\nTXD: 4\r\nBaud (Measured): 7000\r\nBaud (Best Fit): N/A\r\n")
    assert hits[0] == {"txd": 1, "baud_measured": 115273, "baud_best_fit": 115200}
    summ = summarize_txd(hits)
    assert summ["best"]["txd"] == 1 and summ["best"]["baud"] == 115200 and summ["best"]["detections"] == 3
    devs = parse_device_id_listing(DOC_D)
    assert devs[0]["firmware_detail"] == {"manufacturer_id": "0x23B", "part_number": "0xBA00", "version": "0x4"}
    bt = parse_bypass_test(DOC_T)
    assert bt["match"] is True and bt["device_count"] == 1


def test_parse_gpio_reads():
    # 공식 시험 절차서/레퍼런스 §11 형식: 마지막 8비트 덩어리 뒤 공백 + ' (0x' → 공백 2칸
    one = "R\r\r\r\nCH23..CH0: 11111111 11111111 11111111  (0xFFFFFF)\r\n\nGPIO> "
    two = "\r\nCH23..CH0: 11111111 11111111 10111111  (0xFFFFBF)"
    bad = "\r\nCH23..CH0: 11111111 11111111 11111111  (0xFFFFBF)"  # 2진수와 hex 불일치 → 버림
    vals = parse_gpio_reads(one + two + bad)
    assert vals == [0xFFFFFF, 0xFFFFBF]
    s = summarize_gpio(vals)
    assert s["samples"] == 2 and s["toggling_channels"] == [6] and s["low_channels"] == [6]
    assert s["channels"]["6"] == 0 and s["channels"]["0"] == 1


def test_parse_partial_and_aborted_output():
    partial = "\r\nJTAGulating! Press any key to abort...\r\n----\r\nTDI: N/A\r\nTDO: 2\r\nTC"
    assert parse_jtag_blocks(partial) == []
    aborted = "\r\n-----\r\nBYPASS scan aborted!\r\n\nJTAG> "
    st = parse_status(aborted, "bypass")
    assert st["aborted"] and not st["completed"]
    assert parse_status("\r\nNo target device(s) found!\r\nUART scan complete.", "uart")["no_device_found"]
    assert parse_status("\r\nJTAG scan complete.", "jtag")["completed"]  # FW ≤1.11.1 문구
    assert parse_status("\r\nTarget I/O voltage must be defined!", None)["errors"] == ["Target I/O voltage must be defined!"]


def test_corrupted_device_id_is_flagged():
    bad = "\r\nTDI: N/A\r\nTDO: 2\r\nTCK: 0\r\nTMS: 1\r\nDevice ID #1: 0000 1011101000000000 01000111011 1 (0x4BA00477)\r\n"
    dev = parse_jtag_blocks(bad)[0]["devices"][0]
    assert dev["plausible"] is False and any("손상" in n for n in dev["notes"])


# ---------------------------------------------------------------------------
# JEP106
# ---------------------------------------------------------------------------


def test_decode_idcode():
    d = decode_idcode(0x4BA00477)
    assert d["manufacturer"] == "ARM Ltd" and d["part_number"] == "0xBA00" and d["version"] == 4
    assert d["jep106"] == {"bank": 5, "continuation_codes": 4, "id": "0x3B"} and d["plausible"]
    legacy = decode_idcode(0x07926F0F)
    assert legacy["description"].startswith("ARM926EJ-S") and "ARM" in legacy["manufacturer"]
    assert decode_idcode(0x13631093)["manufacturer"].startswith("Xilinx")
    assert decode_idcode(0x00000001)["plausible"] is False
    assert decode_idcode(0x000000FF)["plausible"] is False  # id 0x7F
    unknown = decode_idcode(0x1000007B)  # bank 1, id 0x3D — 선별 목록 밖
    assert unknown["manufacturer"] is None and unknown["plausible"]


def test_openocd_hints(tmp_path):
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "mysoc.cfg").write_text("set _CPUTAPID 0x4ba00477\njtag newtap $_CHIPNAME cpu -expected-id $_CPUTAPID\n")
    (tmp_path / "target" / "other.cfg").write_text("jtag newtap x tap -irlen 4 -expected-id 0x0792603f\n")
    h = openocd_target_hints(0x4BA00477, tmp_path)
    assert h["match"] == "exact" and h["configs"] == ["target/mysoc.cfg"]
    h2 = openocd_target_hints(0x5BA00477, tmp_path)
    assert h2["match"] == "version-insensitive"
    assert openocd_target_hints(0x12345679, tmp_path)["count"] == 0
    assert openocd_target_hints(0x4BA00477, None) is None
