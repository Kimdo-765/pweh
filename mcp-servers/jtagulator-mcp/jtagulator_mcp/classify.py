"""JTAGulator 키 입력 위험도 분류기.

코어(pweh.safety)에는 JTAGulator 용 분류기가 없어서 이 패키지에 둔다. 반환 형식은 코어의
``Classification`` 이며 ``rt().authorize(...)`` 에 그대로 넘긴다.

원칙:
- 분류는 '실제 장치 상태'(수신 버퍼 끝에서 판별한 DeviceContext)를 기준으로 한다. 드라이버가 상태를
  잘못 알고 있어도(예: 채널 번호를 답하려는데 실제로는 전압 프롬프트) 분류기가 실제 프롬프트를 보고 막는다.
- 전압(V) 대화는 DESTRUCTIVE. 'V' 키 자체도 DESTRUCTIVE 로 분류해 jtagulator_set_voltage 의 승인된
  계획 밖에서는 절대 전압 대화에 들어가지 못하게 한다.
- 타깃 핀을 구동하는 스캔(IDCODE/BYPASS/Combined/UART/TXD, D/T)은 MODIFY.
- 알 수 없는 JTAG 명령어를 실행하는 IR/DR discovery(Y), 타깃 칩 핀을 구동하는 핀 매퍼(P), 24채널 출력(GPIO W),
  리셋 후에도 유지되는 영속 모드(O, L), 이후 입력이 분류 없이 타깃 콘솔로 가는 UART 패스스루(P)는 DESTRUCTIVE.
- 실제 입력을 확정할 수 없으면(줄 끝 없음, 제어 문자, 알 수 없는 프롬프트에 숫자) DESTRUCTIVE + uncertain.
- UART 스캔 프로브 문자열은 대상 콘솔로 전송되므로 코어 콘솔 분류기(U-Boot/Linux 둘 다)로 검사한다.
"""

from __future__ import annotations

from typing import Iterable

from pweh.safety import CONTROL_CHAR_RISK, Classification, LineAssembler, Risk, classify_console_line, worst

from .protocol import (
    BENIGN_VALUE_PROMPTS,
    DANGEROUS_VALUE_PROMPTS,
    MAX_LEN_CMD,
    MAX_LEN_UART_USER,
    VTARGET_MAX_TENTHS,
    VTARGET_MIN_TENTHS,
    DeviceContext,
    decode_uart_text_answer,
    effective_line,
    voltage_tenths,
)

O, I, M, D = Risk.OBSERVE, Risk.INTERACT, Risk.MODIFY, Risk.DESTRUCTIVE

_PIN_DRIVE = "범위 안의 모든 채널을 출력 HIGH 로 구동하며 핀 순열을 시도 — 채널이 타깃 출력/제어선에 물려 있으면 충돌·동작 변화 가능"

# 메뉴별 명령 키 → (위험도, 규칙 접미사, 사유)
MENU_COMMANDS: dict[str, dict[str, tuple[Risk, str, str]]] = {
    "main": {
        "J": (O, "nav.jtag", "JTAG 메뉴로 이동"),
        "U": (O, "nav.uart", "UART 메뉴로 이동"),
        "G": (O, "nav.gpio", "GPIO 메뉴로 이동"),
        "S": (O, "nav.swd", "SWD 메뉴로 이동"),
        "I": (O, "version", "버전 정보 표시"),
        "H": (O, "help", "도움말 표시"),
        "V": (D, "voltage", "타깃 I/O 전압(VADJ) 설정 대화 시작 — jtagulator_set_voltage 의 승인된 계획에서만 허용"),
        "A": (D, "scan.all", "모든 스캔(UART 프로브 송신 포함)을 연달아 실행 — 상태 추적 불가, 자동화 금지"),
    },
    "jtag": {
        "J": (M, "scan.jtag", f"JTAG Combined Scan: {_PIN_DRIVE}"),
        "I": (M, "scan.idcode", f"IDCODE Scan: {_PIN_DRIVE}"),
        "B": (M, "scan.bypass", f"BYPASS Scan: {_PIN_DRIVE}"),
        "R": (M, "scan.rtck", f"RTCK Scan: {_PIN_DRIVE}"),
        "D": (M, "device_ids", "Get Device ID(s): 24채널 전부를 출력 HIGH 로 만든 뒤 지정 핀으로 IDCODE 읽기"),
        "T": (M, "bypass_test", "Test BYPASS: 24채널 전부를 출력 HIGH 로 만든 뒤 지정 핀으로 BYPASS 시험"),
        "Y": (D, "irdr_discovery", "IR/DR discovery: 모든 JTAG 명령어(벤더 비공개 포함)를 실행 — 영구 변경 가능"),
        "P": (D, "extest", "Pin mapper(EXTEST): 타깃 칩의 실제 핀을 구동 — 보드 회로가 움직일 수 있음"),
        "O": (D, "openocd_mode", "OpenOCD 영속 모드: EEPROM 에 기록되어 리셋 후에도 채널 0–24 를 HIGH 로 구동"),
    },
    "uart": {
        "U": (M, "scan.uart", f"UART Scan: {_PIN_DRIVE}, 후보 RXD 로 프로브 문자열 송신"),
        "T": (M, "scan.uart_txd", "UART TXD Scan: 채널을 입력으로 감시(수동) — 레벨 변환기가 켜져 타깃 쪽에 약한 풀업이 걸림"),
        "P": (D, "passthrough", "UART 패스스루: 이후 입력이 분류 없이 타깃 콘솔로 전달 — uart-mcp 를 사용"),
    },
    "gpio": {
        "R": (I, "gpio.read", "모든 채널 1회 읽기(입력, 레벨 변환기의 약한 풀업)"),
        "C": (I, "gpio.monitor", "모든 채널 연속 읽기(입력, 레벨 변환기의 약한 풀업)"),
        "W": (D, "gpio.write", "24채널 전부를 출력으로 구동"),
        "L": (D, "logic_analyzer_mode", "로직 분석기 영속 모드: EEPROM 에 기록되어 리셋 후에도 유지"),
    },
    "swd": {
        "I": (M, "scan.swd", f"SWD IDCODE Scan: {_PIN_DRIVE}"),
        "D": (M, "swd.device_id", "Get SWD Device ID: 지정 핀 구동"),
    },
}
SHARED_COMMANDS: dict[str, tuple[Risk, str, str]] = {
    "V": MENU_COMMANDS["main"]["V"],
    "H": (O, "help", "도움말 표시"),
    "M": (O, "nav.main", "메인 메뉴로 이동"),
}

SCAN_START_REASON = {
    "idcode": "IDCODE 스캔 시작",
    "bypass": "BYPASS 스캔 시작",
    "jtag": "JTAG Combined 스캔 시작",
    "uart": "UART 스캔 시작",
    "uart_txd": "UART TXD(수동) 스캔 시작",
}


def menu_command(menu: str | None, key: str) -> tuple[Risk, str, str] | None:
    table = MENU_COMMANDS.get(menu or "", {})
    entry = table.get(key.upper())
    if entry is None and menu not in (None, "main"):
        entry = SHARED_COMMANDS.get(key.upper())
    return entry


def classify_uart_probe(
    data: bytes | None,
    *,
    persistent_paths: Iterable[str] = (),
    unknown_risk: str | Risk = "modify",
) -> Classification:
    """UART 스캔 프로브 바이트를 대상 콘솔 입력으로 보고 분류 (U-Boot/Linux 문맥 미확정 → 둘 다 고려).

    스캔은 프로브를 보드레이트 21개 × 후보 핀마다 반복 송신하므로 맞는 핀·보드레이트에서 여러 번 실행될 수 있다.
    """
    if data is None:
        return Classification(D, "jtagulator.uart_probe.unknown", "프로브 문자열 내용을 확정할 수 없음", None, True)
    text = data.decode("latin-1")
    results: list[Classification] = []
    for ch in sorted(set(text)):
        if ch in CONTROL_CHAR_RISK:
            risk, reason = CONTROL_CHAR_RISK[ch]
            results.append(Classification(risk, "jtagulator.uart_probe.control", reason, repr(ch)))
    # 스캔은 같은 프로브를 순열마다(맞는 보드레이트에서) 반복 송신하므로, 줄 끝 없는 꼬리가 다음 송신의 첫 줄과 이어져
    # 대상 줄 버퍼에서 한 줄로 실행될 수 있다 (예: "_erase X\rflash" → 두 번째 송신에서 "flash_erase X").
    # 한 번 보낸 경우(기존 분류)와 두 번 이어 보낸 경우를 모두 조립해 분류한다 — 줄은 최대 두 송신에 걸치므로 두 번이면
    # '꼬리 + 다음 머리' 로 생기는 줄이 모두 나온다. 한 번 보낸 경우의 꼬리도 따로 분류해 기존보다 느슨해지지 않게 한다.
    for feed in (text, text + text):
        asm = LineAssembler()
        for ln in asm.feed(feed):
            if ln.uncertain:
                results.append(Classification(D, "jtagulator.uart_probe.uncertain", ln.reason or "제어 문자 포함", ln.text, True))
            else:
                results.append(classify_console_line(ln.text, "unknown", persistent_paths=persistent_paths, unknown_risk=unknown_risk))
        if asm.pending or asm.pending_uncertain:
            if asm.pending_uncertain:
                results.append(Classification(D, "jtagulator.uart_probe.uncertain", asm.pending_uncertain, asm.pending, True))
            else:
                c = classify_console_line(asm.pending, "unknown", persistent_paths=persistent_paths, unknown_risk=unknown_risk)
                results.append(
                    Classification(
                        c.risk, c.rule_id, f"줄 끝 없는 입력(반복 송신되면 대상 줄 버퍼에 누적): {c.reason}", c.matched, c.uncertain
                    )
                )
    w = worst(results, Classification(I, "jtagulator.uart_probe.empty", "빈 프로브"))
    return Classification(
        max(w.risk, I),
        f"jtagulator.uart_probe>{w.rule_id}",
        f"UART 스캔 프로브가 대상 콘솔로 송신됨: {w.reason}",
        repr(text),
        w.uncertain,
    )


def classify_scan_start(scan_kind: str | None, probe: Classification | None = None) -> Classification:
    if scan_kind not in SCAN_START_REASON:
        return Classification(D, "jtagulator.space.unknown-scan", "어떤 스캔이 시작될지 확정할 수 없음", " ", True)
    reason = SCAN_START_REASON[scan_kind]
    risk = M
    uncertain = False
    if probe is not None and scan_kind == "uart":
        risk = max(risk, probe.risk)
        uncertain = probe.uncertain
        reason += f" ({probe.reason})"
    rule = f"jtagulator.scan_start.{scan_kind}"
    return Classification(risk, rule, reason, " ", uncertain)


def classify_jtagulator(
    keys: str,
    ctx: DeviceContext,
    *,
    scan_kind: str | None = None,
    persistent_paths: Iterable[str] = (),
    unknown_risk: str | Risk = "modify",
) -> Classification:
    """현재 장치 상태(ctx)에서 keys 를 보냈을 때의 위험도.

    scan_kind 는 스페이스바 프롬프트에서 어떤 스캔이 시작되는지(드라이버가 직전에 보낸, 분류기를 통과한 메뉴 명령)이다.
    """
    unknown = Risk.parse(unknown_risk) if not isinstance(unknown_risk, Risk) else unknown_risk
    if not keys:
        return Classification(O, "jtagulator.empty", "보낼 키 없음")

    # Ctrl-X 재동기화: 어떤 상태에서든 취소/중단/종료/웨이크로만 작용한다 (줄에 0x18 이 섞이면 항상 무효 입력)
    if "\x18" in keys and set(keys) <= {"\x18", "\r"} and keys.count("\r") <= 1 and (keys.endswith("\r") or "\r" not in keys):
        return Classification(I, "jtagulator.resync", "Ctrl-X 재동기화(대화·스캔·패스스루·영속 모드 취소)", repr(keys))

    st = ctx.state
    # LF 1바이트: 스캔/모니터 중이면 중단, 줄 입력(메뉴·값·전압) 중이면 펌웨어가 버림, 스페이스바 대기에서는 무시(1.12)
    # 또는 취소(≤1.11.1). 상태를 모르면(패스스루일 수도 있음) 허용하지 않는다.
    if keys == "\n" and st in ("scanning", "menu", "value", "voltage", "space"):
        return Classification(I, "jtagulator.lf", "LF 1바이트 — 실행 중 스캔 중단 또는 줄 입력에서 무시됨", repr(keys))
    if st == "scanning":
        if len(keys) == 1:
            return Classification(I, "jtagulator.scan.abort", "실행 중인 스캔 중단 키", repr(keys))
        return Classification(D, "jtagulator.scan.multikey", "스캔 중 여러 바이트 — 첫 바이트 뒤는 메뉴 입력으로 해석될 수 있음", repr(keys), True)

    if st == "space":
        if keys == " ":
            # 펌웨어가 어떤 명령의 스페이스바 대기인지는 출력만으로 알 수 없으므로 드라이버가 알려 준 scan_kind 를 쓴다
            return classify_scan_start(scan_kind)
        if len(keys) == 1:
            return Classification(O, "jtagulator.space.abort", "스캔 시작 대기 취소(스페이스가 아닌 키)", repr(keys))
        return Classification(D, "jtagulator.space.multikey", "스페이스바 대기에 여러 바이트", repr(keys), True)

    if st not in ("menu", "value", "voltage"):
        return Classification(D, "jtagulator.unknown-state", f"장치 상태를 확정할 수 없음: {ctx.describe()}", repr(keys), True)

    maxlen = MAX_LEN_UART_USER if (st == "value" and ctx.kind == "uart_text") else MAX_LEN_CMD
    line, terminated = effective_line(keys, maxlen)
    if not terminated or keys.index("\r") != len(keys) - 1:
        return Classification(D, "jtagulator.line.incomplete", "줄 끝(CR) 없음 또는 여러 줄 — 실제 입력을 확정할 수 없음", repr(keys), True)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in keys[:-1]):
        return Classification(D, "jtagulator.line.control", "입력 줄에 제어 문자가 섞여 실제 입력을 확정할 수 없음", repr(keys), True)

    if st == "menu":
        if len(line) != 1:
            return Classification(O, "jtagulator.menu.invalid", "한 글자가 아닌 입력 — 펌웨어가 무효 명령으로 처리", line)
        entry = menu_command(ctx.menu, line)
        if entry is not None:
            risk, rule, reason = entry
            return Classification(risk, f"jtagulator.{ctx.menu}.{rule}", reason, line)
        if not line.isalpha():
            return Classification(O, "jtagulator.menu.invalid", "명령이 아닌 글자 — 펌웨어가 무효 명령으로 처리", line)
        return Classification(unknown, "jtagulator.menu.unknown", f"분류 규칙에 없는 명령 '{line}' (펌웨어 버전에 따라 새 명령일 수 있음)", line, True)

    if st == "voltage":
        v = voltage_tenths(line)
        lo = round((ctx.vmin or VTARGET_MIN_TENTHS / 10) * 10)
        hi = round((ctx.vmax or VTARGET_MAX_TENTHS / 10) * 10)
        if v == 0:
            return Classification(
                D, "jtagulator.voltage.off",
                "VADJ 끄기 — 타깃 전원이 켜져 있으면 채널 클램프 다이오드로 전류가 흐를 수 있음", line,
            )
        if lo <= v <= hi:
            return Classification(
                D, "jtagulator.voltage.set",
                f"타깃 I/O 전압을 {v // 10}.{v % 10} V 로 설정 — 타깃의 실제 I/O 전압과 다르면 타깃을 손상시킬 수 있음", line,
            )
        return Classification(I, "jtagulator.voltage.rejected", "펌웨어가 범위 밖 값으로 거부함(전압 변경 없음)", line)

    # st == "value"
    label = ctx.label or ""
    if ctx.kind == "uart_text":
        probe = classify_uart_probe(decode_uart_text_answer(line), persistent_paths=persistent_paths, unknown_risk=unknown_risk)
        return Classification(max(I, probe.risk), probe.rule_id, probe.reason, line, probe.uncertain)
    if label in DANGEROUS_VALUE_PROMPTS:
        return Classification(D, "jtagulator.dialog.dangerous", f"{label}: {DANGEROUS_VALUE_PROMPTS[label]}", line)
    if ctx.kind is not None or label in BENIGN_VALUE_PROMPTS:
        return Classification(I, f"jtagulator.dialog.{ctx.kind or 'answer'}", f"스캔 설정 입력 ({label})", line)
    if any(c.isdigit() for c in line):
        return Classification(
            D, "jtagulator.dialog.unknown-numeric",
            f"알 수 없는 프롬프트 '{label}' 에 숫자 입력 — 전압 등 위험한 설정일 수 있음", line, True,
        )
    return Classification(unknown, "jtagulator.dialog.unknown", f"알 수 없는 프롬프트 '{label}'", line, True)
