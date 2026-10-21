"""반복 UART 프로브 입력의 공용 위험도 분류. 기존 규칙 ID를 보존한다."""

from __future__ import annotations

from typing import Iterable

from .classifiers import CONTROL_CHAR_RISK, LineAssembler, classify_console_line
from .risk import Classification, Risk, worst

I, D = Risk.INTERACT, Risk.DESTRUCTIVE

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


