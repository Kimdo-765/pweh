"""UART 보드레이트 자동 탐지 (포트를 한 번 열고 같은 연결의 속도를 바꿔 수신 데이터를 점수화).

기기가 출력 중이어야 한다(사람이 전원을 꺼 둔 상태에서 호출하고, 호출이 시작되면 전원을 넣는다). probe="ctrl-c" 면 후보마다 0x03 을 한 번 보내
U-Boot/셸 프롬프트의 응답을 유도한다. 잘못된 속도로 보낸 0x03 은 기기에서 다른 바이트로 읽힐 수 있다
(8N1 파형상 L*H*L*H* 꼴만 가능 → CR/LF 는 될 수 없지만 0x04(Ctrl-D), 0x1C 등은 가능) → 도구는 MODIFY 로 분류한다.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from pweh.errors import PwehError
from pweh.serialtransport import SerialOpenError

from .session import PortSettings, open_serial
from .textutil import printable_ratio

KEYWORDS: tuple[bytes, ...] = (
    b"U-Boot", b"Linux", b"login", b"Starting kernel", b"DRAM", b"autoboot", b"BusyBox", b"mtd", b"console",
    b"<INTERRUPT>", b"Kernel", b"Uncompressing", b"SPI", b"Flash", b"Password", b"Freeing", b"init", b"Booting",
    b"MiB", b"bootargs", b"Environment", b"version", b"Hit any key", b"Please press Enter", b"not found", b"CPU",
)
STANDARD_BAUDS = (300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000, 576000, 921600,
                  1000000, 1152000, 1500000, 2000000, 2500000, 3000000)
MAX_TOTAL_SECONDS = 50.0


def score_sample(data: bytes) -> dict[str, Any]:
    """출력 가능 문자 비율 × 데이터 양 × (부팅 키워드/단어) — 0~1."""
    n = len(data)
    if n == 0:
        return {"score": 0.0, "bytes": 0, "printable_ratio": 0.0, "keyword_hits": [], "lines": 0}
    pr = printable_ratio(data)
    high = sum(1 for b in data if b >= 0x80) / n
    nul_ff = sum(1 for b in data if b in (0x00, 0xFF)) / n
    lines = data.count(b"\n")
    hits = sorted({k.decode() for k in KEYWORDS if k in data})
    words = len(re.findall(rb"[A-Za-z]{3,}", data))
    runs = len(re.findall(rb"(?:\x00{4,}|\xff{4,})", data))  # 긴 0x00/0xFF 연속은 잘못된 속도·배선 문제의 전형
    quality = pr * (1.0 - nul_ff) * (1.0 - 0.5 * high) * max(0.2, 1.0 - 0.1 * runs)
    amount = min(1.0, n / 24.0)
    evidence = max(min(1.0, len(hits) / 2.0), min(1.0, words / 8.0) * 0.8)
    structure = 1.0 if lines else 0.85
    score = quality * (0.5 + 0.5 * amount) * (0.6 + 0.4 * evidence) * structure
    return {"score": round(min(1.0, score), 3), "bytes": n, "printable_ratio": round(pr, 3), "high_bit_ratio": round(high, 3),
            "nul_ff_ratio": round(nul_ff, 3), "keyword_hits": hits, "lines": lines}


def _sample_text(data: bytes, limit: int = 160) -> str:
    text = data.decode("latin-1")
    out = "".join(c if (0x20 <= ord(c) < 0x7F or c in "\n\t") else ("" if c == "\r" else "·") for c in text)
    out = re.sub(r"\n{2,}", "\n", out).strip()
    return out[:limit]


def detect(port: str, candidates: list[int], listen_seconds: float, probe: str, *,
           bytesize: int = 8, parity: str = "N", stopbits: float = 1,
           cancel: Callable[[], bool] | None = None, early_stop: bool = True,
           before_io: Callable[[], Any] | None = None, route: Any = None, lease: Any = None,
           on_transport: Callable[[Any], None] | None = None) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    t0 = time.monotonic()
    truncated = False
    errors: list[str] = []
    ser = None
    try:
        if not candidates or (cancel is not None and cancel()):
            raise PwehError("보드레이트 탐지를 취소했습니다.", code="cancelled")
        settings = PortSettings(port=port, baudrate=int(candidates[0]), bytesize=bytesize, parity=parity,
                                stopbits=stopbits, dtr=False, rts=False)
        if before_io is not None:
            before_io()
        try:
            ser = open_serial(settings, timeout=0.05, before_io=before_io, route=route, lease=lease)
        except SerialOpenError as exc:
            ser = exc.transport
            if on_transport is not None:
                on_transport(ser)
            raise
        if on_transport is not None:
            on_transport(ser)
        for baud in candidates:
            if cancel is not None and cancel():
                break
            if time.monotonic() - t0 + listen_seconds > MAX_TOTAL_SECONDS:
                truncated = True
                break
            if before_io is not None:
                before_io()  # 속도 변경 전 확인. 거부를 후보 실패로 삼키지 않는다.
            try:
                ser.baudrate = int(baud)
            except (ValueError, NotImplementedError) as exc:
                errors.append(f"{baud}: {exc}")
                continue
            ser.reset_input_buffer()
            if probe == "ctrl-c":
                if cancel is not None and cancel():
                    break
                if before_io is not None:
                    before_io()
                ser.write(b"\x03")
                ser.flush()
            data = bytearray()
            end = time.monotonic() + listen_seconds
            while time.monotonic() < end:
                if cancel is not None and cancel():
                    break
                chunk = ser.read(min(4096, 256 * 1024 - len(data)))
                if chunk:
                    data += chunk
                    if len(data) >= 256 * 1024:
                        break
            sc = score_sample(bytes(data))
            sc.update({"baudrate": int(baud), "sample": _sample_text(bytes(data))})
            results.append(sc)
            if early_stop and sc["score"] >= 0.85 and sc["keyword_hits"]:
                break
    finally:
        if ser is not None:
            ser.close()  # 미확인 close는 caller가 handle+lease를 보존하도록 그대로 전파한다.
    ranked = sorted(results, key=lambda r: (-r["score"], -r["bytes"]))
    best = None
    if ranked:
        top = ranked[0]
        second = ranked[1]["score"] if len(ranked) > 1 else 0.0
        if top["score"] >= 0.5:
            best = top
        elif top["printable_ratio"] >= 0.9 and top["bytes"] >= 3 and top["lines"] >= 1 and second < top["score"] * 0.5:
            best = top  # 짧지만 깨끗한 응답(예: 셸 프롬프트)이 한 후보에서만 나옴
    total_bytes = sum(r["bytes"] for r in results)
    out: dict[str, Any] = {
        "candidates": ranked,
        "best": best["baudrate"] if best else None,
        "confidence": best["score"] if best else (ranked[0]["score"] if ranked else 0.0),
        "tested": [r["baudrate"] for r in results],
        "elapsed_seconds": round(time.monotonic() - t0, 2),
    }
    if truncated:
        out["truncated"] = True
        out["note"] = f"총 시간 제한({MAX_TOTAL_SECONDS:.0f}s) 때문에 일부 후보를 시험하지 못했습니다. candidates 를 줄여 다시 호출하세요."
    if errors:
        out["errors"] = errors[:10]
    if total_bytes == 0:
        out["hint"] = ("어떤 보드레이트에서도 수신 데이터가 없습니다. (1) 기기가 지금 출력 중인지 — 사람에게 전원을 먼저 꺼 두게 하고, 호출이 시작되면 전원을 넣게 한다 (probe=\"none\" 권장), "
                       "(2) TX/RX 가 뒤바뀌지 않았는지(어댑터 RX ↔ 기기 TX), (3) GND 연결, (4) 전압 레벨(3.3V/1.8V, 어댑터 VCC 는 연결하지 않음), "
                       "(5) 다른 패드일 가능성 — 로직 애널라이저(sigrok_estimate_baud)나 JTAGulator TXD 스캔으로 확인하세요.")
    elif best is None:
        out["hint"] = ("데이터는 들어오지만 어떤 후보에서도 읽을 수 있는 텍스트가 아닙니다. 목록에 없는 속도(예: 1500000, 3000000), 반전 신호, "
                       "노이즈/GND 불량, 전압 레벨 문제일 수 있습니다. sigrok_estimate_baud 로 실제 비트 폭을 측정하세요.")
    else:
        out["hint"] = f"uart_open(port, baudrate={best['baudrate']}) 로 세션을 여세요."
    return out
