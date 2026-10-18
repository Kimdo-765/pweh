"""JTAGulator 스캔 출력 파서와 결과 요약.

입력은 장치가 보낸 원시 텍스트(latin-1 디코딩)다. 파싱 전에 줄바꿈을 정규화한다(``\\r\\n``/``\\r`` → ``\\n``).
결과 블록은 항상 줄 맨 앞에서 시작하고(펌웨어가 ``\\r\\n`` 을 먼저 출력), 진행 표시 ``-`` 는 자기 줄을 따로 차지한다.
입력 에코는 프롬프트 줄 끝에 붙지만 결과 정규식이 줄 전체에 앵커되어 있어 영향을 받지 않는다.

부분 출력(스캔 진행 중, 중단, 연결 끊김)에서도 완성된 블록만 안전하게 해석한다.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import Any

from .jep106 import decode_idcode, openocd_target_hints

M = re.M

RE_JTAG_BLOCK = re.compile(
    r"^TDI: (?P<tdi>N/A|\d+)\nTDO: (?P<tdo>\d+)\nTCK: (?P<tck>\d+)\nTMS: (?P<tms>\d+)\n"
    r"(?P<body>(?:(?:Device ID #\d+: [^\n]*|TRST#: \d+|Number of devices detected: \d+)\n)*)",
    M,
)
RE_DEVICE_ID = re.compile(
    r"^Device ID #(?P<n>\d+): (?P<ver>[01]{4}) (?P<part>[01]{16}) (?P<mfg>[01]{11}) (?P<fixed>[01]) "
    r"\(0x(?P<idcode>[0-9A-Fa-f]{8})\)$",
    M,
)
RE_ID_DETAIL = re.compile(
    r"^-> Manufacturer ID: 0x(?P<mfg>[0-9A-Fa-f]{3})\n-> Part Number: 0x(?P<part>[0-9A-Fa-f]{4})\n"
    r"-> Version: 0x(?P<ver>[0-9A-Fa-f])$",
    M,
)
RE_TRST = re.compile(r"^TRST#: (?P<trst>\d+)$", M)
RE_NDEV = re.compile(r"^Number of devices detected: (?P<n>\d+)$", M)
RE_UART_BLOCK = re.compile(
    r"^TXD: (?P<txd>\d+)\nRXD: (?P<rxd>\d+|N/A)\nBaud: (?P<baud>\d+)\nData: (?P<rest>[^\n]*)$",
    M,
)
RE_UART_DATA = re.compile(r"^(?P<ascii>.*) \[ (?P<hex>(?:[0-9A-Fa-f]{2} )+)\]$")
RE_UART_TXD_BLOCK = re.compile(
    r"^TXD: (?P<txd>\d+)\nBaud \(Measured\): (?P<measured>\d+)\nBaud \(Best Fit\): (?P<bestfit>\d+|N/A)$",
    M,
)
RE_BYPASS_TEST = re.compile(
    r"^Number of devices detected: (?P<n>\d+)\nPattern in to TDI: +(?P<pin>[01]{32})\n"
    r"Pattern out from TDO: +(?P<pout>[01]{32})\n(?P<result>Match!|No Match!)$",
    M,
)
RE_GPIO_LINE = re.compile(
    r"^CH23\.\.CH0: (?P<b23_16>[01]{8}) (?P<b15_8>[01]{8}) (?P<b7_0>[01]{8})  \(0x(?P<hex>[0-9A-Fa-f]{6})\)$", M
)
RE_PERMS = re.compile(r"^Possible permutations: (?P<n>\d+)$", M)
RE_V_CURRENT = re.compile(r"^Current target I/O voltage: (?P<v>Undefined|\d\.\d)$", M)
RE_V_SET = re.compile(r"^New target I/O voltage set: (?P<v>\d\.\d)$", M)
RE_V_OFF = re.compile(r"^Target I/O voltage off\.$", M)
RE_VERSION = re.compile(r"^JTAGulator FW (?P<ver>\d+(?:\.\d+)+)$", M)
RE_COMPLETE = re.compile(r"^(?P<scan>IDCODE|JTAG combined|JTAG|BYPASS|RTCK|UART|UART TXD) scan complete\.$", M)
RE_ABORTED = re.compile(r"^(?P<scan>IDCODE|JTAG combined|JTAG|BYPASS|RTCK|UART) scan aborted!$", M)
RE_LISTING_DONE = re.compile(r"^IDCODE listing complete\.$", M)
RE_ERROR = re.compile(
    r"^(?P<err>Target I/O voltage must be defined!|Value out of range!|Pin numbers must be unique!|"
    r"No target device\(s\) found!|More than one device detected in the chain!|Too many devices in the chain!|"
    r"EEPROM not responding!)$",
    M,
)
RE_INVALID = re.compile(r"^\?(?: Press 'H' for available commands\.)?$", M)
RE_NOISE = re.compile(r"^[-|]+$", M)

# 스캔 종류 → 완료/중단 문구의 scan 이름 (FW 1.10–1.11.1 의 'JTAG' 포함)
SCAN_DONE_NAMES = {
    "idcode": ("IDCODE",),
    "bypass": ("BYPASS",),
    "jtag": ("JTAG combined", "JTAG"),
    "uart": ("UART",),
    "uart_txd": ("UART TXD",),
}

ERROR_HINTS = {
    "Target I/O voltage must be defined!": "장치의 타깃 I/O 전압이 설정되어 있지 않습니다(리셋되었을 수 있음). jtagulator_set_voltage 를 다시 수행해야 합니다.",
    "Value out of range!": "장치가 입력값을 범위 밖으로 거부했습니다.",
    "Pin numbers must be unique!": "핀 번호가 겹칩니다.",
    "EEPROM not responding!": "JTAGulator EEPROM 오류 — 장치 점검 필요.",
}

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
STANDARD_BAUDS = (115200, 57600, 38400, 19200, 9600)
CONSOLE_HINT_RE = re.compile(
    rb"(?i)(login|password|u-boot|busybox|linux|root@|uboot|hisilicon|starting kernel|command not found|"
    rb"unknown command|autoboot|# ?$|\$ ?$|> ?$)"
)


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------
# 원시 블록 파서
# ---------------------------------------------------------------------------


def parse_device_id_line(m: re.Match[str]) -> dict[str, Any]:
    value = int(m.group("idcode"), 16)
    dev = decode_idcode(value)
    dev["index"] = int(m.group("n"))
    # 2진수 필드가 hex 값과 일치하는지 검사 (전송 오류/잡음 검출)
    bits = int(m.group("ver") + m.group("part") + m.group("mfg") + m.group("fixed"), 2)
    if bits != value:
        dev.setdefault("notes", []).append("2진수 필드와 hex 값이 일치하지 않음 — 수신 데이터 손상 가능")
        dev["plausible"] = False
    return dev


def parse_jtag_blocks(text: str) -> list[dict[str, Any]]:
    """TDI/TDO/TCK/TMS 결과 블록 목록 (IDCODE/BYPASS/Combined 공통)."""
    norm = normalize(text)
    blocks: list[dict[str, Any]] = []
    for m in RE_JTAG_BLOCK.finditer(norm):
        body = m.group("body")
        devices = [parse_device_id_line(dm) for dm in RE_DEVICE_ID.finditer(body)]
        trst = [int(t.group("trst")) for t in RE_TRST.finditer(body)]
        nd = RE_NDEV.search(body)
        blocks.append(
            {
                "tdi": None if m.group("tdi") == "N/A" else int(m.group("tdi")),
                "tdo": int(m.group("tdo")),
                "tck": int(m.group("tck")),
                "tms": int(m.group("tms")),
                "devices": devices,
                "trst_candidates": trst,
                "device_count": int(nd.group("n")) if nd else None,
            }
        )
    return blocks


def parse_uart_data(rest: str) -> dict[str, Any] | None:
    m = RE_UART_DATA.match(rest)
    if not m:
        return None
    hex_bytes = m.group("hex").split()
    data = bytes(int(h, 16) for h in hex_bytes)
    ascii_part = m.group("ascii")
    out: dict[str, Any] = {"data_hex": data.hex().upper(), "data_ascii": ascii_part, "length": len(data), "_bytes": data}
    if len(ascii_part) != len(data):
        out["notes"] = ["ASCII 부분과 hex 바이트 수가 다름 — hex 값을 기준으로 함"]
    return out


def parse_uart_hits(text: str) -> list[dict[str, Any]]:
    norm = normalize(text)
    hits: list[dict[str, Any]] = []
    for m in RE_UART_BLOCK.finditer(norm):
        d = parse_uart_data(m.group("rest"))
        if d is None:
            continue  # 줄이 아직 덜 왔거나 손상됨
        hit = {
            "txd": int(m.group("txd")),
            "rxd": None if m.group("rxd") == "N/A" else int(m.group("rxd")),
            "baud": int(m.group("baud")),
            **d,
        }
        hits.append(hit)
    return hits


def parse_txd_hits(text: str) -> list[dict[str, Any]]:
    norm = normalize(text)
    out = []
    for m in RE_UART_TXD_BLOCK.finditer(norm):
        bf = m.group("bestfit")
        out.append({"txd": int(m.group("txd")), "baud_measured": int(m.group("measured")), "baud_best_fit": None if bf == "N/A" else int(bf)})
    return out


def parse_device_id_listing(text: str) -> list[dict[str, Any]]:
    """'D'(Get Device IDs) 출력: Device ID 줄 + 상세(-> Manufacturer ID ...)."""
    norm = normalize(text)
    devices = []
    for m in RE_DEVICE_ID.finditer(norm):
        dev = parse_device_id_line(m)
        detail = RE_ID_DETAIL.match(norm, m.end() + 1) if m.end() + 1 <= len(norm) else None
        if detail:
            dev["firmware_detail"] = {
                "manufacturer_id": "0x" + detail.group("mfg").upper(),
                "part_number": "0x" + detail.group("part").upper(),
                "version": "0x" + detail.group("ver").upper(),
            }
        devices.append(dev)
    return devices


def parse_bypass_test(text: str) -> dict[str, Any] | None:
    norm = normalize(text)
    m = RE_BYPASS_TEST.search(norm)
    if m:
        return {
            "device_count": int(m.group("n")),
            "pattern_in": m.group("pin"),
            "pattern_out": m.group("pout"),
            "match": m.group("result") == "Match!",
        }
    nd = RE_NDEV.search(norm)
    if nd:
        return {"device_count": int(nd.group("n")), "match": False}
    return None


def parse_gpio_reads(text: str) -> list[int]:
    """GPIO 'R' 출력 줄(CH23..CH0) 목록 → 24비트 값 목록. 2진수와 hex 가 다르면 그 줄은 버린다(손상)."""
    norm = normalize(text)
    out = []
    for m in RE_GPIO_LINE.finditer(norm):
        value = int(m.group("hex"), 16)
        if int(m.group("b23_16") + m.group("b15_8") + m.group("b7_0"), 2) == value:
            out.append(value)
    return out


def summarize_gpio(values: list[int]) -> dict[str, Any]:
    """채널별 마지막 레벨과, 표본 사이에 값이 바뀐(활동이 있는) 채널."""
    if not values:
        return {"samples": 0, "channels": {}, "low_channels": [], "toggling_channels": []}
    last = values[-1]
    changed = 0
    for a, b in zip(values, values[1:]):
        changed |= a ^ b
    channels = {str(ch): (last >> ch) & 1 for ch in range(24)}
    return {
        "samples": len(values),
        "last_value_hex": f"0x{last:06X}",
        "values_hex": [f"0x{v:06X}" for v in values],
        "channels": channels,
        "low_channels": [ch for ch in range(24) if not (last >> ch) & 1],
        "toggling_channels": [ch for ch in range(24) if (changed >> ch) & 1],
        "notes": [
            "입력 채널은 레벨 변환기 때문에 연결되지 않으면 HIGH(1)로 읽힌다. LOW 로 고정된 채널은 GND/구동 중인 신호일 수 있다.",
            "UART TXD 는 유휴 시 HIGH 이며, 송신 중이면 표본 사이에 값이 바뀌어 toggling_channels 에 나타날 수 있다(짧은 표본은 놓칠 수 있음).",
        ],
    }


def parse_status(text: str, scan_kind: str | None = None) -> dict[str, Any]:
    """완료/중단/오류 메시지 해석."""
    norm = normalize(text)
    names = SCAN_DONE_NAMES.get(scan_kind or "", None)
    completed = False
    aborted = False
    for m in RE_COMPLETE.finditer(norm):
        if names is None or m.group("scan") in names:
            completed = True
    for m in RE_ABORTED.finditer(norm):
        if names is None or m.group("scan") in names:
            aborted = True
    errors = [m.group("err") for m in RE_ERROR.finditer(norm)]
    perms = RE_PERMS.search(norm)
    return {
        "completed": completed,
        "aborted": aborted,
        "no_device_found": "No target device(s) found!" in errors,
        "errors": [e for e in errors if e != "No target device(s) found!"],
        "invalid_command": bool(RE_INVALID.search(norm)),
        "permutations": int(perms.group("n")) if perms else None,
        "banner_seen": "Welcome to JTAGulator." in norm,
    }


def count_progress(text: str) -> int:
    """진행 표시 '-' 개수 (스캔 시작 표식 뒤 텍스트에서). 결과 줄 안의 '-' 는 세지 않는다."""
    norm = normalize(text)
    return sum(len(m.group(0)) - m.group(0).count("|") for m in RE_NOISE.finditer(norm))


def first_error(text: str) -> str | None:
    errs = parse_status(text)["errors"]
    return errs[0] if errs else None


# ---------------------------------------------------------------------------
# 요약 / 후보 순위
# ---------------------------------------------------------------------------


def summarize_jtag(blocks: list[dict[str, Any]], kind: str, openocd_scripts: str | None = None) -> dict[str, Any]:
    agg: dict[tuple[Any, ...], dict[str, Any]] = {}
    for b in blocks:
        key = (b["tdi"], b["tdo"], b["tck"], b["tms"])
        a = agg.get(key)
        if a is None:
            a = {
                "tdi": b["tdi"], "tdo": b["tdo"], "tck": b["tck"], "tms": b["tms"],
                "hits": 0, "trst_candidates": [], "devices": [], "device_count": None,
            }
            agg[key] = a
        a["hits"] += 1
        for t in b["trst_candidates"]:
            if t not in a["trst_candidates"]:
                a["trst_candidates"].append(t)
        known = {d["idcode"] for d in a["devices"]}
        for d in b["devices"]:
            if d["idcode"] not in known:
                a["devices"].append(d)
                known.add(d["idcode"])
        if b["device_count"] is not None:
            a["device_count"] = b["device_count"]
    pinouts = list(agg.values())
    for p in pinouts:
        p["plausible_devices"] = sum(1 for d in p["devices"] if d.get("plausible"))
        p["known_manufacturer"] = any(d.get("manufacturer") for d in p["devices"] if d.get("plausible"))
        if openocd_scripts:
            for d in p["devices"]:
                if d.get("plausible"):
                    hint = openocd_target_hints(int(d["idcode"], 16), openocd_scripts)
                    if hint and hint.get("count"):
                        d["openocd_configs"] = hint

    def score(p: dict[str, Any]) -> tuple[Any, ...]:
        return (
            p["known_manufacturer"],
            p["plausible_devices"] > 0,
            (p["device_count"] or 0) > 0,
            p["tdi"] is not None,
            p["hits"],
        )

    pinouts.sort(key=score, reverse=True)
    best = None
    for p in pinouts:
        if kind == "bypass" and (p["device_count"] or 0) > 0:
            best = p
            break
        if kind in ("idcode", "jtag") and p["plausible_devices"] > 0:
            best = p
            break
    notes: list[str] = []
    if not pinouts:
        notes.append("결과 없음: GND 공통 연결, 채널 연결, 전압 설정, 타깃 전원을 확인하세요. JTAG 이 비활성(퓨즈)일 수도 있습니다.")
    if kind == "idcode" and pinouts:
        notes.append(
            "IDCODE 스캔은 TDI 를 찾지 못합니다(TDI: N/A). TDO/TCK/TMS 를 known_pins 로 넣어 jtagulator_bypass_scan 을 돌리거나 "
            "jtagulator_jtag_scan(Combined)으로 TDI 를 찾으세요."
        )
    if len(pinouts) > 1:
        notes.append("여러 핀아웃이 검출됨 — 타깃이 엉뚱하게 응답한 오탐이 섞일 수 있으니 사람이 확인하세요.")
    if any(p["trst_candidates"] for p in pinouts):
        notes.append("TRST# 후보는 해당 채널을 LOW 로 했을 때 응답이 바뀐 채널이며 참고용입니다(리셋/부트모드 핀일 수도 있음).")
    return {"pinouts": pinouts, "best": best, "count": len(pinouts), "notes": notes}


def _uart_score(hit: dict[str, Any]) -> tuple[float, float, bool, bool]:
    data: bytes = hit.get("_bytes") or bytes.fromhex(hit.get("data_hex", ""))
    if not data:
        return 0.0, 0.0, False, False
    printable = sum(1 for b in data if b in PRINTABLE) / len(data)
    newline = (b"\r" in data) or (b"\n" in data)
    keyword = bool(CONSOLE_HINT_RE.search(data))
    std = hit.get("baud") in STANDARD_BAUDS
    score = 0.6 * printable + 0.2 * newline + 0.15 * keyword + 0.05 * std
    return round(score, 3), round(printable, 3), newline, keyword


def summarize_uart(hits: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[int, Any], list[dict[str, Any]]] = {}
    clean_hits = []
    for h in hits:
        score, printable, newline, keyword = _uart_score(h)
        hh = {k: v for k, v in h.items() if not k.startswith("_")}
        hh.update({"score": score, "printable_ratio": printable, "has_newline": newline, "console_keyword": keyword})
        clean_hits.append(hh)
        groups.setdefault((h["txd"], h["rxd"]), []).append(hh)
    candidates = []
    for (txd, rxd), items in groups.items():
        items.sort(key=lambda x: x["score"], reverse=True)
        top = items[0]
        if top["printable_ratio"] >= 0.9 and (top["has_newline"] or top["console_keyword"]):
            conf = "high"
        elif top["printable_ratio"] >= 0.75:
            conf = "medium"
        else:
            conf = "low"
        candidates.append(
            {
                "txd": txd,
                "rxd": rxd,
                "baud": top["baud"],
                "confidence": conf,
                "score": top["score"],
                "sample_ascii": top["data_ascii"],
                "sample_hex": top["data_hex"],
                "bauds_seen": sorted({i["baud"] for i in items}),
                "hits": len(items),
            }
        )
    candidates.sort(key=lambda c: ({"high": 2, "medium": 1, "low": 0}[c["confidence"]], c["score"], c["hits"]), reverse=True)
    best = candidates[0] if candidates and candidates[0]["confidence"] != "low" else None
    notes = ["UART 핀 이름은 타깃 기준: TXD = 타깃이 송신하는 핀(USB-UART 의 RX 에 연결), RXD = 타깃이 수신하는 핀(USB-UART 의 TX 에 연결)."]
    if not candidates:
        notes.append(
            "응답 없음: 타깃이 프로브에 반응하지 않았거나 보드레이트가 표(300–307200)에 없을 수 있습니다. "
            "jtagulator_uart_txd_scan(수동, 자동 보드레이트 측정)으로 TXD 를 먼저 찾아보세요."
        )
    elif best is None:
        notes.append("읽을 수 있는 응답이 없음 — 잘못된 보드레이트의 깨진 데이터일 수 있습니다. printable_only=true 로 다시 시도하거나 TXD 스캔을 쓰세요.")
    if len(candidates) > 1:
        notes.append("여러 핀 쌍에서 응답 — 신뢰도와 샘플 데이터를 보고 사람이 확인하세요.")
    return {"hits": clean_hits, "candidates": candidates, "best": best, "count": len(candidates), "notes": notes}


def summarize_txd(hits: list[dict[str, Any]]) -> dict[str, Any]:
    by_txd: dict[int, list[dict[str, Any]]] = {}
    for h in hits:
        by_txd.setdefault(h["txd"], []).append(h)
    candidates = []
    for txd, items in by_txd.items():
        fits = Counter(i["baud_best_fit"] for i in items if i["baud_best_fit"])
        measured = [i["baud_measured"] for i in items]
        best_fit, n_fit = (fits.most_common(1)[0] if fits else (None, 0))
        candidates.append(
            {
                "txd": txd,
                "baud": best_fit,
                "baud_measured_median": int(statistics.median(measured)) if measured else None,
                "detections": len(items),
                "best_fit_agreement": round(n_fit / len(items), 2) if items else 0.0,
                "best_fit_counts": {str(k): v for k, v in fits.most_common()},
            }
        )
    candidates.sort(key=lambda c: (c["baud"] is not None, c["detections"], c["best_fit_agreement"]), reverse=True)
    notes = []
    if not candidates:
        notes.append("UART 활동 없음: 타깃이 스캔 동안 아무것도 송신하지 않았습니다. 스캔 중에 타깃 전원을 다시 넣어 부팅 로그가 나오게 하세요.")
    else:
        notes.append("TXD 만 찾습니다. RXD 는 jtagulator_uart_scan(known_pins={'txd': N})으로 찾거나 USB-UART 로 직접 확인하세요.")
    return {"hits": hits, "candidates": candidates, "best": candidates[0] if candidates else None, "count": len(candidates), "notes": notes}
