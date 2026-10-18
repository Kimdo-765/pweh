"""로직 신호 파일 리더 (순수 Python, numpy 없음): sigrok srzip(.sr v2) / VCD → 채널별 에지 목록.

srzip v2 (libsigrok 0.5.2 ``src/output/srzip.c``, ``src/session_file.c``, ``src/session_driver.c``):
  - zip 안의 ``version``(ASCII '2', 1 도 허용), ``metadata``(GKeyFile/INI), 로직 청크 ``logic-1-1``, ``logic-1-2``, …
    (번호가 끊길 때까지 순서대로; 구형은 ``logic-1`` 단일 파일), 아날로그 ``analog-1-<N>-<k>``(float32).
  - ``[device 1]``: ``capturefile=logic-1``, ``total probes``, ``samplerate=1 MHz``, ``total analog``,
    ``probe<N>=<이름>`` (N = 채널 인덱스+1 → **비트 위치 N-1**, 비활성 채널은 키 없음), ``unitsize``.
  - 샘플 s 의 채널 b 값 = ``(data[s*unitsize + b//8] >> (b % 8)) & 1``.
VCD (IEEE 1364; libsigrok ``src/input/vcd.c`` 와 같은 해석):
  - ``$timescale`` → tick 주기, ``$var <type> <size> <id> <name> [<idx>]``, ``#<t>`` 타임스탬프,
    값 ``0/1/x/z<id>`` (x/z 는 0 으로 간주, 개수 보고), ``b<bits> <id>``, ``r<real> <id>``(무시).
  - 타임스탬프와 값이 같은 줄에 있어도(sigrok 출력) 별도 줄이어도(표준) 된다. 첫 타임스탬프가 샘플 0.

에지(edge) = 레벨이 바뀌는 tick 위치(바뀐 뒤 첫 샘플). 큰 파일은 청크 단위로 흘려 읽고, 에지 수/처리 바이트 상한을 둔다.
"""

from __future__ import annotations

import configparser
import math
import re
import zipfile
from array import array
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterator

from pweh.errors import NotFound, ValidationFailed

DEFAULT_MAX_EDGES = 2_000_000
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024  # 압축 해제 기준 처리 상한 (1 GiB)
BLOCK_BYTES = 4 * 1024 * 1024


@dataclass
class ChannelRef:
    name: str
    index: int  # srzip: 비트 위치(probeN-1), vcd: $var 선언 순서
    kind: str = "logic"
    sigrok_supported: bool = True  # vcd: sigrok 입력 모듈이 읽는 형식(wire/reg 1비트)인지

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "index": self.index, "kind": self.kind}
        if not self.sigrok_supported:
            d["sigrok_supported"] = False
        return d


@dataclass
class SignalInfo:
    path: str
    format: str  # "srzip" | "vcd"
    channels: list[ChannelRef]
    tick_hz: float | None  # 에지 위치 단위(tick)의 초당 개수: srzip=samplerate, vcd=1/timescale
    samplerate: float | None  # 실제 샘플링 해상도(Hz). vcd 는 sigrok 주석/추정값
    start_tick: int = 0
    end_tick: int | None = None  # 데이터 끝(tick, 배타적)
    unitsize: int | None = None
    analog_channels: list[str] = field(default_factory=list)
    chunk_names: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_samples(self) -> int | None:
        if self.end_tick is None:
            return None
        if self.format == "srzip":
            return self.end_tick - self.start_tick
        if self.samplerate and self.tick_hz:
            return int(round((self.end_tick - self.start_tick) * self.samplerate / self.tick_hz))
        return None

    @property
    def duration_s(self) -> float | None:
        if self.end_tick is None or not self.tick_hz:
            return None
        return (self.end_tick - self.start_tick) / self.tick_hz

    def channel(self, spec: Any) -> ChannelRef:
        return resolve_channel(self, spec)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "samplerate": self.samplerate,
            "tick_hz": self.tick_hz,
            "channels": [c.to_dict() for c in self.channels],
            "analog_channels": self.analog_channels,
            "unitsize": self.unitsize,
            "total_samples": self.total_samples,
            "duration_s": None if self.duration_s is None else round(self.duration_s, 9),
            "metadata": self.metadata,
            "warnings": self.warnings,
        }


@dataclass
class ChannelEdges:
    channel: ChannelRef
    initial_level: int
    edges: array  # array('q'): 레벨이 바뀐 tick 위치 (오름차순)
    start_tick: int
    end_tick: int
    tick_hz: float
    samplerate: float  # 실제 샘플링 해상도 (경고/샘플 수 계산용)
    truncated: bool = False
    unknown_values: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def ticks_per_sample(self) -> float:
        return self.tick_hz / self.samplerate if self.samplerate else 1.0

    @property
    def duration_s(self) -> float:
        return (self.end_tick - self.start_tick) / self.tick_hz if self.tick_hz else 0.0

    def level_at_end(self) -> int:
        return self.initial_level ^ (len(self.edges) & 1)


# ---------------------------------------------------------------------------
# 공통
# ---------------------------------------------------------------------------

_RATE_TEXT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgGtTpPeE]?)\s*(?:[hH][zZ])?\s*$")
_RATE_MULT = {"": 1, "k": 10**3, "m": 10**6, "g": 10**9, "t": 10**12, "p": 10**15, "e": 10**18}


def parse_rate_text(text: str) -> int | None:
    """'1 MHz', '200 kHz', '1.5 MHz', '1000000 Hz', '24000000', '1m' → 정수 Hz (해석 불가 시 None)."""
    m = _RATE_TEXT_RE.match(str(text))
    if not m:
        return None
    try:
        val = Decimal(m.group(1)) * _RATE_MULT[m.group(2).lower()]
    except (InvalidOperation, KeyError):
        return None
    return int(val)


def detect_format(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError as exc:
        raise NotFound(f"신호 파일을 열 수 없습니다: {path} ({exc})")
    if head.startswith(b"PK\x03\x04"):
        return "srzip"
    text = head.lstrip(b"\xef\xbb\xbf").lstrip()
    if text.startswith(b"$"):
        return "vcd"
    return None


def resolve_channel(info: SignalInfo, spec: Any) -> ChannelRef:
    """채널 지정(이름 또는 인덱스)을 ChannelRef 로. 이름 정확 일치 → 대소문자 무시 일치 → 정수 인덱스."""
    if spec is None or (isinstance(spec, str) and not spec.strip()):
        raise ValidationFailed("channel 이 필요합니다.", hint=_channel_hint(info))
    if isinstance(spec, bool):
        raise ValidationFailed(f"잘못된 channel: {spec!r}", hint=_channel_hint(info))
    if isinstance(spec, str):
        s = spec.strip()
        for ch in info.channels:
            if ch.name == s:
                return ch
        low = [ch for ch in info.channels if ch.name.lower() == s.lower()]
        if len(low) == 1:
            return low[0]
        if re.fullmatch(r"\d{1,3}", s):
            spec = int(s)
        else:
            raise ValidationFailed(f"채널 {spec!r} 이 파일에 없습니다.", hint=_channel_hint(info))
    if isinstance(spec, int):
        for ch in info.channels:
            if ch.index == spec:
                return ch
        raise ValidationFailed(f"채널 인덱스 {spec} 이 파일에 없습니다.", hint=_channel_hint(info))
    raise ValidationFailed(f"잘못된 channel: {spec!r}", hint=_channel_hint(info))


def _channel_hint(info: SignalInfo) -> str:
    names = ", ".join(f"{c.name}(#{c.index})" for c in info.channels[:64])
    return f"사용 가능한 로직 채널: {names or '(없음)'}"


def load_info(path: Path | str) -> SignalInfo:
    p = Path(path)
    if not p.is_file():
        raise NotFound(f"신호 파일이 없습니다: {p}")
    fmt = detect_format(p)
    if fmt == "srzip":
        return read_srzip_info(p)
    if fmt == "vcd":
        return read_vcd(p, want=(), max_edges=0)[0]
    raise ValidationFailed(
        f"지원하지 않는 신호 파일 형식입니다: {p.name}",
        hint="순수 Python 리더는 sigrok srzip(.sr) 과 VCD(.vcd)만 읽는다. 다른 형식은 sigrok_export(output_format='srzip' 또는 'vcd')로 변환하라.",
    )


def load_channel_edges(path: Path | str, channel: Any, *, max_edges: int = DEFAULT_MAX_EDGES,
                       max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[SignalInfo, ChannelEdges]:
    p = Path(path)
    info = load_info(p)
    ch = resolve_channel(info, channel)
    if info.format == "srzip":
        return info, srzip_channel_edges(p, info, ch, max_edges=max_edges, max_bytes=max_bytes)
    info2, edges = read_vcd(p, want=(ch.name,), max_edges=max_edges)
    # 에지를 읽은 패스의 정보(해상도 추정 포함)를 쓰되 시간 범위는 전체 파일 기준 유지
    info2.end_tick = max(info2.end_tick or 0, info.end_tick or 0)
    return info2, edges[ch.name]


# ---------------------------------------------------------------------------
# srzip
# ---------------------------------------------------------------------------

def _gkey_unescape(val: str) -> str:
    out, i = [], 0
    while i < len(val):
        c = val[i]
        if c == "\\" and i + 1 < len(val):
            n = val[i + 1]
            out.append({"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _open_zip(path: Path) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ValidationFailed(f"손상되었거나 srzip 이 아닌 파일입니다: {path.name} ({exc})")
    except OSError as exc:
        raise NotFound(f"파일을 열 수 없습니다: {path} ({exc})")


def read_srzip_info(path: Path | str) -> SignalInfo:
    p = Path(path)
    with _open_zip(p) as z:
        names = {i.filename: i for i in z.infolist()}
        if "version" not in names or "metadata" not in names:
            raise ValidationFailed(f"sigrok 세션 파일이 아닙니다 (version/metadata 없음): {p.name}")
        if names["version"].file_size > 64 or names["metadata"].file_size > 4 * 1024 * 1024:
            raise ValidationFailed(f"srzip 메타데이터 크기가 비정상입니다: {p.name}")
        try:
            version = z.read("version").decode("ascii", "replace").strip()
            meta_text = z.read("metadata").decode("utf-8", "replace")
        except (zipfile.BadZipFile, OSError) as exc:
            raise ValidationFailed(f"srzip 메타데이터를 읽을 수 없습니다: {exc}")
    if version not in ("1", "2"):
        raise ValidationFailed(f"지원하지 않는 sigrok 세션 파일 버전: {version!r} (1, 2 만 지원)")
    cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",), comment_prefixes=("#",),
                                   inline_comment_prefixes=None, empty_lines_in_values=False)
    cp.optionxform = str  # type: ignore[assignment]
    try:
        cp.read_string(meta_text)
    except configparser.Error as exc:
        raise ValidationFailed(f"srzip metadata 를 해석할 수 없습니다: {exc}")
    sections = [s for s in cp.sections() if s.startswith("device ")]
    if not sections:
        raise ValidationFailed("srzip metadata 에 [device 1] 섹션이 없습니다.")
    warnings: list[str] = []
    if len(sections) > 1:
        warnings.append(f"장치 섹션이 {len(sections)}개 — 첫 번째({sections[0]})만 사용")
    dev = cp[sections[0]]
    rate = None
    if "samplerate" in dev:
        rate = parse_rate_text(_gkey_unescape(dev["samplerate"]))
        if rate is None:
            warnings.append(f"samplerate 값을 해석할 수 없음: {dev['samplerate']!r}")
    channels: list[ChannelRef] = []
    analog: list[str] = []
    for key, val in dev.items():
        m = re.fullmatch(r"probe(\d+)", key)
        if m and int(m.group(1)) >= 1:
            channels.append(ChannelRef(_gkey_unescape(val), int(m.group(1)) - 1))
            continue
        m = re.fullmatch(r"analog(\d+)", key)
        if m:
            analog.append(_gkey_unescape(val))
    channels.sort(key=lambda c: c.index)
    unitsize = None
    if "unitsize" in dev:
        try:
            unitsize = int(dev["unitsize"])
        except ValueError:
            raise ValidationFailed(f"srzip unitsize 값이 잘못되었습니다: {dev['unitsize']!r}")
        if unitsize < 1 or unitsize > 64:
            raise ValidationFailed(f"srzip unitsize 값이 비정상입니다: {unitsize}")
    try:
        total_probes = int(dev.get("total probes", "0"))
    except ValueError:
        total_probes = 0
    capfile = dev.get("capturefile")
    chunk_names: list[str] = []
    total_bytes = 0
    if capfile:
        if capfile in names:
            chunk_names = [capfile]
        else:
            n = 1
            while f"{capfile}-{n}" in names:
                chunk_names.append(f"{capfile}-{n}")
                n += 1
            if not chunk_names and any(k.startswith(capfile + "-") for k in names):
                warnings.append(f"{capfile}-1 이 없어 로직 청크를 읽지 못함 (청크 번호가 1 부터 시작하지 않음)")
        total_bytes = sum(names[c].file_size for c in chunk_names)
    if channels and unitsize:
        max_bit = max(c.index for c in channels)
        if max_bit >= unitsize * 8:
            warnings.append(f"probe 비트 위치({max_bit})가 unitsize({unitsize}바이트) 범위를 넘음 — 해당 채널은 항상 0")
    total_samples = 0
    if unitsize:
        total_samples = total_bytes // unitsize
        if total_bytes % unitsize:
            warnings.append(f"로직 데이터 길이({total_bytes})가 unitsize({unitsize})의 배수가 아님 — 남는 바이트 무시")
    elif chunk_names:
        warnings.append("unitsize 가 없어 로직 데이터를 해석할 수 없음")
    if not capfile:
        warnings.append("로직 데이터가 없음(capturefile 키 없음 — 아날로그 전용 파일)")
    meta = {
        "version": int(version),
        "sigrok_version": cp.get("global", "sigrok version", fallback=None) if cp.has_section("global") else None,
        "total_probes": total_probes,
        "capturefile": capfile,
        "chunks": len(chunk_names),
        "logic_bytes": total_bytes,
    }
    if rate is None:
        warnings.append("samplerate 가 없음 — 시간/보드레이트 계산 불가")
    return SignalInfo(
        path=str(p), format="srzip", channels=channels, tick_hz=float(rate) if rate else None,
        samplerate=float(rate) if rate else None, start_tick=0, end_tick=total_samples, unitsize=unitsize,
        analog_channels=analog, chunk_names=chunk_names, metadata=meta, warnings=warnings,
    )


def iter_srzip_blocks(path: Path | str, info: SignalInfo, *, block_bytes: int = BLOCK_BYTES,
                      max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[bytes]:
    """로직 데이터를 unitsize 배수로 정렬된 블록으로 흘려 읽는다 (청크 경계의 남는 바이트는 이어 붙임)."""
    unitsize = info.unitsize or 1
    block = max(unitsize, block_bytes - block_bytes % unitsize)
    done = 0
    with _open_zip(Path(path)) as z:
        carry = b""
        for name in info.chunk_names:
            try:
                fh = z.open(name)
            except (KeyError, zipfile.BadZipFile, OSError) as exc:
                raise ValidationFailed(f"srzip 청크 {name} 을 열 수 없습니다: {exc}")
            with fh:
                while True:
                    try:
                        data = fh.read(block)
                    except (zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
                        raise ValidationFailed(f"srzip 청크 {name} 이 손상되었습니다 (CRC/압축 오류): {exc}")
                    if not data:
                        break
                    if carry:
                        data = carry + data
                        carry = b""
                    rem = len(data) % unitsize
                    if rem:
                        carry = data[-rem:]
                        data = data[:-rem]
                    if not data:
                        continue
                    if done + len(data) > max_bytes:
                        data = data[: max(0, (max_bytes - done) // unitsize * unitsize)]
                        if data:
                            yield data
                        raise _ByteLimit()
                    done += len(data)
                    yield data


class _ByteLimit(Exception):
    pass


def _bit_table(bit: int) -> bytes:
    mask = 1 << (bit % 8)
    return bytes(1 if (v & mask) else 0 for v in range(256))


def srzip_channel_edges(path: Path | str, info: SignalInfo, channel: ChannelRef, *, max_edges: int = DEFAULT_MAX_EDGES,
                        max_bytes: int = DEFAULT_MAX_BYTES) -> ChannelEdges:
    if not info.unitsize or not info.chunk_names:
        raise ValidationFailed("이 srzip 파일에는 로직 데이터가 없습니다.", hint="; ".join(info.warnings) or None)
    if not info.samplerate:
        raise ValidationFailed("이 srzip 파일에는 samplerate 가 없어 시간 분석을 할 수 없습니다.")
    unitsize = info.unitsize
    off = channel.index // 8
    edges = array("q")
    warnings: list[str] = []
    if off >= unitsize:
        warnings.append(f"채널 비트 {channel.index} 가 unitsize 범위 밖 — 항상 0 으로 간주")
        return ChannelEdges(channel, 0, edges, 0, info.end_tick or 0, info.tick_hz or 1.0, info.samplerate, warnings=warnings)
    table = _bit_table(channel.index)
    level: int | None = None
    initial = 0
    base = 0
    truncated = False
    end_tick = 0
    try:
        for blk in iter_srzip_blocks(path, info, max_bytes=max_bytes):
            lane = blk[off::unitsize] if unitsize > 1 else blk
            s = lane.translate(table)
            n = len(s)
            if level is None:
                level = s[0]
                initial = level
            find = s.find
            i = 0
            while True:
                j = find(b"\x00" if level else b"\x01", i)
                if j < 0:
                    break
                edges.append(base + j)
                level ^= 1
                i = j + 1
                if len(edges) >= max_edges:
                    truncated = True
                    break
            if truncated:
                end_tick = edges[-1] + 1
                break
            base += n
            end_tick = base
    except _ByteLimit:
        truncated = True
        end_tick = base
        warnings.append(f"처리 상한({max_bytes} bytes)에 도달해 앞부분만 분석함")
    if truncated and len(edges) >= max_edges:
        warnings.append(f"에지 상한({max_edges})에 도달해 앞부분 {end_tick} 샘플만 분석함")
    return ChannelEdges(channel, initial, edges, 0, end_tick, float(info.tick_hz or info.samplerate), float(info.samplerate),
                        truncated=truncated, warnings=warnings)


def srzip_activity(path: Path | str, info: SignalInfo, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """모든 로직 채널의 활동 요약 (에지 수, high 비율, 처음/끝 레벨). 에지 위치는 만들지 않아 빠르다."""
    if not info.unitsize or not info.chunk_names:
        return {"channels": [], "samples_scanned": 0, "truncated": False}
    unitsize = info.unitsize
    stats = []
    for ch in info.channels:
        off = ch.index // 8
        stats.append({"ch": ch, "off": off, "table": _bit_table(ch.index), "valid": off < unitsize,
                      "edges": 0, "ones": 0, "first": None, "last": None})
    scanned = 0
    truncated = False
    try:
        for blk in iter_srzip_blocks(path, info, max_bytes=max_bytes):
            n = len(blk) // unitsize
            for st in stats:
                if not st["valid"]:
                    continue
                lane = blk[st["off"]::unitsize] if unitsize > 1 else blk
                s = lane.translate(st["table"])
                st["ones"] += s.count(1)
                x = int.from_bytes(s, "little")
                t = (x ^ (x >> 8)).bit_count() - s[-1]
                if st["last"] is not None and s[0] != st["last"]:
                    t += 1
                if st["first"] is None:
                    st["first"] = s[0]
                st["last"] = s[-1]
                st["edges"] += t
            scanned += n
    except _ByteLimit:
        truncated = True
    out = []
    for st in stats:
        ch = st["ch"]
        if not st["valid"]:
            out.append({"name": ch.name, "index": ch.index, "edges": 0, "high_ratio": 0.0, "initial_level": 0, "final_level": 0, "note": "unitsize 범위 밖"})
            continue
        out.append({
            "name": ch.name, "index": ch.index, "edges": st["edges"],
            "high_ratio": round(st["ones"] / scanned, 4) if scanned else None,
            "initial_level": st["first"], "final_level": st["last"],
        })
    return {"channels": out, "samples_scanned": scanned, "truncated": truncated}


# ---------------------------------------------------------------------------
# VCD
# ---------------------------------------------------------------------------

_TS_UNITS = {"s": Fraction(1), "ms": Fraction(1, 10**3), "us": Fraction(1, 10**6), "ns": Fraction(1, 10**9),
             "ps": Fraction(1, 10**12), "fs": Fraction(1, 10**15)}
_VCD_SCALAR_TYPES = {"wire", "reg", "logic", "bit", "tri", "wand", "wor", "triand", "trior", "trireg", "tri0", "tri1",
                     "supply0", "supply1", "uwire"}
_SIGROK_COMMENT_RATE = re.compile(r"at ([0-9.]+ ?[kMGT]?Hz)")


def parse_timescale(text: str) -> Fraction | None:
    m = re.fullmatch(r"\s*(\d+)\s*([munpf]?s)\s*", text)
    if not m:
        return None
    num = int(m.group(1))
    if num <= 0:
        return None
    return num * _TS_UNITS[m.group(2)]


@dataclass
class _VcdVar:
    ref: ChannelRef
    ident: str
    size: int


def read_vcd(path: Path | str, *, want: tuple[str, ...] | None = None, max_edges: int = DEFAULT_MAX_EDGES,
             max_bytes: int = 4 * DEFAULT_MAX_BYTES) -> tuple[SignalInfo, dict[str, ChannelEdges]]:
    """VCD 를 읽어 (정보, {채널이름: 에지}) 반환.

    want=None 이면 모든 스칼라 채널의 에지를, () 이면 헤더와 시간 범위만(에지 미수집) 읽는다.
    """
    p = Path(path)
    timescale: Fraction | None = None
    vars_: list[_VcdVar] = []
    by_ident: dict[str, list[_VcdVar]] = {}
    scope: list[str] = []
    comments: list[str] = []
    meta: dict[str, Any] = {}
    warnings: list[str] = []
    in_header = True
    section: str | None = None
    section_toks: list[str] = []
    skip_until_end = False
    pending: tuple[str, str] | None = None  # ("v", value) | ("b", bits) | ("r", "")
    t_cur: int | None = None
    t_first: int | None = None
    t_last: int | None = None
    out_of_order = 0
    unknown_tokens = 0
    unknown_vals: dict[str, int] = {}
    tracked: dict[str, dict[str, Any]] = {}  # ident -> state for wanted channels
    processed = 0
    truncated_bytes = False
    collect = want is None or bool(want)

    def handle_section(name: str, toks: list[str]) -> None:
        nonlocal timescale
        if name == "timescale":
            ts = parse_timescale("".join(toks)) or parse_timescale(" ".join(toks))
            if ts is None:
                warnings.append(f"$timescale 해석 실패: {' '.join(toks)!r}")
            else:
                timescale = ts
        elif name == "scope":
            scope.append(toks[1] if len(toks) >= 2 else (toks[0] if toks else "?"))
        elif name == "upscope":
            if scope:
                scope.pop()
        elif name == "var":
            if len(toks) < 4:
                warnings.append(f"$var 항목이 짧음: {' '.join(toks)!r}")
                return
            vtype, vsize, ident = toks[0], toks[1], toks[2]
            vname = toks[3] + (toks[4] if len(toks) >= 5 and toks[4].startswith("[") else "")
            try:
                size = int(vsize)
            except ValueError:
                size = -1
            if vtype not in _VCD_SCALAR_TYPES or size != 1:
                meta.setdefault("skipped_vars", []).append({"name": vname, "type": vtype, "size": vsize})
                return
            if any(v.ref.name == vname for v in vars_):
                alt = ".".join(scope + [vname]) if scope else vname
                if alt == vname or any(v.ref.name == alt for v in vars_):
                    alt = f"{vname}#{len(vars_)}"
                warnings.append(f"채널 이름 중복 '{vname}' → '{alt}' 로 구분 (sigrok 은 같은 이름을 그대로 씀)")
                vname = alt
            ref = ChannelRef(vname, len(vars_), sigrok_supported=vtype in ("wire", "reg"))
            v = _VcdVar(ref, ident, size)
            vars_.append(v)
            by_ident.setdefault(ident, []).append(v)
            if scope:
                meta.setdefault("scopes", {})[vname] = ".".join(scope)
        elif name == "comment":
            comments.append(" ".join(toks))
        elif name in ("date", "version"):
            meta[name] = " ".join(toks)

    def set_value(ident: str, level: int, unknown: bool) -> None:
        st = tracked.get(ident)
        if st is None:
            return
        if unknown:
            st["unknown"] += 1
        if t_cur is None or t_cur == t_first:
            st["level"] = level
            st["initial"] = level
            return
        if level != st["level"]:
            st["level"] = level
            if st["full"]:
                return
            st["edges"].append(t_cur)
            if len(st["edges"]) >= max_edges:
                st["full"] = True
                st["trunc_at"] = t_cur
                full_count[0] += 1

    full_count = [0]
    fast_range = want is not None and not want  # 헤더 + 시간 범위만
    try:
        fh = open(p, "rb")
    except OSError as exc:
        raise NotFound(f"VCD 파일을 열 수 없습니다: {p} ({exc})")
    with fh:
        stop = False
        for raw in fh:
            if stop:
                break
            processed += len(raw)
            if processed > max_bytes:
                truncated_bytes = True
                break
            if tracked and full_count[0] >= len(tracked):
                break  # 모든 추적 채널이 에지 상한에 도달
            if fast_range and not in_header and t_first is not None:
                break
            line = raw.decode("latin-1")
            for tok in line.split():
                if in_header:
                    if section is None:
                        if tok.startswith("$"):
                            section = tok[1:]
                            section_toks = []
                            if section == "end":
                                section = None
                        continue
                    if tok == "$end":
                        handle_section(section, section_toks)
                        if section == "enddefinitions":
                            in_header = False
                            # 추적할 채널 결정
                            for v in vars_:
                                if collect and (want is None or v.ref.name in want):
                                    tracked.setdefault(v.ident, {"edges": array("q"), "level": 0, "initial": 0,
                                                                 "unknown": 0, "full": False, "trunc_at": None, "names": []})
                                    tracked[v.ident]["names"].append(v.ref.name)
                            if not collect:
                                tracked.clear()
                        section = None
                        continue
                    if tok.endswith("$end") and section != "comment":
                        section_toks.append(tok[:-4])
                        handle_section(section, [t for t in section_toks if t])
                        if section == "enddefinitions":
                            in_header = False
                        section = None
                        continue
                    section_toks.append(tok)
                    continue
                # ---- 본문 ----
                if skip_until_end:
                    if tok == "$end":
                        skip_until_end = False
                    continue
                if pending is not None:
                    kind, val = pending
                    pending = None
                    if kind == "v":
                        set_value(tok, 1 if val == "1" else 0, val not in "01")
                    elif kind == "b":
                        bit = val[-1:] if val else "0"
                        set_value(tok, 1 if bit == "1" else 0, bit not in "01")
                    continue
                c = tok[0]
                if c == "#":
                    if tok[1:].isdigit():
                        t = int(tok[1:])
                        if t_cur is not None and t < t_cur:
                            out_of_order += 1
                            continue
                        t_cur = t
                        if t_first is None:
                            t_first = t
                        t_last = t
                    else:
                        unknown_tokens += 1
                elif c == "$":
                    if tok in ("$dumpvars", "$dumpall", "$dumpon", "$dumpoff", "$end"):
                        continue
                    skip_until_end = True
                elif c in "01xXzZ":
                    val = c.lower()
                    if len(tok) == 1:
                        pending = ("v", val)
                    else:
                        ident = tok[1:]
                        if ident in by_ident:
                            set_value(ident, 1 if val == "1" else 0, val not in "01")
                        elif not (c in "01" and re.fullmatch(r"[0-9.eE+-]+", tok)):
                            unknown_vals[ident] = unknown_vals.get(ident, 0) + 1
                        else:
                            unknown_tokens += 1
                elif c in "bB":
                    pending = ("b", tok[1:].lower())
                elif c in "rR":
                    pending = ("r", "")
                else:
                    unknown_tokens += 1
    if in_header:
        raise ValidationFailed(f"VCD 헤더($enddefinitions)를 찾지 못했습니다: {p.name}")
    if fast_range:
        last = _vcd_last_timestamp(p)
        if last is not None and (t_last is None or last > t_last):
            t_last = last
    if timescale is None:
        warnings.append("$timescale 이 없어 1 us 로 가정")
        timescale = Fraction(1, 10**6)
    tick_hz = float(1 / timescale)
    samplerate = None
    for cmt in comments:
        m = _SIGROK_COMMENT_RATE.search(cmt)
        if m:
            samplerate = parse_rate_text(m.group(1).replace(" ", ""))
            if samplerate:
                meta["original_samplerate"] = samplerate
                break
    if out_of_order:
        warnings.append(f"역순 타임스탬프 {out_of_order}개 무시")
    if unknown_tokens:
        warnings.append(f"해석 불가 토큰 {unknown_tokens}개 무시 (손상되었거나 아날로그 텍스트가 섞인 VCD 일 수 있음)")
    if unknown_vals:
        warnings.append(f"선언되지 않은 식별자 값 변경 {sum(unknown_vals.values())}개 무시")
    if truncated_bytes:
        warnings.append(f"처리 상한({max_bytes} bytes)에 도달해 앞부분만 읽음")
    if comments:
        meta["comments"] = comments[:5]
    meta["timescale_s"] = str(timescale)
    start = t_first or 0
    end = t_last if t_last is not None else start
    channels = [v.ref for v in vars_]
    # 실제 해상도 추정: sigrok 주석 → 에지 간격 최대공약수 → tick
    edges_out: dict[str, ChannelEdges] = {}
    if samplerate is None and tracked:
        # 에지 간격의 최대공약수 = 샘플 주기 후보. 단, 모든 간격이 최소 간격의 배수뿐이면(예: 비트 시간이 정확히
        # 정수 샘플인 합성 신호) GCD 가 비트 시간이 되어 버리므로, 최소 간격이 GCD 의 2배 이상일 때만 채택한다.
        g = 0
        cnt = 0
        dmin = None
        for st in tracked.values():
            e = st["edges"]
            prev = start
            for x in e[:2000]:
                d = int(x - prev)
                g = math.gcd(g, d)
                if d > 0 and (dmin is None or d < dmin):
                    dmin = d
                prev = x
                cnt += 1
        if cnt >= 8 and g > 1 and dmin is not None and dmin >= 2 * g:
            samplerate = tick_hz / g
            meta["resolution_estimated_from_gcd_ticks"] = g
    if samplerate is None:
        samplerate = tick_hz
    for ident, st in tracked.items():
        trunc_at = st["trunc_at"]
        e_end = (trunc_at + 1) if trunc_at is not None else end
        for name in st["names"]:
            ref = next(v.ref for v in vars_ if v.ref.name == name and v.ident == ident)
            w = []
            if st["unknown"]:
                w.append(f"x/z 값 {st['unknown']}개를 0 으로 간주")
            if trunc_at is not None:
                w.append(f"에지 상한({max_edges})에 도달해 앞부분만 분석함")
            edges_out[name] = ChannelEdges(ref, st["initial"], st["edges"], start, max(e_end, start), tick_hz, float(samplerate),
                                           truncated=trunc_at is not None or truncated_bytes, unknown_values=st["unknown"], warnings=w)
    info = SignalInfo(path=str(p), format="vcd", channels=channels, tick_hz=tick_hz, samplerate=float(samplerate),
                      start_tick=start, end_tick=end, metadata=meta, warnings=warnings)
    if want:
        missing = [w for w in want if w not in edges_out]
        if missing:
            raise ValidationFailed(f"VCD 에 채널이 없습니다: {missing}", hint=_channel_hint(info))
    return info, edges_out


_TS_TOKEN_RE = re.compile(rb"(?:^|\s)#(\d+)(?=\s|$)")


def _vcd_last_timestamp(path: Path) -> int | None:
    """파일 끝부분에서 마지막 타임스탬프를 찾는다 (큰 VCD 의 전체 파싱 회피)."""
    try:
        size = path.stat().st_size
        window = 1 << 20
        with open(path, "rb") as fh:
            while True:
                start = max(0, size - window)
                fh.seek(start)
                data = fh.read(size - start)
                matches = list(_TS_TOKEN_RE.finditer(data))
                if matches:
                    return int(matches[-1].group(1))
                if start == 0 or window >= 64 << 20:
                    return None
                window *= 4
    except OSError:
        return None


def vcd_activity(path: Path | str, *, max_edges: int = DEFAULT_MAX_EDGES) -> tuple[SignalInfo, dict[str, Any]]:
    info, edges = read_vcd(path, want=None, max_edges=max_edges)
    out = []
    for ch in info.channels:
        e = edges.get(ch.name)
        if e is None:
            continue
        span = e.end_tick - e.start_tick
        high = 0
        lvl = e.initial_level
        prev = e.start_tick
        for x in e.edges:
            if lvl:
                high += x - prev
            prev = x
            lvl ^= 1
        if lvl:
            high += e.end_tick - prev
        out.append({"name": ch.name, "index": ch.index, "edges": len(e.edges),
                    "high_ratio": round(high / span, 4) if span > 0 else None,
                    "initial_level": e.initial_level, "final_level": e.level_at_end(),
                    **({"truncated": True} if e.truncated else {})})
    return info, {"channels": out, "truncated": any(e.truncated for e in edges.values())}


def activity(path: Path | str) -> tuple[SignalInfo, dict[str, Any]]:
    p = Path(path)
    fmt = detect_format(p)
    if fmt == "srzip":
        info = read_srzip_info(p)
        return info, srzip_activity(p, info)
    if fmt == "vcd":
        return vcd_activity(p)
    raise ValidationFailed(f"지원하지 않는 신호 파일 형식입니다: {p.name}", hint="srzip(.sr) 또는 VCD 만 지원")


__all__ = [
    "ChannelEdges",
    "ChannelRef",
    "SignalInfo",
    "activity",
    "detect_format",
    "iter_srzip_blocks",
    "load_channel_edges",
    "load_info",
    "parse_rate_text",
    "parse_timescale",
    "read_srzip_info",
    "read_vcd",
    "resolve_channel",
    "srzip_activity",
    "srzip_channel_edges",
    "vcd_activity",
]
