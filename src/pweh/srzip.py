"""sigrok 로직 전용 srzip v2 쓰기 — 캡처·시뮬레이터 공용."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Sequence

_SI_PREFIX = ["", "k", "M", "G", "T", "P", "E"]


def format_samplerate(hz: int) -> str:
    """libsigrok ``sr_si_string_u64(x, "Hz")`` 와 같은 문자열: 1500000 → '1.5 MHz', 200 → '200 Hz'."""
    x = int(hz)
    i = 0
    div = 1
    while x // div >= 1000 and i < len(_SI_PREFIX) - 1:
        i += 1
        div *= 1000
    quot = x // div
    fract = ""
    if i:
        fract = (".%0" + str(i * 3) + "d") % (x % div)
        fract = fract.rstrip("0").rstrip(".")
    return f"{quot}{fract} {_SI_PREFIX[i]}Hz"



def write_srzip(
    path: str | Path,
    data: bytes,
    samplerate: int,
    names: Sequence[str | None],
    *,
    unitsize: int = 1,
    chunk_bytes: int = 1024 * 1024,
    total_probes: int | None = None,
    sigrok_version: str = "0.5.2",
) -> Path:
    """로직 전용 srzip v2 파일 쓰기. names[i] = 비트 i 채널 이름 (None 이면 비활성 → probe 키 생략)."""
    p = Path(path)
    if len(data) % unitsize:
        raise ValueError("data 길이가 unitsize 의 배수가 아닙니다")
    total_probes = total_probes if total_probes is not None else len(names)
    meta = ["[global]", f"sigrok version={sigrok_version}", "", "[device 1]", "capturefile=logic-1",
            f"total probes={total_probes}", f"samplerate={format_samplerate(samplerate)}", "total analog=0"]
    for i, nm in enumerate(names):
        if nm is not None:
            meta.append(f"probe{i + 1}={nm}")
    meta += [f"unitsize={unitsize}", ""]
    step = max(unitsize, chunk_bytes - chunk_bytes % unitsize)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with zipfile.ZipFile(tmp, "w") as z:
        z.writestr(zipfile.ZipInfo("version"), "2")
        z.writestr("metadata", "\n".join(meta), compress_type=zipfile.ZIP_DEFLATED)
        for i, off in enumerate(range(0, len(data), step), start=1):
            z.writestr(f"logic-1-{i}", data[off: off + step], compress_type=zipfile.ZIP_DEFLATED)
    tmp.replace(p)
    return p



__all__ = ["format_samplerate", "write_srzip"]
