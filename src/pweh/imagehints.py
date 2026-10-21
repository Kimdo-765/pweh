"""케이스·증거 서버가 공유하는 정지 그림 분석기.

호출자는 검증한 불변 바이트만 넘긴다. 여기서는 원본 경로·EV·케이스를 알지 못하며,
별도 프로세스의 크기 제한 프로토콜로만 그림을 해독한다. MCP 콘텐츠와 산출물 저장은
서버 어댑터가 맡는다. OCR·QR·메타데이터는 지시가 아닌 원본 데이터다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import sysconfig
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from .errors import PwehError, ValidationFailed

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_PIXELS = 40_000_000
MAX_DIMENSION = 32768
MAX_WALL_SECONDS = 45.0
MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_PREVIEW_DIMENSION = 1600
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
_CHILD_ENV_KEYS = {"LD_LIBRARY_PATH", "MAGICK_CODER_MODULE_PATH", "MAGICK_CONFIGURE_PATH"}


@dataclass(frozen=True)
class ImageToolSettings:
    """신뢰한 설치·설정에서 찾은 실행 파일(입력 그림에서는 경로를 받지 않는다)."""

    tesseract: str | None = None
    zbarimg: str | None = None
    tessdata_dir: str | None = None
    child_env: Mapping[str, str] = field(default_factory=dict)
    sources: Mapping[str, str] = field(default_factory=dict)


def resolve_image_tools(config: Any) -> ImageToolSettings:
    """설정 → 명시 환경 변수 → 관리 설치 경로. 암묵적인 PATH 탐색은 하지 않는다."""
    from .toolsdir import image_tool_candidates, tools_dir

    configured = config.tools if hasattr(config, "tools") else (config or {}).get("tools", {})
    selected: dict[str, str | None] = {}
    sources: dict[str, str] = {}
    root = tools_dir()
    for name in ("tesseract", "zbarimg", "tessdata_dir"):
        selected[name] = None
        env_name = "PWEH_" + name.upper()
        for value, source in image_tool_candidates(name, configured.get(name), os.environ.get(env_name), root):
            path = os.path.expanduser(value)
            if name != "tessdata_dir" and not os.path.isabs(path) and source in ("config", "env"):
                path = shutil.which(path) or ""
            if not path or not os.path.isabs(path):
                continue
            p = Path(path)
            valid = p.is_dir() if name == "tessdata_dir" else p.is_file() and os.access(p, os.X_OK)
            if valid:
                # 관리 래퍼의 상대 심볼릭 링크 등은 설치 계약의 일부다.
                selected[name] = str(p.absolute())
                sources[name] = source
                break
    return ImageToolSettings(**selected, sources=sources)


def _validate_options(data: bytes, settings: ImageToolSettings, ocr: bool, ocr_lang: str,
                      qr: bool, preview: bool, crop: Sequence[int] | None, max_seconds: float) -> dict:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise ValidationFailed("그림 입력은 1 바이트 이상 64 MiB 이하의 bytes 여야 합니다.")
    if any(not isinstance(value, bool) for value in (ocr, qr, preview)):
        raise ValidationFailed("ocr·qr·preview 는 boolean 이어야 합니다.")
    if ocr_lang not in ("kor+eng", "eng+kor", "eng", "kor"):
        raise ValidationFailed("OCR 언어는 kor+eng, eng 또는 kor 만 지원합니다.")
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or not math.isfinite(max_seconds) or not 0 < max_seconds <= MAX_WALL_SECONDS:
        raise ValidationFailed("남은 분석 시간은 0 초 초과, 45 초 이하여야 합니다.")
    if crop is not None:
        if not isinstance(crop, (tuple, list)) or len(crop) != 4 or any(isinstance(v, bool) or not isinstance(v, int) for v in crop):
            raise ValidationFailed("crop 은 [x, y, width, height] 정수 4개여야 합니다.")
        if min(crop[:2]) < 0 or min(crop[2:]) < 1 or max(crop) > MAX_DIMENSION:
            raise ValidationFailed("crop 좌표·크기가 허용 범위를 벗어났습니다.")
    if not isinstance(settings, ImageToolSettings):
        raise ValidationFailed("settings 는 ImageToolSettings 여야 합니다.")
    for name in ("tesseract", "zbarimg", "tessdata_dir"):
        value = getattr(settings, name)
        if value is not None and (not isinstance(value, str) or not os.path.isabs(value) or "\x00" in value or len(value) > 4096):
            raise ValidationFailed("그림 분석 도구 설정에는 절대 경로만 사용할 수 있습니다.")
    if any(k not in _CHILD_ENV_KEYS or not isinstance(v, str) or "\x00" in v or len(v) > 16384
           for k, v in settings.child_env.items()):
        raise ValidationFailed("그림 분석 자식 환경 설정에 허용하지 않은 값이 있습니다.")
    return {"ocr": ocr, "ocr_lang": ocr_lang, "qr": qr, "preview": preview,
            "crop": list(crop) if crop is not None else None, "max_seconds": float(max_seconds),
            "settings": asdict(settings),
            "parent_pid": os.getpid(),
            "site_paths": list(dict.fromkeys(sysconfig.get_path(n) for n in ("purelib", "platlib")))}


def _failure(data: bytes, code: str) -> dict:
    return {"report": {"schema": "pweh.image-hints/v1", "status": "failed",
                       "input": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
                       "image": None, "metadata": {}, "structure": {"status": "failed"},
                       "ocr": {"status": "skipped"}, "codes": {"status": "skipped", "items": []},
                       "stego": {"status": "skipped", "indicators": []}, "engines": {},
                       "limits": _limits(), "truncated_reasons": [code], "warnings": [code]},
            "previews": []}


def _limits() -> dict:
    return {"input_bytes": MAX_INPUT_BYTES, "pixels": MAX_PIXELS, "dimension": MAX_DIMENSION,
            "address_space_bytes": 1024 ** 3, "cpu_seconds": 30, "wall_seconds": MAX_WALL_SECONDS,
            "preview_bytes": MAX_PREVIEW_BYTES, "preview_dimension": MAX_PREVIEW_DIMENSION,
            "ocr_pixels": 12_000_000}


def _exchange(argv: list[str], payload: bytes, *, deadline: float,
              cancel_event: threading.Event | None) -> tuple[bytes, str | None]:
    """stdin/stdout/stderr 를 동시에 제한하며 부모가 그룹 종료와 회수를 소유한다."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "OMP_THREAD_LIMIT": "1"}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, close_fds=True, start_new_session=True, cwd="/")
    sel = selectors.DefaultSelector()
    output = bytearray()
    stderr_size = 0
    cursor = 0
    reason = None
    try:
        for pipe, label, event in ((process.stdin, "input", selectors.EVENT_WRITE),
                                   (process.stdout, "output", selectors.EVENT_READ),
                                   (process.stderr, "error", selectors.EVENT_READ)):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, event, label)
        while sel.get_map():
            if cancel_event is not None and cancel_event.is_set():
                reason = "cancelled"
                break
            if time.monotonic() >= deadline:
                reason = "wall_timeout"
                break
            for key, _ in sel.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                pipe = key.fileobj
                if key.data == "input":
                    try:
                        size = os.write(pipe.fileno(), memoryview(payload)[cursor:cursor + 65536])
                        cursor += size
                    except BrokenPipeError:
                        cursor = len(payload)
                    except BlockingIOError:
                        continue
                    if cursor == len(payload):
                        sel.unregister(pipe)
                        pipe.close()
                else:
                    try:
                        chunk = os.read(pipe.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        sel.unregister(pipe)
                        pipe.close()
                    elif key.data == "output":
                        if len(output) + len(chunk) > MAX_OUTPUT_BYTES:
                            reason = "worker_output_limit"
                            break
                        output.extend(chunk)
                    else:
                        stderr_size += len(chunk)
                        if stderr_size > MAX_STDERR_BYTES:
                            reason = "worker_stderr_limit"
                            break
            if reason:
                break
    finally:
        sel.close()
        # poll() 로 리더를 먼저 거두지 않는다. PID 가 재사용되기 전에 그룹 전체를 끝낸다.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe and not pipe.closed:
                pipe.close()
        process.wait()
    return bytes(output), reason


def _decode_response(raw: bytes, data: bytes) -> dict:
    """worker 결과를 다시 제한한다. 미리보기는 단순 PNG 청크만 허용한다."""
    from ._image_formats import inspect_png

    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or set(parsed) != {"report", "previews"}:
        raise ValueError("invalid_worker_response")
    report, previews = parsed["report"], parsed["previews"]
    if not isinstance(report, dict) or report.get("schema") != "pweh.image-hints/v1" or report.get("status") not in {"ok", "partial", "unsupported", "failed"}:
        raise ValueError("invalid_worker_report")
    expected = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if report.get("input") != expected or not isinstance(previews, list) or len(previews) > 2:
        raise ValueError("worker_input_or_preview_mismatch")
    if len(json.dumps(report, ensure_ascii=True)) > 5 * 1024 * 1024:
        raise ValueError("worker_report_limit")
    total = 0
    roles = set()
    for item in previews:
        if not isinstance(item, dict) or item.get("role") not in {"overview", "crop"} or item["role"] in roles or item.get("mime_type") != "image/png":
            raise ValueError("invalid_preview")
        roles.add(item["role"])
        raw_png = base64.b64decode(item.pop("data_b64"), validate=True)
        total += len(raw_png)
        if total > MAX_PREVIEW_BYTES or not raw_png.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("preview_limit")
        checked = inspect_png(raw_png)
        width, height = item.get("width"), item.get("height")
        if any(isinstance(v, bool) or not isinstance(v, int) or not 0 < v <= MAX_PREVIEW_DIMENSION for v in (width, height)):
            raise ValueError("preview_dimension_limit")
        if checked["status"] != "ok" or checked["animated"] or checked["trailing_bytes"] or checked["dimensions"] != [width, height]:
            raise ValueError("invalid_preview_png")
        pos = 8
        while pos < len(raw_png):
            size = struct.unpack_from(">I", raw_png, pos)[0]
            if raw_png[pos + 4:pos + 8] not in (b"IHDR", b"IDAT", b"IEND"):
                raise ValueError("preview_metadata_not_stripped")
            pos += 12 + size
        digest = hashlib.sha256(raw_png).hexdigest()
        if item.get("sha256") != digest:
            raise ValueError("preview_hash_mismatch")
        item["data"] = raw_png
    return parsed


def analyze_image(data: bytes, *, settings: ImageToolSettings | None = None, ocr: bool = True,
                  ocr_lang: str = "kor+eng", qr: bool = True, preview: bool = True,
                  crop: Sequence[int] | None = None, max_seconds: float = 45.0,
                  cancel_event: threading.Event | None = None) -> dict:
    """정지 그림 한 개를 분석해 JSON report 와 PNG bytes previews 를 돌려준다.

    max_seconds 는 서버가 파일 선택·읽기에 쓴 시간을 뺀 남은 값도 받는다. cancel_event 를
    set 하면 자식 그룹을 회수하고 cancelled 예외를 낸다. 해독·도구 실패는 보고서로 남긴다.
    """
    deadline = time.monotonic() + max_seconds if isinstance(max_seconds, (int, float)) else time.monotonic()
    opts = _validate_options(data, settings or ImageToolSettings(), ocr, ocr_lang, qr, preview, crop, max_seconds)
    if cancel_event is not None and cancel_event.is_set():
        raise PwehError("그림 분석이 취소되었습니다.", code="cancelled")
    header = json.dumps(opts, ensure_ascii=True).encode("ascii")
    if len(header) > 32768:
        raise ValidationFailed("그림 분석 설정이 너무 큽니다.")
    payload = struct.pack(">IQ", len(header), len(data)) + header + data
    worker = str(Path(__file__).with_name("_image_worker.py"))
    try:
        raw, reason = _exchange([sys.executable, "-I", "-S", worker], payload,
                                deadline=deadline, cancel_event=cancel_event)
    except OSError:
        return _failure(data, "worker_spawn_failed")
    if reason == "cancelled":
        raise PwehError("그림 분석이 취소되었습니다.", code="cancelled")
    if reason:
        return _failure(data, reason)
    try:
        result = _decode_response(raw, data)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return _failure(data, "invalid_worker_response")
    return result
