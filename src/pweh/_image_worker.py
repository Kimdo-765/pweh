"""경로 없는 정지 그림 해독 worker (부모가 프로세스 그룹과 벽시계를 관리).

실행: 고정 Python -I -S 와 이 파일. stdin 은 12 바이트 길이 머리글 + JSON 옵션 +
원본 bytes, stdout 은 제한된 JSON 한 개다. Pillow 는 RLIMIT 적용 뒤에만 가져온다.
"""

from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import io
import json
import math
import os
from pathlib import Path
import resource
import selectors
import signal
import struct
import subprocess
import sys
import time
import warnings
import xml.etree.ElementTree as ET

MAX_INPUT = 64 * 1024 * 1024
MAX_PIXELS = 40_000_000
MAX_DIMENSION = 32768
MAX_OCR_PIXELS = 12_000_000
MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_TOOL_OUTPUT = 1024 * 1024
MAX_METADATA = 256 * 1024


def _limits() -> None:
    """신뢰할 수 없는 형식·Pillow·외부 실행 파일을 읽기 전에 한도를 적용한다."""
    for key, value in ((resource.RLIMIT_AS, 1024 ** 3), (resource.RLIMIT_CPU, 30),
                       (resource.RLIMIT_FSIZE, 32 * 1024 * 1024), (resource.RLIMIT_CORE, 0),
                       (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(key, (value, value))
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_SETMASK, [])
    # 부모가 사라지면 worker 와 OCR/QR 자식을 같은 그룹에서 함께 끝낸다.
    def parent_gone(_signum, _frame):
        os.killpg(os.getpgrp(), signal.SIGKILL)
    signal.signal(signal.SIGTERM, parent_gone)
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
            raise OSError("pdeathsig_failed")


def _read_exact(size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        part = sys.stdin.buffer.read(min(65536, size - len(buf)))
        if not part:
            raise ValueError("incomplete_worker_input")
        buf.extend(part)
    return bytes(buf)


def _clean_env(extra: dict) -> dict:
    out = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "HOME": "/nonexistent", "OMP_THREAD_LIMIT": "1", "MAGICK_THREAD_LIMIT": "1",
           "MAGICK_MEMORY_LIMIT": "128MiB", "MAGICK_MAP_LIMIT": "0", "MAGICK_DISK_LIMIT": "0",
           "MAGICK_TIME_LIMIT": "20"}
    for key in ("LD_LIBRARY_PATH", "MAGICK_CODER_MODULE_PATH", "MAGICK_CONFIGURE_PATH"):
        if key in extra:
            out[key] = extra[key]
    return out


def _tool(argv: list[str], data: bytes, *, env: dict, deadline: float,
          pass_fds: tuple = (), cap: int = MAX_TOOL_OUTPUT) -> tuple[bytes, int | None, str | None]:
    """자식도 부모 worker 의 그룹·RLIMIT 를 상속한다. 출력 파이프는 따로 제한한다."""
    if time.monotonic() >= deadline:
        return b"", None, "timeout"
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, close_fds=True, pass_fds=pass_fds, cwd="/")
    except OSError:
        return b"", None, "tool_missing"
    sel = selectors.DefaultSelector()
    out = bytearray()
    cursor, errors, reason = 0, 0, None
    try:
        for pipe, event, label in ((proc.stdin, selectors.EVENT_WRITE, "in"),
                                   (proc.stdout, selectors.EVENT_READ, "out"),
                                   (proc.stderr, selectors.EVENT_READ, "err")):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, event, label)
        while sel.get_map():
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            for key, _ in sel.select(min(.05, max(0., deadline - time.monotonic()))):
                pipe = key.fileobj
                try:
                    if key.data == "in":
                        try:
                            n = os.write(pipe.fileno(), memoryview(data)[cursor:cursor + 65536])
                            cursor += n
                        except BrokenPipeError:
                            cursor = len(data)
                        if cursor == len(data):
                            sel.unregister(pipe)
                            pipe.close()
                    else:
                        chunk = os.read(pipe.fileno(), 65536)
                        if not chunk:
                            sel.unregister(pipe)
                            pipe.close()
                        elif key.data == "out":
                            if len(out) + len(chunk) > cap:
                                reason = "output_limit"
                                break
                            out.extend(chunk)
                        else:
                            errors += len(chunk)
                            if errors > 65536:
                                reason = "stderr_limit"
                                break
                except BlockingIOError:
                    continue
            if reason:
                break
    finally:
        sel.close()
        # 그룹 전체의 마지막 회수는 부모가 맡는다. 이 직접 자식은 여기서 거둔다.
        if reason:
            proc.kill()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if not pipe.closed:
                pipe.close()
        try:
            rc = proc.wait(timeout=max(.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
            reason = "timeout"
    return bytes(out), rc, reason


def _version(path: str, *, env: dict, deadline: float) -> str | None:
    out, rc, err = _tool([path, "--version"], b"", env=env,
                         deadline=min(deadline, time.monotonic() + 2), cap=16384)
    if err or rc:
        return None
    lines = out.decode("utf-8", "replace").splitlines()
    return lines[0][:256] if lines else None


def _safe_value(value, budget: list[int], depth: int = 0):
    """메타데이터는 파일·코드가 아닌 제한된 JSON 값으로만 바꾼다."""
    if budget[0] <= 0 or depth > 4:
        return "<metadata-limit>"
    if isinstance(value, dict):
        return {str(k)[:128]: _safe_value(v, budget, depth + 1) for k, v in list(value.items())[:128]}
    if isinstance(value, (list, tuple)):
        return [_safe_value(v, budget, depth + 1) for v in value[:128]]
    if value is None or isinstance(value, (int, bool)):
        budget[0] -= 16
        return value
    if isinstance(value, float) or hasattr(value, "numerator") and hasattr(value, "denominator"):
        try:
            v = float(value)
            if math.isfinite(v):
                budget[0] -= 16
                return v
        except (ValueError, ZeroDivisionError, OverflowError):
            pass
    if isinstance(value, bytes):
        # 바이너리 maker note 등은 무리하게 텍스트로 꾸미지 않는다.
        if b"\0" in value or len(value) > min(65536, budget[0]):
            budget[0] -= 128
            return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    raw = text.encode("utf-8", "replace")
    cap = min(65536, max(0, budget[0]))
    budget[0] -= min(len(raw), cap)
    return raw[:cap].decode("utf-8", "replace")


def _metadata(im, structure: dict, ExifTags) -> dict:
    budget = [MAX_METADATA]
    result = {"exif": {}, "gps": {}, "xmp": structure.get("xmp", []),
              "png_text": structure.get("text", []), "comments": structure.get("comments", []),
              "time_basis": "metadata-verbatim-unknown-timezone", "warnings": []}
    try:
        exif = im.getexif()
        result["exif"] = {str(ExifTags.TAGS.get(k, k)): _safe_value(v, budget)
                          for k, v in list(exif.items())[:128] if k not in (34665, 34853)}
        for ifd, name in ((34665, "exif_ifd"), (34853, "gps")):
            if ifd in exif:
                names = ExifTags.GPSTAGS if name == "gps" else ExifTags.TAGS
                result[name] = {str(names.get(k, k)): _safe_value(v, budget)
                                for k, v in list(exif.get_ifd(ifd).items())[:128]}
        for key in ("xmp", "XML:com.adobe.xmp", "comment", "description"):
            value = im.info.get(key)
            if value is not None:
                result.setdefault("image_info", {})[key] = _safe_value(value, budget)
    except (ValueError, TypeError, OSError, SyntaxError, OverflowError):
        result["warnings"].append("metadata_parse_partial")
    if budget[0] <= 0:
        result["warnings"].append("metadata_limit")
    return result


def _png_preview(im, role: str, crop, Image) -> dict:
    """메타데이터를 버린 새 RGB PNG. 두 미리보기 합계는 부모에서도 다시 제한한다."""
    resized = im.copy()
    resized.thumbnail((1600, 1600))
    while True:
        fresh = Image.new("RGB", resized.size, "white")
        if "A" in resized.getbands():
            rgba = resized.convert("RGBA")
            fresh.paste(rgba, mask=rgba.getchannel("A"))
        else:
            fresh.paste(resized.convert("RGB"))
        buf = io.BytesIO()
        fresh.save(buf, format="PNG")
        raw = buf.getvalue()
        if len(raw) <= MAX_PREVIEW_BYTES // 2:
            return {"role": role, "mime_type": "image/png", "data_b64": base64.b64encode(raw).decode("ascii"),
                    "width": fresh.width, "height": fresh.height, "crop": crop,
                    "sha256": hashlib.sha256(raw).hexdigest()}
        resized.thumbnail((max(1, resized.width * 3 // 4), max(1, resized.height * 3 // 4)))


def _ocr(im, opts: dict, deadline: float, Image) -> tuple[dict, dict]:
    settings = opts["settings"]
    exe, tessdata = settings.get("tesseract"), settings.get("tessdata_dir")
    engine = {"available": bool(exe and tessdata), "version": None, "languages": opts["ocr_lang"]}
    if not opts["ocr"]:
        return {"status": "skipped", "text": "", "words": []}, engine
    if not exe or not tessdata:
        return {"status": "unavailable", "reason": "tool_or_tessdata_missing", "text": "", "words": []}, engine
    languages = opts["ocr_lang"].split("+")
    models = {}
    for lang in languages:
        # 경로는 고정 언어 이름과 신뢰한 설정에서만 온다. 모델도 크기 제한 아래 읽는다.
        model = Path(tessdata) / (lang + ".traineddata")
        try:
            with model.open("rb") as stream:
                digest = hashlib.sha256()
                size = 0
                while chunk := stream.read(65536):
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise ValueError("model_limit")
                    digest.update(chunk)
                models[lang] = {"sha256": digest.hexdigest(), "size": size}
        except (OSError, ValueError):
            return {"status": "unavailable", "reason": "language_model_missing_or_large", "text": "", "words": []}, engine
    engine["models"] = models
    env = _clean_env(settings.get("child_env", {}))
    engine["version"] = _version(exe, env=env, deadline=deadline)
    # 원본은 경로 목록으로 오인될 수 있으므로 새 PNG 만 stdin 으로 넘긴다.
    clean = Image.new("L", im.size)
    clean.paste(im.convert("L"))
    buf = io.BytesIO()
    clean.save(buf, format="PNG")
    argv = [exe, "stdin", "stdout", "--tessdata-dir", tessdata, "-l", opts["ocr_lang"],
            "--oem", "1", "--psm", "11", "-c", "tessedit_create_tsv=1"]
    raw, rc, error = _tool(argv, buf.getvalue(), env=env, deadline=min(deadline - .25, time.monotonic() + 20))
    if error or rc:
        return {"status": "failed", "reason": error or "exit_nonzero", "text": "", "words": []}, engine
    try:
        csv.field_size_limit(65536)
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8", "replace")), delimiter="\t")
        if not reader.fieldnames or not {"level", "left", "top", "width", "height", "conf", "text"}.issubset(reader.fieldnames):
            raise ValueError("invalid_tsv")
        words, lines, last_line, truncated = [], [], None, False
        for row in reader:
            if row.get("level") != "5" or not row.get("text"):
                continue
            if len(words) >= 10000:
                truncated = True
                break
            box = [int(row[k]) for k in ("left", "top", "width", "height")]
            if min(box) < 0 or box[0] + box[2] > im.width or box[1] + box[3] > im.height:
                raise ValueError("invalid_ocr_box")
            confidence = float(row["conf"])
            if not math.isfinite(confidence) or not -1 <= confidence <= 100:
                raise ValueError("invalid_ocr_confidence")
            text = row["text"][:16384]
            words.append({"text": text, "bbox": box, "confidence": confidence})
            line = tuple(row.get(k) for k in ("page_num", "block_num", "par_num", "line_num"))
            if line == last_line:
                lines[-1] += " " + text
            else:
                lines.append(text)
            last_line = line
        return {"status": "partial" if truncated else "ok", "text": "\n".join(lines), "words": words,
                "truncated": truncated, "coordinates": "analysis-image-pixels",
                "image_width": im.width, "image_height": im.height}, engine
    except (ValueError, TypeError, OverflowError, csv.Error, KeyError):
        return {"status": "failed", "reason": "invalid_tsv", "text": "", "words": []}, engine


def _codes(im, opts: dict, deadline: float) -> tuple[dict, dict]:
    settings = opts["settings"]
    exe = settings.get("zbarimg")
    engine = {"available": bool(exe), "version": None}
    if not opts["qr"]:
        return {"status": "skipped", "items": []}, engine
    if not exe or not hasattr(os, "memfd_create"):
        return {"status": "unavailable", "reason": "tool_or_memfd_missing", "items": []}, engine
    env = _clean_env(settings.get("child_env", {}))
    engine["version"] = _version(exe, env=env, deadline=deadline)
    # zbarimg 의 ImageMagick 해독기에는 원본 대신 고정 PGM 과 봉인된 fd 만 준다.
    gray = im.convert("L")
    pgm = f"P5\n{gray.width} {gray.height}\n255\n".encode("ascii") + gray.tobytes()
    fd = os.memfd_create("pweh-image.pgm", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        import fcntl
        view = memoryview(pgm)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        argv = [exe, "--quiet", "--xml", "--nodbus", "--nodisplay", f"/proc/self/fd/{fd}"]
        raw, rc, error = _tool(argv, b"", env=env, deadline=min(deadline - .25, time.monotonic() + 10), pass_fds=(fd,))
    finally:
        os.close(fd)
    if error or rc not in (0, 4):
        return {"status": "failed", "reason": error or "exit_nonzero", "items": []}, engine
    if rc == 4 and not raw.strip():
        return {"status": "ok", "items": []}, engine
    try:
        # zbar 는 UTF-8 XML 을 쓴다. UTF-16/NUL 로 금지 선언 검사를 우회하지 못한다.
        xml = raw.decode("utf-8", "strict")
        if "\x00" in xml or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise ValueError("xml_entities_forbidden")
        root = ET.fromstring(xml)
        items, truncated = [], False
        for symbol in root.iter():
            if symbol.tag.rsplit("}", 1)[-1] != "symbol":
                continue
            if len(items) >= 128:
                truncated = True
                break
            node = next((child for child in symbol if child.tag.rsplit("}", 1)[-1] == "data"), None)
            if node is None:
                continue
            text = node.text or ""
            if node.attrib.get("format") == "base64":
                payload = base64.b64decode("".join(text.split()), validate=True)
                text = payload.decode("utf-8", "replace")
            raw_text = text.encode("utf-8", "replace")
            limited = len(raw_text) > 16384
            truncated |= limited
            items.append({"type": symbol.attrib.get("type", "unknown")[:80],
                          "text": raw_text[:16384].decode("utf-8", "replace"),
                          "truncated": limited, "quality": symbol.attrib.get("quality", "")[:32]})
        return {"status": "partial" if truncated else "ok", "items": items, "truncated": truncated}, engine
    except (ET.ParseError, ValueError, TypeError):
        return {"status": "failed", "reason": "invalid_xml", "items": []}, engine


def _stego(im, structure: dict) -> dict:
    sample = im.crop((0, 0, min(im.width, 256), min(im.height, 256))).convert("RGB").tobytes()
    ratio = sum(b & 1 for b in sample) / max(1, len(sample))
    indicators = []
    if structure.get("trailing_bytes"):
        indicators.append({"kind": "trailing_data", "confidence": "possible"})
    if len(sample) >= 1024 and .49 <= ratio <= .51:
        indicators.append({"kind": "balanced_lsb_sample", "confidence": "possible"})
    return {"status": "ok", "indicators": indicators, "sample_bytes": len(sample), "lsb_one_ratio": ratio,
            "sample_region": [0, 0, min(im.width, 256), min(im.height, 256)],
            "limitations": ["좌상단 표본의 단순 LSB 통계이며 정상 사진에서도 같은 값이 나온다.",
                            "숨은 데이터의 존재·내용을 확인하지 않는다. 손실 압축·색 변환에 영향을 받는다."]}


def analyze(data: bytes, opts: dict) -> dict:
    # -S 로 site 초기화를 건너뛴다. 부모가 고정한 설치 경로만 Pillow 탐색에 더한다.
    for path in opts["site_paths"]:
        sys.path.append(path)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from pweh._image_formats import inspect_structure
    from pweh.imagehints import _failure, _limits as limits_dict

    deadline = time.monotonic() + opts["max_seconds"]
    result = _failure(data, "decode_failed")
    report = result["report"]
    report.update({"limits": limits_dict(), "truncated_reasons": [], "warnings": [], "status": "ok"})
    report["structure"] = inspect_structure(data)
    recognized = data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8", b"BM", b"GIF87a", b"GIF89a",
                                  b"II*\0", b"MM\0*", b"II+\0", b"MM\0+")) or (
        data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    if not recognized:
        report.update(status="unsupported", warnings=["unsupported_image_format"])
        return result
    try:
        from PIL import Image, ImageOps, ExifTags, ImageFile, PngImagePlugin, __version__
    except ImportError:
        report.update(status="failed", warnings=["pillow_missing"])
        return result
    report["engines"]["pillow"] = {"available": True, "version": __version__}
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    PngImagePlugin.MAX_TEXT_CHUNK = 65536
    PngImagePlugin.MAX_TEXT_MEMORY = MAX_METADATA
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    try:
        if report["structure"].get("errors"):
            report.update(status="failed", warnings=["invalid_image_structure"])
            return result
        if report["structure"].get("animated"):
            report.update(status="unsupported", warnings=["animated_or_multiframe"])
            return result
        with Image.open(io.BytesIO(data), formats=["PNG", "JPEG", "WEBP", "BMP", "GIF", "TIFF"]) as original:
            if original.width > MAX_DIMENSION or original.height > MAX_DIMENSION or original.width * original.height > MAX_PIXELS:
                report.update(status="failed", warnings=["pixel_or_dimension_limit"])
                return result
            if getattr(original, "is_animated", False) or getattr(original, "n_frames", 1) != 1:
                report.update(status="unsupported", warnings=["animated_or_multiframe"])
                return result
            original.verify()
        with Image.open(io.BytesIO(data), formats=["PNG", "JPEG", "WEBP", "BMP", "GIF", "TIFF"]) as original:
            report["metadata"] = _metadata(original, report["structure"], ExifTags)
            original.load()
            fmt = original.format
            orientation = original.getexif().get(274)
            im = ImageOps.exif_transpose(original)
        report["image"] = {"format": fmt, "mime_type": Image.MIME.get(fmt), "width": im.width,
                           "height": im.height, "frames": 1, "orientation_applied": orientation,
                           "coordinates": "exif-oriented-pixels"}
        crop = opts["crop"]
        if crop is not None:
            x, y, width, height = crop
            if x + width > im.width or y + height > im.height:
                report.update(status="failed", warnings=["crop_outside_image"])
                return result
            selected = im.crop((x, y, x + width, y + height))
        else:
            selected = im
        report["stego"] = _stego(im, report["structure"])
        if opts["preview"]:
            result["previews"].append(_png_preview(im, "overview", None, Image))
            if crop is not None:
                result["previews"].append(_png_preview(selected, "crop", crop, Image))
        analysis = selected.copy()
        if analysis.width * analysis.height > MAX_OCR_PIXELS:
            scale = math.sqrt(MAX_OCR_PIXELS / (analysis.width * analysis.height))
            analysis.thumbnail((max(1, int(analysis.width * scale)), max(1, int(analysis.height * scale))))
        report["analysis_region"] = {"crop": crop, "source_width": selected.width, "source_height": selected.height,
                                     "width": analysis.width, "height": analysis.height}
        report["ocr"], report["engines"]["tesseract"] = _ocr(analysis, opts, deadline, Image)
        # 실패한 외부 실행기가 자식을 남겼을 수 있으므로 즉시 부모의 그룹 회수로 이어 간다.
        if report["ocr"].get("reason") in {"timeout", "output_limit", "stderr_limit"}:
            report["codes"] = {"status": "skipped", "reason": "previous_tool_limit", "items": []}
        else:
            report["codes"], report["engines"]["zbar"] = _codes(analysis, opts, deadline)
        partial = [report["structure"].get("status"), report["ocr"].get("status"), report["codes"].get("status")]
        if any(s not in {"ok", "skipped"} for s in partial) or report["metadata"].get("warnings"):
            report["status"] = "partial"
        for stage in ("ocr", "codes"):
            reason = report[stage].get("reason")
            if reason:
                report["warnings"].append(stage + ":" + reason)
                if reason in {"timeout", "output_limit", "stderr_limit"}:
                    report["truncated_reasons"].append(stage + ":" + reason)
        return result
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        report.update(status="failed", warnings=["pixel_limit"])
    except MemoryError:
        report.update(status="failed", warnings=["memory_limit"])
    except (OSError, ValueError, SyntaxError, OverflowError, TypeError, KeyError):
        report.update(status="failed", warnings=["decode_failed_or_unsupported"])
    return result


def _template_png(data: bytes, size: tuple[int, int], roi: tuple[int, int, int, int],
                  deadline: float) -> bytes:
    """단순 RGB PNG의 구조·CRC·실제 해독을 확인하고 지정 ROI만 반환한다."""
    from pweh import vision_template as V
    from pweh._image_formats import inspect_png

    V._tick(deadline)
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise V._error("template_input_invalid")
    pos, idat, ended = 8, False, False
    while pos < len(data):
        V._tick(deadline)
        if pos + 12 > len(data):
            raise V._error("template_input_invalid")
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        stop = pos + 12 + length
        if stop > len(data):
            raise V._error("template_input_invalid")
        if pos == 8:
            if kind != b"IHDR" or length != 13:
                raise V._error("template_input_invalid")
            fields = struct.unpack_from(">IIBBBBB", data, pos + 8)
            if fields[:2] != size or fields[2:6] != (8, 2, 0, 0) or fields[6] not in (0, 1):
                raise V._error("template_input_invalid")
        elif kind == b"IDAT":
            idat = True
        elif kind == b"IEND" and length == 0 and idat and stop == len(data):
            ended = True
        else:
            raise V._error("template_input_invalid")
        pos = stop
    if not ended:
        raise V._error("template_input_invalid")
    V._tick(deadline)
    structure = inspect_png(data)
    if (structure["status"] != "ok" or structure["dimensions"] != list(size)
            or structure["animated"] or structure["trailing_bytes"] != 0):
        raise V._error("template_input_invalid")
    V._tick(deadline)
    from PIL import Image, ImageFile

    Image.MAX_IMAGE_PIXELS = V.MAX_DIMENSION ** 2
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data), formats=["PNG"]) as im:
            if im.mode != "RGB" or im.size != size or getattr(im, "n_frames", 1) != 1 or getattr(im, "is_animated", False):
                raise V._error("template_input_invalid")
            im.verify()
        V._tick(deadline)
        with Image.open(io.BytesIO(data), formats=["PNG"]) as im:
            im.load()
            if im.mode != "RGB" or im.size != size or getattr(im, "n_frames", 1) != 1 or getattr(im, "is_animated", False):
                raise V._error("template_input_invalid")
            V._tick(deadline)
            x, y, width, height = roi
            with im.crop((x, y, x + width, y + height)) as cropped:
                raw = cropped.tobytes()
    V._tick(deadline)
    return raw


def _template_match(data: bytes, opts: dict) -> dict:
    """비교 op에는 원문·경로·이미지 대신 닫힌 숫자 봉투만 반환한다."""
    from pweh import vision_template as V
    from pweh.errors import PwehError

    try:
        keys = {"op", "parent_pid", "site_paths", "max_seconds", "reference_length", "candidate_length",
                "reference_size", "candidate_size", "reference_roi", "candidate_roi", "max_mean_error"}
        if type(opts) is not dict or set(opts) != keys or opts["op"] != V.OP:
            raise V._error("template_input_invalid")
        if (type(opts["parent_pid"]) is not int or opts["parent_pid"] <= 0
                or type(opts["site_paths"]) is not list or not 1 <= len(opts["site_paths"]) <= 2
                or any(type(path) is not str or not os.path.isabs(path) or "\x00" in path or len(path) > 4096
                       for path in opts["site_paths"])
                or type(opts["max_seconds"]) not in (int, float) or not 0 < opts["max_seconds"] <= 5):
            raise V._error("template_input_invalid")
        deadline = time.monotonic() + opts["max_seconds"]
        V._tick(deadline)
        for key in ("reference_length", "candidate_length"):
            if type(opts[key]) is not int or not 0 < opts[key] <= V.MAX_PNG_BYTES:
                raise V._error("template_input_invalid")
        if type(data) is not bytes or len(data) != opts["reference_length"] + opts["candidate_length"]:
            raise V._error("template_input_invalid")
        for key in ("reference_size", "candidate_size", "reference_roi", "candidate_roi"):
            if type(opts[key]) is not list:
                raise V._error("template_input_invalid")
        rsize, csize = tuple(opts["reference_size"]), tuple(opts["candidate_size"])
        rroi, croi = tuple(opts["reference_roi"]), tuple(opts["candidate_roi"])
        V._geometry(rsize, rroi)
        V._geometry(csize, croi)
        V._threshold(opts["max_mean_error"])
        if rroi[2:] != croi[2:]:
            raise V._error("template_input_invalid")
        # 검증한 부모 설치 경로만 -S 환경에 더한다. Pillow는 이 뒤에만 불러온다.
        for path in opts["site_paths"]:
            sys.path.append(path)
        rbytes = _template_png(data[:opts["reference_length"]], rsize, rroi, deadline)
        cbytes = _template_png(data[opts["reference_length"]:], csize, croi, deadline)
        result = V.compare_rgb_bytes(rbytes, cbytes, width=rroi[2], height=rroi[3],
                                    max_mean_error=opts["max_mean_error"], deadline=deadline)
        V._tick(deadline)
        return {"op": V.OP, "reference_size": list(rsize), "candidate_size": list(csize),
                "reference_roi": list(rroi), "candidate_roi": list(croi),
                "max_mean_error": opts["max_mean_error"], "result": result}
    except PwehError as exc:
        code = exc.code if exc.code in {"template_input_invalid", "time_limit"} else "template_failed"
        return {"op": V.OP, "error": code}
    except Exception:
        return {"op": V.OP, "error": "template_failed"}


def main() -> None:
    _limits()
    header_size, size = struct.unpack(">IQ", _read_exact(12))
    if not 0 < header_size <= 32768 or not 0 < size <= MAX_INPUT:
        raise ValueError("worker_input_limit")
    header = _read_exact(header_size)
    opts = json.loads(header)
    if type(opts) is dict and "op" in opts:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from pweh.imagehints import _template_json
        from pweh import vision_template as V
        try:
            opts = _template_json(header)
            if type(opts["parent_pid"]) is not int or opts["parent_pid"] != os.getppid():
                raise ValueError("parent_mismatch")
            if size > 2 * V.MAX_PNG_BYTES:
                raise ValueError("template_input_limit")
            result = _template_match(_read_exact(size), opts)
        except Exception:
            result = {"op": V.OP, "error": "template_input_invalid"}
        raw = json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii")
        if len(raw) > V.MAX_OUTPUT_BYTES:
            raise ValueError("template_output_limit")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return
    if os.getppid() != opts["parent_pid"]:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    data = _read_exact(size)
    result = analyze(data, opts)
    report = result["report"]
    # OCR/메타데이터의 제어문자가 JSON 에서 확장돼도 응답 전체 예산을 지킨다.
    if len(json.dumps(report, ensure_ascii=True, allow_nan=False)) > 4 * 1024 * 1024:
        report["ocr"]["text"] = report["ocr"].get("text", "")[:32768]
        report["ocr"]["words"] = report["ocr"].get("words", [])[:100]
        for word in report["ocr"]["words"]:
            word["text"] = word.get("text", "")[:256]
        report["ocr"]["truncated"] = True
        if report["ocr"].get("status") == "ok":
            report["ocr"]["status"] = "partial"
        report["truncated_reasons"].append("report_output_limit")
        report["warnings"].append("report_output_limit")
        if report["status"] == "ok":
            report["status"] = "partial"
        if len(json.dumps(report, ensure_ascii=True, allow_nan=False)) > 4 * 1024 * 1024:
            report["metadata"] = {"status": "partial", "warnings": ["report_output_limit"]}
            report["structure"]["text"] = []
            report["structure"]["xmp"] = []
            report["structure"]["comments"] = []
    raw = json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("worker_output_limit")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
