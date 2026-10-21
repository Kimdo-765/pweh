"""정지 그림 공통 코어: 합성 형식·해독 제한·출력 검증·프로세스 회수."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time
import zlib

import pytest
from PIL import Image, PngImagePlugin

from pweh import imagehints as H
from pweh._image_formats import inspect_structure
from pweh.errors import PwehError, ValidationFailed
from pweh.procutil import pid_alive


def picture(fmt="PNG", size=(96, 64), **kwargs):
    out = io.BytesIO()
    Image.new("RGB", size, (30, 90, 160)).save(out, format=fmt, **kwargs)
    return out.getvalue()


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def run(data=None, **options):
    return H.analyze_image(picture() if data is None else data, ocr=False, qr=False, **options)


def fake_tool(tmp_path, body, name="tool"):
    target = tmp_path / name
    target.write_text(f"#!{sys.executable}\nimport sys,os,time\n"
                      "if '--version' in sys.argv:\n sys.stdout.write('PWEH SYNTHETIC 1.0\\n'); sys.exit(0)\n" + body)
    target.chmod(0o755)
    return str(target)


def models(tmp_path):
    dest = tmp_path / "models"
    dest.mkdir(exist_ok=True)
    for lang in ("kor", "eng"):
        (dest / (lang + ".traineddata")).write_bytes(b"PWEH SYNTHETIC MODEL")
    return str(dest)


TSV_HEADER = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"


def test_png_chunk_boundary_crc_text_and_appended_candidate():
    info = PngImagePlugin.PngInfo()
    info.add_text("hint", "PWEH SYNTHETIC IEND text")
    data = picture(pnginfo=info)
    result = inspect_structure(data + b"PWEH SYNTHETIC PK\x03\x04payload")
    assert result["status"] == "ok"
    assert result["end_offset"] == len(data)
    assert result["trailing_bytes"] == 26
    assert result["text"][0]["text"] == "PWEH SYNTHETIC IEND text"
    assert result["embedded_candidates"][0]["signature"] == "zip"
    corrupt = bytearray(data)
    corrupt[29] ^= 1
    assert "chunk_crc_mismatch" in inspect_structure(bytes(corrupt))["errors"]


def test_png_itxt_ztxt_bomb_and_incomplete_iend():
    png = picture()
    ztxt = chunk(b"zTXt", b"hint\0\0" + zlib.compress(b"A" * 100000))
    bomb = png[:33] + ztxt + png[33:]
    result = inspect_structure(bomb)
    assert result["status"] == "partial"
    assert result["text"] == []
    assert "metadata_limit_or_invalid_compression" in result["warnings"]
    assert inspect_structure(png[:-6])["end_offset"] is None
    info = PngImagePlugin.PngInfo()
    info.add_itxt("XML:com.adobe.xmp", "<hint>합성 힌트</hint>", zip=True)
    assert inspect_structure(picture(pnginfo=info))["xmp"] == ["<hint>합성 힌트</hint>"]


def test_embedded_signature_in_png_ancillary_chunk_and_jpeg_app():
    png = picture()
    wrapped = png[:33] + chunk(b"pwEh", b"PWEH SYNTHETIC PK\x03\x04") + png[33:]
    assert inspect_structure(wrapped)["embedded_candidates"][0]["signature"] == "zip"
    jpg = picture("JPEG")
    payload = b"PWEH SYNTHETIC PK\x03\x04"
    wrapped = jpg[:2] + b"\xff\xe2" + struct.pack(">H", len(payload) + 2) + payload + jpg[2:]
    assert inspect_structure(wrapped)["embedded_candidates"][0]["signature"] == "zip"


def test_jpeg_skips_exif_thumbnail_eoi_and_entropy_stuffing():
    # APP1 안 썸네일 EOI 와 scan 안 stuffed FF / restart 를 주 EOI 로 보지 않는다.
    app = b"Exif\0\0PWEH SYNTHETIC\xff\xd8thumbnail\xff\xd9"
    header = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app) + 2) + app
    scan1 = b"\xff\xda\0\2entropy\xff\0stuffed\xff\xd0restart"
    dht = b"\xff\xc4\0\3x"
    scan2 = b"\xff\xda\0\2second\xff\xd9"
    data = header + scan1 + dht + scan2
    result = inspect_structure(data + b"PK\x03\x04")
    assert result["status"] == "ok"
    assert result["end_offset"] == len(data)
    assert result["trailing_bytes"] == 4
    assert inspect_structure(data[:-2])["end_offset"] is None


@pytest.mark.parametrize("progressive", [False, True])
def test_actual_jpeg_structure_and_xmp(progressive):
    data = picture("JPEG", progressive=progressive)
    xmp = b"http://ns.adobe.com/xap/1.0/\0<hint>PWEH SYNTHETIC</hint>"
    data = data[:2] + b"\xff\xe1" + struct.pack(">H", len(xmp) + 2) + xmp + data[2:]
    parsed = inspect_structure(data)
    assert parsed["status"] == "ok" and parsed["end_offset"] == len(data)
    result = run(data)
    assert result["report"]["status"] == "ok"
    assert result["report"]["metadata"]["xmp"] == ["<hint>PWEH SYNTHETIC</hint>"]


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "BMP", "WEBP", "GIF", "TIFF"])
def test_worker_still_formats_and_plain_png_preview(fmt):
    original = picture(fmt)
    result = run(original)
    report = result["report"]
    assert report["status"] in ("ok", "partial")
    assert report["input"] == {"size": len(original), "sha256": hashlib.sha256(original).hexdigest()}
    assert report["image"]["format"] == fmt
    preview = result["previews"][0]
    with Image.open(io.BytesIO(preview["data"])) as im:
        assert im.format == "PNG" and im.size == (96, 64) and not im.getexif()
    assert "data_b64" not in preview and "data" not in report


def test_metadata_exif_orientation_crop_and_unmasked_text():
    exif = Image.Exif()
    exif[274] = 6
    exif[271] = "PWEH SYNTHETIC CAMERA"
    exif[306] = "2020:01:02 03:04:05"
    data = picture("JPEG", exif=exif)
    result = run(data, crop=[0, 10, 20, 30])
    report = result["report"]
    assert report["image"]["width"] == 64 and report["image"]["height"] == 96
    assert report["metadata"]["exif"]["Make"] == "PWEH SYNTHETIC CAMERA"
    assert report["metadata"]["exif"]["DateTime"] == "2020:01:02 03:04:05"
    assert report["analysis_region"]["crop"] == [0, 10, 20, 30]
    assert [p["role"] for p in result["previews"]] == ["overview", "crop"]
    assert result["previews"][1]["width"] == 20
    info = PngImagePlugin.PngInfo()
    info.add_text("hint", "password=PWEH_SYNTHETIC_NOT_A_SECRET")
    result = run(picture(pnginfo=info))
    assert "PWEH_SYNTHETIC_NOT_A_SECRET" in result["report"]["metadata"]["png_text"][0]["text"]
    assert b"password=" not in result["previews"][0]["data"]


def test_exif_gps_is_data_without_timezone_or_location_inference():
    exif = Image.Exif()
    # 합성 좌표: 실제 위치나 사람의 이동 이력이 아니다.
    exif[34853] = {1: "N", 2: (1., 2., 3.), 3: "E", 4: (4., 5., 6.)}
    result = run(picture("JPEG", exif=exif))
    gps = result["report"]["metadata"]["gps"]
    assert gps["GPSLatitude"] == [1., 2., 3.]
    assert gps["GPSLongitudeRef"] == "E"
    assert result["report"]["metadata"]["time_basis"] == "metadata-verbatim-unknown-timezone"


def test_large_image_analysis_downsamples_and_preview_is_optional(tmp_path):
    header = TSV_HEADER + "5\t1\t1\t1\t1\t1\t0\t0\t10\t10\t99\tPWEH\n"
    exe = fake_tool(tmp_path, "data=sys.stdin.buffer.read()\n"
                    "import struct\nw,h=struct.unpack('>II',data[16:24]); assert w*h<=12000000\n"
                    f"sys.stdout.write({header!r})\n")
    result = H.analyze_image(picture(size=(4000, 3300)), settings=H.ImageToolSettings(tesseract=exe, tessdata_dir=models(tmp_path)),
                             qr=False, preview=False)
    assert result["report"]["ocr"]["status"] == "ok"
    region = result["report"]["analysis_region"]
    assert region["width"] * region["height"] <= 12000000
    assert region["source_width"] == 4000 and not result["previews"]


def test_animated_gif_apng_webp_and_multiframe_tiff_rejected():
    a, b = Image.new("RGB", (12, 12), "red"), Image.new("RGB", (12, 12), "blue")
    for fmt in ("GIF", "PNG", "WEBP", "TIFF"):
        out = io.BytesIO()
        a.save(out, format=fmt, save_all=True, append_images=[b], duration=100, loop=0)
        result = run(out.getvalue())
        assert result["report"]["status"] == "unsupported", fmt
        assert "animated_or_multiframe" in result["report"]["warnings"]
        assert not result["previews"]


def test_pixel_dimension_truncated_and_nonimage_limits():
    png = picture()
    huge = png[:8] + chunk(b"IHDR", struct.pack(">IIBBBBB", 50000, 50000, 8, 2, 0, 0, 0)) + png[33:]
    result = run(huge)
    assert result["report"]["status"] == "failed"
    assert not result["previews"]
    assert run(png[:-10])["report"]["status"] == "failed"
    assert not run(b"\0\0\0\x18ftypmp42PWEH SYNTHETIC VIDEO")["previews"]
    assert run(crop=[90, 0, 20, 20])["report"]["warnings"] == ["crop_outside_image"]


@pytest.mark.parametrize("options", [{"max_seconds": 46}, {"max_seconds": float("nan")},
                                      {"max_seconds": 0}, {"crop": [0, 0, 0, 5]},
                                      {"crop": [False, 0, 5, 5]}, {"ocr_lang": "eng ../../x"},
                                      {"preview": "true"}])
def test_invalid_options_before_spawn(options):
    with pytest.raises(ValidationFailed):
        run(**options)


def test_input_type_size_and_env_limits():
    for value in (b"", bytearray(b"x"), b"x" * (H.MAX_INPUT_BYTES + 1)):
        with pytest.raises(ValidationFailed):
            run(value)
    with pytest.raises(ValidationFailed):
        run(settings=H.ImageToolSettings(tesseract="relative"))
    with pytest.raises(ValidationFailed):
        run(settings=H.ImageToolSettings(child_env={"LD_PRELOAD": "/untrusted"}))


def test_missing_tools_partial_keeps_preview():
    result = H.analyze_image(picture())
    assert result["report"]["status"] == "partial"
    assert result["report"]["ocr"]["status"] == "unavailable"
    assert result["report"]["codes"]["status"] == "unavailable"
    assert len(result["previews"]) == 1


def test_fake_ocr_gets_sanitized_png_fixed_argv_limits_and_clean_env(tmp_path, monkeypatch):
    body = """import resource
data=sys.stdin.buffer.read()
assert data.startswith(b'\\x89PNG\\r\\n\\x1a\\n') and b'SECRET-METADATA' not in data
assert sys.argv[1:3]==['stdin','stdout'] and '--tessdata-dir' in sys.argv
assert resource.getrlimit(resource.RLIMIT_AS)==(1024**3,1024**3)
assert resource.getrlimit(resource.RLIMIT_CPU)==(30,30)
assert 'PWEH_SYNTHETIC_SECRET' not in os.environ and 'TESSDATA_PREFIX' not in os.environ
"""
    text = "암호=PWEH_SYNTHETIC"
    tsv = TSV_HEADER + '5\t1\t1\t1\t1\t1\t0\t0\t10\t10\t97.5\t' + text + '\n'
    body += f"sys.stdout.write({tsv!r})\n"
    exe = fake_tool(tmp_path, body)
    monkeypatch.setenv("PWEH_SYNTHETIC_SECRET", "value")
    monkeypatch.setenv("TESSDATA_PREFIX", "/untrusted")
    info = PngImagePlugin.PngInfo(); info.add_text("hint", "SECRET-METADATA")
    result = H.analyze_image(picture(pnginfo=info), settings=H.ImageToolSettings(tesseract=exe, tessdata_dir=models(tmp_path)), qr=False)
    assert result["report"]["ocr"]["text"] == text
    assert result["report"]["ocr"]["words"][0]["confidence"] == 97.5
    assert result["report"]["engines"]["tesseract"]["version"] == "PWEH SYNTHETIC 1.0"


@pytest.mark.parametrize("body,reason", [
    ("sys.stdout.write('x'*1100000)", "output_limit"),
    ("sys.stderr.write('x'*100000)", "stderr_limit"),
    ("sys.stdout.write('not TSV')", "invalid_tsv"),
    ("sys.stdout.write(" + repr(TSV_HEADER + "5\t1\t1\t1\t1\t1\t0\t0\t99999\t10\t99\tx\n") + ")", "invalid_tsv"),
])
def test_abnormal_ocr_output_is_bounded_partial(tmp_path, body, reason):
    exe = fake_tool(tmp_path, body)
    result = H.analyze_image(picture(), settings=H.ImageToolSettings(tesseract=exe, tessdata_dir=models(tmp_path)), qr=False)
    assert result["report"]["status"] == "partial"
    assert result["report"]["ocr"]["reason"] == reason
    assert result["previews"]


def test_fake_zbar_only_normalized_pgm_and_unmasked_xml(tmp_path):
    xml = '<barcodes xmlns="http://zbar.sourceforge.net/2008/barcode"><source><index><symbol type="QR-Code"><data><![CDATA[https://example.invalid/PWEH-SYNTHETIC]]></data></symbol><symbol type="CODE-128"><data format="base64">aGVsbG8=</data></symbol></index></source></barcodes>'
    exe = fake_tool(tmp_path, "assert '--nodbus' in sys.argv and '--nodisplay' in sys.argv\n"
                    "assert sys.argv[-1].startswith('/proc/self/fd/')\n"
                    "with open(sys.argv[-1],'rb') as f: assert f.read(2)==b'P5'\n"
                    f"sys.stdout.write({xml!r})\n")
    result = H.analyze_image(picture(), settings=H.ImageToolSettings(zbarimg=exe), ocr=False)
    assert [item["text"] for item in result["report"]["codes"]["items"]] == ["https://example.invalid/PWEH-SYNTHETIC", "hello"]


@pytest.mark.parametrize("xml", ['<!DOCTYPE x [<!ENTITY a SYSTEM "file:///private">]><x>&a;</x>', '<!ENTITY a "x"><x/>', '<broken'])
def test_zbar_xml_dtd_entities_and_malformed_rejected(tmp_path, xml):
    exe = fake_tool(tmp_path, f"sys.stdout.write({xml!r})\n")
    result = H.analyze_image(picture(), settings=H.ImageToolSettings(zbarimg=exe), ocr=False)
    assert result["report"]["codes"]["reason"] == "invalid_xml"


def test_zbar_utf16_dtd_does_not_bypass_xml_filter(tmp_path):
    xml = '<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>'.encode("utf-16")
    exe = fake_tool(tmp_path, f"sys.stdout.buffer.write({xml!r})\n")
    result = H.analyze_image(picture(), settings=H.ImageToolSettings(zbarimg=exe), ocr=False)
    assert result["report"]["codes"]["reason"] == "invalid_xml"


def test_worker_output_and_stderr_caps():
    for code, reason in (("import sys;sys.stdout.buffer.write(b'x'*10000000)", "worker_output_limit"),
                         ("import sys;sys.stderr.buffer.write(b'x'*100000)", "worker_stderr_limit")):
        raw, actual = H._exchange([sys.executable, "-c", code], b"", deadline=time.monotonic() + 3, cancel_event=None)
        assert actual == reason and len(raw) <= H.MAX_OUTPUT_BYTES


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_cancel_kills_process_group(tmp_path, cancel):
    child_file = tmp_path / "child.pid"
    # 자신과 자식의 stdout 을 열어 둔다. 부모는 프로세스 그룹 전체를 회수해야 한다.
    code = "import subprocess,time,pathlib,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
    event = threading.Event()
    timer = threading.Timer(.3, event.set) if cancel else None
    if timer:
        timer.start()
    try:
        _, reason = H._exchange([sys.executable, "-c", code, str(child_file)], b"",
                                deadline=time.monotonic() + (.9 if cancel else .3), cancel_event=event)
    finally:
        if timer:
            timer.cancel()
    assert reason == ("cancelled" if cancel else "wall_timeout")
    pid = int(child_file.read_text())
    for _ in range(50):
        if not pid_alive(pid):
            break
        time.sleep(.01)
    assert not pid_alive(pid)


def test_precancel_and_short_budget():
    event = threading.Event(); event.set()
    with pytest.raises(PwehError) as error:
        run(cancel_event=event)
    assert error.value.code == "cancelled"
    result = run(max_seconds=.00001)
    assert result["report"]["truncated_reasons"] == ["wall_timeout"]


def test_parent_validates_preview_and_report(monkeypatch):
    data = picture()
    valid = run(data)
    for mode in ("hash", "metadata", "size", "report"):
        wire = {"report": dict(valid["report"]), "previews": [dict(valid["previews"][0])]}
        p = wire["previews"][0]
        png = p.pop("data")
        if mode == "hash": p["sha256"] = "0" * 64
        if mode == "metadata":
            png = png[:33] + chunk(b"tEXt", b"hidden\0private") + png[33:]
            p["sha256"] = hashlib.sha256(png).hexdigest()
        if mode == "size": p["width"] = 100000
        if mode == "report": wire["report"]["input"] = {"size": 1, "sha256": "0" * 64}
        p["data_b64"] = base64.b64encode(png).decode()
        monkeypatch.setattr(H, "_exchange", lambda *a, _wire=wire, **kw: (json.dumps(_wire).encode(), None))
        assert run(data)["report"]["warnings"] == ["invalid_worker_response"]


def test_locator_has_no_implicit_path_fallback(tmp_path, monkeypatch):
    from pweh import toolsdir
    monkeypatch.setattr(toolsdir, "tools_dir", lambda: tmp_path / "managed")
    for name in ("PWEH_TESSERACT", "PWEH_ZBARIMG", "PWEH_TESSDATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    exe = fake_tool(tmp_path, "", "tesseract")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert H.resolve_image_tools({}).tesseract is None
    assert H.resolve_image_tools({"tools": {"tesseract": "tesseract"}}).tesseract == exe
