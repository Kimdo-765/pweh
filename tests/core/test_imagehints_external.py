"""관리 설치한 OCR/QR 도구를 합성 그림으로 검증한다(실제 케이스 없음)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pweh.config import load_config
from pweh.imagehints import analyze_image, resolve_image_tools

pytestmark = pytest.mark.external
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "image-hints"


def test_tesseract_korean_english_and_language_model_hashes():
    settings = resolve_image_tools(load_config())
    if not settings.tesseract or not settings.tessdata_dir:
        pytest.skip("Tesseract·통합 언어 모델이 설치되지 않음")
    if not all((Path(settings.tessdata_dir) / (lang + ".traineddata")).is_file() for lang in ("kor", "eng")):
        pytest.skip("한국어·영어 모델이 함께 설치되지 않음")
    result = analyze_image((FIXTURES / "ocr-kor-eng.png").read_bytes(), settings=settings, qr=False)
    ocr = result["report"]["ocr"]
    assert ocr["status"] == "ok", result["report"]["warnings"]
    assert "PWEH SYNTHETIC IMAGE HINT" in ocr["text"]
    assert "안녕하세요" in ocr["text"] and "한국어" in ocr["text"]
    engine = result["report"]["engines"]["tesseract"]
    assert engine["version"]
    assert set(engine["models"]) == {"kor", "eng"}
    assert all(len(item["sha256"]) == 64 for item in engine["models"].values())
    assert result["previews"]


def test_zbar_decodes_synthetic_qr_without_dbus_or_display():
    settings = resolve_image_tools(load_config())
    if not settings.zbarimg:
        pytest.skip("zbarimg 가 설치되지 않음")
    result = analyze_image((FIXTURES / "qr.png").read_bytes(), settings=settings, ocr=False)
    codes = result["report"]["codes"]
    assert codes["status"] == "ok", result["report"]["warnings"]
    assert any(c["type"] == "QR-Code" and c["text"] == "PWEH SYNTHETIC IMAGE HINT" for c in codes["items"])
    assert result["report"]["engines"]["zbar"]["version"]
