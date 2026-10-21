"""합성 OCR·QR 그림 생성기. Pillow 12.3.0, qrcode 8.2, NanumGothic.ttf 경로가 필요하다.

사용: python make_fixtures.py /path/to/NanumGothic.ttf
qrcode·글꼴은 생성할 때만 쓰며 PWEH 실행 의존성이 아니다. 실제 사진·증거·개인 데이터가 없다.
"""
from pathlib import Path
import sys

from PIL import Image, ImageDraw, ImageFont
import qrcode

root = Path(__file__).parent
font = ImageFont.truetype(sys.argv[1], 52)
picture = Image.new("RGB", (1200, 280), "white")
draw = ImageDraw.Draw(picture)
draw.text((35, 40), "PWEH SYNTHETIC IMAGE HINT", font=font, fill="black")
draw.text((35, 145), "안녕하세요 한국어 테스트", font=font, fill="black")
picture.save(root / "ocr-kor-eng.png", dpi=(300, 300))
qrcode.make("PWEH SYNTHETIC IMAGE HINT").save(root / "qr.png")
