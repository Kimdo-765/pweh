# 이미지 분석 합성 픽스처

실제 사진·증거·개인 데이터가 없다. `qr.png`는 `PWEH SYNTHETIC IMAGE HINT`,
`ocr-kor-eng.png`는 `PWEH SYNTHETIC IMAGE HINT`와 `안녕하세요 한국어 테스트`만 담는다.

`make_fixtures.py`로 생성했다. 생성 의존성은 Pillow 12.3.0, qrcode 8.2,
NanumGothic.ttf(공식 Ubuntu `fonts-nanum`의 SIL Open Font License 글꼴)다.
글꼴·qrcode 패키지는 저장소에 포함하지 않으며 PWEH의 실행 의존성도 아니다.
시험은 이 PNG 파일들을 그대로 사용하므로 글꼴이나 생성기를 실행할 필요가 없다.
