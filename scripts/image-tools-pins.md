# 이미지 도구 고정 자료

`image-tools-lock.json`은 Ubuntu 22.04 x86_64용이다. 다른 Ubuntu/Debian 버전·아키텍처는
검증한 잠금 자료를 추가하기 전까지 지원하지 않으며 apt 최신 버전으로 대체하지 않는다.

2026-10-21에 공식 `https://archive.ubuntu.com/ubuntu/`의 jammy·jammy-updates
InRelease를 Ubuntu archive keyring으로 검증했다. 서명 키는
`F6ECB3762474EDA9D21B7022871920D1991BC93C`다. InRelease의 SHA256과 크기로
main/universe의 `binary-amd64/Packages.xz`를 확인하고, 그 안의 버전·URL·SHA256을
고정했다. 사용한 InRelease와 Packages.xz의 URL·지문은 JSON의 `sources`에 있다.
잠금 갱신도 이 서명 → 색인 SHA256 → .deb SHA256 순서를 반복해야 한다.

주 패키지와 핵심 라이브러리(`always_extract`)는 이미 설치되어 있어도 고정 .deb를
개인 경로에 푼다. 그 밖의 런타임은 기존 `deb_fetch_extract`처럼 시스템에 있으면
재사용한다. 따라서 호스트 전체를 재현하는 잠금은 아니다. `root/install.json`은
다운로드한 고정 패키지와 재사용한 시스템 런타임의 이름·버전을 구분한다. libc·dpkg 등
기본 운영체제는 설치하지 않는다. maintainer script도 실행하지 않는다.

언어 모델 eng/kor/osd는 `tesseract-ocr-*` 고정 .deb에서 꺼낸 `tessdata_fast`다.
공식 upstream은 <https://github.com/tesseract-ocr/tessdata_fast>이며 Apache-2.0이다.
`.deb`를 검증한 뒤 꺼낸 각 `traineddata`의 SHA256도 기록·검사한다. 통합 경로는
`<tools>/tesseract/tessdata`이고 `configs/tsv`는 PWEH가 만드는 고정 설정 한 줄이다.

Tesseract는 Apache-2.0, ZBar는 LGPL-2.1-or-later, Pillow 12.3.0은 MIT-CMU다.
전이 라이브러리는 각 .deb의 `usr/share/doc/<package>/copyright`를 보존한다.
Pillow는 pyproject에서 버전을 고정하고 일반 Python 패키지 설치 경로를 쓴다.
이 JSON의 다운로드 SHA256 잠금은 `.deb`와 추출 언어 모델에 적용된다.

zbarimg 래퍼는 개인 ImageMagick 모듈·정책 경로를 지정하며 PNG/PNM/PGM/PPM 읽기만
허용한다. 이 정책은 원본 이미지의 해독을 대신하지 않는다. 공통 worker가 Pillow로
검사·정규화한 이미지 하나만 넘기고 `--nodbus --nodisplay`를 고정해야 한다.
