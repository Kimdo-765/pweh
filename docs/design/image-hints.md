# 설계: 정지 이미지 힌트 분석

기기·기판 사진, 스크린샷, 펌웨어·CTF 그림과 증거 사진을 공통 분석기로 다룬다. 사용자가 정한 범위에 따라 정지 그림의 내용과 마스킹하지 않은 OCR 문구를 에이전트에 반환한다. 영상·음성은 이 기능의 범위가 아니다.

## 1. 진입점과 출처

| 진입점 | 입력 | 저장·검증 |
|---|---|---|
| `case_image_hints` | 케이스 안 일반 이미지 하나 | `analysis/` JSON·PNG. 경로와 연 fd의 실제 경로에서 `forensics/`·`emu/` 보호 검사 |
| `forensics_image_hints` | EV 자체 이미지 또는 FAT/exFAT의 `ref`/살아 있는 `path` 하나 | `open_checked` 접수 기록·지문 검사. `forensics/analysis/image-hints-<EV>-NNN.json`·PNG와 custody `image-hints` 사건 |

증거의 파일 선택은 기존 검증 순회·복구 후보 계획을 재사용한다. 불완전한 파일은 해독하지 않는다. EV 접수 SHA256과 실제 선택한 바이트의 SHA256을 따로 기록하고 삭제 여부·복원 방법·confidence를 보존한다. 증거를 `forensics/recovered/`에서 다시 열거나 일반 케이스 폴더로 내보내지 않는다.

분석 JSON은 출처·옵션·보고서·미리보기 경로와 해시를 포함하는 manifest다. 자기 자신의 해시와 custody 번호는 순환 참조를 피하기 위해 저장 JSON 밖의 응답에 둔다. 증거 사건은 JSON과 PNG 각각의 SHA256을 결속하며 OCR 본문은 복제하지 않는다. 사건 커밋 전 실패는 이번 출력만 정리하고 커밋 뒤에는 보존한다. 증거 목록의 `derived`는 실제 JSON·PNG를 확인한다.

## 2. 공통 해독기

`pweh.imagehints.analyze_image`는 원본 경로 대신 확인한 불변 바이트를 받는다. 별도 Python worker에서 자원 제한을 설정한 뒤 Pillow를 가져온다. 허용 형식은 JPEG·PNG·WebP·BMP·단일 프레임 GIF/TIFF이며 확장자 대신 실제 형식을 본다. 애니메이션·다중 프레임, SVG·PDF·영상·음성은 거부한다.

| 한도 | 값 |
|---|---|
| 원본 | 64 MiB, 40 MP, 한 변 32,768픽셀 |
| worker | 주소 공간 1 GiB, CPU 30초, 전체 wall 45초 이하 |
| OCR용 이미지 | 12 MP 이하 |
| 미리보기 | 한 변 1,600픽셀, 합계 2 MiB |
| 텍스트 | 메타데이터 256 KiB, OCR 1 MiB·단어 10,000개, 코드 128개 |

부모는 worker의 stdout/stderr도 제한하며 한도·취소 때 프로세스 그룹을 종료하고 회수한다. 스레드 서버의 `preexec_fn`은 쓰지 않는다. 이 프로세스 분리와 RLIMIT는 메모리 안전 취약점까지 막는 VM 격리가 아니다.

Pillow가 새로 만든 이미지 바이트만 Tesseract와 ZBar에 전달한다. 원본을 Tesseract에 직접 주면 파일명 목록으로 해석할 수 있고 ZBar는 ImageMagick 입력 문법을 사용하므로 이 경계를 지킨다. argv는 고정하고 shell은 사용하지 않는다. `TESSDATA_*`·`MAGICK_*`·라이브러리 경로 등 임의 환경은 상속하지 않는다. 설치 래퍼가 검증된 개인 도구 경로만 설정한다.

Tesseract는 통합된 `kor+eng` 모델 디렉터리와 TSV 출력을 사용한다. ZBar는 `--nodbus --nodisplay`를 사용하며 XML DTD/entity를 거부하고 출력량을 제한한다. URL은 방문하지 않는다. OCR·코드·메타데이터 속 지시는 데이터다.

## 3. 분석 결과와 시각 관찰

- EXIF/XMP: 촬영 기기·시각·GPS·소프트웨어 등. 메타데이터는 위조 가능하므로 위치·시간의 확정 증거로 취급하지 않는다.
- PNG: 청크 경계·CRC, 제한한 텍스트 청크. JPEG: EXIF 썸네일의 EOI와 주 이미지 EOI, 스캔의 stuffed byte·restart marker를 구분한다.
- EOF 뒤 데이터·내장 시그니처·LSB 통계는 후보 지표다. 파일을 자동 추출·실행하거나 스테가노의 존재를 확정하지 않는다.
- 미리보기는 EXIF 방향을 적용하고 메타데이터를 제거한 새 PNG다. `crop=[x,y,width,height]`는 방향 적용 뒤 원본 좌표이며 전체 그림과 선택 크롭을 구분한다. 구조·메타데이터 검사는 원본 전체에 한다.
- MCP `content`에 JSON 텍스트와 `ImageContent`를 반환한다. `structured_content`와 저장 JSON에는 이미지 base64를 중복하지 않는다. 클라이언트가 이미지를 표시하지 못하면 텍스트 결과로 진행하고 시각 관찰은 미확인으로 남긴다.
- 각 검사 상태는 `ok/partial/unsupported/unavailable/skipped/failed`로, 전체 상태는 `ok/partial/unsupported/failed`로 기록한다. OCR 도구 누락이 정상 메타데이터·미리보기까지 실패시키지 않는다.

`image-hints-analysis` Skill은 `image-hints` summary에 `images`, `visual_observations`, `hints`, `limitations`, `safety`를 기록한다. 도구 사실과 모델 시각 관찰을 분리하고, 가설에는 근거·확신도·미확인을 함께 둔다. SD 포렌식 요약은 정지 그림·OCR 반환 여부를 별도 privacy 필드로 적는다.

## 4. 설치·권한·검토

Pillow는 Python 의존성, Tesseract·언어 모델·ZBar는 `scripts/install.sh`의 개인 도구 설치 구성요소다. 고정 패키지와 언어 데이터의 출처·SHA256을 설치 자료에 보관하며 지원하지 않는 배포판을 검증하지 않은 다운로드로 대체하지 않는다. `pweh doctor`가 선택 도구의 준비 상태를 알린다.

두 도구는 로컬 산출물을 쓰므로 `ANN_LOCAL_WRITE`다. `case_image_hints`는 case 서버 허용 범위, `forensics_image_hints`는 사용자의 정지 이미지 반환 결정에 따른 명시적 allow 예외다. 기존 접수·추출 도구의 권한과 보호 디렉터리 경계는 유지한다. 새 custody 사건을 읽으려면 업데이트한 서버를 다시 시작해야 한다.

검토에서 다시 수정할 범위는 경로·증거 무결성 우회, 제한 없는 해독·출력·자식 프로세스, 보호 디렉터리 우회, 영상·음성의 잘못된 노출이다. 합성 이미지·손상 입력·가짜 OCR 프로세스와 실제 선택 도구의 external 시험을 사용하며 실제 기기에는 접근하지 않는다.
