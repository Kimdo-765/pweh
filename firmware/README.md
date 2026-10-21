# PWEH 계측기 펌웨어

`common/`은 고정 프레임 codec과 세션 상태 전이, `espprobe/`는 ESP32-S3 `probe-hello` 프로필이다. USB CDC 두 개의 HELLO/HB·RELEASE/BYE/ABORT만 지원하고 계측 GPIO 기능은 아직 없다. 현재 이름 `esp32s3-devkitc1-hello`는 보드 빌드 식별자이며 실기 검증 선언이 아니다.

소스·dependency lock을 고정한 뒤 Docker 안에서 두 번 독립 빌드하고 모든 산출물을 비교한다. 재현된 release만 `releases/espprobe/<version>/`에 저장한다. 소스 커밋과 산출물 커밋은 구별하며 installer는 사전 빌드를 검증해 복사한다.

- [고정 빌드·검사·재현·설치](../docs/references/espprobe-build.md)
- [프레임·HELLO·USB 계약](../docs/references/espprobe-protocol.md)
- [외부 입력 라이선스와 출처](licenses/README.md)

이 디렉터리의 빌드·설치 도구는 기기를 열거나 펌웨어를 쓰지 않는다. 실제 기기 지원 범위는 서버 및 안전 계약에서 따로 관리한다.
