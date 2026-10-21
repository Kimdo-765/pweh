# espprobe 고정 빌드와 사전 빌드 설치

현재 프로필은 ESP32-S3의 `probe-hello` 하나다. USB CDC 두 개와 HELLO/HB·RELEASE/BYE/ABORT 상태 전이만 구현하며 GPIO 계측·전송 기능은 없다. `esp32s3-devkitc1-hello`는 빌드 식별자이며 실기 검증 결과를 뜻하지 않는다. 실기 포트를 열거나 플래시를 쓰는 명령은 이 빌드 도구에 없다.

## 고정 입력

| 입력 | 고정값 |
|---|---|
| ESP-IDF | v6.1, `linux/amd64` |
| Docker 이미지 | `espressif/idf@sha256:f81b6e077e6af93c312181cd7d4e7936cfbafc5c7f77cbacba8fdd34994f218a` |
| 이미지 config ID | `sha256:1001c0c42918725dcdacfbcfdaa17cbf95370f2d15359e402b99d0a6237cb99c` |
| 외부 component | `espressif/esp_tinyusb` 2.4.0, `espressif/tinyusb` 0.21.0~2 |
| Component Manager | 고정 이미지의 3.0.3 |
| 앱 | `pweh_espprobe`, 버전은 `firmware/espprobe/VERSION` |
| 플래시 배치 | 4 MiB, partition table `0x8000`, factory 앱 `0x10000`, 앱 영역 1 MiB |

이미지의 압축 layer 합계는 약 4.08 GB이고 로컬 image 크기는 약 8.50 GB다. 빌드별 새 volume과 출력 공간도 필요하다. component ZIP·CHECKSUMS의 URL/크기/SHA256은 `scripts/firmware/components-lock.json`, 해제한 전체 파일 집합은 `firmware/dependencies-lock.json`, manager 원본 lock은 `firmware/espprobe/dependencies.lock`에 고정한다. 외부 vendor 소스 전체를 저장소에 복제하지 않는다.

## 준비와 빌드

저장소의 `.venv`와 사용자가 접근할 수 있는 로컬 Docker daemon이 필요하다. `sudo`나 Docker 권한 설정을 자동 변경하지 않는다. 다음 경로는 예시이며 출력 디렉터리는 아직 존재하지 않아야 한다.

```sh
scripts/build_firmware.sh prepare --output /tmp/pweh-fw-deps --dry-run
scripts/build_firmware.sh prepare --output /tmp/pweh-fw-deps
scripts/build_firmware.sh lock --deps /tmp/pweh-fw-deps --output /tmp/pweh-fw-lock
```

`prepare`만 고정 이미지를 pull하고 공식 component URL에 접근한다. 내려받기 컨테이너에는 downloader와 pin 파일만 전달하며 앱 소스나 CMake는 실행하지 않는다. `lock`은 만들어진 로컬 mirror만 사용한다. 기존 lock을 갱신하는 개발자는 생성된 두 lock을 검토하고 소스 커밋에 함께 넣어야 한다. release 빌드는 bundle의 lock과 지정한 소스 커밋의 lock이 바이트 단위로 같아야 시작한다.

API 확인용 예비 빌드는 다음처럼 실행한다. 현재 파일 중 고정된 소스 경로만 복사하고 커밋 식별자는 40자리 `0`으로 표시한다. 이 결과는 release manifest를 만들 수 없다.

```sh
scripts/build_firmware.sh build --deps /tmp/pweh-fw-deps \
  --output /tmp/pweh-fw-preliminary --preliminary
```

release는 검토를 마친 소스 커밋 **S**의 full SHA를 사용한다. `SOURCE_COMMIT`에는 해당 40자리 SHA를 설정한다.

```sh
scripts/build_firmware.sh reproduce --deps /tmp/pweh-fw-deps \
  --output /tmp/pweh-fw-repro --source-commit "$SOURCE_COMMIT"
scripts/build_firmware.sh publish --result /tmp/pweh-fw-repro
scripts/build_firmware.sh verify-release
```

`reproduce`는 S의 Git blob으로 만든 동일한 archive를 서로 다른 새 volume에 넣고 두 번 빌드한다. 로컬 Git replace refs와 export 속성을 적용하지 않으며 링크·submodule 입력은 거부한다. 고정 `/work/src`·`/work/build`, 커밋 시각의 `SOURCE_DATE_EPOCH`, `CONFIG_APP_REPRODUCIBLE_BUILD`, 비활성 ccache를 사용한다. 소스 입력은 읽기 전용 volume이고 빌드 작업은 별도 tmpfs에서 수행한다.

실제 configure/build 컨테이너는 `--network=none`, 읽기 전용 root, 비root uid, capability 제거, `no-new-privileges`, CPU·메모리·PID·wall time 상한을 사용한다. host 기기·Docker socket·home·케이스 디렉터리는 mount하지 않는다. Docker daemon이 WSL 경로를 볼 수 없어도 필요한 입력만 `docker cp`로 자체 volume에 전달한다. 출력 volume 소유자 설정용 helper는 그 volume에만 고정 `chown`을 실행한다. 실패·취소 때 자체 프로세스 그룹, 컨테이너, volume을 각각 회수하며 정리 실패를 별도 기록한다.

## 통과해야 하는 검사

- `main`과 `pweh_common`의 모든 응용 object가 검사 및 최종 link에 포함되어야 한다. 플래시 쓰기·erase·eFuse·무선·전송 전용 RMT·HID/MSC·서버 시작 등의 금지 참조가 있으면 실패한다. SDK 내부의 정상 부팅용 플래시 호출과 응용 object는 구별한다.
- 모든 compile/link 명령과 제한된 response 파일을 펼쳐 중복 정의 허용, symbol weaken, LTO 옵션을 거부한다. `objcopy -Wsymbol`과 linker의 `-Wl,@file`도 검사한다. ELF symbol table은 파일 전체 누적 개수와 중복 범위를 제한한다.
- 최종 ELF의 무선 코드·미해결 무선 참조를 거부한다. 고정 SDK ROM linker 파일에 있는 정확한 이름·주소의 `SHN_ABS` alias만 구별한다. 현재 예외는 ROM 주소 `0x40005b20`의 `ieee80211_crypto_encap`이며 앱이 이를 참조하는 것은 허용하지 않는다. checker 보고서에 alias와 SDK linker 파일의 해시를 남긴다.
- 실제 sdkconfig의 Wi-Fi/BT 비활성, console NONE, secondary console NONE, watchdog 활성·초기화·panic·2초, 재현 설정, USB 클래스 및 flash 배치를 확인한다. defaults 파일만 보고 통과시키지 않는다.
- 응용 및 TinyUSB source에 실제 적용된 전처리 결과에서 `CFG_TUD_CDC_TX_OVERWRITABLE_IF_NOT_CONNECTED=0`을 확인한다. USB device/config descriptor의 모든 바이트를 독립 canonical 값과 비교한다. CDC 두 개의 endpoint 방향·개수와 functional descriptor도 고정된다.
- HELLO가 사용하는 ELF의 policy TLV·USB descriptor·크기 심볼, 소스 커밋·버전·board·profile을 검사한다. capability·TX capability·허용 핀은 모두 비어 있어야 한다.
- 앱 checksum·appended digest·ELF 해시, bootloader, partition table MD5, merged 이미지의 offset·빈 영역을 확인한다. 파티션은 factory 하나이며 NVS·OTA 파티션은 없다.

이 검사는 고정 프로필의 빌드 계약을 확인한다. 실제 보드에서 USB 연결이나 watchdog 동작을 확인했다는 뜻은 아니며 manifest의 `hardware_verified`는 `false`다.

## 해시와 release commit

| 필드 | 해시 대상 |
|---|---|
| `image_sha256` | 앱 ESP image의 마지막 32바이트에 저장된 digest. 그 digest를 제외한 앞부분을 해시하고 비교한 값 |
| `files[].sha256` 중 앱 파일 | appended digest를 포함한 `.bin` 파일 전체 |
| `app_elf_sha256` | 최종 `.elf` 전체. 앱의 `esp_app_desc`에 들어간 값과도 비교 |
| `source_archive_sha256` | 소스 커밋 S에서 고정 경로의 blob으로 만든 archive 전체 |
| `policy_sha256` | HELLO가 실제 사용하는 canonical policy TLV 바이트 |

`image_sha256`는 `esp_partition_get_sha256()`이 앱 파티션에서 검증 후 돌려주는 digest와 맞추기 위한 식별자다. 파일 전체 해시나 ELF 해시와 혼용하지 않는다. `files[]`는 각 산출물의 전체 파일 해시를 별도로 보관한다.

두 빌드의 앱·bootloader·partition table·merged·ELF·map·checker 보고서·dependency lock **8개 모두**가 바이트 단위로 같아야 `runs=2`와 release manifest를 생성한다. 결과는 `firmware/releases/espprobe/<version>/`에 `release.json`, `reproducibility.json`, `SHA256SUMS`와 함께 저장하고 패키지의 `espprobe-releases.json`에도 같은 entry를 넣는다.

S에는 소스와 lock·checker를 담는다. 그 S로 만든 산출물은 별도 커밋 **R**에 넣는다. manifest의 `git_commit`은 S를 가리키며, 자신을 포함하는 R의 해시를 자기 안에 쓰지 않는다. `publish`와 `verify-release`는 S 이후 빌드 입력이 바뀌지 않았는지도 검사한다. 도구는 Git commit을 만들지 않는다.

## 선택 installer

```sh
scripts/install.sh --only espprobe-fw
scripts/install.sh --only espprobe-fw --check
```

`espprobe-fw`는 기본 최소 설치에 포함되지 않는 선택 항목이다. 저장소에 들어 있는 검증된 사전 빌드를 `<tools>/firmware/espprobe/<version>/probe-hello/esp32s3-devkitc1-hello/`로 복사한다. 설치 시 다운로드·Docker 빌드·포트 접근은 없다. manifest, payload, USB/policy, 이미지 배치를 다시 검증하고 stage를 확인한 뒤 교체한다. symlink 목적지는 거부하며 변경된 기존 설치를 교체하려면 `--force`가 필요하다. release가 없는 checkout에서는 설치했다고 표시하지 않고 건너뛴다.

## 근거와 시험

합성 ELF/ESP image와 가짜 실행기로 forbidden reference, symbol 중복·범위, linker response, descriptor 변이, hash 혼동, Git replace, archive 탈출, timeout·고아 프로세스 회수, 설치 무결성·rollback을 시험한다. 실제 Docker 빌드의 결과와 한계는 해당 release의 `build-check.json`·`reproducibility.json`에 남긴다.

공식 설명: [IDF Docker image](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-guides/tools/idf-docker-image.html), [IDF reproducible builds](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-guides/reproducible-builds.html), [ESP image format](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/advanced-topics/firmware-image-format.html), [partition API](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/storage/partition.html), [component lock](https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/dependencies_lock.html), [offline component mirror](https://docs.espressif.com/projects/idf-component-manager/en/latest/use/how_to_offline_usage.html). 내려받은 정확한 입력의 라이선스 원문과 출처는 [firmware/licenses](../../firmware/licenses/README.md)에 있다.
