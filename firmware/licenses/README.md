# 외부 펌웨어 입력의 라이선스 원문

이 파일들은 빌드에 사용한 고정 Docker 이미지 또는 exact-version component bundle에서 가져온 원문이다. [sources.json](sources.json)은 각 사본의 원본 위치와 SHA256을 기록한다. `/opt/esp/...`는 공개 Docker 이미지 내부 경로이며 개발자의 host 경로가 아니다. 원문의 저작권자 이름과 주소는 upstream의 라이선스 고지다.

| 사본 | 출처·범위 |
|---|---|
| `esp-idf-LICENSE.txt` | ESP-IDF v6.1 최상위 Apache-2.0 LICENSE |
| `esp_tinyusb-LICENSE.txt` | espressif/esp_tinyusb 2.4.0 component의 LICENSE |
| `tinyusb-LICENSE.txt` | espressif/tinyusb 0.21.0~2 component의 MIT LICENSE |
| `freertos-LICENSE.md` | 고정 IDF의 FreeRTOS-Kernel MIT LICENSE |
| `lwip-COPYING.txt` | 고정 IDF의 lwIP COPYRIGHT·BSD 조건 |
| `mbedtls-LICENSE.txt`, `psa-crypto-LICENSE.txt` | 고정 IDF의 Mbed TLS·TF-PSA-Crypto 라이선스 |
| `esp-libc-COPYING.NEWLIB.txt`, `esp-libc-COPYING.picolibc.txt` | IDF esp_libc가 제공하는 원문 |
| `newlib-COPYING.NEWLIB.txt` | 고정 Xtensa toolchain에 포함된 newlib의 파일별 고지 |
| `libgcc-COPYING3.txt`, `libgcc-COPYING.RUNTIME.txt` | 고정 toolchain의 GPLv3와 GCC Runtime Library Exception |

Docker 이미지는 `espressif/idf@sha256:f81b6e077e6af93c312181cd7d4e7936cfbafc5c7f77cbacba8fdd34994f218a`, toolchain은 그 안의 `xtensa-esp-elf/esp-15.2.0_20251204`다. IDF 최상위에는 별도 `NOTICE` 파일이 없었다. component 입력의 모든 파일 해시는 [dependencies-lock.json](../dependencies-lock.json)에 있다.

최소 `main` dependency closure의 map을 기준으로 FreeRTOS·libc·libgcc 및 link 입력에 나타나는 lwIP·Mbed TLS의 별도 고지를 함께 보존했다. map의 archive 이름만으로 해당 archive의 모든 코드가 최종 바이너리에 남았다고 주장하지 않는다. 정확한 link 결과는 각 release의 ELF·map에 남긴다. source에 포함된 파일별 SPDX·copyright 표기는 각 고정 upstream source에도 유지된다.

사전 빌드를 다시 배포할 때 이 디렉터리의 고지와 해당 release의 manifest·dependency lock을 함께 유지한다. 빌드·해시·소스 커밋 결속은 [빌드 문서](../../docs/references/espprobe-build.md)를 따른다.
