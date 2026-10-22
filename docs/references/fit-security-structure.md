# FIT 서명 선언의 구조 관찰

`fw_sd_surface(image_path=...)`의 `fit_security`는 입력 이미지 안의 비압축 FDT v17을
제한된 범위에서 찾아 서명·키 관련 선언 구조를 기록한다. 기존 env·문자열 분석 뒤 같은 호출의
남은 시간만 사용한다. 저장 JSON과 공개 응답에 같은 section을 남기며 `max_results`로 생략하지 않는다.
`rootfs_dir`만 지정한 결과는 `not-examined`다.

## 관찰 대상과 의미

| 위치 | 분류 | 관찰 |
|---|---|---|
| `/images/<image>/signature*` | image-signature | 이미지 서명 선언 |
| `/configurations/<config>/signature*` | configuration-signature | 설정 서명 선언 |
| `/signature`의 직접 자식 | control-key | control-DTB 형태의 공개키 후보 |

서명 위치, 알고리즘의 고정 분류, 값의 길이, key hint 존재, 선언 목록의 개수와 관련 속성의
형식만 관찰한다. 이름은 구조 안의 순서 번호로 나타낸다. `node_offset`은 입력 파일 기준이다.
새 section에는 임의 노드명·키 힌트·서명/키 바이트·이미지 payload·예외 원문을 넣지 않는다.
기존 SD 문자열 근거와 다른 도구의 원문 반환 계약까지 바꾼다는 뜻은 아니다.

`required`·`required-mode`와 `hashed-nodes`·`hashed-strings`는 선언이다. 선언 목록이 실제로
서명한 범위인지, 키가 일치하거나 신뢰되는지, 해당 DTB가 실제 부팅에 사용되는지는 확인하지 않는다.
외부 데이터 위치를 따라가거나 압축을 풀지 않는다. 이 범위는 U-Boot의
[서명 문서](https://docs.u-boot.org/en/v2024.01/usage/fit/signature.html)와
[FIT 구조 문서](https://docs.u-boot.org/en/v2024.01/usage/fit/source_file_format.html)를 따른 제한된 관찰이다.

다음 값은 항상 false다: `cryptographic_verification_performed`, `key_trust_verified`,
`boot_enforcement_verified`, `sd_route_link_verified`.
서명이 있거나 없는 것만으로 안전·무서명 업데이트·취약점 여부를 판정하지 않는다.
기존 `fit_signature_keys`는 `key-name-hint` **문자열 표지**이며 구조 검사 결과와 별개다.

## 완료도와 부분 결과

스키마 식별자는 `pweh.fit-security-structure/v1`이다. `status`는 `complete`, `partial`,
`not-examined`이며, `complete`는 제한된 관찰을 마쳤다는 뜻이다.

- `coverage.search_end`: 허용된 검색 바이트 구간의 끝.
- `coverage.positions_examined_end`: `[0,n)`의 magic 시작 위치를 검사한 연속 범위.
  크기 S의 입력에서 가능한 시작 위치 수는 `max(0,S-3)`이다.
- `search_complete`, `structures_complete`, `output_complete`: 검색·구조 검사·결과 보존의 완료 여부.
- `pending_offset`: 찾았지만 검사나 결과 보존을 마치지 못한 현재 후보 위치.
- `blobs[].structure_status`: `complete`, `malformed`, `unsupported`, `limited`.
  전체 구조를 못 읽었으면 개수는 null, 존재 여부는 unknown일 수 있다.
- `entries_complete`: 해당 구조의 항목 목록을 모두 보존했는지. 관찰 개수와 반환한 항목 수를 구분한다.

정상 구조를 완주한 범위에만 `absent`를 쓴다. 후보0개는 입력 전체의 서명 부재나 안전을 증명하지 않는다.
검색 cap에 걸친 선언 범위와 실제 잘린 입력을 구분한다. 구조 정보의 부분 결과는 기존 SD-01~09의
상태·심각도를 바꾸지 않으며 해당 section의 완료도·사유로 확인한다.

## 고정 한도

| 항목 | 상한 |
|---|---|
| 검색 | 입력 크기·기존 이미지 예산·256 MiB 중 최소, 64 KiB 청크 |
| 구조 후보 / 보존 구조 / 항목 | 64 / 32 / 모든 구조 합128 |
| FDT / 문자열 블록 | 64 MiB / 1 MiB |
| 구조당 노드 / 깊이 / 속성 / 토큰 | 8192 / 32 / 32768 / 65536 |
| 전체 토큰 / 복사한 이름·작은 값 | 131072 / 2 MiB, 실패한 후보 비용도 누적 |
| 예약 메모리 범위 / 관련 선언 목록 | 1024쌍 / 8 KiB·100항목 |
| 새 section JSON | UTF-8 64 KiB |

큰 data·signature value·키 값은 내부 offset/length로만 유지한다. 이름/작은 값은 복사 전에
예산을 확인하며 중복 속성·형제 이름·블록 겹침·잘못된 순서/종결을 거부한다.
v16은 이 새 관찰에서 unsupported다. 기존 다른 FDT 도구의 지원 범위는 유지한다.
시간 한도는 협력적 검사이며 전체 RSS·커널 대기의 강제 한도가 아니다.

## verify 환경값과 실제 검증

`verify=n`은 환경값이 비활성으로 설정된 관찰이다. 확인한 U-Boot의 일반 bootm 경로에서는
이 값이 FIT 검증 호출에 영향을 주지만, 모든 벤더·빌드·SPL·다른 부팅 경로의 검증 강제를
환경값 하나로 확정할 수 없다. 대상의 빌드·부팅 경로와 신뢰 키를 추가로 확인해야 한다.
근거: [v2024.01 bootm_start](https://github.com/u-boot/u-boot/blob/v2024.01/boot/bootm.c#L67-L79),
[FIT 선택·적재 경로](https://github.com/u-boot/u-boot/blob/v2024.01/boot/image-fit.c#L1852-L1866).
