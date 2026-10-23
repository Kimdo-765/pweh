# NFC 파일 선언의 제한 구조·diff 코어

`pweh.nfc_formats`는 caller가 제공한 불변 `bytes`를 검사하는 순수 Python 코어다. 파일·태그·장치·네트워크·프로세스를 열지 않는다. 결과는 **파일에 저장된 선언과 바이트 표현**에 관한 것으로, 태그 식별·소유·허가·실제 읽기·제품 진위의 증명이 아니다. 이 순수 코어의 운영 입구와 tag inventory 결속은 [NFC 스캔 결속 분석](nfc-inventory-analysis.md)을 따른다. 코어 자체는 인증·에뮬레이션·쓰기 기능을 제공하지 않는다.

## 지원 범위와 근거

지원하는 제한 프로필은 Flipper NFC 파일 `Version: 4`의 `ISO14443-3A` header와 `NTAG/Ultralight` data format 2 중 NTAG213/215/216이다. 고정된 공식 자료를 기준으로 한다.

- [Flipper firmware 1.5.1 형식 문서](https://raw.githubusercontent.com/flipperdevices/flipperzero-firmware/1.5.1/documentation/file_formats/NfcFileFormats.md): header와 NTAG 필드의 이름·표현.
- [동일 버전 ISO14443-3A 구현](https://raw.githubusercontent.com/flipperdevices/flipperzero-firmware/1.5.1/lib/nfc/protocols/iso14443_3a/iso14443_3a.c): generic UID 길이 4/7/10 bytes. 문서의 4/7 설명보다 이 구현이 넓다. v4 ATQA는 텍스트의 MSB 순서를 유지한다.
- [동일 버전 Ultralight 구현](https://raw.githubusercontent.com/flipperdevices/flipperzero-firmware/1.5.1/lib/nfc/protocols/mf_ultralight/mf_ultralight.c): Pages read와 무관하게 선언 total만큼 Page 항목을 저장하므로, 저장된 0값이나 항목 존재로 실제 읽힌 페이지를 구별할 수 없다.
- [NXP NTAG213/215/216 Rev.3.2](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf): §8.5와 Table 8의 영역 배치, §8.8.1의 PWD/PACK 읽기 특성. READ/FAST_READ의 해당 바이트는 실제 자격증명 대신 0으로 표시된다.

| 주장 모델 | total pages | 사용자 페이지 | dynamic lock | CFG0/CFG1 | PWD/PACK |
|---|---:|---|---|---|---|
| NTAG213 | 45 | 4–39 | page 40, bytes 0–2 | 41/42 | 43/44 |
| NTAG215 | 135 | 4–129 | page 130, bytes 0–2 | 131/132 | 133/134 |
| NTAG216 | 231 | 4–225 | page 226, bytes 0–2 | 227/228 | 229/230 |

페이지·바이트 번호는 0부터 시작한다. 공통 static lock은 page 2 bytes 2–3, capability container는 page 3이다. dynamic lock 페이지의 byte 3과 PACK 페이지의 bytes 2–3은 reserved로 분류한다. CFG 비트값·락 활성·AUTH0/PROT·인증 가능 여부를 해석하지 않는다. UID/BCC·서명·NDEF·제조사 식별·내용 해독도 범위 밖이다.

다른 형식·버전·계열·NTAG 모델의 **명시적인 선언**은 unsupported다. 임의 binary를 CU 형식으로 자동 식별하거나 CU binary를 파싱하지 않는다. `.nfc`/`.shd` 파일명을 받지 않으며 companion 파일 병합·실제 에뮬레이션 이력 인증도 없다.

## Python API

```python
from pweh.nfc_formats import NfcLimits, inspect_nfc, diff_nfc

# data/before/after는 caller가 이미 보유한 합성 또는 허가된 bytes다.
# deadline은 time.monotonic() 기준 절대 시각이다.
report = inspect_nfc(data, deadline=deadline, limits=NfcLimits())
comparison = diff_nfc(before, after, deadline=deadline, cancel=cancel_check)
```

`bytearray`, `memoryview`, 문자열·경로를 대신 받지 않는다. 두 함수는 닫힌 dict만 반환하며 private parser 객체를 내보내지 않는다. 공개 top-level key는 `schema_version`, `operation`, `status`, `profile`, `summary`, `coverage`, `limitations`다. `schema_version=1`은 내부 결과 버전이며 등록된 운영 schema가 아니다.

- `ok`: 요청한 제한 구조 또는 저장 페이지 비교를 완료했다.
- `partial`: 시간·입력/행/페이지/출력 상한, 부분 읽기 선언, 알 수 없는 확장 필드 또는 검증하지 못한 제품 주장이 있다.
- `malformed`: 실제 관찰한 문법·필수 구조 위반이다. 잘못된 UTF-8, 중복, 잘린 hex, 범위 밖 번호, EOF에서 확인한 필수 필드/Page 누락 등이 해당한다.
- `unsupported`: 정상적으로 식별한 선언이 지원 범위 밖이거나, header-only/서로 다른 layout이라 페이지 비교를 수행할 수 없다.

손상된 header를 미지원 제품으로 추정하지 않는다. 최초 구조 위반에서 중단하며 위반 뒤의 데이터를 정상처럼 합치지 않는다. 앞에서 확인한 malformed를 뒤의 시간 만료로 덮어쓰지 않는다. `profile`은 `iso14443-3a`·`ntag213`·`ntag215`·`ntag216`·`unknown` 중 하나이며 물리 장비 식별이 아니다.

## 문법과 검사 범위

UTF-8 strict, 맨 앞 BOM 한 개, LF/CRLF를 허용한다. 마지막 개행이 없어도 완전한 마지막 행이면 처리한다. NUL, CR 단독, 다른 control, 중간 BOM은 malformed다. key·정수·hex 문법은 ASCII이며 앞뒤 ASCII 공백/TAB만 제거한다. 빈 줄과 `#`로 시작하는 주석은 무시하고 inline 주석·escaping·Unicode 정규화는 하지 않는다.

hex byte는 두 자리씩이며 필드 길이를 정확히 검사한다. 공통 UID는 4/7/10 bytes, ATQA는 2, SAK는 1이다. NTAG의 UID 길이가 7이 아니면 `claimed_uid_length_mismatch`로 partial 및 페이지 비교 제외다. 이는 generic UID 문법 실패나 제품 진위 판정과 다르다.

NTAG 필수 필드는 Data format version, type, Signature 32 bytes, Mifare version 8 bytes, Counter/Tearing 0–2, Pages total/read, 모든 선언 Page다. Counter와 optional `Failed authentication attempts`는 unsigned 32-bit 파일 표현만 검사한다. optional 항목이 없으면 0을 보충하지 않는다. Tearing은 각각 1 byte, Page는 4 bytes다. 정수는 부호 없는 ASCII decimal이며 Counter 최대 10자리, 페이지 관련 수는 최대 3자리다.

동일 값의 재선언도 중복으로 거부한다. key 순서 자체는 검사 대상이 아니며 EOF에서 필수 필드·상호 모순을 확인한다. 알 수 없는 필드는 이름·값을 출력하지 않고 개수와 `unknown_field`만 기록하며 full 비교에서 제외한다. 상한으로 미검사 영역이 남으면 뒤의 필드 누락을 추정하지 않는다.

inspect summary의 `stored_valid_pages`는 **문법상 수용한 저장 record 수**다. 물리적으로 읽은 페이지 수나 각 record의 내용 신뢰도를 뜻하지 않는다. `consumed_bytes`는 검사한 행까지의 prefix, `unexamined_bytes`는 나머지이며 합계는 입력 길이다. 행 도중 시간·길이 상한에 걸리면 그 행은 미완료 영역에 남는다. `input_exhausted`는 입력 전체를 구조 검사했는지 표시한다. malformed 행에서 중단하면 마지막 행이라도 완주로 승격하지 않는다. `missing_pages_count`는 전체 입력과 유효한 total/페이지 범위를 확인한 경우에만 계산한다. `truncated_reasons`는 고정 사유 목록으로 구조 위반/지원 범위 사유도 포함한다.

## 저장 페이지 비교의 조건과 결과

`full_declared_pages=True`는 지원 모델의 필수 필드가 유효하고, total이 표와 같으며, `Pages read == Pages total`, 각 Page가 한 번씩 저장되어 있고, 모순·unknown 필드·검사 중단이 없을 때만 나온다. 실제 태그를 완전히 읽었다는 증거는 항상 미확인이다.

`Pages read < Pages total`이면 모든 Page가 0으로 저장되어 있어도 `read_mapping=unknown`, partial이다. 최초 N개를 읽었다고 추정하거나, 누락을 0으로 채우거나, 0을 빈 메모리·초기화 상태·실제 비밀값으로 해석하지 않는다. 이 코어는 부분 입력의 공통 페이지도 비교하지 않는다.

두 입력이 모두 full-declared이고 같은 claimed model/total일 때만 비교한다. diff `summary.before/after`는 각 입력의 닫힌 status/profile/summary/coverage이며, 나머지 summary는 다음 의미다.

- `same_uid_claim`: 유효하게 관찰한 UID 선언의 동등성 boolean. 미관찰/손상 입력이거나 입력 검사를 완주하지 못했으면 null. 선언이 달라도 같은 layout의 저장 bytes 비교는 가능하다. `device_association_verified`는 항상 false다.
- `pages_compared`, `changed_pages_count`, `stored_pages_equal`: 실제로 비교한 저장 페이지에 대한 수치·boolean. 미비교이면 각각 0/null/null이다. 페이지 비교 중 시간 만료이면 변경 수는 lower bound이고 동등성은 null이다.
- `changes`: `{page, regions}`만 포함한다. regions는 manufacturer/static_lock/capability_container/user_data/dynamic_lock/configuration/credential_storage/reserved의 고정 enum이다. 실제로 바뀐 byte의 영역만 표시한다.
- `counter_fields_changed`: 두 full-declared 구조의 Counter 선언이 달랐는지만 나타낸다. 물리 카운터 값·증감·delta·원인·실행 동작을 추정하지 않는다. 페이지 비교 자격이 없으면 null이다.
- `changes_returned/changes_omitted`: 반환 목록 수와 이미 관찰한 변경 중 생략 수다. 비교 미완료일 때 전체 파일의 누락 변경 수는 알 수 없다.

공통 coverage의 `comparison_complete`, `changes_complete`, `changed_pages_count_is_lower_bound`로 비교 자체의 중단과 목록만 잘린 경우를 구분한다. 목록 상한에 도달해도 비교가 끝났으면 변경 수는 정확하다. 출력 단계에서 시간이 만료돼도 이미 완료한 비교 사실은 유지하고 목록을 생략한다.

UID·ATQA·SAK·Signature·Mifare version·Tearing·페이지 내용·PWD/PACK·원시 Counter/실패 횟수는 반환하지 않는다. 전후 bytes, 비밀 hash, entropy, 자유 mask dict, URL, 제조사 ID도 만들지 않는다. PWD/PACK 페이지의 저장 표현이 같거나 다르다는 것이 실제 자격증명의 같음/변경을 증명하지 않는다.

## 상한과 고정 오류

| NfcLimits | 기본값/상한 |
|---|---:|
| max_input_bytes | 입력당 1 MiB, diff 두 입력 합계 최대 2 MiB |
| max_lines | 입력당 4096 |
| max_line_bytes | 개행 제외 입력 행 8192 bytes |
| max_pages | 입력당 512 records |
| max_changes | 반환 변경 목록 512개 |
| max_output_bytes | UTF-8 compact JSON 64 KiB, 최소 4096 bytes |

한도는 양의 정수로 낮출 수만 있으며 bool도 거부한다. 최소 출력 공간은 필수 envelope를 위한 것이다. deadline은 finite monotonic 절대 시각이고 시작 기준 최대 5초로 제한된다. diff의 두 파싱·비교·출력은 이 시각을 공유한다. 행 탐색과 긴 문자 검사, 페이지 비교, 출력 항목 구성 중 취소·시각을 확인한다. 만료 후에는 입력을 다시 해석하지 않고 확보한 고정 크기 종료 결과만 마무리한다.

출력은 `ensure_ascii=True`, compact separators, 비유한 수 금지 JSON의 실제 byte 길이를 기준으로 제한한다. 전체 결과를 한 항목씩 줄여 반복 직렬화하지 않고, 고정 envelope 공간과 항목별 크기로 prefix를 정한다.

`cancel`은 None 또는 인자 없이 bool을 반환하는 callable이다. True는 `PwehError.code='cancelled'`, 일반 예외·비bool 반환은 원문·원래 exception chain 없는 `callback_error`다. KeyboardInterrupt/SystemExit는 상위 실행기로 전달한다. 잘못된 입력 타입·한도·deadline은 각각 `invalid_input`, `invalid_limits`, `invalid_deadline` 고정 오류다. 입력 원문은 오류에 넣지 않는다.
