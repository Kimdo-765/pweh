# Flipper RAW 제한 프로필

`pweh.rf_formats.inspect_sub_raw`는 이미 메모리에 있는 bytes의 선언 문법과 pulse 통계를 검사하는 순수 코어다. 파일·장치·RF를 열지 않는다. 등록 파일을 분석·저장하는 공개 입구는 `pweh-sdr`의 [`sdr_analyze`](rf-raw-analysis.md)이며 이 코어를 그대로 사용한다. 결과는 파일 선언에 대한 검사다. 캡처의 완전성·실제 주파수·대상·허가·수신 품질·재생 가능성을 증명하지 않는다.

## API와 한도

```python
from pweh.rf_formats import RawLimits, inspect_sub_raw

report = inspect_sub_raw(data, deadline=deadline, cancel=cancel, limits=RawLimits())
```

`data`는 정확한 `bytes`, `deadline`은 유한 monotonic 시각, `cancel`은 없거나 bool을 반환하는 콜백이다. `RawLimits`는 frozen이며 기본 상한보다 낮출 수만 있다. bool·음수·NaN/Inf·표현할 수 없는 큰 마감 값 등 잘못된 호출 인자는 고정 `ValidationFailed`로 거부한다.

| 한도 | 기본·최대 |
|---|---:|
| 입력 bytes | 1 MiB |
| 줄 내용 길이 / 물리 줄 수 | 8192바이트 / 8192줄 |
| 전체 pulse | 65536개 |
| 누적 절댓값 duration | 2^63−1 μs |
| 처리 단계 | 100000 |
| 실행 시간 | 5000 ms |
| JSON 결과 | 64 KiB, 최소 허용 한도 4096바이트 |

실 마감은 호출자 deadline과 시작 시각+runtime 한도 중 이른 쪽이다. 각 줄·숫자 token·문자 검사 중간에 시간을 확인한다. 처리 단계는 물리 줄 시도와 숫자 token 시도마다 하나다. 줄 경계 검색도 줄 상한+CRLF 범위만 읽고, 전체 pulse 배열을 만들지 않는다. 취소 콜백은 빠르게 반환하는 협력 함수여야 하며, Python 콜백 자체를 강제 중단하는 watchdog은 없다.

취소는 결과 대신 고정 `PwehError(code="cancelled")`, 콜백 실패·비bool 반환은 고정 `rf_raw_failed`다. 예외에 입력이나 콜백 오류 문자열을 넣지 않는다. 순수 코어는 입력 크기 상한 초과를 내용을 decode하지 않고 `partial/input_limit`로 반환한다. 공개 `sdr_analyze`는 1 MiB 초과 파일을 읽기 전에 입구 오류로 거부하므로 그 파일의 부분 보고서를 만들지 않는다.

## 지원 문법

프로필 식별자는 `flipper-subghz-raw-v1-strict`다. 일반 FlipperFormat의 모든 순서·표기 변형을 지원한다는 뜻은 아니다.

- UTF-8 strict와 맨 앞 BOM 하나, LF/CRLF를 받는다. 마지막 완전한 줄은 개행 없이도 가능하다. 빈 줄·SP/TAB 줄 및 첫 SP/TAB 뒤 `#`인 전체 주석 줄을 허용한다. 주석도 인코딩·길이 상한을 검사하고 버린다. inline comment는 지원하지 않는다.
- 단독 CR, 중간 BOM, NUL/DEL, TAB 외 C0/C1 제어문자는 malformed다. UTF-16/32 BOM은 unsupported이고 잘못된 UTF-8은 malformed다. Unicode normalization이나 숫자·대소문자 접기는 하지 않는다.
- 필드는 열 0의 ASCII identifier와 `:`다. 값 앞뒤 SP/TAB만 제거한다. metadata는 `Filetype → Version → Frequency → Preset → Protocol` 순서이며 모두 수용한 뒤 `RAW_Data`를 받는다. scalar 중복은 같은 값이어도 거부한다.
- Filetype은 `Flipper SubGhz RAW File`, Version은 1, Protocol은 RAW다. Version/Frequency는 최대 10글자의 ASCII decimal uint32이며 선행 0은 허용한다. Frequency 0도 파일 선언값일 뿐, 실제 RF 설정의 유효성을 판정하지 않는다.
- Preset은 아래 5종만 지원한다. Custom과 모르는 이름은 unsupported다.

| 고정 preset |
|---|
| `FuriHalSubGhzPresetOok270Async` |
| `FuriHalSubGhzPresetOok650Async` |
| `FuriHalSubGhzPreset2FSKDev238Async` |
| `FuriHalSubGhzPreset2FSKDev12KAsync` |
| `FuriHalSubGhzPreset2FSKDev476Async` |

`RAW_Data`는 한 줄에 1..512개의 signed int32 decimal token이다. 토큰 최대 11글자, 문법은 `-?[0-9]+`이며 0/-0을 거부한다. 첫 값은 양수, 이후는 줄 경계를 넘어 부호가 교대한다. `+1`, 홀로 `-`, 소수·hex·exponent·underscore·범위 초과는 malformed다. `-2147483648`의 절댓값은 Python 정수로 집계한다. 반복 RAW_Data와 한 양수만 있는 파일도 가능하며, 끝 음수나 짝수 개수 조건은 없다.

최소 한 RAW_Data 줄이 있어야 한다. `File_name`이나 `Radio_device_name`을 따라 다른 파일을 읽지 않는다. Key/BinRAW/custom preset이나 다른 필드 뒤에서 RAW를 찾아 재시도하지 않는다. `.ook`/VCD 생성·프로토콜 해독·키/ID/롤링코드 판정·송신·재생은 구현 범위 밖이다.

## 상태와 통계의 범위

| status | 의미 |
|---|---|
| `complete` | 지원 문법을 EOF까지 확인하고 최소 한 pulse를 수용했다. |
| `partial` | 입력·줄·pulse·duration·단계·시간 예산으로 검사를 끝내지 못했다. |
| `malformed` | 제한 프로필의 구문·필수 항목·중복/순서·숫자·부호 규칙 위반이다. |
| `unsupported` | 다른 Filetype/Version/preset/protocol/필드 또는 명시적인 UTF-16/32다. |

빈 파일/주석만 있는 파일은 missing_header다. Version 2는 unsupported, Version x는 malformed다. 같은 scalar 반복·RAW 전 필수 선언 누락·줄당 513개는 malformed다. 자원 상한이 먼저 닿으면 보지 못한 뒤쪽 오류를 추정하지 않고 partial로 남긴다. 이미 판정한 malformed/unsupported를 마지막 시간 확인이 덮어쓰지 않는다.

현재 RAW_Data 줄 전체가 성공해야 전역 통계·마지막 부호·수용 위치가 바뀐다. 마지막 token 오류나 한도에 닿으면 그 줄 앞부분도 집계하지 않는다. 결과는 다음 닫힌 필드만 가진다.

- `metadata`: 수용한 고정 filetype/version/protocol, `declared_frequency_hz`, 고정 `declared_preset`. 아직 받지 않았거나 지원하지 않는 값은 null이다.
- `statistics`: pulse 개수·선언된 duration 합·수용 RAW 줄 수, 양/음별 count·절댓값 min/max/sum. 개수가 0이면 min/max=null, sum=0이다. TE·cluster·packet 추정은 없다.
- `coverage`: 입력 크기·수용 prefix·남은 suffix, 줄/단계 수, EOF 확인 여부와 통계 범위. `accepted_prefix_bytes + remaining_bytes == input_bytes`이며 남은 범위는 미수용이지 전혀 읽지 않았다는 뜻이 아니다. BOM도 prefix framing에 포함한다.
- `stop`: 첫 중단의 고정 code·줄 번호·byte offset만. EOF/입구 중단에는 줄 번호가 null이다. EOF에서 필수 누락이면 남은 bytes가 0이어도 complete가 아니다.

`schema="pweh.rf-raw-inspection/v1"`는 내부 결과 버전이다. 순수 코어는 반환 객체 외 파일 저장이나 Skill 요약 등록을 하지 않는다. 공개 도구는 이 객체 전체를 입력 아티팩트 ID·SHA가 있는 `rf-raw-analysis` 봉투로 저장하며, `flipper-rf-analysis` Skill은 별도의 `rf-analysis` 요약을 기록한다. 코어는 원시 pulse 배열·키/ID·자유 필드·파일명/경로·주석·원문 오류·hash를 반환하지 않는다. 작은 pulse 수에서는 집계만으로 일부 개별 값을 유추할 수 있으므로 익명화라고 부르지 않는다.

`input_completeness_verified`, `capture_verified`, `device_association_verified`, `authorization_assessed`, `decoded`, `transmitted`는 항상 false다. 예를 들어 마지막 token 12가 문법적으로 완전해도 원래 123이 잘린 것인지는 알 수 없다.

## 고정 형식 근거

[공식 1.5.1 형식 문서](https://github.com/flipperdevices/flipperzero-firmware/blob/1.5.1/documentation/file_formats/SubGhzFileFormats.md)의 RAW 규칙을 기준으로 한다. 문서 예제 일부의 연속 양수는 부호 교대 규칙과 불일치하므로 조용히 보정하거나 정상 fixture로 쓰지 않는다.

RAW 전용 Filetype과 Version, frequency 타입은 [1.5.1 types.h](https://github.com/flipperdevices/flipperzero-firmware/blob/1.5.1/lib/subghz/types.h), writer 순서·signed int32 청크·level 교대는 [1.5.1 raw.c](https://github.com/flipperdevices/flipperzero-firmware/blob/1.5.1/lib/subghz/protocols/raw.c)와 대조했다. writer의 수신 필터를 파일 허용 범위나 실제 캡처 검증으로 바꾸지 않는다. 실제 장비·캡처가 아닌 합성 bytes로 제한 프로필을 검증한다.
