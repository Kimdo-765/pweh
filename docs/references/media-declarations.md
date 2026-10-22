# 선택 BMFF의 상자 구조와 제한된 선언 관찰

`forensics_media_inventory`는 완전히 읽은 선택 파일 하나에서 ISO-BMFF 상자 경계와
허용 계층의 `mvhd`·`mdhd`·`pssh` 선언을 관찰한다. 선언된 길이는 실제 재생 길이가 아니며,
시각 필드의 상태나 보호 상자 존재는 촬영 시각·암호화 여부를 입증하지 않는다.

## 입력·보고서 호환

```text
forensics_media_inventory(case_id, evidence_id, partition=None,
                         ref=None, path=None, method="auto", max_seconds=45)
```

EV 자체 또는 FAT/exFAT·TAR/ZIP에서 파일 하나를 고른다. `ref`와 `path`는 배타적이며,
직접 EV는 둘 다 생략하고 `partition=None`, `method="auto"`로 선택한다. 불완전 읽기나
입력 한도 초과를 앞부분 성공으로 바꾸지 않는다. 빈 파일도 새 profile의 미지원 결과로 기록한다.

보고서 schema는 `pweh.media-inventory/v1`을 유지하고 profile별로 닫힌 두 형식을 구분한다.

| profile | 의미 |
|---|---|
| `mp4-quicktime-box-v1` | 기존 상자 관찰 보고서. `declarations`가 없고 기존 어휘·limitations만 허용한다 |
| `mp4-quicktime-declarations-v1` | 새 실행이 생성하는 보고서. 아래 `declarations`가 필수이며 배열은 비어 있을 수 있다 |

기존 보고서를 다시 쓰거나 새 검사를 수행한 것으로 해석하지 않는다. 두 profile의 필드·어휘·
limitations를 섞은 보고서는 거부한다. 새 결과를 old profile로 생성하는 옵션은 없다.

## 지원 계층과 해석 범위

| 선언 | 허용 계층 | 읽는 범위 |
|---|---|---|
| `mvhd` | 최상위 `moov`의 직계 자식 | FullBox version 0/1의 creation/modification 상태·timescale·duration prefix |
| `mdhd` | 최상위 `moov/trak/mdia`의 직계 자식 | 위와 같은 시간 단위·길이 prefix |
| `pssh` | 최상위 `moov` 또는 `moof`의 직계 자식 | FullBox version 0/1과 식별자·데이터 영역의 길이 관계 |

flags는 0만 지원한다. 같은 type이 다른 계층에 있으면 `skipped/unsupported_context`로
남기고 선언 row를 만들지 않는다. `mdat/meta/udta/uuid/unknown` payload나 `stsd` 내부에서
같은 문자열을 검색하지 않는다. 여러 선언은 각각 보존하며 대표 track·최대·합계 duration을 고르지 않는다.

timing은 box header 뒤 payload의 **20bytes(version 0) 또는 32bytes(version 1)** prefix만
검사한다. `mvhd`의 rate/volume/matrix/next_track_ID와 `mdhd`의 language/predefined 등
뒤 필드는 opaque다. 이 prefix가 완전하다는 사실은 전체 header의 필수 길이·예약 값·규격
적합성을 검증한 것이 아니다. `tkhd/elst`·sample table·fragment 시간도 해석하지 않는다.

PSSH는 SystemID를 건너뛰고, version 1의 KID_count와 DataSize로 영역이 해당 상자 끝에
정확히 맞는지만 계산한다. KID 배열에 비례한 순회·복사·비교·해시는 하지 않는다.
SystemID/KID/data/URL과 그 원문·hex·개별 해시·길이/count 값은 공개하지 않는다.

## 선언 필드

`declarations`의 필수 필드는 `scope="mvhd-mdhd-pssh-selected-contexts"`,
`status`(`complete/partial`), `timing`, `pssh`, `coverage`와 세 false 값이다.
`coverage`에는 `traversal_complete`, `fields_complete`, 중복 없는 고정 `reasons`가 있다.
`absolute_times_returned`, `sample_entries_examined`, `sample_encryption_examined`는 항상 false다.

각 timing row는 다음 필드를 모두 가진다.

| 필드 | 값·의미 |
|---|---|
| `box_index`, `parent_index` | 반환한 상자와 부모의 index, 각각 0–4095 |
| `kind` | `mvhd` 또는 `mdhd` |
| `version` | 지원하는 0/1 또는 null. 미지원 원시 version은 반환하지 않음 |
| `status` | 해당 제한 선언의 `complete/unsupported/malformed` |
| `creation_time_state`, `modification_time_state` | `zero/nonzero/unread`만. 원시 정수·epoch 변환·UTC 없음 |
| `timescale` | null 또는 0–4294967295 |
| `duration_units` | null 또는 0–18446744073709551614. version 0은 최대4294967294 |
| `duration_state` | `declared/zero/indeterminate/unread` |
| `issues` | 아래 고정 사유 0–1개 |

duration 0은 0 선언으로 보존한다. 해당 정수 폭의 all-ones는 `indeterminate`와 null이며
오류가 아니다. timescale 0은 원래 값과 duration을 보존하되 `zero_timescale/malformed`다.
유효한 두 값은 정수 비로 해석할 수 있지만 도구는 초·float·반올림 길이를 반환하지 않는다.

PSSH row에는 **`box_index`, `parent_index`, `version`, `status`, `issues` 다섯 필드만** 있다.
고정 issue는 `unsupported_declaration_version`, `unsupported_declaration_flags`,
`truncated_declaration_fields`, `zero_timescale`, `pssh_length_mismatch`다.
version/flags 미지원은 unsupported, 부족한 필드·길이 관계·timescale 0은 malformed다.
여기서 malformed는 제한된 선언 검사 결과이며 실제 녹화 손상이나 전체 형식 부적합 판정이 아니다.

## 완료도와 한계 읽기

`report.status`(`ok/partial/unsupported`), `framing_status`, `recognition`,
`declarations.status`는 서로 다른 관찰이다. 상자 경계가 완전해도 선언이 미지원·불완전이면
`framing_status=complete`와 전체 `status=partial`이 함께 나올 수 있다.

`declarations.coverage.traversal_complete`는 기존 `coverage.structure_complete`와 같다.
`fields_complete`는 반환한 선언 row가 모두 complete일 때 true이며 row 0개도 true다.
두 값이 모두 true이면 선언 section은 complete다. **0개/complete는 전체 보호 신호 부재나
평문 확인이 아니다.** brand 인식이 없는 fragment는 선언이 완전해도 전체 unsupported일 수 있다.

삭제·복구 방법·부모 상태 불확실성이나 알려진 컨테이너 목록 잘림은 top-level `coverage`와
전체 상태에 남긴다. 이 출처 문제를 선언 바이트 검사 상태와 혼동하지 않는다. 선택 파일을
완전히 읽었다고 전체 이미지·파일시스템·아카이브를 검사한 것도 아니다.

기존 `header/skipped/unexamined` 범위는 선택 입력 전체를 겹침 없이 나눈다.
실제로 읽은 고정 선언 필드는 `declaration_fields`, 건너뛴 식별자는
`declaration_identifiers`, opaque 뒤쪽은 `declaration_payload`로 구분한다.
필드 해석 실패가 있어도 읽지 않은 payload를 검사 완료 바이트로 세지 않는다.
시간·상자·범위·출력 한도 때문에 현재 row를 게시할 수 없으면 그 상자부터 미검사로 남긴다.

다음 top-level 값은 항상 false다.

```text
media_decoded
playback_verified
recording_time_verified
encryption_assessed
format_conformance_assessed
```

보호 sample entry/CENC auxiliary/sample bytes는 미검사다. 상자 존재·부재·엔트로피·NAL header로
암호화/평문을 확정하지 않는다. 원시 파일명·경로·자유 FourCC/brand·UUID·자유 메타데이터를
반환하지 않으며, 선택 파일 전체의 출처 SHA는 선언 식별자·시각의 개별 해시와 다르다.

## 고정 한도·저장·요약

| 항목 | 최대 한도 |
|---|---|
| 완전 선택 입력 | 64 MiB |
| 선택·읽기·검사 공통 시간 | 45초, `max_seconds`는 유한한 양수만 |
| 상자·깊이 | 4096개·8 |
| brand | 표당64개·전체256개 |
| 범위 | 8193개 |
| timing/PSSH row | 합계가 반환 상자 수 이하, 상자당 최대1개 |
| 저장 보고서 JSON | 1 MiB, 코어는 source 봉투용16 KiB를 남김 |

마감은 협력적으로 확인하며 커널 I/O의 강제 시간 제한이나 전체 RSS 한도를 뜻하지 않는다.
취소·선택 무결성 실패는 고정 오류이며 원문을 오류에 붙이지 않는다. 동일 worker가 입력 fd와
검증·저장을 소유하고 `media-inventory` 보관 사건에 0444 JSON을 결속한다. 응답의
`analysis{path,sha256,size,custody_seq,custody_hash}`는 저장 결과를 가리킨다.

`media_inventory_results[]` 요약은 기존 `evidence_id`, `analysis_path`, `sha256`, `status`,
`selected_size`, `boxes_reported` 여섯 필드만 유지한다. 선언값을 요약이나 녹화 타임라인으로
자동 복사하지 않는다. 증거 목록 `derived`에서 결과 해시·보관 기록을 확인한다.

이 확장은 선택 파일의 선언 관찰이다. `media_candidates`와 [저장 후보 prefix 추출](media-prefix-extract.md),
원시 이미지 구간 카빙, 벤더 인덱스, 실제 녹화 타임라인, 암호화 판정의 완료 범위를 바꾸지 않는다.
전체 입력·보관 계약은 [architecture §6.8](../architecture.md#68-pweh-forensics-선택),
경합·검사 한계는 [safety §3.6](../safety.md#36-sd-카드-증거의-알려진-한계-pweh-forensics)을 따른다.

## 형식 근거

- [Apple Movie header](https://developer.apple.com/documentation/quicktime-file-format/movie_header_atom)와
  [Media header](https://developer.apple.com/documentation/quicktime-file-format/media_header_atom): 선언 단위·길이와 뒤 필드의 구분.
- [AOSP MPEG4Extractor 고정 소스](https://android.googlesource.com/platform/frameworks/av/+/a4af050bab773a75c799bb9cbd886e3b83655daf/media/extractors/mp4/MPEG4Extractor.cpp): version별 폭·timescale/duration 해석의 구현 근거. 플레이어의 보정·디코딩 동작은 가져오지 않는다.
- [W3C CENC stream format](https://www.w3.org/TR/2024/NOTE-eme-stream-mp4-20240718/): 보호 sample entry·sample 관계와 PSSH 구분.
- [W3C cenc initialization data §4](https://www.w3.org/TR/2026/NOTE-eme-initdata-cenc-20260604/): PSSH version/count/DataSize 구조. 식별자나 실제 샘플 암호화 판정을 추가하지 않는다.
