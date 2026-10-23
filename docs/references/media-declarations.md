# 선택 BMFF의 상자 구조와 제한된 선언 관찰

`forensics_media_inventory`는 완전히 읽은 선택 파일 하나에서 ISO-BMFF 상자 경계와
허용 계층의 `mvhd`·`mdhd`·`pssh`와 sample-entry의 제한 보호 선언 prefix를 관찰한다.
선언된 길이는 실제 재생 길이가 아니며,
시각 필드의 상태나 보호 상자 존재는 촬영 시각·암호화 여부를 입증하지 않는다.

## 입력·보고서 호환

```text
forensics_media_inventory(case_id, evidence_id, partition=None,
                         ref=None, path=None, method="auto", max_seconds=45)
```

EV 자체 또는 FAT/exFAT·TAR/ZIP에서 파일 하나를 고른다. `ref`와 `path`는 배타적이며,
직접 EV는 둘 다 생략하고 `partition=None`, `method="auto"`로 선택한다. 불완전 읽기나
입력 한도 초과를 앞부분 성공으로 바꾸지 않는다. 빈 파일도 새 profile의 미지원 결과로 기록한다.

보고서 schema는 `pweh.media-inventory/v1`을 유지하고 profile별로 닫힌 세 형식을 구분한다.

| profile | 의미 |
|---|---|
| `mp4-quicktime-box-v1` | 기존 상자 관찰 보고서. `declarations`가 없고 기존 어휘·limitations와 최대 깊이 8을 유지한다 |
| `mp4-quicktime-declarations-v1` | 기존 timing/PSSH 선언 보고서. `declarations`가 필수이고 `protection`은 없으며 깊이는 최대 8이다 |
| `mp4-quicktime-protection-declarations-v1` | 새 실행의 고정 profile. timing/PSSH와 `declarations.protection`이 필수이며 깊이는 최대 10이다 |

기존 보고서를 다시 쓰거나 보호 검사를 수행한 것으로 해석하지 않는다. 세 profile의 필드·어휘·
limitations를 섞은 보고서는 거부한다. 새 결과를 old profile로 생성하는 옵션은 없다.

## 지원 계층과 해석 범위

| 선언 | 허용 계층 | 읽는 범위 |
|---|---|---|
| `mvhd` | 최상위 `moov`의 직계 자식 | FullBox version 0/1의 creation/modification 상태·timescale·duration prefix |
| `mdhd` | 최상위 `moov/trak/mdia`의 직계 자식 | 위와 같은 시간 단위·길이 prefix |
| `pssh` | 최상위 `moov` 또는 `moof`의 직계 자식 | FullBox version 0/1과 식별자·데이터 영역의 길이 관계 |

flags는 0만 지원한다. 같은 type이 다른 계층에 있으면 `skipped/unsupported_context`로
남기고 timing/PSSH row를 만들지 않는다. `mdat/meta/udta/uuid/unknown` payload 안의
같은 문자열을 검색하지 않는다. 아래 허용 stsd 경로도 child 경계로만 순회하며 payload를 재검색하지 않는다. 여러 선언은 각각 보존하며 대표 track·최대·합계 duration을 고르지 않는다.

timing은 box header 뒤 payload의 **20bytes(version 0) 또는 32bytes(version 1)** prefix만
검사한다. `mvhd`의 rate/volume/matrix/next_track_ID와 `mdhd`의 language/predefined 등
뒤 필드는 opaque다. 이 prefix가 완전하다는 사실은 전체 header의 필수 길이·예약 값·규격
적합성을 검증한 것이 아니다. `tkhd/elst`·sample table의 시간·sample 위치·fragment 시간도 해석하지 않는다.

PSSH는 SystemID를 건너뛰고, version 1의 KID_count와 DataSize로 영역이 해당 상자 끝에
정확히 맞는지만 계산한다. KID 배열에 비례한 순회·복사·비교·해시는 하지 않는다.
SystemID/KID/data/URL과 그 원문·hex·개별 해시·길이/count 값은 공개하지 않는다.

## 선언 필드

새 profile의 `declarations`는 `scope="mvhd-mdhd-pssh-sample-protection-selected-contexts"`,
`status`(`complete/partial`), `timing`, `pssh`, `protection`, `coverage`와 세 관찰 flag를 가진다.
`coverage`에는 `traversal_complete`, `fields_complete`, 중복 없는 고정 `reasons`가 있다.
`absolute_times_returned`, `sample_encryption_examined`는 항상 false다.
`sample_entries_examined`는 지원 encv/enca prefix row를 한 개 이상 게시했을 때만 true다.
모든 entry·보호 필드·sample body를 검사했다는 뜻이 아니며 뒤 child가 실패해도 그 관찰은 남는다.
옛 declarations-v1의 scope는 `mvhd-mdhd-pssh-selected-contexts`이고 세 flag 모두 false였다.

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

## 제한 보호 선언

다음 부모 사슬에 있는 구조만 관찰한다. 숫자는 최상위 깊이 1 기준이다.

```text
moov(1)/trak(2)/mdia(3)/minf(4)/stbl(5)/stsd(6)
  /encv|enca(7)/sinf(8)/schm(9)
                      /schi(9)/tenc(10)
```

p는 일반/확장 box header 뒤 payload 시작이다. 아래 길이는 header를 제외한 payload 길이다.

| 구조 | 지원 prefix·필드 | 건너뛰거나 지원하지 않는 범위 |
|---|---|---|
| stsd | v0·flags0·최소 8B, FullBox와 u32 entry 수 | v1 이상/flags 미지원. count만큼 배열을 선할당하지 않고 실제 경계·게시 수를 대조 |
| encv | 최소 78B가 존재하면 p+78부터 child | prefix 값·codec 이름·치수·예약값은 해석하지 않음 |
| enca | p+8의 audio version이 0, 최소 28B일 때 p+28부터 child | audio v1/v2·그 밖의 version은 미지원. audio 수치·예약값은 미검사 |
| 그 밖의 entry | box 경계와 `other` 분류 | payload를 열거나 보호 이름을 재검색하지 않음 |
| schm | v0·flags0·정확히 12B, scheme_type만 cenc/cbcs/other/unread | scheme_version·URI·다른 FourCC 원문 미반환. URI/다른 길이 미지원 |
| tenc | v0/v1·flags0·최소 24B, FullBox와 p+6의 기본 상태만 zero/one/other/unread | 예약·패턴·IV 길이·KID·constant-IV·tail 미검사 |

`other` entry는 unknown뿐 아니라 이미 아는 box 종류가 잘못된 entry 위치에 있는 경우도
포함한다. 예를 들어 stsd 직계 sinf/tenc는 원래 `boxes.kind`를 유지하면서 entry는 other이고,
그 payload에 있는 보호 상자를 child로 해석하지 않는다. `schm.scheme_type=other`와
`tenc.default_is_protected_state=other`는 지원 밖이다. 원래 숫자나 FourCC는 공개하지 않는다.

tenc의 complete는 이 고정 필드 관찰만 뜻한다. 최소 24B가 있다는 확인을 24B 전체의 의미
검사로 세지 않는다. 조건부 constant-IV의 존재·길이·내용도 검사하지 않는다. sample groups나
auxiliary data가 기본값을 바꾸는지 확인하지 않으므로 zero/one 어느 값도 실제 sample의
평문/암호화 여부를 증명하지 않는다.

`protection`은 scope/status/tables/entries/schemes/track_defaults/coverage와 아래 세 false의
닫힌 10필드다. scope는 `stsd-encv-enca-sinf-schm-tenc-prefixes`다.
`full_tenc_examined`, `sample_auxiliary_examined`, `identifiers_returned`는 항상 false다.

| 배열 | 각 행의 정확한 필드 |
|---|---|
| tables | box_index, version(0/null), entries_declared(u32/null), entries_reported, entries_complete, status, issues |
| entries | box_index, parent_index, kind(encv/enca/other), prefix_kind(visual/audio-v0/unsupported/unread), status, issues |
| schemes | box_index, parent_index, entry_index, version(0/null), scheme_type(cenc/cbcs/other/unread), status, issues |
| track_defaults | box_index, parent_index, entry_index, version(0/1/null), default_is_protected_state(zero/one/other/unread), status, issues |

모든 index는 게시된 `boxes`의 index다. entry_index는 해당 sample-entry box를 가리키며
별도 순번·track ID가 아니다. 네 배열의 행 합계는 게시 상자 수 이하이고 같은 box의 행을
중복 게시하지 않는다. 서로 다른 상자 index의 중복 schm/tenc는 각각 보존하지만 그 사이의
유일성·활성 선택·상속·scheme 연결을 추정하지 않는다.

entries_reported는 해당 stsd 아래 게시된 직접 entry 수다. entries_complete=true이면
선언 수와 보고 수가 같고 child 순회도 끝났다. count prefix를 읽은 table.status는 complete여도
예산 중단으로 entries_complete=false일 수 있다. count와 실제 경계가 어긋나면
stsd_entry_count_mismatch로 멈추고 이후 bytes를 재검색하지 않는다.

행 status는 complete/unsupported/malformed다. version/flags/고정 필드 부족은 기존
unsupported_declaration_version/unsupported_declaration_flags/truncated_declaration_fields를
재사용한다. 지원 밖 version/flags에는 unsupported_protection_shape도 함께 남긴다.
다음 여섯 보호 사유가 추가된다.

```text
stsd_entry_count_mismatch
unsupported_sample_entry
unsupported_audio_entry_version
unsupported_protection_shape
unsupported_protection_scheme
unsupported_protection_value
```

미지원 또는 잘린 prefix의 scheme/default 값은 unread이고, null은 검사하지 못한 필드다.
읽지 못한 entry header만으로 가상의 unsupported_sample_entry 행을 만들지 않는다.

## 완료도와 한계 읽기

`report.status`(`ok/partial/unsupported`), `framing_status`, `recognition`,
`declarations.status`는 서로 다른 관찰이다. 상자 경계가 완전해도 선언이 미지원·불완전이면
`framing_status=complete`와 전체 `status=partial`이 함께 나올 수 있다.

`declarations.coverage.traversal_complete`는 기존 `coverage.structure_complete`와 같다.
새 profile의 바깥 `fields_complete`는 timing/PSSH 행이 모두 complete이고
protection.fields_complete도 true일 때만 true다. 두 값이 모두 true이면 선언 section은 complete다. **0개/complete는 전체 보호 신호 부재나
평문 확인이 아니다.** brand 인식이 없는 fragment는 선언이 완전해도 전체 unsupported일 수 있다.

protection.coverage는 traversal_complete/fields_complete/reasons의 세 필드다.
순회 완료는 전체 structure_complete를 보수적으로 따르고, 필드 완료는 네 보호 배열의 모든
행이 complete일 때만 true다. 미지원 other entry를 빼서 완료로 올리지 않는다.
보호 status는 두 완료 값이 모두 true일 때만 complete다.

보호 reasons는 전체 구조/예산 사유와 **실제 보호 행의 issues**만 반영한다. timing/PSSH에만
있는 version/flags/truncated 사유는 같은 이름이어도 보호 reasons로 옮기지 않는다.
따라서 상자 경계는 완전하고 timing/PSSH만 malformed이면 빈 protection은 complete·reasons=[]를
유지할 수 있고 바깥 declarations만 partial이다. zero_timescale/pssh_length_mismatch 역시
보호 사유가 아니다. 어느 선언이 한도를 막아 전체 framing이 partial이면 보호 순회도 partial이다.

삭제·복구 방법·부모 상태 불확실성이나 알려진 컨테이너 목록 잘림은 top-level `coverage`와
전체 상태에 남긴다. 이 출처 문제를 선언 바이트 검사 상태와 혼동하지 않는다. 선택 파일을
완전히 읽었다고 전체 이미지·파일시스템·아카이브를 검사한 것도 아니다.

기존 `header/skipped/unexamined` 범위는 선택 입력 전체를 겹침 없이 나눈다.
실제로 읽은 고정 선언 필드는 header의 `declaration_fields`다. PSSH 식별자 영역은
skipped의 `declaration_identifiers`, opaque 뒤쪽은 `declaration_payload`다. 보호 prefix에서
건너뛴 예약·패턴·KID/IV·tail은 declaration_payload로 남기며 식별자별 해석을 추가하지 않는다.
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

허용 entry의 고정 prefix 밖, 전체 tenc·constant-IV·sample groups·CENC auxiliary·sample bytes는 미검사다. 상자 존재·부재·엔트로피·NAL header로
암호화/평문을 확정하지 않는다. 원시 파일명·경로·자유 FourCC/brand·UUID·자유 메타데이터를
반환하지 않으며, 선택 파일 전체의 출처 SHA는 선언 식별자·시각의 개별 해시와 다르다.

## 고정 한도·저장·요약

| 항목 | 최대 한도 |
|---|---|
| 완전 선택 입력 | 64 MiB |
| 선택·읽기·검사 공통 시간 | 45초, `max_seconds`는 유한한 양수만 |
| 상자·깊이 | 4096개·새 profile 10(옛 두 저장 profile은 8) |
| brand | 표당64개·전체256개 |
| 범위 | 8193개 |
| 선언 row | timing/PSSH와 보호 네 배열은 각각 합계가 반환 상자 수 이하, 해당 상자당 최대 1개 |
| 저장 보고서 JSON | 1 MiB, 코어는 source 봉투용16 KiB를 남김 |

새 실행의 기본 깊이 10은 tenc의 허용 경로까지 포함한다. 내부 시험 등에서 한도를 9 이하로
낮추면 정상 경로도 depth_limit/partial일 수 있다. 공개 깊이 선택 인자는 없다.

새 profile의 limitations는 기존 앞 11개를 유지하고 마지막 sample_encryption_boxes_unexamined를
다음 네 값으로 교체한 15개다. 옛 두 profile의 목록은 바꾸지 않는다.

```text
sample_protection_prefixes_only
full_tenc_and_constant_iv_unexamined
sample_auxiliary_and_groups_unexamined
protection_declarations_not_encryption_proof
```

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

보호 prefix는 2026-10-24 확인한 고정 1차 구조 근거에서 좁힌 지원 집합이다. ISO 전체 적합성 검사는 아니다.

- [Bento4 v1.6.0-641 Stsd](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4StsdAtom.cpp): entry 수 구조. upstream v1을 포함하는 전체 지원을 따르지 않고 v0·flags0만 선택한다.
- [같은 tag SampleEntry](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4SampleEntry.cpp)와 [Protection](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4Protection.cpp): visual 78B·audio-v0 28B와 sinf 관계의 근거.
- [같은 tag Schm](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4SchmAtom.cpp)·[Tenc](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4TencAtom.cpp)·[CommonEncryption](https://github.com/axiomatic-systems/Bento4/blob/v1.6.0-641/Source/C%2B%2B/Core/Ap4CommonEncryption.cpp), [FFmpeg n7.1 mov_read_tenc](https://github.com/FFmpeg/FFmpeg/blob/n7.1/libavformat/mov.c#L7188-L7251): 고정 필드 위치 대조. 구현마다 다른 조건부 constant-IV 처리까지 가져오거나 통합하지 않는다.
