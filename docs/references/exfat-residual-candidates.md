# exFAT 잔여 영역의 미디어 후보와 단일 추출

`forensics_media_candidates`, `forensics_dhav_candidates`, `forensics_media_unit_candidates`는
`region="residual"`로 명시한 exFAT 파일 하나의 ValidDataLength 뒤를 검사한다.
기본값 `region="data"`는 기존 파일·EV 구간 선택과 보고서 형식을 유지한다.

```text
forensics_media_candidates(case_id=..., evidence_id=..., partition=1,
                          ref=..., region="residual")
forensics_media_unit_candidates(case_id=..., evidence_id=..., format="jpeg",
                               partition=1, ref=..., region="residual")
```

## 선택과 한도

residual은 명시한 정수 partition(1..4096)과 FS ref가 모두 필요하다. path·offset·length는
함께 쓰지 않는다. 같은 exFAT 볼륨에서 검증된 일반 파일 하나만 선택하며 FAT·아카이브·
전체 EV·디렉터리는 받지 않는다. 다른 파티션이나 파일을 자동으로 찾지 않는다.

원래 DataLength(DL)와 ValidDataLength(VDL)는 `0 ≤ VDL < DL ≤ 2^63-1`이어야 한다.
엔진이 보정한 VDL이 원래 값과 다르면 거부한다. 선택 크기는 정확히 `DL-VDL`이며
1 byte..64 MiB다. 전체 DL이64 MiB를 넘더라도 잔여 선택이 상한 안이면 검사할 수 있다.
VDL이0인 선택도 가능하지만 빈 잔여나 불완전 복구 계획·짧은 읽기는 성공 처리하지 않는다.

method는 auto 또는 엔진이 해당 항목에 제공하는 chain·nofatchain·contiguous·
skip-allocated·stale-chain이다. 구체 복구 방법과 삭제·부모 상태·신뢰도를 보존한다.
선택과 후보 검사는 같은 최대45초 마감을 공유하며 읽기는 최대64 KiB 조각이다.
기존 형식별 후보·검사·출력 상한을 늘리지 않는다.

## 출처와 좌표

잔여 source는 기존 파일 출처16필드에 `region="residual"`, `data_length`,
`valid_data_length`를 더한 닫힌19필드다. selected_size는 DL-VDL,
selected_sha256은 실제 읽은 잔여 전체의 해시다. evidence_sha256은 접수 때의 EV 해시이며
이번 호출이 전체 EV를 재해시했다는 뜻이 아니다. 이름·경로·물리 클러스터 목록은 싣지 않는다.

candidate.offset은 **잔여 선택 안의 상대 위치**다. `VDL + candidate.offset`은 원래 파일의
논리 위치이며 EV 물리 위치가 아니다. 이미 선택한 잔여 bytes를 추출할 때 VDL을 다시 더하지
않는다. 기존 EV 구간 source의 offset/evidence_size와 잔여 출처를 섞지 않는다.

| 형식 | 잔여 profile |
|---|---|
| BMFF | `ftyp-contiguous-exfat-residual-v1` |
| DHAV | `dhav-record-exfat-residual-v1` |
| JPEG | `jpeg-baseline-marker-exfat-residual-v1` |
| AVC Annex B | `avc-annexb-delimited-nal-exfat-residual-v1` |
| MPEG-2 PS | `mpeg2-ps-bounded-pack-prefix-exfat-residual-v1` |
| XM | `xm-length-delimited-frame-exfat-residual-v1` |

params는 partition/method/max_seconds/region이며 미디어 단위에는 format도 있다.
기존 파일 profile의 한계에 exfat_valid_data_length_residual_only,
logical_offsets_not_evidence_offsets, no_original_recording_or_deletion_verification을 더한다.
잔여라는 이유만으로 partial을 만들지는 않으며 기존 검색·구조·복구 불확실성은 유지한다.

## 저장된 후보의 추출

기존 [BMFF 추출](media-prefix-extract.md), [DHAV 추출](dhav-record-extract.md),
[미디어 단위 추출](media-unit-extract.md)에 저장 보고서와 후보 번호만 넘긴다. 새 region이나
위치 인자는 없다. 원래 partition/ref/구체 method로 잔여 전체를 다시 선택하고19필드 각각의
타입·값과 해시를 대조한다. 부모 상태나 신뢰도가 바뀌어도 자동으로 더 확실한 결과로 바꾸지 않는다.

선택 범위의 단일 후보만 기존 출력 규칙으로 쓰고 extract 보관 사건의 region을 residual로
기록한다. 원래 source·status·coverage와 미검사 범위를 보존한다. complete는 지정 bytes의
복사 완료다. 요약은 기존 후보 참조 배열·recovered를 사용하고 잔여 의미와 한계를 notes에 적는다.

VDL 뒤의 바이트라는 사실은 이전 녹화·삭제 시점·원본 파일 경계·완전 녹화·재생의 증명이 아니다.
후보0건도 잔여에 미디어가 없다는 증명이 아니다. 영상·음성·시각·암호화를 해독하거나 판단하지
않으며 에이전트는 추출물을 직접 열지 않는다.
