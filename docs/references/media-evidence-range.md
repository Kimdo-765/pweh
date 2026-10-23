# 증거 이미지의 명시 구간에서 미디어 후보 찾기

명시 exFAT partition/ref의 ValidDataLength 뒤 선택은 별도 [잔여 계약](exfat-residual-candidates.md)을 따른다.
잔여 source19필드와 전용 profile을 사용하며 아래의 기존 파일·EV 구간 계약은 유지한다.

`forensics_media_candidates`는 접수된 이미지 EV에서 `offset`과 `length`로 지정한 한 구간을
검색할 수 있다. 두 값은 바이트 단위 정수이며 함께 지정한다. 구간은 최대64 MiB이고 EV 범위
안에 있어야 한다. 이 모드에서는 `partition/ref/path`를 생략하고 `method="auto"`를 사용한다.

```text
forensics_media_candidates(
    case_id=..., evidence_id=..., offset=1048576, length=4194304
)
```

두 인자를 생략하면 기존처럼 EV 전체 또는 FAT/exFAT·TAR/ZIP의 선택 파일 전체를 읽는다.
큰 EV를 자동으로 잘라 읽지 않는다. 명시 구간이 파일 전체와 같아도 구간 모드로 기록한다.
구간 선택은 미할당·삭제·잔여 영역을 판정한 것이 아니다.

## 위치와 완료도의 의미

후보의 `offset`과 검사 범위는 **선택한 구간 안의 상대 위치**다. 구간 모드에서만
`source.offset + candidate.offset`이 이미지 EV 안의 위치다. 기존 FS·삭제 복구·아카이브
파일의 논리 위치에 이 계산을 적용하지 않는다.

검색 대상은 같은 `ftyp` 기반 연속 최상위 상자 prefix이며 새 형식을 해석하지 않는다.
구간 밖은 검사하지 않으므로 앞 구간에서 시작한 후보를 놓칠 수 있다. 구간 끝이나
`size0`, `selection_end`, `next_ftyp`는 원본 파일 끝이나 녹화 전체의 경계가 아니다.
후보의 `confidence="possible"`와 영상·음성·시각·재생·암호화 검증 false는 유지한다.

## 보고서와 재선택

스키마는 `pweh.media-candidates/v1`이고 구간 profile은 `ftyp-contiguous-ev-range-v1`이다.
기존 파일 선택은 `ftyp-contiguous-top-level-v1`을 유지한다. 두 profile의 source/params를
섞은 보고서는 받지 않는다.

| 필드 | 의미 |
|---|---|
| `source.evidence_sha256` | 접수 때 기록한 전체 EV 해시 |
| `source.evidence_size` | 접수 기록과 열린 파일에서 대조한 전체 EV 크기 |
| `source.offset` | EV 기준 구간 시작 |
| `source.selected_size` | 구간 길이, 요청한 `params.length`와 같음 |
| `source.selected_sha256` | 실제 읽은 구간 전체의 SHA-256 |
| `source.method` | `byte-range` |
| `source.complete` | 요청한 구간을 전부 읽었음 |

`confidence="high"`는 선택 바이트의 신원을 뜻하며 후보나 녹화의 확신이 아니다.
이 호출이 전체 EV를 다시 해시했다는 뜻도 아니다. 전체 검증은 `forensics_verify_start`의
별도 결과를 확인한다. 이름·경로·본문은 후보 보고서에 추가하지 않는다.

저장된 후보는 기존 `forensics_extract_media_candidate(analysis_path=..., candidate_index=...)`로
추출한다. 새 위치나 길이를 다시 지정하지 않는다. 같은 EV에서 원래 구간 전체를 다시 읽고
위치·길이·해시를 대조한 뒤 보고서에 저장된 후보 prefix만 작성한다.
구간 전체의 해시와 출력 prefix의 해시는 별개다. 결과와 한계는
[미디어 후보 추출 계약](media-prefix-extract.md)을 따른다.

## 읽기·보관 기록과 한도

기존 소유/허가·보관 기록·무결성 입구를 통과한 파일 기술자를 빌려 최대64 KiB 조각으로 읽는다.
읽기 전후와 보관 기록 커밋 전 같은 파일의 신원·크기를 다시 확인한다. 범위 밖·짧은 읽기·변경은
요청 길이를 줄여 성공으로 바꾸지 않는다. 원시 디스크를 열거나 파일 시스템을 마운트하지 않는다.

입력64 MiB·후보128개·보고서1 MiB·선택과 검색의 공통45초 한도는 기존과 같다. 검색 시간이
끝난 결과는 검사 범위가 명시된 partial로 저장할 수 있지만, 커밋 전 취소·파일 변경은 거부한다.
prefix 작업은 별도의 기존45초 마감을 모든 단계가 공유하며 출력·취소·정리 계약을 유지한다.
이 한 구간의 결과를 카드 전체 검색·파일 재조립·완전한 녹화 복구로 보고하지 않는다.
