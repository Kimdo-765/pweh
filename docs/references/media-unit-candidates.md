# 선택 미디어 단위의 구조 후보

`forensics_media_unit_candidates`는 접수한 EV 또는 선택한 완전 파일·명시 구간에서
JPEG, AVC Annex B, MPEG-2 PS, XM 중 지정한 형식의 제한된 구조 후보를 찾는다.
반환하는 것은 위치·길이·고정 경계 분류다. 영상·음성·픽셀을 해독하지 않는다.

```text
forensics_media_unit_candidates(case_id=..., evidence_id=..., format="jpeg", ref=...)
forensics_media_unit_candidates(case_id=..., evidence_id=..., format="avc-annexb",
                               offset=1048576, length=4194304)
```

## 선택과 출처

format은 `jpeg`, `avc-annexb`, `mpeg2-ps`, `xm` 중 하나이며 자동 판별이나 별칭은 없다.
ref/path로 FAT/exFAT·TAR/ZIP의 파일 하나를 고른다. 둘을 함께 지정하지 않으며 삭제 파일은
ref와 복구 method로 고른다. ref/path를 생략하면 EV 자체를 선택한다(partition 생략,
method=auto). 선택은 최대64 MiB이며 불완전한 파일의 앞부분을 성공으로 처리하지 않는다.

offset/length는 정수를 함께 지정한다. offset≥0, length는1..64 MiB이며 실제 EV 안에 있어야
한다. ref/path/partition과 함께 쓰지 않고 method=auto를 유지한다. 구간 밖은 검사하지 않는다.
빈 완전 선택이나 지원 밖 형식은 unsupported가 될 수 있다.

source는 기존 선택 출처16필드 또는 명시 구간18필드다. evidence_sha256은 접수 EV 해시,
selected_sha256은 실제 읽은 선택 전체의 해시다. 구간에는 evidence_size/offset을 더하고
params의 offset/length와 묶는다. params는 format/partition/method/max_seconds 및 구간의
offset/length다. complete=true는 선택 bytes를 완전히 읽었다는 의미다.

candidate.offset은 **선택 상대**다. 구간에서만 source.offset을 한 번 더하여 EV 위치를
계산한다. 파일 시스템·삭제 복구·아카이브의 상대 위치를 물리 EV 위치로 바꾸지 않는다.

## 지원 subset과 추출 경계

| format | 관찰하는 단위 | 경계와 제한 |
|---|---|---|
| jpeg | baseline 단일 scan codestream | SOI·SOF0·SOS·EOI, segment 길이와 entropy stuffing·restart 순서. EOI를 포함한다 |
| avc-annexb | AVC NAL 하나 | 다음 시작 표지와 고정 NAL header가 관찰되어야 닫힌다. 현재 prefix를 포함하고 trailing zero·다음 prefix는 제외한다 |
| mpeg2-ps | MPEG-2 pack의 검증된 앞부분 | 유효 pack header와 길이 있는 media PES를 확인한다. 다음 유효 pack/B9는 종료 근거이며 현재 bytes에 포함하지 않는다 |
| xm | 선언 길이의 frame 단위 | FC/FE16byte, FD/FA/F98byte header와 양수 payload 길이. header와 payload를 포함한다 |

JPEG는 precision8, component1..4의 동일 단일 scan, baseline selector·고정값을 검사한다.
APP/COM 안의 가짜 EOI는 segment 길이로 건너뛴다. DQT/DHT는 경계만 보며 표·MCU 의미는
검증하지 않는다. DRI가0이면 restart를 허용하지 않고, 양수이면 RST0부터 순서를 확인한다.
progressive·DNL·다중 scan·계층/산술 방식은 이 subset 밖이다.

AVC는 type1..12의 forbidden bit·ref 제약과 제한된 escape 규칙을 검사한다. type10/11은
header-only이므로 최소 단위4bytes, 다음 prefix/header를 포함한 선택 최소8bytes가 가능하다.
다른 type은 payload가 필요하다. 긴 zero run·3/4byte prefix를 구분하고 동일 prefix를 중복
anchor로 세지 않는다. 선택 끝이나 EV 끝만으로 마지막 NAL을 닫지 않는다. SPS/PPS·slice·
SEI·RBSP 의미와 access unit/frame 경계는 해석하지 않는다.

PS는 MPEG-2 pack marker/stuffing과 제한된 PES header·PTS/DTS framing만 검사한다.
시각 값은 반환하지 않는다. media PES 하나와 양수 payload가 필요하다. 선택 끝·잘린 packet·
미지원 packet·잘못된 packet·길이0 packet 앞에서 멈추면 마지막 검증 packet까지의
`framing_status=prefix` 후보다. 다음 유효 BA/B9로 닫혀도 unit은 pack prefix이며 전체
program·녹화 완성을 뜻하지 않는다. MPEG-1·TS·복잡한 PES extension은 지원하지 않는다.

XM 길이는 little-endian이며 header를 제외한 payload 크기다. FC/FE의 T 상위 비트는
치수 확장이므로0을 강제하지 않는다. 문서에 있는 제한된 type 선언만 검사하며 날짜·치수·
샘플률·차량 정보·본문은 해석하거나 반환하지 않는다. 선언 길이가 맞아도 실제 모델 지원,
원본 파일 경계·프레임 적합성·재생은 확인되지 않는다.

## 보고서와 완료도

schema는 `pweh.media-unit-candidates/v1`이다. 형식별 file profile과 대응하는 ev-range
profile을 사용하며 기존 BMFF/DHAV 보고서와 섞지 않는다. 후보의 열 개 필드는
index/offset/length/format/unit/unit_subtype/boundary_kind/framing_status/end_reason/confidence다.
confidence는 possible이며 raw header·시각·channel·stream ID·내용·개별 단위 해시는 없다.

summary는 관찰·기각·지원 밖·불완전 anchor와 closed/prefix 후보를 구분한다. coverage의
search_positions_examined는 선택 byte 시작 위치의 처리 prefix다. 읽기·작업량과 다르다.
unexamined_positions와 pending_anchor_offset은 자원 한도로 처리하지 못한 부분이다.
부분 probe의 row는 저장하지 않고 앞서 완결한 후보만 보존한다.

- search_complete: 선택 범위의 시작 위치를 모두 검색했는지.
- candidate_checks_complete: 이미 관찰한 anchor에 미완료 검사가 없는지.
- candidate_list_complete: 검색과 관찰 후보 처리를 모두 마쳤는지.
- PS prefix 여부는 위 완료도와 별개다. 목록을 완성했어도 prefix가 있으면 status=partial이다.

status는 ok/partial/unsupported다. 시간·한도·열린 tail·PS prefix·출처 불확실성이 있으면
partial이며, 후보0건도 미디어 부재를 뜻하지 않는다. 삭제·부모삭제/미확인·복구 신뢰도·
컨테이너 목록 잘림은 보존한다. container_examined=false는 전체 컨테이너 검사를 주장하지 않는다.

media_decoded, playback_verified, recording_time_verified, encryption_assessed,
format_conformance_assessed, original_file_boundary_verified, complete_recording,
payload_semantics_examined는 항상 false다. 표지 검색은 payload bytes를 지날 수 있지만
본문 의미를 해석하지 않는다. 후보끼리 겹칠 수 있으며 후보 수는 파일·프레임·녹화 수가 아니다.

## 예산·저장·다음 단계

선택·읽기·검사는 공통 max_seconds(유한 양수, 최대45초)를 사용한다. 입력64 MiB,
1024 anchor probe, 128후보, 8192구조 단계, 작업량128 MiB, 최종 JSON1 MiB 상한이다.
search_bytes_charged와 structure_bytes_charged의 합은 보수적으로 예약한 검사 작업량이며
고유 입력 bytes나 OS I/O 양이 아니다. 중첩 재검사도 다시 차감하며 작업 상한을 늘리지 않는다.

JSON은 `forensics/analysis/media-unit-candidates-EV-NNNN-NNN.json`에0444로 저장하고
`media-unit-candidates` 보관 기록에 해시·출처·params를 결속한다. 시간 초과 partial은 저장할
수 있지만 취소·불완전 선택·무결성 실패는 성공으로 바꾸지 않는다. 같은 EV fd와 최종
입력/출력 검사를 유지하며, 커밋 뒤 취소·보조 기록 실패는 이미 저장한 결과를 보존한다.

필요한 후보 하나는 [forensics_extract_media_unit](media-unit-extract.md)에 이 보고서의
analysis.path와 index를 넘겨 추출한다. 추출물은 직접 열지 않는다. SD 요약의
`media_unit_candidate_results[]`에는 EV, 결과 위치/해시, status, format, selected_size,
candidates_reported의7필드만 남기고 상세 한계는 보고서와 notes에 보존한다.

큰 EV의 자동 전체 검색·미할당 분류·조각 재조립·녹화 타임라인은 이 도구의 범위가 아니다.
선택 명시 구간과 [DHAV 스트리밍 검색](dhav-scan.md)은 각각 별도 계약을 따른다.

## 문헌 근거

JPEG marker·baseline syntax는 [ITU T.81 Annex B](https://www.w3.org/Graphics/JPEG/itu-t81.pdf),
AVC 경계·NAL header는 [ITU H.264](https://www.itu.int/rec/T-REC-H.264/en)와
[RFC6184 §5.3](https://www.rfc-editor.org/rfc/rfc6184.html#section-5.3)을 따른다.
header-only 종료 NAL은 [FFmpeg n7.1의 syntax 구현](https://github.com/FFmpeg/FFmpeg/blob/n7.1/libavcodec/cbs_h264_syntax_template.c)과 대조했다.
PS는 [ITU H.222.0](https://www.itu.int/rec/T-REC-H.222.0/en)과
[FFmpeg n7.1 mpeg.c](https://github.com/FFmpeg/FFmpeg/blob/n7.1/libavformat/mpeg.c)의 구조를 대조했다.
XM은 OpenIPC가 게시한 [vendor 형식 문서](https://github.com/OpenIPC/python-dvr/blob/6ea861a1e99cab5922084a4a0eac6fe2d5b6120d/doc/%E7%A0%81%E6%B5%81%E5%B8%A7%E6%A0%BC%E5%BC%8F%E6%96%87%E6%A1%A3.pdf)와
[같은 고정 커밋의 구현](https://github.com/OpenIPC/python-dvr/blob/6ea861a1e99cab5922084a4a0eac6fe2d5b6120d/dvrip.py)을 사용했다.
위 자료의 전체 표준·모델 지원을 구현한 것은 아니며 이 문서의 subset과 고정 제한을 따른다.
