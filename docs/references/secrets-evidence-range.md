# 명시 EV 텍스트 구간의 비밀값 후보 검사

`forensics_scan_secrets`의 offset/length를 함께 지정하면 같은 접수 EV의 작은 구간을
마스킹 검사한다. 구간 전체를 읽고 UTF-8·미디어·허용 문자 검사를 통과한 뒤, 선택 경계의
불완전한 줄을 제외하고 기존 자격증명·토큰 규칙을 적용한다. 원문을 반환하지 않는다.

```text
forensics_scan_secrets(case_id=..., evidence_id=..., offset=1048576,
                      length=4096, method="auto", max_hits=200, max_seconds=45)
```

위 숫자는 호출 형태를 보이는 예다. 실제 범위는 사용자의 목적과 확보한 metadata로 정한다.
파일 내용이나 구간을 에이전트가 직접 열어 고르지 않는다. 전체 카드 자동 검색·바이너리 안의
문자열 섬 찾기·미디어 해독·자동 XOR 키 탐색은 제공하지 않는다.

## 입력 선택

- offset와 length는 exact 정수 쌍이다. bool·float·문자열·한쪽만 지정한 입력은 받지 않는다.
- offset은 0 이상, length는 1바이트~4 MiB, 선택 끝은 실제 EV 크기 이하여야 한다.
  EV 크기와 위치는 signed 64-bit 범위이며 큰 EV를 통째로 읽지 않는다.
- partition/ref/path는 생략하고 method=auto를 사용한다. 파일/아카이브 선택과 혼용하지 않는다.
- 두 값을 모두 생략하면 기존 전체 EV 또는 FAT/exFAT·TAR/ZIP의 완전 파일 선택이다.
  기존 파일의 크기 제한을 넘는 입력을 자동으로 잘라 성공시키지 않는다.
- 원 EV의 영상·음성 파일명 거부는 구간에서도 유지한다. raw 및 명시 XOR 보기의 미디어 매직,
  UTF-8 strict(BOM 허용), 허용 Unicode 검사를 먼저 적용한다. 원문의 문법을 고치거나 trim하지 않는다.
- xor_key는 생략 또는 기존 정수 144(0x90)만, max_hits는 1..200, max_seconds는 유한한 양수..45다.

텍스트 선택 reader는 같은 열린 EV fd의 64 KiB 이하 읽기로 요청 구간만 읽는다.
`no_outside_range_read`는 **이 내용 선택과 경계 문맥 peek**의 제한이다. 기존
`fingerprint_fd`/`recheck_opened`의 EV 앞뒤 1 MiB 무결성 읽기는 그대로 유지한다.
전체 I/O가 구간 안에만 있다고 표현하거나 EV 권위 검사를 생략하지 않는다.

## 선택 경계와 미검사 줄

서버가 두 경계 상태를 계산한다. prefix_complete는 offset==0, suffix_complete는
offset+length==evidence_size다. 공개 인자로 이 값을 지정할 수 없다. 이 값은 선택이
EV 끝에 닿았는지만 나타내며 원래 파일 경계를 확인한 결과가 아니다.

지원 텍스트에 기존 CR/LF/CRLF 논리줄 규칙을 적용한 뒤 다음을 제외한다.

1. offset>0이면 첫 논리줄의 내용과 종결자를 모두 미검사한다. 선택 직전에 줄바꿈이 있는지
   구간 밖을 읽거나 추측하지 않는다.
2. 구간 끝이 EV 끝이 아니고 마지막 줄이 CR/LF로 끝나지 않았으면 그 줄도 미검사한다.
3. 두 조건이 같은 한 줄이면 한 번만 제외한다. EOF 종결자 뒤의 가상 빈 줄은 추가하지 않는다.

제외된 줄은 credential 검사나 지문 계산을 하지 않으며 **후보·digest 자체를 만들지 않는다**.
이는 기존 파일 안에서 열린 인용부호 등 때문에 value_complete=false/digest=null인 후보를
남기는 동작과 다르다. 안쪽 완전한 줄의 규칙·마스킹·케이스 솔트 지문은 그대로다.
선택이 UTF-8 문자 중간에서 잘리면 unsupported이며 문자 대체·앞뒤 잘라내기·선택 밖 보완을 하지 않는다.
XOR를 지정해도 같은 bytes 좌표에서 그 보기의 줄 경계를 판정한다.

기존 시간·줄·후보·범위 한도를 먼저 확인하고 경계 줄 또는 긴 줄을 분류한다.
경계 조건과 16 KiB 초과가 겹치면 selection_boundary 하나로 기록한다.
`scanned_bytes + framing_bytes + unscanned_bytes = input_bytes`를 유지하며,
경계 줄을 제외했다면 partial·analysis_complete=false·hits_are_lower_bound=true다.
selection_uncertain은 기존 복구 출처용 필드이므로 range에서는 false이며 원 파일 경계 확인을 뜻하지 않는다.
후보 0건은 미검사 줄·구간 밖·카드 전체에 비밀이 없다는 증거가 아니다.

## 출처와 저장

schema는 기존 `pweh.secrets-scan/v1`이며 새 range만
`profile="utf8-masked-secrets-ev-range-v1"`를 사용한다. 기존 파일 보고서는 profile 없이
옛 source/params/사유/limitations로 검증하며 새 검사를 소급하지 않는다.

새 source는 다음 9필드다.

| 필드 | 의미 |
|---|---|
| kind | evidence |
| evidence_id | 접수 EV |
| evidence_sha256 | 접수 기록의 EV 해시 |
| evidence_size | 열린 EV의 전체 크기 |
| offset / length | 명시 선택 구간 |
| selected_sha256 | 이번에 읽은 구간 전체, XOR 전 bytes의 SHA256 |
| selected_size | length와 같은 완전 읽기 크기 |
| complete | true, 요청 구간을 전부 읽었다는 뜻 |

선택 SHA는 이번 구간의 결속이며 접수 SHA나 빠른 무결성 재확인을 이번 EV 전체 재해시로
표현하지 않는다. source에 가짜 파일명·ref·삭제 상태·복구 신뢰도를 덧붙이지 않는다.
params는 xor_key/max_hits/decoder/max_seconds/prefix_complete/suffix_complete의 6필드다.
후보 offset은 선택 상대, line은 창 기준이고 EV 위치는 source.offset+match.offset이다.

limitations는 기존 single_selected_file_only를 single_explicit_ev_range_only로 바꾸고,
selection_boundary_lines_unexamined·no_outside_range_read·no_whole_evidence_assessment를 더한다.
그 밖의 기존 규칙·한도·무원문 원칙은 같다. 한 줄 16 KiB·100,000줄·200후보·1024범위·JSON1 MiB다.

케이스 확인·선택·읽기·SHA·검사에 같은 45초 이하 마감을 쓴다. 읽기 중 시간 만료는 실패이고
완전 읽기 뒤의 scanner 시간 제한은 partial일 수 있다. 부분 결과 저장에도 기존 최종 EV·출력·
보관 기록 검증과 취소 확인을 적용하며 새 45초를 만들지 않는다. 커밋 전 취소는 새 출력/사건 없이
끝나고 커밋 뒤 결과는 보존한다. 기존 report/analysis/warnings 반환 봉투와
`forensics/analysis/secrets-scan-<EV>-NNN.json` 0444·secrets-scan 사건을 유지한다.

## SD 요약

`secret_scan_results`는 기존 8필드만 사용한다. source의 구간·경계 상태를 새 요약 필드로
복제하지 않고 원보고서와 notes에 한계를 남긴다. 분석 해시 키는 analysis_sha256이다.

```json
{
  "evidence_id": "EV-0001",
  "analysis_path": "forensics/analysis/secrets-scan-EV-0001-001.json",
  "analysis_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "partial",
  "hits": 0,
  "scanned_bytes": 0,
  "unscanned_bytes": 4096,
  "reasons": ["selection_boundary"]
}
```

위 예시는 경계 줄만 있어서 검사하지 못한 합성 결과 형태다. 실제 요약에는 반환된 상태·계수·
해시를 그대로 사용한다. privacy.secret_plaintext_returned=false를 유지하고 원문·계정·키·URL을
추가하지 않는다. 자격증명의 유효성·현재 사용·침해·카드 전체 안전을 판정하거나 로그인하지 않는다.
