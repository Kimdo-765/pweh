# CU Ultralight 계열 페이지 snapshot (소유 증명, 읽기 전용)

`pweh-nfc`는 고정 ChameleonUltra reader(공식 v2.3.0)로 MIFARE Ultralight 계열 태그의 저장 페이지를 읽어
같은 케이스 UL inventory(`UT-`)에 결속한 snapshot을 만든다. 구현 검증은 가짜 transport·합성 태그로 했다.
실제 USB/RF 동작·진품·물리적으로 같은 태그는 확인하지 않았다. 연결·전송 규칙은 [CU 전송 계약](cu-ntag-read-provider.md),
READ 없는 계열 식별은 [HF 식별 계약](cu-hf-identify.md), UL scan·inventory 원장은 [NFC 스캔 결속 분석](nfc-inventory-analysis.md)을 따른다.

## 범위 (설계 §1.3·§6.2의 2026-11-02 개정)

저장소 소유자는 2026-11-02에 "not credential이어도 본인 소유면 상관없음", "현재 GVB 카드로 진행"이라고 결정했다.

- 이 기능은 사람이 `tag-ownership` 증명으로 **사용자 본인 소유이거나 소유자의 서면 허가를 받은 태그**라고 확인한 Ultralight 계열 태그
  한 장의 저장 페이지만 읽는다. 대상 계열은 MF0ICU1, MF0ICU2(공개 페이지), EV1 MF0UL11/MF0UL21/MF0ULH11/MF0ULH21이다.
- 사용자 본인의 사용했거나 만료된 종이 교통 승차권(GVB, EV1 MF0UL11) 같은 자격증명도 이 조건이면 **읽기 전용**으로 포함한다.
- 그대로 제외한다: 모든 쓰기(0xA2/0xA0)와 매직 UID 쓰기, 에뮬레이션·복제·재생, PWD_AUTH(0x1B), UL C 3DES 인증(0x1A)과 CU 2018–2022,
  키 복구, READ_SIG/READ_CNT/FAST_READ/CHECK_TEARING/VCSL, LF 125 kHz(마스킹·거부), Classic/Plus/ISO14443-4/EMV/DESFire(기존 정책 그대로).
  "소유면 충분하다"는 이 Ultralight 읽기 전용 예외 밖의 다른 계열·도구로 넓히지 않는다.
- snapshot 파일은 로컬 케이스에만 있다. 에이전트는 snapshot을 직접 열지 않는다. 도구·job 결과에는 원시 UID·페이지 바이트가 없고
  분석은 구조·관찰 범위만 돌려준다. 자동 허용 pweh-case·pweh-fwtriage·pweh-sigrok는 `nfc/cu-ul-read-NNN.json`·`nfc/cu-read-NNN.json` 이름을
  입력·디렉터리 순회(`nfc/`·케이스 루트)·가져오기 복사에서 거부한다(`pweh.evidence.NFC_SNAPSHOT_RE`). 파일 도구·REA는 그 검사 밖이라 규칙으로 지킨다.

어떤 Ultralight 경로도 보내지 않는 명령:

| 분류 | 명령 |
|---|---|
| 인증 | PWD_AUTH 0x1B, UL-C AUTHENTICATE 0x1A, CU 2018–2022 |
| 쓰기 | WRITE 0xA2, COMPAT_WRITE 0xA0 |
| 다른 태그 opcode | READ_CNT 0x39, FAST_READ 0x3A, READ_SIG 0x3C, CHECK_TEARING 0x3E, VCSL 0x4B |
| 다른 CU 명령 | 2016, 2100, 2101, 1001, 모든 setter·emulator·slot 명령 |
| UL에 쓰지 않는 RAW option | fc, ec, e4(keep=1) |

키 탐색과 에뮬레이션도 하지 않는다.

## 흐름

1. `nfc_cu_connect` → 같은 태그 한 장을 올린 채 `nfc_cu_identify`로 family가 `ultralight_`로 시작하는지 먼저 확인한다.
2. `nfc_cu_ul_scan(case_id, session_id)`: READ 없이 scan2000·keep=0 GET_VERSION만 보낸다. 증명이 없으면 CU 사용권을 놓은 뒤
   바로 `attestation_required`를 돌려준다(아래 증명 절). 증명 뒤 다시 부르면 `US-` scan_ref를 남긴다.
3. `nfc_tag_inventory_add(case_id, scan_ref)`: 같은 증명을 다시 확인하고 `UT-` tag_ref를 만든다.
4. `nfc_cu_read_start(case_id, session_id, tag_ref)`: UT- tag_ref는 CU 사용권을 **예약하기 전에** 증명을 다시 확인한다. 없으면 frame·예약 없이
   `attestation_required`(+`tag_ref`, `family`, `ul_identity_digest`, `page_reads_sent=false`, `job_started=false`)다. 증명이 있으면 결속을
   다시 풀어 같은지 보고 같은 id를 동기 확인한 뒤 예약하고 MODIFY gate(`cu.ul-read`)를 거쳐 job(`nfc-cu-read`)을 시작한다.
5. `nfc_job_status`로 receipt를 확인하고 `registered=true`의 artifact_id만 `nfc_parse_file`·`nfc_diff_dumps`(같은 UT- tag_ref)에 넘긴다.
6. 끝나면 같은 session_id로 `nfc_cu_disconnect`한다. UL job도 kind `nfc-cu-read`·`meta.session_id`라 disconnect가 취소한다.

승인 action(`cu.ul-read`)은 `operation=ul_read`, session_id, family, pages_total, read_last_target, withheld_pages, `raw_option=f4`,
`activation_per_page=true`, UL 프로필 이름·hash, attestation_id와 inventory 결속(ul_identity_digest 제외)을 포함한다.

## 계열 표

| family | GET_VERSION | 페이지 | READ 대상 | 보류(요청하지 않음, null) | 근거 |
|---|---|---:|---|---|---|
| `ultralight_ev1_mf0ul11` | `0004030101000b03` | 20 | 0x00–0x11 | 0x12–0x13 PWD·PACK(읽으면 00h) | MF0ULX1 §8.5·§8.6.1·§10.1·§10.2 |
| `ultralight_ev1_mf0ulh11` | `0004030201000b03` | 20 | 0x00–0x11 | 0x12–0x13 | 같음 |
| `ultralight_ev1_mf0ul21` | `0004030101000e03` | 41 | 0x00–0x26 | 0x27–0x28 | 같음 |
| `ultralight_ev1_mf0ulh21` | `0004030201000e03` | 41 | 0x00–0x26 | 0x27–0x28 | 같음 |
| `ultralight_or_ultralight_c` | 없음(`00-empty`·`01-empty`) | 48 | 0x00–0x2B | 0x2C–0x2F UL C 키(읽을 수 없음) | MF0ICU1 §7.5.2·§7.6.5, MF0ICU2 §7.5.7·§7.5.8·§9.2 |

READ 0x30은 4페이지(16B)를 돌려주고 decode 끝에서 00h로 roll-over하며 그보다 높은 주소는 NAK다(MF0ICU1 §7.6.5, MF0ICU2 §9.2, MF0ULX1 §10.2).
MF0ICU1은 00–0Fh를 decode하고 읽기 보호가 없다. MF0ICU2·EV1은 AUTH0 이상이 READ 보호일 때 그 page부터 NAK이고 그 아래는 AUTH0 바로 앞에서 roll-over한다.
builder는 0x2C 이상·보류 page·keep=1 option을 만들 수 없다(`build_ul_read`).

## frame 순서

모든 RAW는 `2010 f4 0064 …`(activate·wait·append CRC·auto-select·check CRC, keep=0)다. firmware는 keep=0 호출 끝마다 성공·NAK·timeout·
선택 실패와 관계없이 field를 끈다(rc522.c L1594-1600, L1670-1672). auto-select는 WUPA 0x52로 시작해 IDLE·HALT 태그를 깨운다.

1. job 안 frame 전: UL inventory 결속 재검사와 같은 증명 id의 동기 확인(`ul_require`). 철회·만료면 **frame 0개**로 `nfc_attestation_required`다.
2. `[1002]` reader mode 확인.
3. `[2000]` scan → Type 2 이고 UID·ATQA·SAK가 inventory identity와 같아야 한다(아니면 READ 없이 `nfc_identity_mismatch`).
4. `[2010 f4 0064 0008 60]` GET_VERSION → 같은 family여야 한다. EV1은 정확8B, 원조는 `00-empty`·`01-empty`만 원조 계열로 분류된다.
   8B·`03-empty`는 다른 계열이라 `nfc_identity_mismatch`(READ 없음), 잘못된 응답은 `nfc_scan_invalid`다.
5. p = 0 … last_target마다 `[2010 f4 0064 0010 30 p]` 한 번(태그를 매번 새로 선택). 응답 16B 중 첫 4B만 page p로 남기고 뒤 12B는 메모리에서만 대조한다.
   - p = 0: `d[0:3]=UID[0:3]`, `d[3]=BCC0(88⊕UID0⊕UID1⊕UID2)`, `d[4:8]=UID[3:7]`, `d[8]=BCC1(UID3⊕UID4⊕UID5⊕UID6)`.
   - p ≥ 1: `d[0:4]`가 앞 응답의 `d[4:8]`과 같아야 한다(activation 사이 겹침 대조, 읽기 중 태그 교체도 막는다).

frame 수: UL11/H11 21, UL21/H21 42, 보호 없는 UL C 47(최대), MF0ICU1 20, AUTH0=a 보호는 3+a+1이다(모두 45초 안).

## 멈춤 규칙

`wrapped_at(p)`(p ≥ 3) = 앞 응답의 `d[4:16]`이 page0+1+2와 같음. 경계 근거일 뿐이며 page를 채우지 않는다.

| p의 응답 | read_end | stop_reason | 게시 | 세션 |
|---|---|---|---|---|
| last_target의 data(대조 통과) | `end_of_targets`, page null | null(완료) | 예 | ready |
| NAK, p ≥ 3, wrapped | `nak_with_rollover`, page p | null(진품 NXP 동작을 가정한 인증 없는 공개 페이지 완료) | 예 | ready |
| NAK, p ≥ 3, wrap 아님 | `nak_without_rollover`, page p | `tag_nak` | 예(부분) | ready |
| NAK, p < 3 | — | `nfc_identity_mismatch`(UID 페이지 미검증, 예: EV1 AUTH0 ≤ 2·PROT=1) | 아니오 | terminal |
| rf 오류(status 0x01·0x02·0x03·0x07, 길이 ∉ {0,16}) | `stopped`, page k | `nfc_scan_invalid` | k ≥ 3이면 예 | terminal |
| frame 사이 시간 한도 | `stopped`, page k | `time_limit` | k ≥ 3이면 예 | terminal |
| UID/BCC/겹침 불일치·취소·재검증·route·decoder·protocol 오류 | — | — | 아니오 | terminal |

멈춘 뒤에는 아무것도 보내지 않는다. field는 keep=0과 2000의 after-hook으로 꺼지지만 펌웨어 경로 주장이라 `rf_off_verified=false`다.
사용한 EV1 승차권은 AUTH0 위가 보호되어 있을 수 있다. 그러면 NAK로 끝난 부분 snapshot이 정상 결과이며 PWD/PACK은 null이다. 인증하지 않는다.

## 변형 추정 (추정, 인증으로 확인하지 않음)

`observed_variant`: EV1은 family 그대로다. 원조 UL/UL C는 0x10을 넘게 관찰했거나 `nak_with_rollover`가 3 ≤ page < 0x10이면 `ultralight_c`,
그 밖은 `ultralight_or_ultralight_c`다. 첫 NAK가 정확히 0x10이면 MF0ICU1의 끝인지 AUTH0=10h·AUTH1 bit0=0인 UL C인지 나눌 수 없어 모호로 둔다.
roll-over로 경계를 추정하는 것과 읽기 동작으로 변형을 추정하는 것은 모두 추론이다.

## snapshot·원장·분석

- 파일 `nfc/cu-ul-read-NNN.json`: canonical ASCII JSON+LF, 64 KiB 이하, O_EXCL, 0444. schema `pweh.nfc-cu-ul-snapshot/v1`,
  profile `cu-ultralight-pages-v1`. binding(UT-/US-/지문/seq/hash 7값), `attestation{kind: tag-ownership, attestation_id}`, reader(UL_KNOWN 행 전체),
  identity, pages_total·read_last_target·withheld_pages, pages(관찰 prefix만 hex, 나머지·보류 null), read_end·observed_variant·read_complete·stop_reason,
  `activation_per_page=true`, 미관찰 signature·counters·tearing, false flag 10개(NTAG 8개 + read_sig_sent·read_cnt_sent).
- 원장: device-read(source `nfc-mcp/nfc_cu_read_start`, attestation_id = 읽기 때 증명 id, extra 정확 15키). 원장 append 직전(`before_append`)과
  artifact 등록 check에서 같은 증명 id를 다시 확인한다. append 직전에 철회·만료되면 device-read 행·파일을 남기지 않는다. 원장 append 뒤
  등록 check에서 드러나면(등록 실패와 같다) device-read 행 하나와 0444 snapshot은 남고 job은 실패하며(`nfc_attestation_required`, 등록 예외는
  `nfc_artifact_registration_failed`) partial receipt는 `registered=false`·artifact_id null·`artifact_registration_incomplete`다. 등록 type은 `nfc-cu-ul-snapshot`이다.
- receipt: NTAG receipt 키 + `read_end`, `observed_variant`, `attestation_id`. 원시 UID·페이지는 없다.
- `nfc_parse_file`·`nfc_diff_dumps`에 UT- tag_ref를 주면 `nfc/cu-ul-read-NNN.json`만 받는다. 가져온 v4·NTAG snapshot·혼합은 `nfc_source_mismatch`다.
  NT- 흐름도 UL snapshot을 `nfc_source_mismatch`로 거부한다. 입구(모든 FD 닫음) 뒤 ctx 없이 증명을 다시 확인하고(없으면 `attestation_required`,
  `analysis_recorded=false`) 분석 단계와 등록 check에서 같은 id를 동기 재확인한다. 철회·만료 뒤에는 기존 snapshot도 다시 증명할 때까지 분석하지 않는다.
  현재 id가 읽기 때 id와 달라도 받으며 둘 다 기록한다(`source.tag_ownership_attestation_id`, `files[].read_attestation_id`).
- 보고서 schema `pweh.nfc-ul-file-analysis/v1`(profile `cu-ultralight-snapshot-analysis-v1`), 출력 `analysis/nfc-ul-file-NNN.json`·`nfc-ul-diff-NNN.json`.
  inspect 요약은 family·observed_variant·pages_total·read_last_target·pages_observed·withheld_pages_count·read_end·read_complete·stop_reason·미관찰 필드다.
  diff는 같은 family·identity·binding·reader·snapshot 프로필·read_last_target이어야 하고 양쪽 관찰한 보류되지 않은 page만 비교한다.
  `pages_compared + before_only + after_only + neither_observed + withheld + comparison_unexamined = pages_total`, `changed_pages`(번호만),
  `read_end_changed`, `stored_pages_equal`(양쪽 완료·같은 read_end·비교 완료일 때만 bool, 아니면 null).
- 한계 목록: `stored_page_responses_only`, `validated_prefix_pages_only`, `signature_counters_tearing_unobserved`, `withheld_pages_not_observed`,
  `per_page_activation_not_atomic`, `nak_boundary_inferred_unverified`, `variant_inferred_from_read_behaviour`, `physical_same_tag_not_verified`,
  `console_causality_not_verified`, `tag_ownership_is_human_statement`.
- Skill 요약(`nfc-analysis`, mode `scan-bound-offline`)의 tags·results에 UL 항목(`UT-`/`US-`, family, ul_identity_digest,
  tag_ownership_attestation_id / `analysis/nfc-ul-(file|diff)-NNN.json`)을 넣을 수 있다. NTAG 항목과 서로 섞이지 않는 닫힌 oneOf다.

## 사람 증명

- kind `tag-ownership`, 질문 하나(문구 고정, 바꾸면 기존 기록은 충족하지 않는다):
  `owned_tag`(yes/no, 기대 yes) "방금 CU 리더에 올려 스캔한 태그 한 장(위 대상의 계열·지문)은 내가 소유했거나 소유자의 서면 허가를 받은 것이다".
- subject `{tag_family, ul_identity_digest(Ultralight 전용 domain의 케이스 솔트 지문), policy_profile}`, binding은 케이스, 기본 7일.
  subject에는 원시 UID가 없다. `tag-purpose` 기록은 이 확인을 충족하지 않는다.
- 모든 UL 입구(scan·inventory_add·read_start·parse/diff)는 `ctx=None`으로 확인한다. 호출 안에서 사람을 기다리지 않고 곧바로
  `attestation_required`를 돌려주며 사람이 별도 터미널에서 `pweh attest <id>`로 답한 뒤 에이전트가 같은 인자로 다시 부른다.
  `decided_via`는 cli-tty·elicitation 기록을 모두 받는다. denied면 다시 부르지 않고 보고한다.

## 근거

확인한 것:
- firmware v2.3.0(commit 4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1): option `f4`의 비트 구성(app_cmd.c L713-722), auto-select 실패 시 antenna off와
  scan 상태 반환(rc522.c L1592-1600), check_crc에서 3B 미만 응답은 빈 payload와 전송 상태(오류 없으면 0x00, L1639-1659), timeout 0x01(L380),
  CRC 불일치 0x03(L1648), `!keepField`면 상태와 관계없이 antenna off(L1670-1672), 2000의 after-hook antenna off(app_cmd.c L3271, L2102-2104).
- datasheet: 위 계열 표의 READ·roll-over·NAK·AUTH0·PWD/PACK 00h·키 페이지 규칙, UL/UL C는 예상하지 않은 명령 뒤 IDLE/HALT로 가고 UL C는
  NAK마다 reset(MF0ICU1/2 §7.2, MF0ICU2 §8.3), BCC 규칙(§7.5.1·§8.5.1), 원본 서명은 복사될 수 있음(AN11340 §6).

확인하지 못한 것(하드웨어 확인 항목, 모두 닫힌 쪽으로 실패한다):
- 실제 RC522가 4bit NAK를 status 0x00·빈 payload로 알리는지, parity/protocol 오류(0x07/0x02)로 알리는지. 후자면 `stopped`/`nfc_scan_invalid`
  부분 snapshot(3페이지 이상)이고 세션은 terminal이다. 완료로 바뀌지 않는다.
- 원조 UL이 0x60에 NAK로 답하는지 무응답인지(`00-empty`·`01-empty` 모두 원조로 받는다). `01-empty`는 scan 뒤 태그가 field를 벗어난 경우와 섞인다.
  읽기 직전 GET_VERSION이 다시 원조 계열이어야 하므로 NTAG처럼 8B로 답하는 태그는 READ 없이 멈추고, 태그가 없으면 READ0 선택 실패로 3페이지 미만이라
  snapshot이 없다. 두 번 모두 `01-empty`로 보인 다른 Type 2 태그는 원조 계열로 읽힐 수 있다(읽기 전용, 변형 추정만 틀린다).
- 1–2B 쓰레기 응답은 check_crc에서 NAK와 구별되지 않는다. roll-over 근거가 없으면 `tag_nak` 부분이라 완료로 주장하지 않는다.
- READ 부작용: UL READ는 카운터를 바꾸지 않는다(EV1 카운터는 INCR_CNT, UL C 29h 카운터는 WRITE로만 바뀐다)고 읽었다.
- frame당 약 0.25–0.35초(host 재검증이 대부분), 복제·emulator 태그의 동작.
