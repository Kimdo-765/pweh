---
name: game-save-unlock-analysis
description: Offline save and unlock analysis of an owned game console or toy (ESP32 toys, MCU+EEPROM devices, Linux handhelds) with pweh-fwtriage - ESP partitions/app/NVS (fw_esp_partitions, fw_esp_image_info, fw_esp_nvs, fw_esp_to_elf), the game string pack (fw_strings_hunt patterns="game"), cheat-input tables (fw_find_seq_tables), save snapshot diffs against on-screen values (fw_save_diff) and save checksums (fw_checksum_find); classifies unlocks by unlock_source and records the save-analysis summary. Save value changes only on explicit request - fw_patch_build makes the patch and, after a fresh verified backup and the human's attestation, shows a write command the human runs in a separate terminal (never the agent); fw_verify_writeback checks the readback. No NFC, no play automation, sold-token content report-only, results stay local. Triggers - hidden game unlock, high score, save file, NVS, cheat code. 게임 세이브 분석, 해금 조건, 하이 스코어, 숨은 게임, 치트 입력.
---

# 게임 세이브·해금 분석 (game-save-unlock-analysis)

`orchestrator/master-prompt.md` §3.1 의 게임 콘솔 분석 경로다. 소유/서면 허가가 기록된 케이스에서만 쓴다. 기기에는 에이전트가 아무것도 쓰지 않는다 — 사용자가 원한 세이브 값 변경은 사람이 쓴다(9단계).
결과는 연구·방어용이고 로컬에만 둔다(온라인 리더보드·대회·계정에 제출하지 않는다). 설계 근거는 `docs/design/game-console-flipper-rf.md` §1.3·§1.4·§3.5·§4 다.

## 목적

- 숨은 콘텐츠의 **해금 조건**(디버그 메뉴, 치트 입력, 카운터, 날짜, 사용자 소유 태그 분기)을 펌웨어에서 찾는다.
- **세이브 값**(하이 스코어, 진행도, 해금 플래그)의 위치·인코딩과 그것을 덮는 **체크섬**을 찾는다.
- 해금 조건마다 `unlock_source`(in-device / owned-tag / sold-token / online-purchase / unknown)를 정하고, 기기·게임이 온라인과 동기화할 수 있는지(`online_capable`) 기록한다.
- 끝에 `save-analysis` 요약을 남긴다(master-prompt §5).

## 언제 쓰나

- **쓴다**: 게임 콘솔 분석 목표이고 펌웨어나 세이브를 확보했거나 확보할 수 있을 때. "숨은 게임 해금 조건", "하이 스코어가 어디 저장되나", "세이브 체크섬" 요청.
- **쓰지 않는다**
  - 케이스나 소유/허가 증명이 없다 → master-prompt Phase 0.
  - 펌웨어가 아직 없다 → ESP32 면 `esp32-flash-dump`, 리눅스·MCU 기기면 master-prompt §4 Phase A·B 가 먼저다.
  - NFC 태그 읽기·에뮬레이션, 플레이 자동화 → 아직 없다(사용자에게 그렇게 알린다). 세이브 값 변경은 9단계(사용자가 명시적으로 원할 때만).
  - 시판 콘솔(Switch·PlayStation·Xbox)의 세이브 → 암호화·서명돼 있어 분석·수정 대상이 아니다(복제 방지 우회 경계).

## 전제 조건

- **case_id**: `case_get` 의 case.authorized 가 true 여야 한다. 아니면 멈춘다(master-prompt §1-1).
- **이전 요약** (`case_get_step_results(case_id="<id>")`): firmware-dump-via-uart 요약의 data.output.path 를 펌웨어로 쓴다. verification.match 가 true 가 아니면 다시 읽기를 먼저 제안한다.
- **MCP 서버**: pweh-case, pweh-fwtriage, rea(RISC-V ESP 칩·리눅스 기기의 디컴파일), 세이브 스냅샷을 다시 덤프하면 pweh-esp.

## 안전 규칙

1. **소유/허가 확인과 `case_create` 가 먼저다.** 스냅샷을 다시 덤프할 때의 하드웨어 규칙은 `esp32-flash-dump` 를 그대로 따른다(연결마다 칩 리셋).
2. **기기에는 사람만 쓴다.** 에이전트는 세이브·플래시·eFuse 에 쓰지 않고, 쓰기 명령을 실행하지 않는다(셸이 있어도). 값 변경은 사용자가 명시적으로 원할 때만 `fw_patch_build` 로 패치를 만들고,
   서버가 검증된 새 백업과 사람 증명을 확인한 뒤 보여 주는 명령을 사람이 별도 터미널에서 실행한다(master-prompt §1 규칙 3 의 예외). 그 밖의 쓰기 명령은 만들거나 건네지 않는다.
3. **범위 밖 (항상 거부)**: 결제·교통·출입·호텔·신분 자격증명, 남의 태그·피규어 복제, 다운로드한 덤프 에뮬레이션, amiibo 류 콘솔 키 기반 태그 암호(복호·재암호·재서명),
   판매 토큰·DLC·온라인 구매로 여는 콘텐츠(entitlement)의 해금, 온라인 동기화되는 서명·HMAC 위조, 키 복구·PWD 무차별 대입. 이런 단서는 **보고만** 한다.
4. **게이트**: 스냅샷 덤프가 `status: approval_required` 면 무엇을·왜·위험을 설명하고, 사용자가 **별도 터미널**에서 `pweh approve <approval_id>` 하면 같은 인자 + `approval_id` 로 한 번만 재시도한다.
   `status: denied` 면 우회하지 않는다(다른 인자로 다시 보내기, 셸에서 esptool 실행, 설정·승인 파일 수정 금지). 에이전트는 `pweh approve` 를 실행하지 않는다.
5. **비밀값**: NVS 의 Wi-Fi 비밀번호·토큰은 `fw_esp_nvs`·`fw_save_diff` 가 마스킹 + 케이스 솔트 다이제스트로만 돌려준다. 원문을 다른 경로로 꺼내려 하지 않고, 보고서에도 개수만 적는다.
6. **결과는 후보다.** 문자열·표·체크섬 후보는 디컴파일(REA)이나 사람이 화면으로 확인하기 전까지 confidence `possible` 이다. 확인하지 못한 것은 확인했다고 적지 않는다.

## 사용하는 MCP 도구

| 도구 | 용도 |
|---|---|
| `case_get`, `case_get_step_results`, `case_set_phase` | 권한·이전 요약 확인, 단계 상태(phase 이름은 game-save-unlock-analysis) |
| `fw_esp_partitions` | 파티션 표: NVS·원시 데이터·파일 시스템 파티션과 세이브 쓰기 분류(write_class) |
| `fw_esp_image_info`, `fw_esp_to_elf` | 앱 이미지 헤더·세그먼트·앱 설명, ELF 변환(REA 입력) |
| `fw_esp_nvs` | NVS 항목(namespace/key/값), 지운 이전 값, CRC 유효 개수. 비밀은 마스킹 |
| `fw_strings_hunt`, `fw_hunt_patterns` | 게임 문자열 팩(`patterns="game"`): debug-menu, cheat-input, unlock-condition, save-format, save-integrity, nfc-tag, clock, online-sync, entitlement |
| `fw_find_seq_tables` | 치트 입력(버튼 시퀀스) 표 후보 — 코나미형 모양 점수 |
| `fw_save_diff` | 세이브 스냅샷 비교(bytes·nvs)와 화면 관찰값 매칭 |
| `fw_checksum_find` | 세이브 체크섬 후보(합·xor·CRC·adler·fletcher), 기대 오탐 수 |
| `esp_read_flash_start`, `esp_job_status` | 세이브 스냅샷 덤프(NVS 파티션 범위만, `esp32-flash-dump` 규칙) |
| `open_binary`, `search_strings`, `xrefs`, `procedure_pseudo_code`, `close_binary` | REA 디컴파일로 후보 확인 (RISC-V·리눅스 기기) |
| `case_add_finding`, `case_add_note`, `case_record_step` | 발견사항, 사람 관찰 기록, 최종 summary |

## 절차

### 1. 시작: 권한·이전 결과·기기 종류

`case_get(case_id="<id>")` 로 권한을, `case_get_step_results(case_id="<id>")` 로 펌웨어 경로와 칩(esp32-flash-dump 요약의 source.chip)을 확인한다.
`case_set_phase(case_id="<id>", phase="game-save-unlock-analysis", status="in-progress")`. 기기 종류(device.kind)를 정한다: ESP32 장난감·휴대기 / MCU+EEPROM / 리눅스 휴대기 / 아케이드.

### 2. ESP 구조 (ESP32 기기)

```
fw_esp_partitions(case_id="<id>", path="dumps/esp-flash.bin")
fw_esp_image_info(case_id="<id>", path="dumps/esp-flash.bin", partition="factory")
fw_esp_nvs(case_id="<id>", path="dumps/esp-flash.bin", partition="nvs")
```
- 앱 파티션 이름은 표에 있는 것을 쓴다(factory, ota_0, app0 …). 표를 못 찾으면(found=false) 플래시 암호화나 잘못 읽은 덤프다 → `fw_entropy` 로 확인하고 보고한다.
- `fw_esp_nvs` 의 `crc_summary` 에서 항목 CRC 가 하나도 맞지 않으면 CRC 규칙이 이 기기와 다를 수 있다(실기 검증 전) — 값은 참고만 하고 limitations 에 적는다.
- `next_steps` 의 "세이브로 보이는 키"(score·level·unlock·coin …)를 5단계 후보로 적어 둔다. `fat`·`spiffs`·`littlefs` 파티션은 파일 시스템 해석 전까지 분석만 한다(write_class `filesystem-analysis-only`).

### 3. 해금 조건 단서

```
fw_strings_hunt(case_id="<id>", path_or_dir="dumps/esp-flash.bin", patterns="game")
fw_find_seq_tables(case_id="<id>", path="dumps/esp-flash.bin", partition="factory")
```
- 리눅스 기기는 추출한 rootfs 디렉터리에 `fw_strings_hunt(patterns="game")` 를 쓴다(큰 트리는 `background=true` 또는 `patterns="game:cheat-input"` 처럼 범주로 좁힌다).
- entitlement 범주(DLC·구매·라이선스·토큰)와 amiibo 류 태그 히트는 `unlock_source` sold-token / online-purchase 후보로 **보고만** 한다.
- online-sync 범주(HTTP 클라이언트·MQTT·클라우드·업로드)와 NVS 의 Wi-Fi 설정은 `online_capable` 근거다. 결과를 온라인으로 보내지 않도록 사용자에게 알린다.
- 치트 입력 표 후보는 `address_hex`(디컴파일러 주소)로 4단계에서 참조를 확인한다. 코나미형(`konami_like`)이 우선이다.

### 4. 디컴파일로 확인 (가능할 때)

- **RISC-V ESP 칩**(C3·C6·H2 …): `fw_esp_to_elf(case_id="<id>", path="dumps/esp-flash.bin", partition="factory", rea_compat=true)` → 응답 `elf_path_abs` 를
  `open_binary(path="<elf_path_abs>", provider_id="ghidra")` 로 연다. `search_strings` → `xrefs` → `procedure_pseudo_code` 로 단서 문자열·표 주소를 쓰는 함수를 본다. 끝나면 `close_binary`.
- **Xtensa ESP 칩**(ESP32·S2·S3): REA 가 ELF 를 열지 못한다. 디컴파일 없이 문자열·표·세이브 비교로만 판단하고 confidence 를 `possible` 로 둔다. limitations 에 "Xtensa — REA 미지원" 을 적는다.
- **리눅스 기기**: 추출한 게임 바이너리를 `open_binary` 로 연다(firmware-static-analysis 와 같은 방식).
- 확인한 것만 confidence 를 올린다: 비교 루틴이 표를 읽으면 `likely`, 사람이 소유 기기에서 화면으로 확인하면 `confirmed`.

### 5. 세이브 스냅샷 (값 위치 찾기)

점수·진행이 바뀔 때마다 세이브 영역을 다시 덤프한다(3개 이상, 템플릿 A·B). ESP32 면 NVS 파티션 범위만 읽는다(수 초).
```
esp_read_flash_start(case_id="<id>", port="COM3", offset="0x9000", size="0x6000", output_name="nvs-snap-01")
```
- offset·size 는 2단계 `fw_esp_partitions` 의 NVS 파티션 값이다. 덤프마다 칩이 리셋되므로 게임이 값을 저장한 뒤(게임 오버·메뉴 복귀)에 덤프한다.
- 사람이 화면에서 본 값(점수 등)을 스냅샷마다 받는다(템플릿 B). 모르면 null.
```
fw_save_diff(case_id="<id>", paths=["dumps/nvs-snap-01.bin", "dumps/nvs-snap-02.bin", "dumps/nvs-snap-03.bin"], mode="nvs",
             observations=[{"label": "score", "values": [1200, 3450, 5100]}])
```
- `observation_matches` 의 키가 그 값의 위치다. NVS 가 아닌 원시 세이브(EEPROM 덤프, 리눅스 세이브 파일, ESP raw-user-data 파티션)는 `mode="bytes"` 로 비교하고 `offset_abs`·`encoding` 을 기록한다.
  NVS 를 담은 범위(전체 플래시 포함)는 바이트로 비교하지 않는다(비밀값을 가릴 수 없어 서버가 거부) — NVS 는 nvs 모드, 그 밖의 영역은 offset/length 로 NVS 를 빼고 비교한다.
- blob 안의 값이면 `fw_esp_nvs(…, export_blobs=true)` 로 blob 파일을 스냅샷마다 남겨 `mode="bytes"` 로 비교한다.

### 6. 체크섬

```
fw_checksum_find(case_id="<id>", paths=["dumps/eeprom-01.bin", "dumps/eeprom-02.bin", "dumps/eeprom-03.bin", "dumps/eeprom-04.bin"])
```
- NVS 항목은 NVS 자체 CRC 가 덮으므로 이 단계가 필요 없다(NVS 안의 blob 내부 체크섬은 내보낸 blob 파일로 찾는다).
- `strong` 후보만 체크섬으로 기록한다. 8비트 체크섬은 저장값이 서로 다른 스냅샷 3개 이상, 16/32비트는 2개 이상부터 strong 이 될 수 있다(범위가 크면 더 필요). `weak` 이나 후보 없음은 limitations 에 적는다.
- 큰 영역은 `offset`·`length`(세이브 블록) 나 `algorithms` 로 좁힌다(`truncated` 면 CRC 일부를 못 본 것이다).
- 후보가 없고 해시·HMAC 단서(save-integrity 범주)가 있으면 키가 있는 MAC·서명일 수 있다 → strength `keyed-mac`/`signature`/`unknown` 으로 적고 재계산하지 않는다.

### 7. 발견사항

근거가 있는 해금 조건·세이브 위치만 `case_add_finding` 으로 남긴다(category `other`, severity `info`). evidence 는 fwtriage 결과면 type `triage` + `ref` = result_path 다.
```
case_add_finding(case_id="<id>", finding={
  "title": "치트 입력 표 후보 (코나미형 10입력) — 숨은 스테이지 해금 조건 후보",
  "category": "other", "severity": "info", "confidence": "possible", "status": "unverified",
  "summary": "앱 rodata 0x3c0123a0 에 위·위·아래·아래·왼·오·왼·오·B·A 모양의 버튼 id 표가 있다. 입력 비교 루틴은 아직 확인하지 못했다.",
  "location": {"firmware": "dumps/esp-flash.bin", "address": "0x3c0123a0"},
  "evidence": [{"type": "triage", "ref": "analysis/seq-tables-001.json", "excerpt": "konami_like=true values=[1,1,2,2,3,4,3,4,6,5]"}],
  "reasoning": "작은 알파벳(버튼 id 6종)의 10입력 배열이고 코나미형 모양이다. Xtensa 라 REA 로 참조를 확인하지 못해 possible 로 둔다.",
  "verification_plan": "사람이 소유 기기의 타이틀 화면에서 그 순서로 입력해 화면 변화를 확인한다(기기에 쓰지 않음)."
})
```

### 8. 요약 기록과 마무리

`case_record_step(case_id="<id>", skill="game-save-unlock-analysis", step="summary", status, summary, data=<save-analysis>)` 를 호출한다(아래 출력 절).
해금 조건이 sold-token·online-purchase 뿐이면 그 사실을 보고하고 끝낸다. 값 변경을 원하면 아래 9단계로 간다(원하지 않으면 여기서 끝).

### 9. 값 변경 (선택 — 사용자가 명시적으로 원할 때만)

ESP NVS 정수 항목(`target={"type": "nvs", "partition": "nvs"}`)이나 사용자 데이터 파티션(`raw-region` + 6단계의 strong 체크섬)만 바꾼다. 순서를 건너뛰지 않는다.
1. 사용자에게 무엇을 어떤 값으로 바꿀지 확인한다(템플릿 B 와 같은 `[확인 필요]`). `unlock_source` 가 in-device·owned-tag 가 아니거나 `online_capable` 이 yes 면 만들지 않는다.
2. 계획: `fw_patch_build(case_id="<id>", base_path="dumps/esp-flash.bin", target={"type": "nvs", "partition": "nvs"}, edits=[{"namespace": "game", "key": "hiscore", "value": 999999}], purpose="score", unlock_source="in-device", online_capable="unknown")`
   → stage `planned`(패치 이미지, 바뀌는 값, 플래시 암호화 근거). 거부되면(암호화·nvs_keys·CRC 규칙 불일치·비밀 키) 우회하지 않고 보고한다.
3. 쓰기 직전 백업: 템플릿 D 로 네트워크를 끊게 한 뒤 응답 `next_steps` 의 `esp_read_flash_start(…, verify="double", after="no-reset")` 로 대상 범위를 새로 읽는다(칩이 다운로드 모드에 머문다).
4. 같은 인자 + `backup_path` 로 다시 부른다. `status: attestation_required` 면 사용자가 **별도 터미널**에서 `pweh attest <attestation_id>` 로 답한다(네트워크 차단·재부팅 없음·변경 의사·판매 토큰 콘텐츠 아님). 같은 인자로 다시 부르면 stage `ready` 와 `command` 가 온다.
   백업을 읽은 뒤에는 쓰기가 끝날 때까지 그 기기에 어떤 esp 도구로도 연결하지 않는다(연결마다 칩이 리셋된다 — 서버가 원장에서 보고 백업을 낡은 것으로 거부한다).
5. `command` 를 사용자에게 그대로 전하고(템플릿 E), 사용자가 별도 WSL 터미널에서 실행한다. 에이전트는 실행하지 않는다. 명령이 sha256 확인에서 멈추면 파일이 바뀐 것이다 — 다시 4로.
6. 읽기 확인: `next_steps` 의 `esp_read_flash_start` 로 대상 범위를 다시 읽고 `fw_verify_writeback(case_id="<id>", patch_path="<응답의 patch_path>", readback_path="<읽은 파일>")`.
   `applied` 면 사람이 RESET 으로 부팅해 오프라인에서 화면 확인, `not-applied`·`differs` 면 부팅하기 전에 사용자와 정한다.
   되돌리려면 플래시 전체를 다시 두 번 읽어 새 base 로 원래 값으로 바꾸는 패치를 같은 절차로 만들거나, 사람이 PWEH 밖에서 백업 파일을 쓴다(`docs/safety.md` §5).
7. summary 의 `patches[]` 에 `result_path`·`stage`(applied 등)·`purpose`·`unlock_source`·`ledger_seq` 를 적는다.

## 사람에게 요청할 일 (템플릿)

**A. 세이브 스냅샷 준비**
```
[사람 작업 필요] 세이브 스냅샷 (점수·진행을 바꾸며 3번 이상)
1. 기기를 네트워크에서 끊어 주세요(Wi-Fi 공유기 차단 또는 앱 연동 해제). 결과가 온라인 순위에 올라가지 않게 하기 위해서입니다.
2. 게임을 한 판 하고 점수가 저장되는 시점(게임 오버, 메뉴 복귀)까지 진행해 주세요.
3. 화면의 점수·진행 값을 그대로 알려 주시고 "완료" 라고 해 주세요. 제가 세이브 영역만 다시 읽습니다(읽을 때마다 기기가 재부팅됩니다 — 저장되지 않은 진행은 사라집니다).
4. 점수가 다르게 나오도록 2–3을 두 번 더 반복합니다.
```

**B. 화면 관찰값 확인**
```
[확인 필요] 스냅샷마다 화면에서 본 값
- 스냅샷 1·2·3 의 점수(또는 레벨·코인)를 순서대로 알려 주세요. 모르는 값은 "모름" 이라고 해 주세요.
- 값이 같으면 위치를 좁힐 수 없습니다. 서로 다른 값이 둘 이상 필요합니다.
```

**C. 범위 밖 해금 보고**
```
[보고] 판매 토큰·온라인 구매로 여는 콘텐츠
- 이 콘텐츠는 따로 파는 토큰(피규어·카드) 또는 온라인 구매로 열리는 것으로 보입니다(근거: analysis/strings-hunt-001.json).
- 복제 방지·저작권 보호 경계라 해금·패치하지 않고 보고만 합니다.
```

**D. 쓰기 전 네트워크 차단**
```
[사람 작업 필요] 값 변경 준비 (네트워크 차단)
1. 기기를 네트워크에서 끊어 주세요(Wi-Fi 공유기 차단 또는 앱 연동 해제). 쓰기와 확인이 끝날 때까지 다시 연결하지 않습니다.
2. 기기는 USB 로 연결된 그대로 두고, 끄거나 리셋하지 마세요. 제가 대상 영역을 한 번 더 읽어 백업합니다(읽은 뒤 기기는 다운로드 모드에 머뭅니다).
3. "완료" 라고 해 주세요.
```

**E. 쓰기 명령 실행 (사람)**
```
[승인 필요] 세이브 값 쓰기 — 사람이 직접 실행
- 바꾸는 값: <changes 의 before → after>. 백업: <backup 경로>. 패치 sha256: <앞 16자>.
- 별도의 WSL(또는 리눅스) bash 터미널에서 아래 명령을 그대로 실행해 주세요(PowerShell 아님). 저는 실행하지 않습니다.
  <command>
- 명령은 먼저 패치 파일의 sha256 을 확인하고(다르면 쓰지 않음), 파티션 범위만 씁니다. 끝나면 기기는 다운로드 모드에 머뭅니다 — 리셋하지 말고 결과를 알려 주세요.
```

## 실패 처리

| 상황 | 대응 |
|---|---|
| 파티션 표 없음(found=false) | `fw_entropy` 로 암호문인지 확인. 플래시 암호화면 분석 범위가 크게 줄었다고 보고(우회하지 않음) |
| NVS 항목 CRC 가 모두 불일치 | CRC 규칙 미검증 — 값은 참고, limitations 에 기록 |
| `observation_matches` 없음 | 값이 다른 스냅샷을 더 받거나, 저장 시점 뒤에 덤프했는지 확인. blob 안이면 export_blobs 후 bytes 비교 |
| 체크섬 후보가 weak 뿐 | 스냅샷을 더 모으거나 범위를 좁혀 다시 실행 |
| REA open_binary 거부 | Xtensa 면 정상(미지원). RISC-V 면 `rea_compat=true` 로 다시 만든다. 사유를 limitations 에 |
| 스냅샷 덤프 실패 | `esp32-flash-dump` 의 실패 처리 절을 따른다 |

## 출력 (요약 기록)

data 는 `save-analysis` 스키마다(`schema_get(name="save-analysis")`). `patches` 는 9단계로 만든 패치만 적는다(없으면 빈 목록).
아래 예시는 합성 데이터(`tests/fwtriage/esp_builders.py`, ESP32-S3 흉내)로 이 서버를 돌린 흐름을 바탕으로 한 값이다. 실제 기기 값이 아니다. 이 data 는 save-analysis 스키마 검증을 통과한다.

```json
{
  "device": {"kind": "esp32-toy", "chip": "ESP32-S3", "model": "toy-arcade (합성)", "firmware_sha256": null},
  "firmware": {"path": "dumps/esp-flash.bin", "partitions_path": "analysis/esp-partitions-001.json", "elf_path": "extract/esp-app-001/toy-arcade.elf"},
  "saves": [
    {"location": {"partition": "nvs", "nvs_namespace": "game", "nvs_key": "hiscore"}, "value_label": "high score", "encoding": "nvs-u32",
     "checksum": null, "evidence": ["analysis/save-diff-001.json", "analysis/esp-nvs-001.json"], "confidence": "confirmed"}
  ],
  "unlock_conditions": [
    {"kind": "cheat-input", "unlock_source": "in-device", "description": "코나미형 10입력 버튼 표 후보 (0x3c0123a0) — 입력 비교 루틴은 Xtensa 라 REA 로 확인하지 못함",
     "evidence": ["analysis/seq-tables-001.json", "analysis/strings-hunt-001.json"], "confidence": "possible", "finding_id": "F-001"}
  ],
  "online_capable": "unknown",
  "online_evidence": ["online-sync 범주 히트 없음", "NVS 에 nvs.net80211 Wi-Fi 설정 있음 (값은 마스킹)"],
  "patches": [],
  "finding_ids": ["F-001"],
  "limitations": ["ESP32-S3(Xtensa) ELF 는 REA 가 열지 못해 디컴파일로 확인하지 못함", "사용자가 값 변경을 원하지 않아 패치를 만들지 않음",
                  "NVS CRC 규칙은 실기 검증 전 — 이 덤프는 항목 CRC 가 모두 일치"],
  "next_actions": ["사람이 소유 기기에서 치트 입력 후보를 입력해 화면 확인"],
  "notes": ["스냅샷 3개(nvs-snap-01..03), 관찰값 score=[1200, 3450, 5100]"]
}
```

```
case_record_step(case_id="<id>", skill="game-save-unlock-analysis", step="summary", status="success",
  summary="ESP32-S3 장난감: 하이 스코어 = NVS game/hiscore(u32, 확인), 치트 입력 표 후보 1건(possible). 온라인 가능 여부 미확인",
  data=<위 JSON>,
  artifacts=["analysis/esp-partitions-001.json", "analysis/esp-nvs-001.json", "analysis/save-diff-001.json", "analysis/seq-tables-001.json"],
  next_actions=["사람이 치트 입력 후보 확인"], blockers=[])
```
서버가 스키마 검증에 실패하면 메시지대로 data 를 고쳐 다시 저장한다.

## 다음 단계

- `report_generate(case_id="<id>")` 후 master-prompt §10 형식으로 보고한다. 한 일과 아직 할 수 없는 일(값 수정·NFC·플레이 자동화)을 나눠 쓴다.
- 결과를 온라인(리더보드·계정)으로 보내지 않도록 다시 알린다.

## 참고

- `orchestrator/master-prompt.md` §1 절대 규칙, §3.1 게임 콘솔 분석, §5 데이터 전달.
- `mcp-servers/fwtriage-mcp/README.md`(ESP·세이브 도구와 한계), `docs/architecture.md` §6.6, `docs/safety.md` §3.5(비밀값)·§4.
- `skills/esp32-flash-dump/SKILL.md`(덤프·하드웨어 규칙), `docs/design/game-console-flipper-rf.md`(범위와 설계).
