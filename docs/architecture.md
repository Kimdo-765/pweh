# PWEH 아키텍처와 구현 계약

이 문서는 PWEH 파이프라인을 구성하는 서버·Skill·오케스트레이터 사이의 **계약**이다.
구현자와 Skill 작성자는 여기 적힌 도구 이름, 인자, 반환 형식, 파일 위치를 그대로 따라야 한다.
도구를 더 추가하는 것은 괜찮지만, 여기 적힌 이름과 의미는 바꾸지 않는다.

## 1. 전체 구조

```
[사람]  물리 연결(UART 케이블, 프로브, 로직 애널라이저 클립), 전원 껐다 켜기, 위험 작업 승인(pweh approve), 사람 증명(pweh attest)
   │
[에이전트]  Claude Code / Codex / Cursor — orchestrator/master-prompt.md + skills/*/SKILL.md 를 따른다
   │
   ├─ pweh-case        (mcp-servers/case-mcp)        케이스, 단계 결과, 발견사항, 보고서, 프로필, 승인 상태
   ├─ pweh-uart        (mcp-servers/uart-mcp)        UART 콘솔: 포트, 세션, U-Boot, Linux 셸, 덤프(job)
   ├─ pweh-sigrok      (mcp-servers/sigrok-mcp)      로직 애널라이저 스캔/캡처/디코딩, 보드레이트 추정
   ├─ pweh-openocd     (mcp-servers/openocd-mcp)     OpenOCD 프로세스 + TCL RPC: 스캔체인, 메모리/플래시 읽기
   ├─ pweh-jtagulator  (mcp-servers/jtagulator-mcp)  JTAGulator 핀아웃 스캔 (선택)
   ├─ pweh-fwtriage    (mcp-servers/fwtriage-mcp)    오프라인 펌웨어 트리아지 (외부 도구 없이 동작)
   ├─ pweh-esp         (mcp-servers/esp-mcp)         ESP32 계열 esptool 읽기 전용: 칩·보안 정보, 플래시 덤프(job) (선택)
   └─ rea              (외부: rea-agents 6.5)        binwalk/unblob 추출, Ghidra 디컴파일, sigrok 디코딩
            │
      [대상 기기]  (또는 테스트용 pweh.mocktarget 시뮬레이터)
```

공통 코어 패키지 `pweh` (`src/pweh/`) 가 설정, 케이스 저장소, 안전 게이트, 사람 증명·출처 원장·비밀값 마스킹(§4), 작업(job) 관리, MCP 헬퍼를 제공한다.

## 2. 저장소 레이아웃

| 경로 | 내용 |
|---|---|
| `src/pweh/` | 공통 코어: `config.py`, `case.py`, `safety/`(분류기·게이트·승인·사람 증명·비밀값 마스킹), `provenance.py`(출처 원장), `jobs.py`, `runtime.py`, `mcpkit.py`, `report.py`, `cli.py`, `audit.py`, `errors.py`, `fsutil.py`, `formats.py`(mtdparts·uImage·U-Boot env·md.b/crc32 출력 파서), `schemas/`, `mocktarget/`, `data/` |
| `mcp-servers/<name>-mcp/<name>_mcp/` | 서버 패키지 (`server.py` 에 `server` 객체와 `main()`), `mcp-servers/<name>-mcp/README.md` |
| `skills/<skill>/SKILL.md` | 에이전트용 워크플로 (`.claude/skills/` 에 심볼릭 링크) |
| `orchestrator/` | `master-prompt.md`, `pipeline-config.yaml` |
| `schemas/` | → `src/pweh/schemas` 심볼릭 링크 (JSON Schema) |
| `docs/` | 안전/하드웨어/MCP 설정 가이드, `references/` (프로토콜·출력 형식 조사 자료) |
| `examples/` | 실제 실행(시뮬레이터)으로 만든 예제 케이스 |
| `tests/` | pytest. `tests/mock-targets/` 는 녹화 로그와 그 생성 스크립트(시뮬레이터 프로필·합성 펌웨어 빌더는 `src/pweh/mocktarget/`) |
| `cases/` | 실제 분석 케이스 (git 제외) |
| `.pweh/state/` | 승인 레코드(`approvals/`), 사람 증명(`attestations/`), 출처 원장(`provenance/<case>.jsonl`), 마스킹 솔트(`salts/<case>.key`), 전역 감사 로그(`audit.jsonl`) (git 제외, 에이전트 수정 금지. 모두 처음 쓸 때 만든다) |

패키징: 루트 `pyproject.toml` 하나로 모든 패키지를 설치한다 (`pip install -e ".[dev]"`).
콘솔 스크립트: `pweh`, `pweh-case-mcp`, `pweh-uart-mcp`, `pweh-openocd-mcp`, `pweh-sigrok-mcp`,
`pweh-jtagulator-mcp`, `pweh-fwtriage-mcp`, `pweh-esp-mcp`, `pweh-mock-device`.

## 3. 케이스 디렉터리 (Skill 사이의 데이터 전달)

```
cases/<case_id>/
  case.json            schemas/case.schema.json — 대상, 소유/허가 증명, 단계(phase) 상태, 아티팩트 색인, 단계 결과 색인
  audit.jsonl          이 케이스의 모든 안전 결정/기기 조작
  steps/NNNN-<skill>-<step>.json   schemas/step-result.schema.json
  uart/<session>.log   타임스탬프 텍스트 로그 (RX/TX 구분)
  uart/<session>.raw   수신 원시 바이트
  uart/<session>.events.jsonl  송신 명령/안전 결정/문맥 변화 이벤트 (비밀번호는 마스킹)
  uart/<session>-boot-NN.log   uart_capture_boot 가 저장한 부팅 로그 발췌
  uart/esptool-<명령>-NNN.log  pweh-esp 의 esptool 출력 로그 (esptool-chip-info / esptool-security-info / esptool-<name>-readN)
  dumps/<name>.bin     덤프 결과 + dumps/<name>.json (메타데이터) + 진행 중이면 <name>.state.json 과
                       부분 파일(UART 덤프 <name>.bin.part, OpenOCD 덤프 <name>.part).
                       pweh-esp 덤프는 이중 읽기의 2차 결과 <name>.read2.bin 을 함께 둔다. 읽는 동안에는 숨은 예약 파일 .<name>.readN.partial 과
                       소유 표식 .<name>.owner.partial 만 두고, 최종 파일(.bin/.read2.bin/.json)은 끝날 때 덮어쓰지 않고 만든다
  extract/<label>-NNN/ 추출 결과 (REA extract_firmware 의 output_directory 는 case_paths 의 new_output_dir 사용)
                       fw_carve: <idx>-<name>.bin (idx 2자리) + index.json / fw_extract_squashfs: 트리 + 옆에 <label>-NNN.manifest.json
  analysis/            fwtriage JSON, 디컴파일 발췌, 메모
  signals/             *.sr / *.vcd / 디코딩 텍스트
  jtag/                OpenOCD 로그·세션 상태(openocd-<n>.log/.json), 메모리 덤프(기본 위치. kind=flash-dump 면 dumps/),
                       레지스터 스냅샷, JTAGulator 세션 기록(jtagulator-<n>.log)과 스캔 원시 출력·결과(jtagulator-<n>-<scan>-<k>.log/.json)
  jobs/<job_id>.json   백그라운드 작업 상태
  notes/               보드 사진 같은 사람 자료 (case_import_file(dest_subdir="notes")). case_add_note 메모는 case.json 에 저장
  findings.json        발견사항 목록 (각 항목은 schemas/finding.schema.json)
  report.md            report_generate 결과
  attestations.json    사람 증명의 읽기 전용 사본(0400, 그 케이스의 증명 레코드가 바뀔 때 다시 만든다. 사람이 보는 용도 — 보고서 생성기는 아직 읽지 않는다).
                       권위 기록은 .pweh/state/attestations/ — 서버는 이 파일을 증거로 읽지 않는다
```

규칙:
- 모든 하드웨어 도구는 `case_id` 를 받고, 산출물을 해당 케이스 하위 디렉터리에 쓰고, `case.register_artifact(...)` 로 등록한다.
- 하드웨어 도구는 `rt.case(case_id, hardware=True)` 로 케이스를 열어 소유/허가 증명을 강제한다 (`safety.require_authorization`).
- 경로는 항상 `case.path(...)` / `case.resolve_path(...)` 로 만든다 (케이스 밖 경로 차단).
- 각 Skill 은 끝날 때 `case_record_step(step="summary", data=<Skill 출력 스키마>)` 를 호출한다.
  다음 Skill 은 `case_get_step_results` 로 이전 요약을 읽는다.

| Skill | summary data 스키마 |
|---|---|
| uart-shell-acquisition | `schemas/uart-recon.schema.json` |
| firmware-dump-via-uart | `schemas/firmware-dump.schema.json` |
| firmware-static-analysis | `schemas/static-analysis.schema.json` |
| logic-analyzer-protocol-decode | `schemas/signal-capture.schema.json` |
| cctv-auth-bypass-hunt | `schemas/auth-hunt.schema.json` |

- firmware-dump-via-uart 밖에서 얻은 덤프(JTAG, SPI 클립, ESP32 esptool)도 다음 Skill 이 찾을 수 있게 `skill="firmware-dump-via-uart"` 로 firmware-dump 요약을 남긴다(master-prompt §5).
  `esp32-flash-dump` Skill 은 따로 요약 스키마를 두지 않고 이 규칙을 따른다: `method` `esptool-read-flash`, `verification.method` `double-read`
  (`expected`/`actual` = 두 읽기의 sha256, `match`). 값은 `esp_read_flash_start` job `result.summary_hint` 에 그대로 있다(§6.7).
- ESP32 덤프용 스키마 값: firmware-dump `method` 의 `esptool-read-flash`, static-analysis `firmware.source` 의 `esptool-dump`.

단계(phase) 상태 — `case.json` 의 `phases` (코드: `src/pweh/case.py`):
- **파이프라인 단계**(`PIPELINE_PHASES`, 보안 분석 목표): `uart-shell-acquisition`, `firmware-dump-via-uart`, `logic-analyzer-protocol-decode`,
  `firmware-static-analysis`, `cctv-auth-bypass-hunt`, `report`. `case_create` 가 모두 `pending` 으로 만든다.
- **선택 단계**(`OPTIONAL_PHASES`, 다른 목표·계측기용 Skill 에 예약한 이름): `game-save-unlock-analysis`, `nfc-behavior-analysis`, `game-play-automation`,
  `flipper-rf-analysis`, `sd-card-forensics`, `espprobe`. 미리 만들지 않는다. 그 Skill 이 summary 를 기록하거나 `case_set_phase` 로 상태를 정할 때 처음 생기므로,
  그 목표를 쓰지 않는 케이스의 `case.json`·보고서는 그대로다. 이 Skill 들은 아직 없다(에이전트용 문서 — master-prompt·Skill — 에는 이 이름을 적지 않는다).
  Skill 을 만들 때 `SKILL_DATA_SCHEMAS`·master-prompt §5 표·`report._PHASE_LABEL` 에 함께 등록한다.
- 상태 값: `pending`, `in-progress`, `done`, `partial`, `failed`, `skipped`, `blocked`. summary 의 status 는 `success` → `done`, `in-progress` → `in-progress`,
  나머지(`partial`·`failed`·`blocked`·`skipped`)는 같은 이름으로 옮긴다(`SUMMARY_PHASE_STATUS`).
  두 목록에 없는 Skill 의 summary 는 단계 상태를 만들지 않는다(예: `esp32-flash-dump` 는 요약을 `firmware-dump-via-uart` 로 기록한다). `case_set_phase` 는 단계 이름을 검사하지 않는다.
- 보고서(`report_generate`) §4 는 파이프라인 단계 표와 그 요약 뒤에, 상태나 요약이 기록된 파이프라인 밖 단계가 있을 때만 `### 선택 단계` 를 붙인다
  (표 + `####` 단계별 요약. 선택 단계는 레지스트리 순서, 등록되지 않은 Skill 은 기록 순서). 요약의 `data` 는 싣지 않는다. 그런 단계가 없으면 보고서는 전과 같다.
- 분석 목표(보안 분석 / 게임 콘솔 분석 / RF·하드웨어 분석 / SD 카드 포렌식)는 `case.json` 필드가 아니다. master-prompt Phase 0 이 `case_create` 의 `notes` 에 적는다
  (보안 분석만 지원, 나머지는 준비 중 — master-prompt §3·§3.1·§9).

아티팩트 kind 어휘: `uart-log`, `uart-raw`, `uart-events`, `flash-dump`, `memory-dump`, `partition`,
`firmware-image`, `extracted-tree`, `signal-capture`, `signal-decode`, `jtag-dump`, `jtag-scan`, `triage-report`,
`rea-evidence`, `decompilation`, `report`, `other`.

`jtag-scan` 은 핀아웃 스캔 기록(JTAGulator 세션 기록, 스캔 원시 출력, 결과 JSON)용이다. 단 현재 pweh-jtagulator 구현은 이 파일들을
`kind="other"` 로 등록하고 종류를 `extra.type`(`session-transcript`, `scan-raw`, `scan-result`, `device-ids`, `bypass-test`, `gpio-read`)에 둔다.
`register_artifact` 는 kind 값을 검증하지 않으므로 이 어휘는 문서 계약이다.

## 4. 안전 모델 (모든 서버 필수)

위험도 (`pweh.safety.Risk`): `OBSERVE < INTERACT < MODIFY < DESTRUCTIVE`.

| 위험도 | 예 | 기본 정책 |
|---|---|---|
| OBSERVE | 포트 목록, 버퍼 읽기, 로직 캡처 | 허용 |
| INTERACT | `printenv`, `md.b`, `sf read`(RAM), `crc32`, `cat /proc/mtd`, `scan_chain`, `mdw` | 허용 |
| MODIFY | `setenv`(저장 안 함), `boot`, `reset`, `halt`, DTR/RTS 토글, 서비스 시작, JTAGulator 스캔, 결과를 저장하는 `crc32 <주소> <크기> <대상>`, `/dev/watchdog`·`/dev/mem` 읽기, esptool 연결(`flash-id`·`get-security-info`·`read-flash` — 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁) | 허용 (`safety.modify_policy`) |
| DESTRUCTIVE | `saveenv`, `sf erase/write`, `nand erase/write`, `mw`, `flash_erase`, `dd of=/dev/mtd*`, 시스템 디렉터리 밖 실행 파일 실행(`./x`, `/tmp/x`), `PATH`/`LD_PRELOAD` 변경, OpenOCD `flash write_image`/`mww`, JTAGulator 전압 설정, esptool `write-flash`/`erase-flash`·eFuse(pweh-esp 는 정책과 무관하게 거부) | **거부** (`safety.destructive_policy`) |

- 분류기: `classify_uboot`, `classify_linux`, `classify_openocd`, `classify_console_line`(문맥별), `LineAssembler`(분할 쓰기/줄 편집 대응. 기기가 입력 일부를 버렸을 수 있으면 `mark_uncertain` 으로 남은 입력을 uncertain 처리).
  U-Boot 약어, `run`/`boot` 간접 실행(추적한 env 로 재귀 분류), 빈 Enter 반복, 명령 위치의 변수/글롭, `eval`/`sh -c`/파이프-to-셸 등을 보수적으로 처리한다.
  - U-Boot: `env run <var>`(약어 `en r` 포함)은 `run <var>` 처럼 재귀 분류하고(`uboot.env.run>…`, 모르는 변수면 DESTRUCTIVE), `time <명령>`(약어 `t`/`ti`/`tim`)은 안쪽 명령 기준이다(`uboot.time>…`).
    결과를 메모리·env 에 저장하는 체크섬 형태(`crc32 <주소> <크기> <대상>`, `md5sum`/`sha1sum`/`hash … <대상>`·`*<주소>`)는 MODIFY(`uboot.<명령>.store`), 조회 형태는 INTERACT 다.
  - Linux: 실행될 **내용**을 확인할 수 없는 경우를 DESTRUCTIVE 로 본다.
    - `/bin`·`/sbin`·`/usr/bin`·`/usr/sbin` 바로 아래가 아닌 경로로 지정한 실행 파일(`./x`, `x/y`, `/tmp/x`, `/bin/../tmp/x`, `nohup`·`env`·`timeout`·`busybox`·`exec` 경유 포함, `linux.exec-nonsystem`).
      그 밖 경로의 래퍼 이름(`/tmp/nohup ls`)은 래퍼로 믿지 않는다. 이름 표(`cat`, `sh` …)보다 먼저 보므로 `/tmp/cat` 은 `cat` 이 아니다.
    - `PATH`·`LD_PRELOAD`·`LD_LIBRARY_PATH`·`LD_AUDIT`·`ENV`·`BASH_ENV` 변경(접두 할당, `env`, `export`/`readonly`/`declare`/`typeset`/`local`, `linux.env-hijack`).
    - 셸에 파일·here-doc 을 표준 입력으로 넘기기(`sh < f`, `sh <<EOF`, `ash -s < f` — `linux.script`/`linux.script-stdin`), `chroot`/`pivot_root`/`switch_root`, 바인드·오버레이 마운트(`linux.mount.bind`).
    - 시스템 실행 파일·라이브러리·설정 경로(`/bin` `/sbin` `/usr/bin` `/usr/sbin` `/lib` `/usr/lib` `/etc` 아래) 쓰기(`linux.write.system` — 리다이렉션, `cp`/`mv`/`ln`/`tee` 대상).
      상대 경로 대상은 `classify_linux(cwd=…)` 의 현재 디렉터리와 같은 줄 안의 `cd` 로 해석한다(`cd /usr/bin && cp /tmp/x md5sum` = DESTRUCTIVE).
      cwd 를 모르면 MODIFY(`linux.write.file`, uncertain). uart-mcp 는 세션이 보낸 `cd` 로 cwd 를 추적해 넘긴다(`linux_cwd_effect`, `cd` 는 성공한다고 봄).
    - `exec <명령>` 은 안쪽 명령 기준(최소 MODIFY)이다. 여는 것만으로 부작용이 있는 `/dev/watchdog*`(타이머 시작 → 재부팅)·`/dev/mem`·`/dev/kmem`·`/dev/port` 읽기는 MODIFY(`linux.read.side-effect-device`)다.
      `ls`/`stat`/`lsof`/`du`, `-exec` 없는 `find` 처럼 장치를 열지 않는 명령은 제외한다. `fdisk -l` 과 `[ … ]`/`[[ … ]]` 는 INTERACT 다.
- 서버는 코어 분류기 위에 더 엄격한 **로컬 분류기**를 얹을 수 있다. 원칙은 `risk = worst(코어, 로컬)` 이고 로컬 규칙은 결과를 더 엄격하게만 만든다.
  코어에 그 장비용 분류기가 없으면 로컬 분류기가 그 자리를 맡되, 대상 콘솔로 가는 텍스트는 코어 콘솔 분류기로도 검사한다.
  - `openocd_mcp.guard`: `classify_command` = worst(코어 `classify_openocd`, 로컬 규칙).
    코어 `classify_openocd` 는 단어 단위 근사 분류기라 **혼자서는 Jim Tcl 의 실행 경로를 다 다루지 못한다**(코어 독스트링에 명시. 코어는 이제 `\n` 으로만 줄을 나누지만 그것으로 충분하지 않다).
    그래서 기기로 가는 Tcl 텍스트(`openocd_command`, `openocd_start` 의 `extra_commands`·사용자 cfg, 서버가 만든 명령)는 모두 이 함수를 거친다.
    로컬 파서가 나눈 **문장마다 코어 분류를 다시** 돌리고, 코어가 놓치는 다음 형태를 DESTRUCTIVE 로 올린다(모두 xPack OpenOCD 0.12.0-7 의 Jim 에서 실행 확인).
    - 이름 우회와 명령 위치 치환: `::mww`, `m\ww`, 명령 위치의 `[…]`/`{*}`.
    - 스크립트 본문 위치: 따옴표로 감싼 본문(`capture "flash erase_sector …"`), 옵션 뒤 `catch` 본문, `dict for/with/update/map`·`loop` 본문,
      이벤트 핸들러 `-event <이름> <본문>`(target configure/create, jtag configure), 명령 접두 `-command <명령>`(`lsort -command mww {0 0}` 은 mww 를 호출).
    - 간접 실행: `update`, `vwait`, `xtrace`, `curry`.
    - 호스트 탈출과 핀 구동: `popen`/`socket` 같은 Jim 호스트 탈출, `irscan`/`drscan`/`svf`.
    - 중괄호 없는 식(`expr`, `if`/`elseif`/`while` 조건, `for` 검사식)의 변수·명령 치환: expr 가 치환 결과를 다시 해석한다(이중 치환, `expr $x`).
      `expr {…}`, `if {[catch {halt}]} …` 처럼 중괄호로 감싸면 안쪽 `[…]` 만 재귀 분류한다.
    - 이 서버가 끈 telnet/GDB 명령 서버를 다시 여는 `telnet port N`, `gdb port N`, `gdb_port N`, `-gdb-port N`(값이 `disabled` 면 MODIFY). 그 포트로 들어온 명령은 게이트를 거치지 않는다.
    - 코어 표에 없는 첫 단어(점 없는 타깃 이름 `cpu0` 등) 뒤의 위험한 하위 명령(`cpu0 mww …` → DESTRUCTIVE. `cpu0 read_memory …` 는 MODIFY 그대로).
    - semihosting 켜기(`openocd.local.semihosting`): `arm semihosting`·`arm semihosting_fileio` 뒤의 값이 끄는 값(`disable`/`off`/`false`/`no`/`0`)이 아니거나
      변수·명령 치환이면 DESTRUCTIVE 다. OpenOCD 는 값을 대소문자 없이 해석한다(`arm semihosting ENABLE`, `arm semihosting on`, `arm semihosting $x` 모두 켜짐을 실측).
      조회(`arm semihosting`)와 끄기는 MODIFY 그대로다.
    - semihosting proc: 세션의 OpenOCD 에서 가드가 찾은 proc(본문에 `semihost` 가 있거나 그런 proc 을 부르는 proc, 전이적)의 호출(`openocd.local.semihosting-proc`).
      코어도 ESP 표준 proc `configure_event_examine_end`·`configure_openocd_events`·`create_esp_target`(`openocd.esp.semihosting-proc`)과 이름에 `semihost` 가 든 명령(`openocd.semihosting-proc`)을 DESTRUCTIVE 로 본다.
    - OpenOCD 훅 변수 `post_init_commands`·`pre_shutdown_commands` 에 `lappend`/`set`/`append`/`lset` 로 넣는 값(원소가 eval 됨 — 실측)은 스크립트로 분류한다
      (`lappend pre_shutdown_commands "mww 0 0"` → 안쪽 `mww` 기준 DESTRUCTIVE. 예전에는 INTERACT 로 통과해 `openocd_stop` 때 실행됐다).
    - 사용자 cfg 안의 init 계열 명령(`init`, `target`/`transport`/`jtag`/`dap` … `init`, `jtag arp_init`, `post_init_commands` 수정)은 semihosting 가드보다 먼저 init 을 돌리므로
      DESTRUCTIVE(`openocd.local.init-before-guard`)다. `extra_commands` 에서는 아예 `validation_failed` 다(§6.4).
    - 알려진 하위 명령 그룹(`flash`, `nand`, `arm`, `jtag`, `esp` …)의 하위 명령 자리가 변수·명령 치환이면 DESTRUCTIVE(`openocd.local.dynamic-subcommand`).
      코어는 `[…]` 를 떼어 보므로 `flash [string cat erase_sector] 0 0 last` 가 `flash`(인자 없음, INTERACT)로 보였다.

    코어 표(`classify_openocd`)의 OpenOCD 포크·칩 명령: 업스트림 `program` 과 Espressif 포크의 플래시 프로그래밍 proc `program_esp`·`program_esp_bins`
    (예전 `program_esp32`, 그 밖의 `program_*` 포함)는 DESTRUCTIVE 다(`openocd.flash.program_esp`, 그 밖의 이름은 `openocd.flash.program_proc`).
    호스트 파일·네트워크로 쓰는 `esp gcov`(타깃 펌웨어가 호스트 경로와 모드를 정함)·`esp apptrace`·`esp sysview`·`esp sysview_mcore` 의 `start`/`dump`·`xtensa tracedump`,
    임의 명령어를 실행하는 `xtensa exe`, 플래시 전압 스트랩 `<칩> flashbootstrap <값>`(`openocd.esp.flashbootstrap`)도 DESTRUCTIVE 다.
    `flashbootstrap` 규칙은 바로 앞 단어가 ESP 칩 그룹(`esp32`, `esp32s2`, `esp32s3`, `esp32c3` …)인 `<칩> flashbootstrap …`·`<타깃> <칩> flashbootstrap …` 에만 적용하고,
    그 뒤에도 일반 표·명령 규칙을 그대로 돌려 더 위험한 쪽을 쓴다(`program flashbootstrap`·`load_image flashbootstrap` 은 DESTRUCTIVE, 값 없는 `esp32 flashbootstrap` 은 `openocd.unknown`).
    호스트 파일을 쓰는 `profile <초> <파일>`(gmon), 트레이스 출력 `<tpiu|swo> create|configure … -output <파일|:포트>`(`openocd.trace.output`), `tpiu config internal <파일>`(`openocd.tpiu.config.internal`)도 DESTRUCTIVE 다.
    스텁을 돌리는 검증·설정(`esp verify_bank_hash`, `esp flash_stub_clock_boost`, `esp compression` …)은 MODIFY, `esp apptrace status` 는 INTERACT 다.
    칩 이름(`esp32`, `esp32s3`)은 단일 코어 cfg 의 점 없는 타깃 이름이기도 해서 하위 명령 표로 만들지 않았다.

    결과를 낮추는 예외는 둘뿐이다.
    - `classify_managed`: 서버가 직접 만든 정확한 형식의 덤프 명령(`dump_image`/`flash read_bank`/`flash verify_bank`/`verify_image`, 경로가 케이스의 `jtag/`·`dumps/` 안)만 INTERACT 로 본다.
      같은 명령을 `openocd_command` 로 보내면 여전히 거부한다.
    - `classify_target_read`: 서버가 만든 `<타깃> read_memory …`/`<타깃> md[bhwd] …` 의 타깃 접두는 서버가 `target names` 로 확인했고
      명령 이름과 겹치지 않는(`target_name_conflict`) 타깃일 때만 떼고 분류한다(§6.4).
  - `sigrok_mcp.policy`: 코어에 sigrok 분류기가 없어 `classify_sigrok_argv` 가 실행할 argv 그대로를 분류한다(USB 캡처·스캔 OBSERVE, 시리얼/네트워크 `conn` INTERACT).
    출력 가능 장치·허용 목록 밖 드라이버·출력/설정을 바꾸는 config 키처럼 MODIFY 이상인 것은 `rt().authorize` 에 넘기지 않고 `status: "denied"`(`gate.via: "sigrok-policy"`)로 거부하므로,
    `destructive_policy: approve` 여도 승인 경로가 없다.
    `ftdi-la` 는 기본 허용 목록에서 뺐다(`SHARED_ADAPTER_DRIVERS`). 제품 문자열 확인 없이 범용 FTDI VID/PID 만으로 장치를 잡아, 같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·JTAG 어댑터·JTAGulator 를
    LA 로 열고 커널 드라이버를 떼며 핀을 bitbang 입력으로 바꾸기 때문이다. 전용 FTDI LA 만 쓰는 환경이면 운영자가 `sigrok.capture_drivers_allow` 에 넣는다.
    디코드(`sigrok_decode` job, `sigrok_uart_autodecode` 의 sigrok-cli 경로)도 프로세스를 띄우기 직전에 argv 를 다시 분류해 오프라인 명령(`sigrok.offline`)만 실행한다.
  - `esp_mcp.policy`: 코어에 esptool 분류기가 없어 `classify_esptool_argv` 가 서버가 검증한 인자로 직접 조립한 argv(실행할 argv 그대로)를 분류한다. 원시 esptool 인자를 받는 도구는 없다.
    허용하는 명령은 이것뿐이다: `version`(OBSERVE, `esp.version`), `flash-id`·`get-security-info`·`chip-id`·`read-mac`(MODIFY, 규칙 id `esp.info.<명령>`),
    `read-flash`(MODIFY, `esp.read-flash` — 출력은 케이스 `dumps/` 안의 서버 예약 경로만). 서버가 실제로 쓰는 것은 `flash-id`·`get-security-info`·`read-flash` 다.
    MODIFY 인 이유: esptool 은 연결할 때 DTR/RTS 또는 USB-Serial/JTAG 리셋으로 칩을 ROM 다운로드 모드에 넣고 보통 RAM 에 플래셔 스텁을 올린다.
    USB-Serial/JTAG 연결이면 워치독 레지스터를 끄고, SPI 플래시에 리셋 명령(0x66/0x99)을 보내며, 끝나면 `--after` 에 따라 다시 리셋한다. 모두 휘발성이고 플래시·eFuse 에 쓰는 명령은 보내지 않는다.
    그래서 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`(`esp.after.no-reset`)·`--after soft-reset`(`esp.after.soft-reset`)은 DESTRUCTIVE 다: 레거시 스텁(esptool 4.8~5.2 의 기본)은
    FLASH_BEGIN 때 SPI 플래시 상태 레지스터를 다시 쓴다(비휘발성). `--chip auto` 는 칩에 남은 스텁을 `--no-stub` 이어도 스텁으로 다루므로 서버는 사용자의 `after="no-reset"` 을
    늘 `no-reset-stub` 으로 바꿔 argv 를 만들고(`policy.stub_safe_after`), `soft-reset` 은 인자 검증에서 거부한다. `watchdog-reset` 은 esptool v5·v4.12 이상에서만 받는다.
    `--no-stub` 과 `--chip esp8266`·`auto` 의 조합도 DESTRUCTIVE 다(`esp.nostub.esp8266`): ESP8266 ROM 에는 플래시 연결 명령이 없어 esptool 이 FLASH_BEGIN(0, 0) 을 보낸다.
    인자 검증(`policy.validate_no_stub`)도 `no_stub=True` 면 ESP8266 이 아닌 칩을 `chip` 으로 명시하게 한다.
    그 밖의 모든 것은 DESTRUCTIVE 다: 플래시 쓰기·삭제(`esp.cmd.flash-write`), RAM 적재·실행(`esp.cmd.ram-exec`), 임의 메모리 쓰기·읽기(`esp.cmd.mem-write`, `esp.cmd.mem-read`),
    오프라인 이미지 도구(`esp.cmd.offline`), 이 서버가 쓰지 않는 명령(`esp.cmd.unsupported`), 모르는 명령(`esp.cmd.unknown`), espefuse·espsecure·rfc2217 서버 실행 파일(`esp.exe.forbidden`),
    금지·모르는 옵션(`esp.opt.forbidden`, `esp.opt.unknown`), `@파일` 인자 확장(`esp.argv.unparsed`), 빠졌거나 검증한 포트와 다른 `--port`(`esp.port.missing`, `esp.port.mismatch`),
    허용 밖 값과 `--connect-attempts 0`(`esp.opt.value`), 명령 뒤의 추가 인자(`esp.argv.extra`), 케이스 `dumps/` 밖 출력(`esp.output.outside`).
    DESTRUCTIVE 는 `rt().authorize` 에 넘기지 않고 `status: "denied"`(`gate.via: "esp-policy"`)로 거부하므로 `destructive_policy: approve` 여도 승인 경로가 없다(`pweh approve` 로도 풀 수 없다).
  - `jtagulator_mcp.classify`: 코어에 JTAGulator 분류기가 없어 보낼 키 계획을 실제 장치 프롬프트 기준으로 분류한다(스캔·`D`/`T` = MODIFY, `V` 키·전압 대화(0 V 포함)·`Y`/`P`/`O`/`W`/`L`/`A`/UART 패스스루 = DESTRUCTIVE).
    UART 스캔 프로브 문자열은 코어 `classify_console_line` 결과와 worst 를 취한다. 대상 콘솔은 순열마다 프로브를 다시 받으므로,
    한 번 보낸 형태와 두 번 이어 붙인 형태(줄 끝 없는 꼬리가 다음 송신의 머리와 이어짐 — `_erase X\rflash` → `flash_erase X`)를 모두 분류한다.
    `jtagulator_connect` 는 포트 형식을 제한하고(장치 절대경로·`COMn`·`socket://`·`rfc2217://`·`loop://`. `spy://`·`hwgrep://` 같은 다른 pyserial URL 은 거부) 포트를 exclusive 로 연다.
    그래서 다른 세션(uart-mcp 콘솔 등)이 잡은 포트에는 재동기화 키(Ctrl-X, CR)를 보내지 않고 거부한다.
  - `uart_mcp.guard`: 세션이 지금까지 보낸 바이트를 기억하는 코어 `LineAssembler` 사본으로 기기에서 완성될 줄을 조립해 줄마다 분류한다(`uart_write("sa")` + `uart_write("veenv\r")` → `saveenv`).
    로컬 규칙은 결과를 더 엄격하게만 만든다.
    - DESTRUCTIVE 인 줄: 탭(자동완성)·ESC(방향키/히스토리)가 섞인 줄, U-Boot/unknown 문맥의 250자 초과 줄(CBSIZE 를 넘으면 기기가 분류한 줄과 다른 줄을 실행. linux-shell 은 1000자),
      상위 비트 바이트가 섞인 줄(`uart.high-bit`. 데이터 비트가 8 보다 적은 세션은 기기가 받는 하위 비트로, 8비트 세션은 하위 7비트로도 분류).
    - U-Boot 가 받을 수 있는 문맥(uboot/unknown/booting/login/password)의 `\r\n` 은 명령 + 빈 줄(직전 명령 반복)로 하나 더 분류한다.
      직전 송신이 `\r` 로 끝났으면 다음 호출의 첫 `\n` 도 빈 줄이다(호출 경계를 넘는 CRLF — 1회용 승인을 `\n` 으로 다시 실행하지 못하게). BREAK 직후 5초 안의 첫 송신은 SysRq 가능성 때문에 최소 MODIFY 다.
    - **기기 준비 상태**: 부팅 중이거나, 줄 끝을 보낸 뒤 새 프롬프트가 아직 없거나(명령 실행 중), 마지막 프롬프트 뒤 재부팅·커널 시작 증거가 있으면,
      기기가 앞 글자를 소비·버릴 수 있다(`xsaveenv` 의 `x` 만 먹히면 `saveenv`). 그때 완성되는 비어 있지 않은 줄은 DESTRUCTIVE(`uart.device-busy`)이고, 남은 미완성 입력은 Ctrl-C 로 비울 때까지 uncertain 이다.
      한 `uart_write` 페이로드의 여러 줄은 첫 줄 뒤가 모두 이 규칙에 걸린다.
    - **모르는 직전 명령의 반복**: 이 세션이 줄을 보낸 적도 재부팅을 본 적도 없고 이어 받은 명령도 없으면, U-Boot 가 받을 수 있는 문맥의 빈 Enter 는 DESTRUCTIVE(`uart.repeat-unknown`)다.
      세션을 열기 전에 기기에서 실행된 명령(사람이 친 `mw` 등)을 모르기 때문이다. 같은 서버 프로세스에서 같은 케이스·포트를 다시 열면 앞 세션의 마지막 U-Boot 명령을 이어 받는다(`uart_open` 의 `inherited_last_command`. env 는 이어 받지 않음).
      코어 `classify_uboot("")` 는 직전 명령이 없으면 여전히 INTERACT(`uboot.empty`)이므로, 이 규칙은 uart 경로에만 있다.
    - `env run <var>`/`time <명령>` 은 안쪽 명령 기준으로 분류한다(코어에도 같은 규칙이 생겼지만 uart 경로의 보호가 남도록 이중으로 둔다). `run`·`boot`·`$var` 값 안과 빈 Enter 의 반복 대상에도 적용한다.
    - 문맥 오판 교차 검사: uboot 문맥의 줄도 리눅스로 해석해(DESTRUCTIVE 이거나 U-Boot 가 모르는 명령이면) worst 를 취한다.
      linux-shell 문맥에서는 리눅스가 모르는 명령, 인자가 주소·`$var`·`${var}` 모양인 `cp`/`mw` 같은 U-Boot 메모리 명령, `reset` 을 U-Boot 분류와 worst 로 본다.
    - login/password/booting/unknown 문맥의 일반 송신은 두 분류기의 worst 다(로그인 입력을 INTERACT 로 보는 경로는 `shell_login` 뿐). 수동 문맥(`uart_set_context`)은 자동 감지 문맥과 둘 다로 분류해 엄격한 쪽을 쓴다.
    - 문맥 추적(`tracker.py`)은 우리 입력의 에코와 보낸 텍스트를 그대로 되풀이한 출력(U-Boot `echo Linux version 9.9`)을 phase·부팅 증거로 쓰지 않는다.
      U-Boot 프롬프트로 본·학습한 문자열은 리눅스 증거만으로 linux-shell 로 올리지 않는다(unknown 유지).
- 게이트 사용법 (async 도구 안에서):

```python
cls = classify_console_line(line, session.context, uboot_ctx=session.uboot_ctx,
                            persistent_paths=rt.config.safety.persistent_paths,
                            unknown_risk=rt.config.safety.unknown_command_risk)
decision = await rt.authorize(tool="uart_send_command", action={"session_id": sid, "line": line},
                              classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx)
if not decision.allowed:
    return gate_response(decision)          # ok=false, status=approval_required|denied, approval_id, message
```

- `action` 딕셔너리는 재시도 시 정확히 같아야 한다 (승인 지문). 타임아웃·approval_id 같은 실행 옵션은 넣지 않는다.
- approve 정책일 때: 클라이언트가 elicitation 을 지원하면 확인 폼, 아니면 `approval_required` + approval_id →
  사람이 별도 터미널에서 `pweh approve <id>` → 에이전트가 같은 인자 + `approval_id` 로 재호출 (1회용, 만료 있음).
- 백그라운드 작업 안에서 명령을 보낼 때도 같은 분류기로 검사한다. 작업은 시작 시점에 계획된 명령 목록이
  모두 INTERACT 이하인지 확인하고, 아니면 시작을 거부한다.
  uart 덤프 job 은 보내는 명령마다 다시 분류하고(INTERACT 를 넘으면 `job_command_denied`), 케이스 소유/허가 증명도 명령마다 다시 확인한다(도중에 철회되면 `authorization_required` 로 멈춤).
- MODIFY 동작을 job 으로 돌릴 때(예: JTAGulator 스캔)도 이 규칙 안에서 한다. MODIFY 시작 입력(메뉴 키, 대화 답, 스캔 시작 스페이스바)은
  게이트를 통과한 **도구 호출 안에서** 보내고, job 은 출력을 감시하며 INTERACT 인 중단 키(JTAGulator 는 LF 1바이트)만 보낸다.
  job 은 시작 전에 이 계획이 INTERACT 이하인지 확인하고, 도구 호출과 job 의 모든 송신은 실제 장치 상태(수신 버퍼 끝의 프롬프트)로 다시 분류된다.
  다른 job 도 실행 중에 다시 검사한다: sigrok 은 프로세스를 띄우기 직전에 argv 를(캡처·디코드 모두), openocd 덤프 job 은 청크 명령마다 검사하고 INTERACT 를 넘으면 중단한다.
- 예외: pweh-esp 의 read-flash job 은 job 안에서 MODIFY 를 실행한다. esptool 프로세스가 읽기마다 다시 연결(리셋·스텁)하기 때문이다.
  그래서 게이트는 도구 호출 안에서 계획한 read-flash argv(MODIFY `esp.read-flash`)로 한 번 판단한다. 승인 지문에는 포트·칩·범위·`output_name`·`verify`·리셋 모드
  (실제 `after` 와 바꾸기 전의 `after_requested`, 1차 읽기의 `read1_after`·`read1_baud`)가 들어가고,
  `modify_policy: approve` 면 승인 한 번이 이중 읽기 두 번을 모두 덮는다. 출력 경로를 예약한 뒤에는 읽기마다 실제 argv 를 다시 분류한다.
  job 은 esptool 을 띄우기 직전마다 그 argv 를 다시 분류해 정확히 MODIFY `esp.read-flash` 가 아니면 멈추고(`safety_denied`), 케이스 소유/허가도 다시 확인한다(철회되면 `authorization_required`).
  계획 밖의 명령은 보내지 않는다.
- 이 분류기는 협조적이지만 성급한 에이전트의 실수를 막기 위한 것이며 적대적 우회를 완벽히 막는 샌드박스가 아니다.
  강한 격리가 필요하면 MCP 서버를 별도 OS 계정으로 실행한다 (docs/safety.md).

게이트 밖의 공통 안전 기능 셋(사람 증명·출처 원장·비밀값 마스킹)은 코어에 있고, 아래처럼 쓴다.

- **사람 증명(attestation)** — `src/pweh/safety/attestations.py`. 사람만 확인할 수 있는 사실(콘솔 오프라인, 결제 수단 제거, 배선 = 채널 라벨과 잰 전압,
  태그의 목적·소유, 쓰기 방지 장치, 가져온 파일의 출처 …)이나 물리 부작용이 있는 MODIFY 의 전제 조건을 에이전트가 스스로 채우지 못하게 한다.
  승인(1회 소비, 짧은 만료)과 달리 **소비되지 않고** 대상·바인딩·만료에 묶여 재사용된다.
  **아직 증명을 요구하는 도구는 없다.** 코어(저장소, `rt().attest`, `pweh attest`)만 있고, 그런 사실이 필요한 서버를 만들 때 쓴다.
  - 레코드: `.pweh/state/attestations/att-<16진 10자>.json`(`pweh.attestation/v1`). `kind` 는 닫힌 집합이다(`tag-purpose`, `wiring`, `console-offline`,
    `payment-locked`, `hdmi-source`, `bridge-serial`, `write-blocker`, `provenance-import`, `instrument-pin`, `radio-target`, `module-kc` — 코드에서만 늘린다).
    `subject`(서버가 만든 정규화 JSON + `subject_sha256`), `binding{scope: case|connection|job|instrument, case_id|connection_id|job_id|instrument_id}`, `fingerprint`,
    `questions[{id, text, type: yesno|value, expected?: yes}]`, `answers`(y/n 과 사람이 직접 입력한 값), `status`(pending|approved|denied|revoked|expired),
    `valid_seconds`, `expires_at`, `decided_via`(cli-tty|elicitation), `decided_by`, `decided_at`, `revoked_at`, `requested_by{server, tool}`, `created_at`.
    지문 = sha256(정규화 JSON `{kind, subject, binding}`). `expired` 는 읽을 때 계산하는 상태다(파일은 바꾸지 않는다).
  - 서버 사용법 (async 도구 안에서):

    ```python
    from pweh.safety import attestation_response

    dec = await rt().attest("console-offline", {"console": serial}, {"scope": "case", "case_id": case.id}, questions,
                            case.id, ctx, "콘솔 오프라인 확인", tool="input_connect")
    if not dec.satisfied:
        return attestation_response(dec)    # ok=false, status=attestation_required|denied, attestation_id, kind, questions, how, message
    ```

    `rt().attest` 는 `AttestationDecision` 을 돌려준다(충족이면 `dec.record` 가 증명 레코드).
    안에서 `require(kind, subject, binding, questions=…)` 로 승인·미만료·미철회 레코드를 찾는다(소비하지 않음. 서버가 지금 묻는 질문을 모두 받은 레코드만).
    없으면 pending 을 만들고(같은 지문에 같거나 더 많은 질문을 묻는 pending 은 재사용), 클라이언트가 지원하면 elicitation 폼(항목마다 답 + 4자리 확인 코드)을 띄운다.
    그 밖에는 `attestation_required` → 사람이 별도 터미널에서 `pweh attest <id>`(TTY 전용) → 에이전트가 같은 인자로 다시 호출한다(증명 id 를 넘기지 않는다).
    확인 경로는 `safety.approval_methods` 를 따른다(새 설정 키 없음). 두 경로를 모두 쓸 수 없거나 사람이 폼을 거절·취소하면(확인 코드가 틀려도) `denied` 다.
    폼 표시 자체가 실패하면(오류·시간 초과) pending 그대로 CLI 경로로 넘어간다(`cli` 가 켜져 있을 때).
    pending 은 `approval_ttl_seconds` 뒤 만료된다. 승인 뒤 유효 기간은 범위별 코드 기본값이다
    (case 7일, connection 12시간, job 24시간, instrument 는 철회할 때까지. 서버가 `valid_seconds` 로 60초~90일을 줄 수 있다).
    `valid_seconds` 는 **새로 만드는 레코드**에만 적용된다 — 같은 지문의 기존 레코드(승인·대기)는 그 레코드의 만료를 따르므로, 더 최근의 확인이 필요하면 바인딩을 좁힌다(연결 토큰·job).
  - 확인 항목: `expected: "yes"` 가 없는 yesno 는 정보 항목이라 '아니오'여도 승인된다. 값 항목은 비어 있지 않으면 충족이고 범위·형식은 검사하지 않는다
    — 서버가 `dec.record["answers"]` 로 직접 검사한다.
  - 증거는 `.pweh/state/attestations/` 의 레코드뿐이다. subject 는 서버 자신의 스캔·측정 결과로 만든다. 에이전트가 넘긴 `attested_*` 인자, 케이스 파일,
    `cases/<id>/attestations.json`(사람이 보는 읽기 전용 사본 — 보고서 생성기는 아직 읽지 않는다), 승인 id(`ap-…`)는 증거가 아니다. subject·binding 의 최상위 `attested*` 키는 지문에서 빠진다
    (`ignored_agent_fields`). `require` 는 후보마다 schema·id 형식·파일 이름·kind·지문(다시 계산)·상태·만료·철회·`decided_via`·답을 다시 확인한다.
  - 무효화: 만료, 사람의 철회(`pweh attest --revoke <id>`), 바인딩 변화(연결 토큰·job·케이스가 바뀌면 지문이 다르다), 서버가 질문을 늘림.
  - 사람 쪽 명령: `pweh attest <id>`(항목마다 답), `pweh attest --list`(기본 대기 중만, `--all` 이면 모든 상태), `pweh attest --revoke <id>`.
    모두 대화형 터미널 전용이다(TTY 가 아니면 아무것도 보여 주지 않고 종료 코드 2). 승인이 되는 답이면 기록하기 전에 화면의 4자리 확인 코드를 입력받는다(`pweh approve` 와 같은 수준).
    결정은 `decided_via: "cli-tty"`, `decided_by` = OS 계정 이름(실제 uid 기준, `$USER` 가 아님)으로 남는다(폼으로 답하면 `elicitation`·`client-user`).
    증명을 결정하거나 조회하는 MCP 도구는 없다(`approval_status` 는 승인 `ap-…` 만 본다). 이름이 비슷한 `pweh case attest <case_id>` 는 케이스 소유/허가 증명이다.
- **출처 원장(provenance)** — `src/pweh/provenance.py`, `.pweh/state/provenance/<case_id>.jsonl`(0600). 한 줄 = 정규화 JSON
  `{schema, seq, ts, case_id, kind, path, sha256, size, source{server, tool, 장치 식별…}, attestation_id, extra | fact_kind + data, prev}`.
  `prev` 는 앞 줄 정규화 JSON 의 sha256 이다(첫 줄은 케이스 id 에 묶인 시작값). 여러 서버 프로세스가 파일 잠금 안에서 체인을 검증한 뒤 덧붙인다(깨진 원장에는 덧붙이지 않는다).
  출처 확인은 `case.json` 아티팩트의 `producer`(에이전트가 자유롭게 넘기는 값)를 보지 않고 이 원장만 본다.
  - kind 와 기록하는 곳: `device-read`(기기 읽기 코드 경로만 — 지금은 `esp_read_flash_start` 가 끝까지 성공(`succeeded`)한 덤프의 읽기 파일. 이중 읽기면 두 파일이고,
    실패·취소 때 보존한 1차 읽기는 기록하지 않는다), `device-fact`(`esp_chip_info`·`esp_security_info` 결과. data 를 원장에 그대로 둔다), `imported-unattested`(`case_import_file`).
  - `verify(case, path)` → `{trusted, kind, record, reason, path, sha256}`: 체인 전체를 검증하고(하나라도 깨지면 모두 불신 — `ledger-chain-broken`), 그 경로의 마지막 항목과
    지금 파일의 sha256 을 맞춘다(`sha256-mismatch`. 그 밖의 불신 이유는 `not-recorded`, `file-missing`). `device-read` 는 신뢰하고, `imported-unattested` 는 `provenance-import` 증명
    (같은 sha256·같은 케이스 — `provenance_import_target`, `PROVENANCE_IMPORT_QUESTIONS`)이 있을 때만 신뢰한다(`imported-attested`).
    `device-read` 는 출처(기기에서 읽음)이지 무결성이 아니다 — 이중 읽기가 어긋난 덤프(`source.match=false`)는 기록하지만 `verify` 는 신뢰하지 않는다(`device-read-mismatch`).
    검증하지 않은 단일 읽기(`match=null`)는 출처로 신뢰하므로, 무결성이 필요한 쪽(패치 base 등)은 `record.source.verify` 를 따로 확인한다.
  - 확인과 사용 사이에 에이전트가 케이스 파일을 바꿀 수 있다. 쓰는 쪽은 `verify` 가 돌려준 sha256 을 승인 지문·job 인자에 묶고, 실행 직전 같은 sha256 인지 다시 해시하거나 확인한 바이트를 그대로 쓴다.
    **아직 `verify` 를 부르는 도구는 없다.** 출처가 중요한 작업(에뮬레이션·올리기·패치 base·계측기 플래시 절차)을 만드는 서버가 이 함수로 확인한다.
  - 기록 실패는 기기 결과를 막지 않는다. 응답의 `provenance: {recorded: false, reason}` 로 알리고(덤프는 job `result.warnings` 에도), 원장에 없는 파일은 불신이다(fail closed).
  - 한계: 해시 체인과 증명 레코드의 재확인에는 비밀 키가 없다. 실수와 단순 변조를 드러낼 뿐, 같은 OS 계정의 프로세스가 원장 전체를 일관되게 다시 쓰거나,
    올바른 `prev` 로 끝에 줄을 덧붙이거나, 레코드를 처음부터 위조하는 것은 막지 못한다(docs/safety.md §3.5). 보호 상태는 케이스 id 로만 묶인다
    — 사람이 `cases/<id>` 를 지운 뒤 같은 id 로 케이스를 다시 만들면 예전 원장·증명·솔트를 이어받는다.
  - `case_import_file` 은 state_dir 안의 파일을 가져오지 않는다(보호 상태를 케이스로 복사해 읽어 내지 못하게). 대상은 `O_EXCL` 로 새로 만든다(같은 이름의 파일·링크가 있으면 거부).
- **비밀값 마스킹** — `src/pweh/safety/masking.py`. 게이트 `action` 과 `classification.matched` 에는 원문 대신 `rt().secret_digest(case_id, 값)`
  (`sha256:` + sha256(케이스 솔트 ‖ 값)의 앞 16 hex) 또는 `<given>` 만 넣는다. 그러면 승인 지문·감사 로그·승인 레코드·`approval_status` 응답에 원문이 남지 않는다.
  같은 케이스의 같은 값은 늘 같은 다이제스트라 재시도 지문이 맞고, 케이스가 다르면 달라진다. 증명 subject 에 비밀이 들어가야 할 때도 다이제스트를 쓴다.
  응답·보고서에는 `mask_secret(값)` 을 쓴다(16자 이상은 앞뒤 2자와 길이, 10–15자는 앞뒤 1자와 길이, 더 짧은 값과 바이트는 길이만).
  솔트는 `.pweh/state/salts/<case_id>.key`(32 바이트, 0600, 처음 쓸 때 만들고 바꾸지 않는다)다.
  게이트 `action` 에 비밀을 넣도록 설계된 도구는 `shell_login`(비밀번호 → `<given>`) 하나이고, 다이제스트를 쓰는 도구는 아직 없다.
  비밀번호 프롬프트에 `uart_send_command` 로 입력하면 원문이 게이트 작업 내용과 감사 로그에 남는다 — 로그인은 `shell_login` 으로 한다.
  - 한계: 솔트는 같은 OS 계정의 에이전트가 읽을 수 있다(파일 도구, 자동 허용된 REA `open_binary` + `read_bytes`). 다이제스트는 보고서·감사 로그를 읽는
    제3자에게서 원문을 가리지만, 에이전트에게서 낮은 엔트로피 값(짧은 PIN, 32비트 PWD_AUTH, 24–32비트 ID)을 가리지는 못한다 — 그런 값은 게이트에 넣지 않는다(`<given>`).

## 5. 코딩 규칙

- Python 3.10 호환 (`match` 문 사용 금지 아님, 하지만 `typing.Self`, `tomllib` 사용 금지). 외부 의존성은 `mcp`, `pyserial`, `PyYAML`, `jsonschema` 와 표준 라이브러리만.
- 주석·docstring·도구 설명은 **한국어**, 식별자와 기술 용어는 영어. 도구 이름은 영어 snake_case.
- 서버 구조는 참조 구현 `mcp-servers/case-mcp/case_mcp/server.py` 를 따른다:
  - `server = create_server(NAME, title=..., instructions=...)` (`pweh.mcpkit`)
  - `def rt() -> Runtime: return get_runtime(NAME)`
  - 도구: `@server.tool(description=..., annotations=ANN_*)` 다음 줄에 `@safe_tool`
  - 기기에 영향을 주는 도구는 `async def ...(..., ctx: Context)` 이며 블로킹 I/O 는 `await run_blocking(fn, ...)`.
  - 반환은 항상 `dict` (`{"ok": True, ...}`), 오류는 `PwehError` 계열 예외 (`pweh.errors`) — `safe_tool` 이 ToolError 로 변환.
  - 오래 걸리는 작업: `rt().jobs.start(kind, fn, description=..., case_id=..., exclusive_key="port:/dev/ttyUSB0")` 후
    `register_job_tools(server, rt, prefix)` 가 만든 `<prefix>_job_status` 로 폴링.
  - `def main(): server.run()` + `__main__.py`.
- stdout 은 MCP 프로토콜 채널이다. `print()` 금지, 로그는 `logging.getLogger("pweh.<server>")` (stderr).
- 외부 도구 경로는 설정(`rt().config.tool_path("sigrok_cli")` 등)과 환경변수(`PWEH_SIGROK_CLI`, `PWEH_OPENOCD`)로 찾는다.
  없으면 `ToolMissing` 예외 + 설치 힌트.
- 모든 subprocess 는 타임아웃을 두고, 인자 리스트(쉘 문자열 금지)로 실행한다.

## 6. 서버별 도구 계약

표기: `이름(인자...) → 반환 핵심 필드`. 모든 반환에는 `ok` 가 있다. 하드웨어 도구는 모두 `case_id` 를 받는다.

### 6.1 pweh-case
`case_create(title, authorization, target?, profile?, case_id?, notes?)`, `case_set_authorization`, `case_list`, `case_get(case_id, include_artifacts?, include_steps?)`,
`case_update_target`, `case_set_phase`, `case_add_note`, `case_paths(case_id, purpose, label) → new_output_dir`,
`case_record_step(case_id, skill, step, status, summary, data?, artifacts?, next_actions?, blockers?, started_at?)`,
`case_get_step_results(case_id, skill?, summaries_only?)`, `case_register_artifact`, `case_import_file(case_id, source_path, kind?, dest_subdir?, description?)`,
`case_hash_file(case_id, path, offset?, length?) → sha256, md5, crc32` *(추가)*,
`case_add_finding(case_id, finding)`, `case_update_finding`, `case_list_findings`, `report_generate(case_id)`,
`pipeline_profiles`, `pipeline_profile(name)`, `pipeline_safety_policy`, `approval_status(approval_id)`, `approvals_pending`, `schema_get(name)`.

- `case_hash_file` 은 케이스 안 파일(또는 `offset`/`length` 구간, 정수 또는 `"0x50000"`·`"64k"`)의 해시를 계산한다. 덤프 교차 검증용이다:
  tftpput·SPI 클립으로 받은 파일과 UART 덤프의 같은 구간 비교, 기기 측 `md5sum`/`crc32` 값과 대조.
- `case_import_file` 은 가져온 파일을 출처 원장에 `imported-unattested` 로 기록하고 응답에 `provenance{recorded, kind: "imported-unattested", seq, sha256, note}` 를 붙인다(§4).
  기록에 실패하면 `recorded: false` 와 `reason` 이고 가져오기는 그대로 된다. 이 서버에는 기기 읽기(`device-read`)로 기록하는 경로가 없다.
- `case_set_phase` 는 단계 이름을 검사하지 않는다(파이프라인 단계와 선택 단계 — §3).
- 사람 증명(`att-…`)을 결정하거나 조회하는 도구는 없다. `approval_status`·`approvals_pending` 은 승인만 본다(증명은 사람이 `pweh attest` 로 — §4).
- 도구별 설명과 기본값 전체: `mcp-servers/case-mcp/README.md`, `docs/references/pweh-mcp-tools.md`.

### 6.2 pweh-uart
세션은 서버 프로세스 메모리에 유지되며, 포트당 백그라운드 수신 스레드가 링 버퍼(기본 4 MiB, `uart.read_buffer_bytes`) + 로그 파일에 계속 기록한다
(도구 호출 사이에 도착한 출력도 잃지 않는다). 수신 커서는 RX 누적 바이트 오프셋이다. 세션 id 는 `<label 또는 uart>-NNN` 이다.
서버가 재시작되면 세션이 사라지므로 다시 연다(덤프는 같은 인자로 다시 부르면 `.state.json` 에서 이어받는다).
기기로 가는 모든 바이트는 `uart_mcp.guard`(§4)로 분류한 뒤 게이트를 거친다. "내용대로" 는 보내는 줄의 분류 결과가 위험도라는 뜻이다.
아래 시그니처는 실제 인자와 기본값 전체다(설명 원문: `docs/references/pweh-mcp-tools.md`, 동작 상세: `mcp-servers/uart-mcp/README.md`).

| 도구 | 설명 / 반환 |
|---|---|
| `uart_list_ports(include_links=False)` | OBSERVE. `ports[{device, description, hwid, vid, pid, serial_number, manufacturer, likely_usb_uart, in_use_by}]`, `count`(없으면 `hint`). `include_links=true` 면 `/dev/serial/by-id/…` 링크도 넣는다. TCP 시리얼(ser2net, 시뮬레이터)은 목록에 없으니 `uart_open` 에 `socket://host:port` 로 준다 |
| `uart_open(case_id, port, baudrate=115200, bytesize=8, parity="N", stopbits=1, line_ending="\r", dtr=False, rts=False, profile=None, label=None, approval_id=None)` | INTERACT(`dtr`/`rts`=true 면 MODIFY — 리셋·부트모드 핀일 수 있음). `session_id, log_path, raw_path, events_path`(케이스 상대), `context`, `cursor`. `port` 는 장치 절대경로(이미 있으면 문자 장치여야 함) 또는 pyserial URL(`socket://`, `loop://`, `rfc2217://`)이고 장치 경로는 flock 으로 독점한다. 다른 pyserial URL(`spy://` — 포트 이름만 정해도 호스트 파일을 덮어씀, `hwgrep://` — 임의 포트를 잠금 없이 열어 봄 등), 상대 경로, 일반 파일, (Windows 가 아닌 곳의) `COMn`, 제어 문자는 게이트 전에 `validation_failed` 다(`uart_detect_baud` 도 같다). DTR/RTS 는 열기 **전에** 설정하며 기본 False 로 두어 보드 리셋을 피한다. `profile`(생략 시 케이스 프로필)이 프롬프트·autoboot 정규식과 인터럽트 키를 정한다. U-Boot 를 받을 수 있는 문맥에서는 `line_ending` 과 무관하게 `\r` 만 보낸다(`\r\n` 은 명령 + 빈 줄 = 반복). 그 밖의 반환: `port`, `baudrate`, `framing`, `line_ending`, `dtr`, `rts`, `profile`, `phase`, `artifacts`, `next_steps`, `socket://` 면 `note`(보드레이트를 전달하지 않음). 같은 서버 프로세스에서 같은 케이스·포트의 앞 세션이 U-Boot 명령을 보낸 뒤 닫혔으면 그 명령을 `inherited_last_command` 로 돌려주고 이 세션의 직전 명령으로 삼는다(빈 Enter = 그 명령의 반복. env 는 이어 받지 않음). 없으면 새 세션의 빈 Enter 는 `uart.repeat-unknown`(DESTRUCTIVE, §4) |
| `uart_close(session_id)` | 정리 작업이라 게이트 없음. 실행 중인 job 취소 → 수신 스레드·포트 정지 → 로그 3종(`uart-log`/`uart-raw`/`uart-events`) 아티팩트 등록 → `rx_bytes`, `tx_bytes`, 로그 경로, `artifacts`, `job_cancelled`. 끊어진(`disconnected`) 세션도 닫는다 |
| `uart_sessions(case_id=None)` | OBSERVE. `sessions[{session_id, case_id, port, state(open/disconnected), context, auto_context, manual_context, phase, boot_stage, prompt, learned_prompts, rx_bytes, tx_bytes, pending_input, pending_uncertain, device_ready, device_busy_reason, uboot_env_tracked, env_source, last_uboot_command, job_id, log_path, …}]`, `count`. `device_ready=false` 면(`device_busy_reason`: 부팅 중, 명령 실행 중 등) 지금 보내는 줄은 `uart.device-busy` 로 거부되니 프롬프트를 기다리거나 `uart_sync` 한다. `pending_uncertain` 이면 남은 미완성 입력을 `uart_sync` 로 비운다 |
| `uart_read(session_id, since_cursor=None, max_bytes=8192, wait_seconds=0, tail=False)` | OBSERVE. `text`(CRLF→LF 정규화. 원시 바이트는 `uart/<session>.raw`), `bytes`, `cursor_start`, `cursor_end`, `more`, `context`, `prompt`, `state`, 요청한 커서 앞부분이 링 버퍼에서 밀려났으면 `lost_bytes`·`note`. `since_cursor` 생략 시 에이전트 읽기 위치(직전 `uart_read`/명령의 `cursor_end`)부터. `wait_seconds` 최대 50 |
| `uart_write(session_id, data, encoding="text"\|"hex", approval_id=None)` | 내용대로. 원시 쓰기(최대 4096 바이트). 완성되는 줄마다 `uart_mcp.guard` 로 분류하고 제어 문자는 `CONTROL_CHAR_RISK`. 한 페이로드의 여러 줄은 첫 줄 뒤가 모두 DESTRUCTIVE(`uart.device-busy` — 기기가 앞 줄을 실행하는 동안 보낸 입력), 상위 비트 바이트가 섞인 줄은 DESTRUCTIVE(`uart.high-bit`). 줄을 보내기 전에 프롬프트가 곧 돌아오는지 최대 0.5초 기다린다(Ctrl-C 같은 제어 문자만이면 기다리지 않음) → `bytes_written`, `cursor`, `plan`(줄별 분류), `context`, 줄 끝 없이 남으면 `pending_input`·`note`. 일반 명령은 `uart_send_command` 를 쓴다 |
| `uart_send_command(session_id, command, timeout=10, expect=None, approval_id=None, max_output=20000)` | 내용대로. 한 줄 + 줄끝 전송 후 에코 다음의 프롬프트(또는 `expect` 정규식 — 에코 줄 뒤에서 줄마다 `^$` 적용, CR 은 LF 로 취급)까지 대기 → `output`(에코·프롬프트 제거), `matched`, `match`, `match_kind`, `timed_out`(오류 아님), `context`, `prompt`, `cursor_start`/`output_start`/`output_end`/`cursor_end`(긴 출력은 이어서 `uart_read`), `elapsed_seconds`, `classification`, 잘렸으면 `output_truncated`. `command` 에 줄바꿈은 넣을 수 없다(한 호출에 한 줄). 보내기 전에 프롬프트를 최대 0.5초 기다린다. `timeout` 최대 600초(클라이언트 제한 고려). U-Boot 에서 빈 `command` 는 직전 명령 반복으로 분류된다 — 새 프롬프트는 `uart_sync`. `setenv baudrate …` 를 보내면 `warning` 으로 다음 절차를 알려 준다: 같은 서버 프로세스에서 `uart_close` → 새 속도로 `uart_open`, 응답에 `inherited_last_command` 가 있을 때만 `uart_write("\r")`, 없으면 사람에게 전원 재투입. 로그인은 `shell_login` |
| `uart_wait_for(session_id, pattern, timeout=30, since_cursor=None)` | OBSERVE(아무것도 보내지 않음). 정규식 대기(줄마다 `^$`, 호출 사이에 온 출력 포함. 끝나지 않은 줄 끝에 닿은 매치는 줄이 끝나거나 60 ms 조용해질 때까지 보류) → `matched, match, groups, text`(최대 8000자, 넘으면 `text_clipped`), `cursor_start`, `match_start`, `cursor_end`, `timed_out`, `context`, `state`, 끊기면 `disconnected`. `timeout` 최대 600초 |
| `uart_set_context(session_id, context, prompt=None)` | 송신 없음. `uboot`/`linux-shell`/`login`/`password`/`booting`/`unknown` 수동 지정, `auto` 는 해제. `prompt` 는 `uboot`/`linux-shell` 의 특이한 프롬프트 문자열을 학습시킨다. 분류는 수동·자동 문맥 둘 다로 해서 엄격한 쪽을 쓰므로 수동 지정으로 **완화할 수 없고**, 재부팅·phase 변화 증거가 나오면 수동 지정이 풀린다. `uboot` 프롬프트로 학습한 문자열은 이후 리눅스 증거만으로 linux-shell 이 되지 않는다(지워지지 않음) → `context`, `manual_context`, `auto_context`, `phase`, 수동·자동이 다르면 `warning` |
| `uart_sync(session_id, timeout=3, approval_id=None)` *(추가)* | INTERACT. Ctrl-C(0x03) 한 번으로 새 프롬프트와 문맥 증거를 얻고(U-Boot 는 `<INTERRUPT>` 출력) 미완성 입력(uncertain 표시 포함)을 비운다. U-Boot 프롬프트를 깨울 때 빈 Enter 대신 쓴다 → `context`, `prompt`, `prompt_kind`, `evidence`(`uboot`/`linux`/`null`), `reply`, `timed_out`(부팅·명령 실행 중이면 `hint`), `cursor_end` |
| `uart_send_break(session_id, duration=0.25, approval_id=None)` | MODIFY. BREAK 전송(`duration` 최대 2초). 이후 5초 안의 첫 송신은 리눅스 Magic SysRq 가능성 때문에 최소 MODIFY → `duration`, `sysrq_window_seconds`. 지원하지 않는 포트는 `status: "unsupported"` |
| `uart_set_signals(session_id, dtr=None, rts=None, approval_id=None)` | MODIFY(보드 리셋 가능). → `dtr`, `rts`. PTY·`socket://` 처럼 신호가 없는 포트는 `status: "unsupported"` |
| `uart_detect_baud(case_id, port, candidates=None, listen_seconds=2.5, probe="ctrl-c"\|"none", approval_id=None)` | `probe="ctrl-c"` 는 **MODIFY**(다른 속도로 보낸 0x03 은 기기에서 다른 바이트로 읽힐 수 있음), `probe="none"` 은 INTERACT. 후보마다 포트를 열고(DTR/RTS 끔) 읽은 데이터를 점수화(출력 가능 문자 비율, 부팅 키워드, 0x00/0xFF 연속 감점) → `candidates`(점수순), `best`, `confidence`, `tested`, `elapsed_seconds`, `port`, `probe`, `listen_seconds`, `hint`(데이터 없음: TX/RX·GND·무출력·전압), 시간 제한으로 일부만 시험했으면 `truncated`. 기기가 출력 중이어야 하므로 부팅 출력을 듣는다: 사람에게 전원을 먼저 꺼 두게 하고 '준비' 답을 받은 뒤 호출하며, 사람은 호출이 시작되면 전원을 넣는다. 부팅 중에 Ctrl-C 프로브가 맞는 속도로 닿으면 autoboot 가 멈출 수 있으니 이때는 `probe="none"` 을 쓴다. 이 포트로 열린 세션이 없어야 하고 총 50초 제한 |
| `uart_capture_boot(session_id, duration=30, until=None, stop_on_prompt=True)` | OBSERVE(아무것도 보내지 않아 게이트는 없고 케이스 소유/허가만 확인). 사람에게 전원을 먼저 꺼 두게 한 뒤 호출하고, 호출이 시작되면 사람이 전원을 넣는다. `duration`(최대 300초) 또는 `until` 정규식까지 수집한다. `stop_on_prompt=true` 면 이 창에서 부팅이 시작된 뒤 로그인/셸/U-Boot 프롬프트가 나오고 1.5초 조용할 때 멈춘다. 파싱 결과 `uboot_version`, `autoboot_message`, `bootdelay`, `kernel_version`, `cmdline`, `mtdparts`, `partitions`, `login_prompt`, `shell_prompt`, `flash`, `flash_write_warnings`, `stages`. 그 밖에 `captured_bytes`, `stopped_by`(`until`/`duration`/`prompt:<종류>:<문맥>`/`disconnected`/`cancelled`), `cursor_start`/`cursor_end`, `excerpt_path`(발췌 `uart/<session>-boot-NN.log`, `uart-log` 아티팩트로 등록), `text_tail`(끝 3000자), `context`, 데이터가 없으면 `hint`, 플래시 쓰기 징후가 보이면 `warning` |
| `uboot_interrupt(session_id, keys=None, window_seconds=30)` | INTERACT(보낼 키 계획의 분류값). 사람에게 기기 전원을 **먼저 꺼 두게** 하고 '준비' 답을 받은 뒤 호출한다. 사람은 호출이 시작되면 전원을 넣는다(도구가 먼저 감시를 시작해야 한다). 부팅 출력(또는 autoboot 메시지)이 보이면 인터럽트 키(`keys` 또는 프로필 `interrupt_sequences`, generic-ipcam 기본 Ctrl-C. 빈 Enter 는 새 부팅을 본 뒤에만 보내고 프롬프트가 수신 끝에 있으면 보내지 않음)를 약 50 ms 마다 보내고, U-Boot 프롬프트가 나오면 멈춘 뒤 Ctrl-C 로 깨끗한 프롬프트를 받는다. 호출 시점에 이미 부팅 중·리눅스 실행 중이던 기기의 이전 출력은 판단에 쓰지 않고 창 동안 새 부팅을 기다린다(그동안 리눅스에 키를 보내지 않음, `autoboot_silent` 프로필 제외). 커널 시작 전의 `Password:` 는 부트로더 잠금이라 키 송신을 멈춘다 → `interrupted, outcome`(`prompt`/`uboot_password`/`linux`/`kernel`/`window_expired`/`cancelled`/`disconnected`), `new_boot_seen`(호출 뒤 새 부팅을 봤는지), `prompt`, `autoboot_message`, `bootdelay`, `keys_used`, `keys_sent`, `boot_output_bytes`, 건너뛴 키는 `skipped_keys`, 이미 U-Boot 프롬프트였으면 `already_at_prompt`, 실패 시 `explanation`(무출력, 보드레이트, 늦은 키·keyed/무음 autoboot, 부트로더 비밀번호 잠금, 이전 부팅 출력만 봄, 리눅스 도달). `window_seconds` 최대 120 |
| `uboot_printenv(session_id)` | INTERACT. `env{}`, `count`, `bootargs`, `bootcmd`, `bootdelay`, `mtdparts`, `partitions[{name, offset, size}]`, `flash_size`/`flash_size_source`(`-`(나머지 전체) 파티션 크기 계산에 쓴 값과 출처: `uboot_info` 의 sf probe 또는 이 세션이 본 부팅 로그. 모르면 `null` 이고 그 파티션 `size` 도 `null` + `note`), `loadaddr`, `load_addresses`, `environment_size`, `complete`/`tracked`. 출력이 완전할 때(`Environment size` 줄)만 세션의 env 추적에 반영한다(`run`/`boot` 분류의 기준, 아니면 `warning`). `uboot_info` 보다 먼저 부른다 |
| `uboot_info(session_id, probe_flash=True)` | INTERACT(명령마다 게이트). `version`, `bdinfo{dram_start, dram_size, relocaddr, sp_start, …}`, `commands[]`, `has{}`(help 목록 기준 사용 가능 여부. U-Boot 약어 규칙(유일한 접두어)으로만 되는 것은 `has_via{}` 에 실제 명령 이름. help 를 파싱하지 못하면 `null` = 모름이며 `false` 가 아니다), `partitions[]`(추적 env 의 mtdparts, `-` 는 플래시 크기로 채움), `flash{type, model, size_bytes, …}`(`probe_flash=true` 면 `sf probe 0`. 크기를 찍지 않는 칩은 `size_bytes: null` 이고 부팅 로그 사실이나 mtdparts 합 `size_bytes_lower_bound` 로 보완), `safe_ram_addr`·`ram_window`(DRAM 안에서 U-Boot 자신(relocaddr/malloc/스택)과 하위 1 MiB 를 피한 주소, env `loadaddr`·bootcmd 의 `sf read` 주소 우선), `safe_ram`, `boot_facts`, `notes`. help 에 `sf` 가 없으면 sf probe 를 건너뛴다 |
| `uboot_dump_start(case_id, session_id, offset, length, source="sf"\|"nand"\|"mmc"\|"ram", ram_addr=None, chunk_size=65536, output_name=None, verify="crc32"\|"double"\|"none", resume=True, retries=3, final_check=True, sf_probe="0")` | INTERACT · job. 시작 응답 `status: "started"`, `job_id`, `output`, `part_path`(`dumps/<name>.bin.part`), `state_path`, `metadata_path`, `chunks`, `chunk_size`, `ram_addr`, `resume_from_chunk`, `estimated_seconds`(현재 보드레이트·프레이밍 기준 예상 시간), `notes`. 청크마다 `sf read`(nand: `nand read`, mmc: `mmc read` 512 B 블록, ram: 적재 없이 `offset` 이 RAM 주소) → `md.b` 파싱·검증(주소 연속성/바이트 수) → `crc32` 비교, 실패 청크는 `retries` 번 재시도(Ctrl-C 로 프롬프트 회복). `verify="double"` 은 같은 범위를 두 번 읽어 비교하며 기기에 `crc32` 가 없으면 자동으로 바뀐다. 완료 시(`final_check=true` 이고 전체가 RAM 창에 들어가면 전체 범위를 한 번 더 대조) sha256 + `dumps/<name>.json` + 아티팩트(`flash-dump`/`memory-dump`). `offset`/`length`/`chunk_size`/`ram_addr` 는 정수 또는 `"0x50000"`·`"64k"`·`"16M"`, `chunk_size` 최대 256 KiB. `ram_addr` 생략 시 `uboot_info` 의 `safe_ram_addr`. 주소가 DRAM 밖이거나 U-Boot 영역을 침범하면 거부하지만, `uboot_info` 를 부르지 않아 DRAM 범위를 모르면 직접 준 `ram_addr` 은 검사하지 못하고 `notes` 에 그렇게 적는다. `source="sf"` 이고 플래시 크기를 알면 범위가 크기를 넘을 때 거부한다. `sf_probe` 는 덤프 전에 보내는 `sf probe` 인자(`null` 이면 생략) |
| `shell_login(session_id, username=None, password=None, timeout=15)` | INTERACT(마스킹 로그인 경로). askfirst(`Please press Enter`)면 Enter, `login:` 이면 username, `Password:` 면 password 를 그 프롬프트가 수신 끝에 보일 때만 보낸다. `username` 을 생략하면 askfirst 콘솔 활성화만 한다(로그인 없는 콘솔. `login:` 이 나오면 `username_required`). 비밀번호는 `.log`·이벤트·감사 기록·승인 지문에서 마스킹된다. 사용자가 알려 준 계정만 쓰고 세션당 3회 실패하면 더 시도하지 않는다(`login_attempts_exceeded`) → `logged_in`, `status`, `prompt`, `steps`, `context`, `elapsed_seconds`, `cursor_end`, 실패 시 `message`/`hint`, 성공 시 `banner` 와 `user`(이번 호출이 username 을 보냈을 때만). `status`: `ok`, `already_logged_in`, `password_required`, `username_required`(카운트하지 않음), `login_incorrect`, `login_failed`(같은 프롬프트가 다시 나옴), `context_unknown`(U-Boot 일 수 있는 프롬프트 — 아무것도 보내지 않고 phase 증거도 넣지 않음 → `uart_sync`), `uboot_prompt`, `uboot_password_prompt`(커널 시작 전 `Password:` = 부트로더 잠금, 아무것도 보내지 않음 — 추측 금지), `stuck_askfirst`, `unknown_prompt`, `timeout`, `disconnected`, `cancelled` |
| `shell_identify(session_id)` | INTERACT(읽기 전용 명령 묶음, 명령마다 게이트). `uname`, `kernel_version`, `arch`, `hostname`, `cpu`·`cpuinfo`, `mtd[]`(/proc/mtd 파싱), `cmdline`(`mtdparts` → `partitions`), `mounts`, `processes`, `listening`, `busybox`(버전)·`busybox_applets`, `user`(`id`), `has_base64`/`has_hexdump`/`has_md5sum`, `missing_commands`. linux-shell 문맥이 아니면 거부 |
| `shell_dump_start(case_id, session_id, path, offset=0, length=None, method="auto"\|"hexdump"\|"base64", chunk_size=65536, output_name=None, resume=True, retries=3)` | INTERACT · job. 청크마다 `dd … 2>/dev/null \| base64`(없으면 `\| hexdump -C`) 출력을 파싱하고 같은 범위의 `\| md5sum` 과 비교(기기에 `md5sum` 필요), 실패 청크는 재시도. `path` 는 절대 경로(문자 `[A-Za-z0-9_./+-]`, `..` 금지)이고 `/dev/` 아래는 저장장치만 읽는다: `mtdN`(`mtdNro`), `mtdblockN`, `mmcblkN`·`mmcblkNpM`·`mmcblkNboot0/1`, `ubiX_Y`, `ubiblockX_Y`, `sdX`·`sdXN`, `nand…`. `/dev/watchdog`(여는 순간 타이머가 시작돼 재부팅), `/dev/mem`·`/dev/port`(읽기 부작용) 같은 그 밖의 장치는 `validation_failed` 로 거부한다. `length` 생략 시 `/proc/mtd` 크기(또는 `wc -c`). 시작 응답 `status: "started"`, `job_id`, `output`, `part_path`, `state_path`, `metadata_path`, `chunk_size`, `resume_from_chunk`. 완료 시 `dumps/<name>.bin` + `.json`(`method` `linux-base64`/`linux-hexdump`, `verification.method` `md5-device`) + 아티팩트(`/dev/mtdN`·`/dev/mtdblockN` 은 `partition`, 그 밖은 `other`) |
| `uart_job_status(job_id, wait_seconds=0)`, `uart_job_cancel(job_id)`, `uart_jobs(active_only=False)` | `register_job_tools(..., "uart")`. 덤프 job 의 `progress`/`eta_seconds` 는 **이번 실행**(재개 포함) 기준이고, 전체 진행은 `meta.overall_progress`, `meta.overall_done_bytes`/`meta.overall_total_bytes`, `meta.eta_seconds_estimate`, `message` 에 있다. 취소·실패해도 좋은 청크는 `.part`/`.state.json` 에 남고, `result`(= `meta.partial_result`)에 `status: cancelled\|failed` 와 완료 청크·바이트가 남는다 |

- 문맥은 프롬프트 정규식만으로 정하지 않는다. phase 증거(U-Boot: `<INTERRUPT>`, `Unknown command '…' - try 'help'`, autoboot·배너 / 리눅스: 커널 부팅 마커, `-sh: …: not found`, BusyBox, login)가 있어야 `uboot`/`linux-shell` 로 확정한다.
  `hisilicon # ` 처럼 두 정규식에 다 맞거나 증거가 없으면 `unknown` 이고, unknown 은 두 분류기의 worst 로 분류된다(`md.b` 도 MODIFY). 이미 프롬프트에 있는 기기에 붙었으면 `uart_sync` 로 확정한다.
- 승인 지문(`action`): `uart_write`/`uart_send_command` 는 기기에서 완성될 줄(`lines`)과 분류 문맥을 넣고, U-Boot 가 받을 수 있는 문맥이면 실행 의미도 넣는다.
  빈 줄의 반복 대상 `repeat_of`(모르면 `"<unknown>"`)와, 줄이 참조하는 env 값 `env_refs`(`run x`·`boot`(bootcmd)·`$len` → 지금 추적 중인 값, run 값 안의 참조까지)다.
  그래서 `run x` 를 승인받은 뒤 `setenv x …` 로 내용을 바꾸면 같은 `approval_id` 는 `approval_mismatch` 로 쓸 수 없다.
  승인과 쓰기 사이에 상태가 바뀌어 기기에서 완성될 줄이 달라지거나 위험도가 올라가면, 쓰기 직전의 재분류에서 `state_changed` 로 거부한다.
- 덤프 job 은 자동 감지 문맥이 맞을 때만 시작한다. `uboot_dump_start` 는 먼저 Ctrl-C 동기화를 시도하고, `shell_dump_start` 는 linux-shell 이 아니면 거부한다(수동 지정만으로는 시작하지 않음).
  시작 전에 계획한 모든 명령이 INTERACT 이하인지 검사하고(`job_plan_denied`), 실행 중에도 명령마다 다시 분류하며(`job_command_denied`) 케이스 소유/허가를 다시 확인한다(`authorization_required`). 문맥이 바뀌면(재부팅 등) 멈춘다.
- 재개: 같은 `output_name` 과 같은 범위·`chunk_size`(U-Boot 는 `source`, 셸은 `path`·실제 방식 포함)로 다시 부르면 다음 청크부터 이어받는다(`ram_addr` 은 달라도 된다).
  같은 이름의 진행 중 덤프가 다른 인자로 시작됐으면 job 을 띄우기 전에 `validation_failed` 로 거부하고, `resume=false` 면 처음부터 받는다. 완료된 `dumps/<name>.bin` 은 덮어쓰지 않으므로 새 `output_name` 을 쓴다.
- 덤프 메타데이터 `dumps/<name>.json` 은 firmware-dump 스키마에 그대로 옮긴다: `method`(`uboot-md`/`linux-base64`/`linux-hexdump`), `source{…}`, `output{path, sha256, size}`,
  `verification{method, match, chunks_verified, full_range}`(`method`: `crc32-chunks` / `md5-device` / `verify="double"` 이면 `double-read` / `none`), `chunks{size, count, retries, resumed_from, checks[]}`, `baudrate`,
  `duration_seconds`(마지막 실행) · `duration_seconds_total`(재개를 포함한 전체 합계), `runs[]`, `notes`. job `result` 도 `duration_seconds`/`duration_seconds_total` 을 함께 준다.
- 처리량(115200 baud, 8N1): `md.b` ≈ 2.3 KB/s(바이트당 약 4.94 문자, 16 MiB ≈ 2시간), `base64` ≈ 8 KB/s(16 MiB ≈ 33분), `hexdump -C` ≈ 2.3 KB/s(0xFF 영역은 `*` 접기로 빠름).
  사용자에게 알리는 예상 시간은 `uboot_dump_start` 의 `estimated_seconds` 를 그대로 쓴다.
- 연결이 끊기면(USB 분리, 소켓 종료) 세션은 `disconnected` 가 된다. 쓰기 도구는 `disconnected` 오류, `uart_read` 는 계속 된다. `uart_close` 후 `uart_open` 으로 다시 연다.

### 6.3 pweh-sigrok
로직 애널라이저/오실로스코프의 **입력 전용** 캡처, 신호 파일 디코딩·변환, 순수 Python 보드레이트 추정.
경로 인자는 케이스 상대 경로(`signals/x.sr`, `signals/` 는 생략 가능)이며 케이스 밖 경로는 거부한다.
`sigrok_scan` 은 예외로 `case_id` 가 선택이다(시리얼/네트워크 `conn` 을 줄 때만 필수).
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

| 도구 | 설명 / 반환 |
|---|---|
| `sigrok_version()` | sigrok-cli·libsigrok·libsigrokdecode 버전, 실행 파일 `path`, 드라이버·디코더 수 `counts`. sigrok-cli 가 없으면 `tool_missing` 오류 + 설치 힌트 |
| `sigrok_list(kind="drivers", query=None)` | kind: `drivers`, `decoders`, `input-formats`, `output-formats`, `transforms`, `all` → `items`, `count`. `query` 는 id/설명 부분 문자열 필터. drivers 항목에는 이 서버의 캡처 정책(`capture_allowed`, `output_capable`, `reason`)이 붙는다 |
| `sigrok_decoder_help(decoder)` | 디코더의 필수/선택 채널, 옵션(값 목록·기본값), annotation 클래스/행, 바이너리 클래스, 문서, `example_stack`. 이름이 libsigrokdecode 버전마다 다르므로 `sigrok_decode` 의 스택·annotation 문자열은 하드코딩하지 말고 여기서 확인한다 |
| `sigrok_scan(driver=None, conn=None, case_id=None, timeout_s=None)` | 연결된 장치 `devices[{driver, conn, description, channels, capture_allowed, …}]`, `count`. 인자가 없으면 모든 드라이버로 USB 등을 자동 탐지한다(OBSERVE). 시리얼/네트워크 `conn` 은 드라이버가 그 포트로 식별 바이트를 보내므로 INTERACT 이고 `case_id` 가 필요하며, 다른 프로세스(예: uart-mcp 콘솔 세션)가 포트를 열고 있으면 `Busy` |
| `sigrok_device_info(case_id, driver, conn=None, timeout_s=None)` *(추가)* | `--show` 파싱: `driver_functions`, `channel_groups`, `samplerates` 또는 `samplerate_range`, `triggers`(지원 트리거 문자), `max_samples`, `capture_allowed`. 장치를 열기만 하고 설정은 바꾸지 않는다. 캡처 전에 samplerate 를 고를 때 쓴다 |
| `sigrok_capture(case_id, driver, samplerate="1m", duration_ms=None, samples=None, channels=None, triggers=None, output_name=None, conn=None, capture_ratio=None, background=None, timeout_s=None)` | **`duration_ms` 와 `samples` 중 정확히 하나**가 필요하다(둘 다 없거나 둘 다 주면 `validation_failed`. 기본값으로 채우지 않고 무한 캡처도 없다). `signals/<name>.sr`(srzip) 저장 + `signal-capture` 아티팩트 → `path`, `samplerate`(정수 Hz), `samples`, `channels`, 채널별 `activity`, `next_steps`. 트리거를 쓰거나 예상 시간이 20초를 넘거나 `background=true` 면 **job** 으로 돌고 `{status: "started", job_id, planned_path}` 를 바로 돌려준다. job 의 `result` 는 동기 응답과 같고, 취소하면 `<name>-partial.sr` 를 보존·등록한다. `channels` 예 `["D0=RX","D1=TX"]`(0번부터 연속 선택 권장), `triggers` 는 바꾼 이름으로 쓴다(`"RX=f"`), `capture_ratio` = 트리거 전 비율(%) |
| `sigrok_decode(case_id, input_path, decoders, annotations=None, input_format=None, samplenum=False, max_lines=400, background=None, …)` | 스택마다 **채널 매핑이 필수**다(`"uart:rx=RX:baudrate=115200"`. rx 가 선택 채널인 uart 도 예외 없음 — sigrok 은 매핑이 없거나 틀리면 조용히 첫 채널을 디코드한다). 입력 파일에 없는 채널 이름도 거부한다. 전체 결과는 `signals/<입력>.<디코더>.txt`(`signal-decode`) → `lines`(앞 `max_lines` 줄 목록), `lines_total`, `instances`, `output_path`, `output_truncated`(512 MiB 상한). 동기 실행은 55초에서 멈추며 큰 입력은 자동으로(또는 `background=true`) job |
| `sigrok_export(case_id, input_path, output_format="vcd", output_name=None, input_format=None, timeout_s=None)` | 형식 변환(srzip↔vcd, csv 등. `output_format` 은 `sigrok_list(kind="output-formats")` 의 id) → `output_path`, `output_info`. `signals/` 에 저장 + `signal-capture` 아티팩트. 아날로그 채널이 섞인 .sr 을 로직 전용 형식으로 바꿀 때는 로직 채널만 내보낸다 |
| `sigrok_file_info(case_id, input_path, input_format=None)` *(추가)* | 순수 Python(srzip/VCD 는 sigrok-cli 불필요): `format`, `samplerate`, `channels`, `total_samples`, `duration_s`, 채널별 `activity`(에지 수, high 비율, 처음/끝 레벨), `uart_candidates` |
| `sigrok_estimate_baud(case_id, input_path, channel=None, data_bits=8, parity="none")` | 순수 Python 펄스 폭 분석 → `baudrate`, `baudrate_raw`, `confidence`(0~1), `idle_level`(1=정상, 0=반전 → `invert_rx=yes`), `inverted`, `candidates`, `samples_per_bit`, `frame_check`, `warnings`(4배 미만 오버샘플링 등), `suggested_decoder`, 보드레이트가 섞였으면 `segments`. `channel` 이 없거나 `"auto"` 면 활동 채널을 모두 평가해 고르고 `per_channel` 을 붙인다 |
| `sigrok_uart_autodecode(case_id, input_path, channel=None, baudrate=None, data_bits=8, parity="none", engine="auto", background=None, …)` | 추정한(또는 `baudrate` 로 지정한) 보드레이트·극성으로 uart 디코드 → `text_preview`, `hex_preview`, `framing_errors`, `boot_hints`(U-Boot 배너, autoboot 프롬프트, 커널 버전/cmdline, mtdparts, login …), `uart_estimate{channel, baudrate, confidence, idle_level}`(signal-capture 스키마에 그대로 쓴다), `decode_text_path`/`bytes_path`(`.txt`/`.bin`, `signal-decode`). `engine`: `auto`(sigrok-cli 가 있으면 사용) / `sigrok` / `python` |
| `sigrok_job_status(job_id, wait_seconds=0)`, `sigrok_job_cancel(job_id)`, `sigrok_jobs(active_only=False)` | `register_job_tools(..., "sigrok")` — 캡처·디코드 job |

- 정책 거부(`sigrok_mcp.policy`, §4): 출력 가능 장치(전원공급기·전자부하·신호발생기·릴레이·`baylibre-acme`), 로직 애널라이저/오실로스코프 허용 목록 밖 드라이버,
  출력·설정을 바꾸는 config 키는 `sigrok_capture`·`sigrok_scan`·`sigrok_device_info` 에서 `{ok: false, status: "denied", gate: {via: "sigrok-policy"}}` 로 끝난다.
  게이트에 넘기지 않으므로 승인 경로가 없다. 다른 드라이버 이름으로 다시 시도하거나 설정을 고치지 말고 사용자에게 보고한다
  (측정 전용 장비를 허용 목록에 넣는 것은 운영자가 `pipeline-config.yaml` 의 `sigrok.capture_drivers_allow` 로 한다).
- `ftdi-la` 는 측정 전용 LA 드라이버지만 기본 허용 목록에서 뺐다(`SHARED_ADAPTER_DRIVERS`, `sigrok_list` 항목과 거부 메시지의 `reason` 에 이유가 나온다).
  제품 문자열 확인 없이 범용 FTDI VID/PID(FT232R/FT2232H/FT4232H/FT232H)만으로 장치를 잡아, 같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·JTAG 어댑터·JTAGulator 를 열고 커널 드라이버(ftdi_sio)를 떼며 핀을 bitbang 입력으로 바꿀 수 있기 때문이다.
  전용 FTDI LA 보드만 연결된 환경이면 운영자가 `sigrok.capture_drivers_allow` 에 `ftdi-la` 를 넣는다.
- 디코드(`sigrok_decode` job, `sigrok_uart_autodecode` 의 sigrok-cli 경로)도 sigrok-cli 를 띄우기 직전에 argv 를 다시 분류해 오프라인 명령(`sigrok.offline`)만 실행한다.
  캡처·스캔 argv 가 섞이면 OBSERVE 여도 `safety_denied` 로 거부한다.
- 같은 장치로는 캡처를 동시에 하나만 돌린다(장치 잠금과 job 배타 키는 서버 프로세스 안에서만 유효).
- `sigrok_estimate_baud`, `sigrok_file_info`, `sigrok_uart_autodecode(engine="python")` 는 sigrok-cli 없이 동작한다.
- signal-capture 요약: `capture.file` ← `sigrok_capture.path`, `capture.samplerate` ← `sigrok_capture.samplerate`,
  `uart_estimate` ← `sigrok_uart_autodecode.uart_estimate`, `decoders[].output_file` ← `sigrok_decode.output_path`.

### 6.4 pweh-openocd
OpenOCD 프로세스 관리 + TCL RPC. TCL 포트만 127.0.0.1 에 열고 telnet/GDB 포트는 끈다(다시 여는 명령은 DESTRUCTIVE). 보내는 모든 Tcl 텍스트는 `openocd_mcp.guard.classify_command` 로 분류한다(§4 — 코어 `classify_openocd` 만으로는 불완전).
덤프 job 이 도는 케이스에서는 halt/resume/reset·쓰기·MODIFY 이상 원시 명령이 `busy` 로 거부되고, 조회 도구는 현재 청크가 끝날 때까지 기다린다.
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

| 도구 | 설명 / 반환 |
|---|---|
| `openocd_list_configs(kind="interface", pattern=None, limit=200)` *(추가)* | scripts 디렉터리의 cfg 목록(`interface`/`target`/`board`/`all`, `pattern` 은 부분 문자열 필터) → `scripts_dir`, `configs[]`, `count`, `truncated`. 값을 `openocd_start` 의 `interface_cfg`/`target_cfg` 에 그대로 쓴다 |
| `openocd_start(case_id, interface_cfg, target_cfg=None, transport=None, adapter_speed_khz=None, extra_commands=None, tcl_port=6666, extra_cfgs=None, ready_timeout=30, approval_id=None)` | **MODIFY**(JTAG/SWD 초기화가 타깃 상태에 영향). `extra_commands` 의 init 계열 명령(`init`, `::init`, `ocd_init`, `target`/`transport`/`jtag`/`dap`/`flash`/`nand`/`pld`/`tpiu`/`swo` `init`, `jtag arp_init`·`arp_init-reset`, `jtag_init`, `init_reset`, `post_init_commands` 수정 — catch·eval·if·capture·따옴표 본문과 `-event` 본문, switch 목록 안 본문·apply 람다·proc 본문·defer·subst 의 `[…]`·`-command` 접두 안 포함)은 `validation_failed` 다(init 은 semihosting 가드 뒤에 서버가 실행한다). 게이트는 `extra_commands`, 서버가 만든 transport/adapter speed 명령, 사용자 cfg 의 **내용 전체**까지 분류한 최악값으로 판단한다(사용자 cfg 의 init 계열 명령은 DESTRUCTIVE `openocd.local.init-before-guard`, `$변수`·`-event`·`proc` 를 쓰는 cfg, `telnet port N`/`gdb port N` 재활성화, 중괄호 없는 `expr`/`if` 조건의 치환은 DESTRUCTIVE → 기본 거부). 사용자 cfg 는 신뢰 scripts 디렉터리 밖의 경로, 그리고 OpenOCD 기본 검색 위치(`$OPENOCD_SCRIPTS`, `~/.config/openocd`, `~/.openocd`, site)에서 찾은 이름이다. 1 MiB 를 넘는 사용자 cfg 는 잘라 분류하지 않고 `validation_failed` 로 거부한다. 승인 지문에 사용자 cfg 의 sha256(`custom_cfg_sha256`)이 들어가 승인 뒤 내용이 바뀌면 승인이 맞지 않고, 프로세스를 띄우기 직전에 다시 해시해 다르면 `safety_denied` 로 띄우지 않는다. 표준 cfg 는 확인된 절대경로로 넘기고, 신뢰 scripts 디렉터리는 모두 `-s` 로 넘겨(표준 cfg 안의 `source [find …]` 가 `~/.openocd` 같은 사용자 위치의 같은 이름 파일보다 먼저 찾음) OpenOCD 를 빈 작업 디렉터리에서 띄운다. `target_cfg` 는 문자열 또는 목록, `tcl_port=0` 이면 빈 포트 자동. 준비 완료 = 로그의 `Listening on port N for tcl connections` + `version` 왕복. 로그 `jtag/openocd-<n>.log`, 상태 `jtag/openocd-<n>.json`. **semihosting 은 항상 꺼 둔 채 끝내고 시작 뒤에도 계속 확인한다**(`mcp-servers/openocd-mcp/openocd_mcp/semihosting.py` 의 Tcl 가드 `pweh_semihosting_guard <단계>`): 표준 cfg 는 내용을 분류하지 않는데 xPack `target/esp_common.cfg` 는 ESP32 계열 cpu0/cpu1 의 `examine-end` 핸들러에서 `arm semihosting enable` 을 실행한다(켜지면 타깃 펌웨어가 호스트 파일·명령에 접근). 관련 핸들러(본문에 `semihost` 가 있거나 semihosting proc 이름이 든 타깃·TAP 이벤트 핸들러)만 `try {원래 본문} finally {모든 타깃 중 켜진 것을 끔}` 으로 감싼다(다른 핸들러·ARM 표준 cfg 는 바이트 단위로 그대로). `-f` 하나하나와 `extra_commands` 하나하나 바로 뒤의 init 조기 실행 검사(`[command mode]` 가 `config` 가 아니면 모든 타깃의 semihosting 을 끄고 OpenOCD 를 오류로 끝냄 → 로그 표식으로 `init-before-semihosting-guard`) → 단계: `pre-init`(모든 cfg·`extra_commands` 뒤, init 직전 — `[command mode]` 가 `config` 가 아니면 init 이 이미 돈 것, 아니면 감싸기) → `post-init`(init 직후, TCL 포트가 열리기 전 — init 중(init_board/init_targets) 설치된 핸들러와 TAP 핸들러까지 다시 감싸고 타깃마다 조회해 켜져 있으면 끔) → `verify`(연결 직후 TCL RPC 로 **반드시**: 가드가 전역 변수에 남긴 시작 단계 기록과 새 확인 결과를 받으므로 로그 형식과 무관). 로그의 `PWEH-SEMIHOSTING …` 표식은 `-d3` 이상의 `User : … handle_echo(): ` 접두도 읽고 `script_debug(): command - echo …` 줄은 무시한다. 가드가 없거나 결과가 불완전하면 `semihosting-verification-failed`, init 이 가드보다 먼저 돌았으면(init 을 직접 실행하는 표준 cfg 포함) `init-before-semihosting-guard`, 감싸기·끄기 실패나 스크립트 오류면 `semihosting-neutralization-failed`(`semihosting_failures`) — 모두 OpenOCD 를 끄고 빈 실행 디렉터리를 지운 뒤 `start_failed` 로 돌려준다. 반환: `tcl_port`, `pid`, `log_path`, `version`, `health`(`ok`/`degraded`), `startup`(`taps`, `auto_newtap_suggestions`, 오류/경고), `diagnosis[]`(code + 힌트, 무력화했으면 `semihosting_neutralized`), `scan_chain`, `targets`, `semihosting_neutralized`(`<타깃>:<이벤트>` = 감싼 핸들러, `tap:<TAP>:<이벤트>`, `<타깃>:after-init` = init 직후 켜져 있어 끔, `<타깃>:after-start` = 연결 직후 확인에서 끔), `semihosting`(`verified`, `source: "rpc"`, `log_markers`(로그 표식이 있었는지), `phases`(`pre-init`·`post-init`·`verify`. 조기 실행 검사로 끝났으면 `early-check`), `handlers_wrapped`, `targets`: 타깃별 `off`/`disabled`/`unsupported`, `procs`(가드 자신의 proc 을 뺀 semihosting proc), `phase_targets`, `unwrapped`, `init_before_guard`, `failures`; 상태 파일과 `openocd_status` 의 `semihosting.startup` 에도 같은 값). **시작에 실패해도 예외를 던지지 않고** `ok: false, status: "start_failed"` 와 `reason`, `errors`, `diagnosis`, `log_tail`, `argv` 를 돌려준다(로그와 진단 보존) |
| `openocd_attach(case_id, host="127.0.0.1", tcl_port=6666, approval_id=None)` | 이미 떠 있는 OpenOCD(사람이 띄운 것, 원격 Raspberry Pi 등)의 TCL 포트에 연결한다. 이 케이스가 전에 `openocd_start` 로 띄운 프로세스면 `jtag/openocd-<n>.json` 으로 입양해 `openocd_stop` 으로 끌 수 있게 한다. 입양한 프로세스에 semihosting 가드 proc 이 있으면 `check` 를 돌려 `semihosting_check`·`semihosting_warning` 을 붙이고, 끄지 못하면 OpenOCD 를 종료해 `status: "semihosting_failsafe"` 로 돌려준다(가드가 없으면 경고만). 사람이 띄운 외부 OpenOCD 는 무력화·확인하지 않는다. 원격 호스트면 메모리 덤프는 `read_memory` 방식으로 자동 전환되고 플래시 덤프는 할 수 없다 |
| `openocd_stop(case_id, shutdown_attached=False, approval_id=None)` | 실행 중인 덤프 job 을 먼저 취소한다(부분 결과 보존). 서버가 띄운/입양한 프로세스는 `shutdown` → SIGTERM → SIGKILL 로 끄고(프로세스 수명 관리라 게이트 없음, 감사 기록) 로그를 `other` 아티팩트로 등록한다. attach 한 외부 OpenOCD 는 연결만 끊고, `shutdown_attached=true` 일 때만 MODIFY 게이트를 거쳐 `shutdown` 을 보낸다 |
| `openocd_status(case_id, log_lines=40)` | `alive`, `connected`, `mode`, `version`, `tcl_port`, `uptime_seconds`, `log_tail`, 진단, `active_jobs`, 살아 있으면 `targets`/`target_state`. 이 서버가 띄운 세션이면 `semihosting`(시작 보고가 아니라 최신 상태: `policy`, `verified`, `targets`, `handlers_wrapped`, `procs`, `neutralized_at_start`, `reneutralized[{at, trigger, items}]`, `last_check`, `check_pending`, `failsafe`, `startup`)과 `semihosting_live`(읽기 전용 가드 확인 — 끄기 정책인데 켜진 타깃·감싸지 않은 핸들러가 보이면 그 자리에서 다시 무력화), fail closed 로 종료됐으면 `semihosting_failsafe`. 세션이 없으면 이 케이스의 이전 실행 기록(`previous_runs`) |
| `openocd_command(case_id, command, approval_id=None, timeout=30, max_output_chars=20000)` | 원시 Tcl. 조회(`scan_chain`, `targets`, `mdw`, `read_memory`, `flash banks`/`info` …)=허용, `halt`/`reset`/`resume` 등=MODIFY, `mww`/`write_memory`/`flash write·erase`/OTP·eFuse·옵션바이트=DESTRUCTIVE(기본 거부), 원시 `dump_image`/`flash read_bank`(호스트 파일 쓰기)=거부 → 덤프 도구를 쓴다. telnet/GDB 포트 재활성화, 점 없는 타깃 이름 뒤의 위험한 하위 명령(`cpu0 mww …`)도 DESTRUCTIVE 다. Tcl 식(`expr`, `if`/`while` 조건, `for` 검사식)은 항상 중괄호로 감싼다: 중괄호 없는 변수·명령 치환은 이중 치환이라 DESTRUCTIVE 다. 중괄호 조건이라도 `$변수` 로 시작하면(`if {$x} …`) 코어가 명령 위치의 변수로 보고 거부하므로, 변수 대신 실제 값과 타깃 이름을 쓴다. `list [catch {capture {CMD}} r] $r` 봉투로 실행 → `output`. Tcl 오류면 `ok: false, status: "tcl_error"`, `error`, `diagnosis`. 긴 출력은 `jtag/command-output-<n>.txt`. 호스트 파일을 쓰는 `profile <초> <파일>`·`-output` 트레이스, semihosting proc 호출, 훅 변수(`post_init_commands`·`pre_shutdown_commands`)에 넣는 위험한 값도 DESTRUCTIVE 다(§4). MODIFY 이상(`unknown_command_risk: interact` 면 모든 명령)이면 실행 뒤 semihosting `check` 를 돌려 `semihosting_check`(`status`: `ok`/`reneutralized`/`pending`/`skipped`/`failsafe`/`reported`, `phase`, `trigger`, `at`, `targets`, `reneutralized`/`unwrapped`, `verified`)를 붙이고, 무력화했으면 `semihosting_reneutralized`(`<타깃>:<이벤트>`, `tap:<TAP>:<이벤트>`, `<타깃>:after-command`)·`semihosting_warning` 도 붙인다. 끄지 못했거나 가드가 사라졌거나 결과가 불완전하면 OpenOCD 를 종료하고 `ok: false, status: "semihosting_failsafe"`, `semihosting_failsafe{reasons, stop_method, process, trigger, at}` 와 `message`/`hint` 를 돌려준다 — 그 뒤 기기 도구는 `device_error`('semihosting 을 끄지(확인하지) 못해 서버가 OpenOCD 를 종료했습니다: …'). 명령이 시간 초과면 OpenOCD 를 죽이지 않고 확인을 미뤄 다음 RPC 전에 하며(그 확인이 끝나지 않으면 `busy`), 승인된 명령이 semihosting 을 켜고 성공하면 `semihosting_policy: "enabled-by-approval"`(이후 `openocd_stop` 까지 보고만) |
| `openocd_scan_chain(case_id)` | `taps[{tap_name, enabled, idcode, expected[], irlen, ircap, irmask, mismatch, decoded{manufacturer, part, version, valid}}]`, `count`, `hints`(IDCODE 가 0x00000000/0xffffffff 면 배선·전원 힌트) |
| `openocd_targets(case_id)` | `targets[{index, current, name, type, endian, tap_name, state}]`(state: running/halted/reset/unknown/examine deferred/tap-disabled), `current` |
| `openocd_halt(case_id, target=None, approval_id=None, timeout=15)` | MODIFY. `target` 을 주면 그 타깃을 현재 타깃으로 바꾼 뒤 정지한다 → `messages`(예: `target halted …, pc: …`), `state`, `semihosting_check`(뒤에 도는 semihosting 확인 — `semihosting_reneutralized`/`semihosting_failsafe` 는 `openocd_command` 와 같다) |
| `openocd_resume(case_id, address=None, target=None, approval_id=None)` | MODIFY. `address` 를 주면 그 주소에서 실행한다(실기기 펌웨어가 다시 돈다). 뒤에 semihosting 확인(`semihosting_check`, `openocd_command` 와 같음) |
| `openocd_reset(case_id, mode="halt", approval_id=None, timeout=30)` | MODIFY. `mode`: `halt`(리셋 직후 정지) / `run` / `init`(reset-init 스크립트 실행 후 정지). 리셋은 `examine-end` 같은 핸들러를 다시 실행하므로 뒤에 semihosting 확인(`semihosting_check`, `openocd_command` 와 같음) |
| `openocd_read_registers(case_id, names=None, target=None, refresh=True, max_refresh=64, save=True)` | `reg` 파싱 → `registers`, `target_state`, `snapshot_path`(`jtag/registers-<n>.json`, `jtag-dump` 아티팩트). running 타깃은 값이 없을 수 있으니 먼저 `openocd_halt` |
| `openocd_read_memory(case_id, address, count, width=32, target=None, phys=False)` | 작은 범위만 읽는다(count×width/8 ≤ 4096 바이트, width 8/16/32/64) → `values`(타깃 엔디언 정수), `bytes_hex`, `hexdump`(메모리 순서), `endian`, `method`. Cortex-A 의 mem_ap 타깃을 `target` 으로 주면 CPU 를 멈추지 않고 읽는다. `target` 은 서버가 `target names` 로 확인한 이름만 쓴다: 세션(프로세스 시작·연결 단위) 캐시에 없으면 한 번 다시 조회하고, 그래도 없으면 보내기 전에 `validation_failed`(사용 가능한 이름 안내, 점 있는 이름도 같음)다. OpenOCD/Tcl 명령과 같은 이름(`mww`, `reset`, `flash` …)은 목록에 있어도 거부한다. 확인된 타깃의 `<타깃> read_memory …`/`<타깃> md* …` 는 INTERACT(점 없는 `mem_ap`·`cpu0` 포함)이고, 목록을 얻지 못하면 접두를 떼지 않아 이전 분류(점 없는 이름은 MODIFY)를 따른다 |
| `openocd_dump_memory_start(case_id, address, length, output_name=None, chunk_size=65536, target=None, method="auto", verify=False, resume=True, kind="memory-dump", retries=2, chunk_timeout_s=None)` | job → `job_id`, `output`. 청크마다 `dump_image` 를 케이스 경로로만 실행한다. **기본 저장 위치는 `jtag/<name>.bin`**(+ `<name>.json` 메타데이터, 진행 중 `.part`/`.state.json`)이고 **`kind="flash-dump"` 면 `dumps/`** 다. OpenOCD 가 쓴 파일이 보이지 않으면(원격) `read_memory` 방식으로 자동 전환한다. `verify=true` 면 청크를 두 번 읽어 비교한다. 같은 `output_name`·같은 인자로 다시 부르면 `.state.json` 에서 이어받는다(주소/길이가 다르면 거부, `resume=false` 면 처음부터, 기존 `.bin` 은 덮어쓰지 않음). 완료 `result`: `path`, `sha256`, `size`, `metadata_path`, `chunks`, `source`. 대부분의 코어는 먼저 halt 가 필요하다(`not halted` 는 재시도 없이 실패). `target` 은 시작 전에 `openocd_read_memory` 와 같은 방식으로 확인하고, 확인된 이름은 청크마다 하는 명령 재검사에도 쓴다(목록을 얻지 못하면 점 없는 이름의 덤프는 시작 거부) |
| `openocd_flash_banks(case_id, probe=False, info=False)` | `banks[{bank, name, driver, base, size, bus/chip width, target}]`, `notes`. `probe=true` 면 각 뱅크를 flash probe 한 뒤 다시 조회, `info=true` 면 섹터/보호 상태까지. 카메라 SoC(HiSilicon/Ingenic/SigmaStar)의 SPI NOR 컨트롤러는 OpenOCD 드라이버가 없어 비어 있는 경우가 많다 |
| `openocd_flash_read_start(case_id, bank, offset=0, length=None, output_name=None, chunk_size=65536, verify=False, resume=True, retries=2, chunk_timeout_s=None)` | job. 청크마다 `flash read_bank` 를 케이스 경로로만 실행해 **항상 `dumps/<name>.bin`**(+ `.json`, sha256, `flash-dump` 아티팩트)에 저장한다. `verify=true` 면 청크마다 `flash verify_bank` 로 재확인. 로컬 OpenOCD 에서만 된다(원격 attach 불가) |
| `openocd_write_memory(case_id, address, values, width=32, target=None, phys=False, verify=True, approval_id=None)` | **DESTRUCTIVE**(기본 거부). `destructive_policy: approve` 일 때만 사람 승인(`pweh approve <id>`) 후 같은 인자 + `approval_id` 로 1회 실행. `values` 는 최대 1024개. 목록에 없거나 명령 이름과 겹치는 `target` 은 승인을 묻기 전에 거부하고, `verify` 확인 읽기는 확인된 타깃이면 INTERACT 로 분류한다. 뒤에 semihosting 확인(`semihosting_check`) |
| `openocd_flash_write(case_id, path, address, erase=True, unlock=False, verify=True, approval_id=None, timeout=600)` | **DESTRUCTIVE**(기본 거부). `path` 는 케이스 안 파일만. 승인 지문에 파일 sha256 이 들어가 승인 뒤 파일이 바뀌면 실행되지 않는다. 뒤에 semihosting 확인(`semihosting_check`) |
| `openocd_job_status(job_id, wait_seconds=0)`, `openocd_job_cancel(job_id)`, `openocd_jobs(active_only=False)` | OpenOCD 는 단일 스레드이고 프로토콜 수준 취소가 없어, 취소는 현재 청크가 끝난 뒤 반영된다 |

- 덤프 메타데이터 `<name>.json`: `method: "jtag-openocd"`, `output{path, sha256, size}`, `verification{method: "size-only", match, reread}`,
  `chunks{size, count, retries, resumed_from}`, `source`. firmware-dump 스키마 필드에 그대로 옮긴다.
- SPI NOR 우회(OpenOCD 플래시 드라이버가 없을 때): U-Boot `sf probe; sf read <RAM> <off> <len>` → `openocd_halt` →
  `openocd_dump_memory_start(address=<RAM>, length=<len>, kind="flash-dump")` 로 `dumps/` 에 받고 UART 덤프와 sha256 을 비교한다.

### 6.5 pweh-jtagulator (선택)
JTAGulator(FW 1.10–1.12)의 USB-시리얼 텍스트 메뉴를 조작해 JTAG(IDCODE/BYPASS/Combined)·UART 핀아웃을 찾는다. 찾은 핀아웃은 pweh-uart(콘솔)·pweh-openocd(JTAG)로 넘긴다.
키 입력은 `jtagulator_mcp.classify` 로 분류한다(§4). 원시 키 입력 도구는 없고, JTAG `Y`/`P`/`O`, GPIO `W`/`L`, 메인 `A`, UART 패스스루는 노출하지 않는다(분류기가 DESTRUCTIVE 로 막음).
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

**승인과 전압 상태는 연결에 묶인다.**
- `jtagulator_connect` 를 할 때마다(같은 포트 재사용 포함) 서버의 전압 상태는 '미설정'으로 초기화된다. 포트를 열고 닫을 때 DTR 로 JTAGulator 가 리셋되어
  VADJ 가 꺼졌을 수 있기 때문이다. 스캔·`D`/`T`·GPIO 읽기는 그 연결에서 `jtagulator_set_voltage` 가 성공하고 장치가 `New target I/O voltage set: x.y` 로
  확인한 뒤에만 시작한다(아니면 오류 code `voltage_not_set`).
- 게이트를 거치는 모든 동작(전압 설정, 스캔, `D`/`T`, GPIO 읽기)의 승인 지문에는 포트, 연결마다 새로 만드는 토큰, 전압(전압 설정은 요청값, 그 밖의 동작은
  이 연결에서 확인된 값)이 들어간다. 그래서 승인했지만 쓰지 않은 `approval_id` 는 다시 연결하거나 포트·전압이 바뀌면 쓸 수 없다(재측정·재승인).

| 도구 | 설명 / 반환 |
|---|---|
| `jtagulator_connect(case_id, port, baudrate=115200, timeout_seconds=12, allow_untested_firmware=False)` | INTERACT. 포트를 열고 Ctrl-X 재동기화로 메뉴 프롬프트를 찾은 뒤 펌웨어 버전을 읽는다. `port` 는 장치 절대경로(`/dev/ttyUSB0`, `/dev/serial/by-id/…`), Windows `COMn`, `socket://`·`rfc2217://`(원격), `loop://`(테스트)만 받는다(`spy://`·`hwgrep://` 같은 다른 pyserial URL 과 제어 문자는 `validation_failed`). 포트는 exclusive(flock)로 열어, 다른 세션(uart-mcp 콘솔 등 — 대상 콘솔일 수 있음)이 잡은 포트면 재동기화 키를 한 바이트도 보내지 않고 `device_error` 로 실패한다 → `connection{port, firmware, firmware_supported, connection_token, voltage, menu, active_job_id, …}`, `firmware`, `reused`, `warnings`(영속 모드에서 빠져나왔으면 VADJ 재설정 경고), `next_steps`. FW 1.10 미만은 `allow_untested_firmware=true` 없이는 전압 설정·스캔을 거부한다. 세션 기록 `jtag/jtagulator-<n>.log`. 케이스당 연결 하나, 포트당 케이스 하나 |
| `jtagulator_disconnect(case_id)` | 실행 중인 스캔을 중단(LF)하고 끝나기를 기다린 뒤 포트를 닫고 세션 기록을 등록한다 → `port`, `transcript`. 정리 작업이라 소유/허가 검사와 게이트를 거치지 않는다. 포트를 닫으면 DTR 리셋으로 VADJ 가 꺼질 수 있으니 타깃 전원을 먼저 끈다 |
| `jtagulator_version(case_id)` | 메인 메뉴 `I` → `firmware`, `supported`(1.10–1.12 여부), `version_lines` |
| `jtagulator_status(case_id=None)` *(추가)* | 장치 I/O 없음. `connections[]`(포트, 펌웨어, 현재 메뉴, 이 연결에서 확인된 전압, 실행 중 작업), `connected`. `case_id` 를 생략하면 전체 |
| `jtagulator_set_voltage(case_id, volts, approval_id=None)` | **DESTRUCTIVE**(기본 거부. `volts=0` 으로 VADJ 를 끄는 것도 DESTRUCTIVE — 타깃 전원이 켜져 있으면 클램프 다이오드로 전류가 흐를 수 있다). 사람이 멀티미터로 잰 타깃 I/O 전압만 쓴다(1.4–3.3 V, 0.1 V 단위. 단위가 안 맞거나 범위 밖이면 승인 요청 없이 거부하고 반올림하지 않는다). approve 정책이면 `status: "approval_required"` + `approval_id` + `operator_checklist`(사용자에게 보여 줄 확인 목록). 성공하면 `volts`, `previous`, `device_output`, `scans_allowed` |
| `jtagulator_gpio_read(case_id, samples=1, interval_ms=100)` *(추가)* | INTERACT, 동기(GPIO `R`, 수동 관찰). 채널을 입력으로 두고 `samples` 번 읽는다 → `values_hex`, `low_channels`(LOW 고정), `toggling_channels`(활동), `channels`, `artifacts`. 전압 설정 필요 |
| `jtagulator_uart_txd_scan(case_id, start_channel, end_channel, duration_seconds=20, ignore_nonstandard=False, idle_timeout_seconds=60, approval_id=None)` *(추가)* | MODIFY · job(UART `T`, FW 1.10+). 채널을 입력으로만 두고 `duration_seconds` 동안 UART 활동을 감시해 TXD 채널과 보드레이트를 잰다(`summary.best{txd, baud}`). 타깃에 아무것도 보내지 않는 가장 안전한 첫 단계다 — 감시 중에 사람이 타깃을 재부팅하면 좋다 |
| `jtagulator_idcode_scan(case_id, start_channel, end_channel, pins_low=False, pins_low_ms=100, pins_high_ms=100, idle_timeout_seconds=120, max_duration_seconds=None, approval_id=None)` | MODIFY · job(JTAG `I`). TDO/TCK/TMS(+TRST# 후보)와 Device ID(JEP106 제조사 해석). TDI 는 찾지 못한다 → `jtagulator_bypass_scan(known_pins=…)` 또는 `jtagulator_jtag_scan`. 순열 n!/(n-3)! |
| `jtagulator_bypass_scan(case_id, start_channel, end_channel, known_pins=None, pins_low=False, …)` | MODIFY · job(JTAG `B`). TDI/TDO/TCK/TMS(+TRST# 후보)와 체인 장치 수. IDCODE 미지원 타깃도 찾는다. `known_pins={"tdo":2,"tck":0,"tms":1}` 로 아는 핀을 고정하면 훨씬 빠르다(24채널 전체는 255,024 순열, 최소 약 3시간) |
| `jtagulator_jtag_scan(case_id, start_channel, end_channel, pins_low=False, …)` *(추가)* | MODIFY · job(JTAG `J` Combined, FW 1.8+). IDCODE 순열을 돌다 유효한 IDCODE 가 나오면 남은 채널로 TDI 를 BYPASS 시험해 4핀 + Device ID 를 한 번에 찾는다(IDCODE 를 지원하는 타깃에서는 BYPASS 스캔보다 훨씬 빠름) |
| `jtagulator_uart_scan(case_id, start_channel, end_channel, text="\r", known_pins=None, delay_ms=10, printable_only=False, …)` | MODIFY · job(UART `U`). (TXD, RXD) 순열마다 보드레이트 21개(300–307200)로 `text` 를 후보 RXD 로 보내고 응답(최대 16바이트)을 받는다 → `summary.best{txd, rxd, baud, confidence}`. `text` 는 1–16 바이트이며, 이스케이프(`\r` `\n` `\xHH`)를 해석해 hex 로 입력하므로 정확히 그 바이트만 간다(CR 자동 추가 없음, 시작 응답의 `text_hex` 로 확인). 대상 콘솔이 여러 번 받으므로 코어 콘솔 분류기로 검사해 DESTRUCTIVE 프로브는 게이트 전에 오류로 거부한다(승인 레코드 없음). 줄 끝 없는 꼬리가 다음 송신의 머리와 이어질 수 있어 한 번 보낸 형태와 두 번 이어 붙인 형태를 모두 검사한다(`_erase X\rflash` → `flash_erase X` 로 거부). `known_pins={"txd": N}` 으로 TXD 를 고정한다 |
| `jtagulator_get_device_ids(case_id, tdo, tck, tms, approval_id=None)` *(추가)* | MODIFY, 동기(JTAG `D` — 펌웨어가 24채널 전부를 출력 HIGH 로 만든 뒤 실행). 아는 핀으로 IDCODE 상세를 읽는다 → `devices`, `count`, `pins`, `artifacts`(`jtag/jtagulator-<n>-device-ids-<k>.json`) |
| `jtagulator_bypass_test(case_id, tdi, tdo, tck, tms, approval_id=None)` *(추가)* | MODIFY, 동기(JTAG `T`, 24채널 HIGH). 체인 장치 수를 세고 32비트 무작위 패턴이 BYPASS 로 그대로 돌아오는지 본다 → `match`, `device_count`, `pattern_in`/`pattern_out`. 찾은 핀아웃 검증용 |
| `jtagulator_job_status(job_id, wait_seconds=0)`, `jtagulator_job_cancel(job_id)`, `jtagulator_jobs(active_only=False)` | 스캔 폴링·취소. 취소하면 스캔을 중단하고 부분 결과를 남긴다(`cancelled`) |

- 스캔 공통: TXD 스캔을 뺀 스캔은 범위 안의 모든 채널을 출력 HIGH 로 구동하므로, 전원 레일·리셋·부트모드 핀은 빼고 실제로 연결한 채널만 범위에 넣는다.
  시작 응답은 `job_id`, `permutations`, `lower_bound_seconds`(문서화된 25 kHz JTAG 클럭으로 계산한 최소값, 실측 아님), `raw_log`, `result_json`.
  끝나면 `jtagulator_job_status` 의 `result` 에 `summary.best`(가장 그럴듯한 핀아웃), `summary.notes`, `artifacts` 가 있다. 스캔 중 다른 장치 도구는 `busy`.
- MODIFY job 패턴(§4): 스캔 대화(메뉴 키·채널·옵션·스페이스바)는 게이트 통과 직후 도구 호출 안에서 보내고, job 은 출력 감시와 중단 키(LF 1바이트, INTERACT)만 보낸다.
- UART 핀 이름은 타깃 기준이다: TXD = 타깃 송신 핀(USB-UART 의 RX 에 연결), RXD = 타깃 수신 핀(USB-UART 의 TX 에 연결).
- 산출물: `jtag/jtagulator-<n>.log`(세션 기록), `jtag/jtagulator-<n>-<scan>-<k>.log`/`.json`(스캔 원시 출력 / 결과, `pweh.jtagulator-scan/v1`),
  `…-device-ids-<k>`, `…-bypass-test-<k>`, `…-gpio-<k>`. 모두 `kind="other"` 로 등록하고 종류는 `extra.type` 에 둔다(§3).

### 6.6 pweh-fwtriage
외부 도구 없이(순수 Python + PyYAML) 동작하는 빠른 트리아지. REA(binwalk/unblob/Ghidra)를 대체하지 않고 보완한다.
하드웨어를 건드리지 않아 안전 게이트 대상이 아니고 펌웨어 안의 어떤 것도 실행하지 않는다(외부 프로그램은 `fw_extract_squashfs` 의 `unsquashfs`/`sasquatch` 뿐).
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

- **`result_path`**: `case_id` 를 받는 `fw_*` 도구는 모두 전체 결과 JSON 의 케이스 상대 경로 `result_path`(`analysis/<도구>-NNN.json`, `triage-report` 아티팩트)를 돌려준다.
  응답의 목록은 `max_results`(기본 50)로 잘리고 합계·`truncated` 로 더 있는지 알린다. 케이스가 없는 `fw_hunt_patterns` 에는 `result_path` 가 없다.
- **`background=true`**(`fw_identify`, `fw_entropy`, `fw_extract_squashfs`, `fw_elf_info`, `fw_rootfs_audit`, `fw_strings_hunt`, `fw_crack_hashes`): 응답은 `job_id` 이고
  `fwtriage_job_status` 의 `result` 가 인라인 응답과 같다(`result_path` 포함). `max_seconds` 는 시간 예산이며 넘으면 부분 결과로 끝난다(`summary.timed_out`/`truncated`).
- 오프셋·크기 인자는 정수 또는 `"0x150000"`, `"64k"`, `"2M"` 같은 문자열을 받는다.

| 도구 | 설명 / 반환 |
|---|---|
| `fw_identify(case_id, path, offset=0, length=None, max_results=50, include_nested=False, max_seconds=120, background=False)` | 헤더 검증으로 오탐을 줄인 시그니처 스캔: uImage(헤더·데이터 CRC), FIT/DTB, squashfs(v1~4, 벤더 매직), jffs2, UBI/UBIFS, cramfs/romfs/erofs/ext2·3·4, gzip/xz/lzma/bzip2(시험 해제로 정확한 크기), zstd/lz4(프레임 검증), ELF, cpio, ARM zImage, zip, PEM, U-Boot env, U-Boot·커널 버전 문자열 → `regions[{offset_hex, kind, size, confidence, details}]`, `padding_runs`(0xFF/0x00), `nested_omitted`(투명 컨테이너 안쪽 항목 수, `include_nested=true` 면 목록에 포함), `next_steps`. `analysis/identify-NNN.json` |
| `fw_entropy(case_id, path, block_size=65536, offset=0, length=None, high_threshold=7.5, annotate=True, …)` | 블록 Shannon 엔트로피 → `high_runs`(카이제곱으로 균일=암호화·강한 압축 / 비균일=일반 압축 구분), `unexplained_high_entropy_runs`(알려진 시그니처로 설명되지 않는 고엔트로피 = 암호화·난독화 의심), `low_runs`(패딩), `profile`(한 줄 프로파일), `stats`. `analysis/entropy-NNN.json` |
| `fw_uboot_env(case_id, path, sizes=None, align=4096, include_default_env=True, max_results=16)` | U-Boot env 블록 탐색(후보 크기별 CRC, redundant 플래그, 빅엔디안 CRC 보완) → `envs[]`(env 전체, 주요 변수, mtdparts 해석), `recommended_layout`, `embedded_default_envs`(U-Boot 바이너리에 내장된 CRC 없는 기본 env), `mtdparts_strings`. `analysis/uboot-env-NNN.json` |
| `fw_carve(case_id, path, mtdparts=None, partitions=None, output_label="parts", mtd_device=None, probe=True)` | mtdparts 문자열 또는 `[{name, offset, size}]` 로 분할한다. 둘 다 없으면 CRC 유효 env(mtdparts/bootargs) → 내장 기본 env → 이미지 속 `mtdparts=` 문자열 → DTB partition 노드 순으로 레이아웃을 정한다. **출력은 `extract/<label>-NNN/<idx>-<name>.bin`**(idx 2자리, 이름은 `[A-Za-z0-9._-]` 로 정리) **+ `index.json`** 이고 파티션마다 `partition` 아티팩트로 등록하며 시작 위치의 형식을 판별한다 → `partitions[]`, `layout`, `output_dir`, `index_path`, `result_path`(`analysis/carve-NNN.json`) |
| `fw_uimage_info(case_id, path, offset=0)` | legacy uImage 헤더(이름, load/entry, OS/arch/type/압축, 헤더·데이터 CRC, multi 크기표, 실제 페이로드 형식과 헤더 압축 표시 일치 여부) 또는 FIT/DTB(images, configurations, 해시. DTB 면 model/compatible/bootargs/partition 노드) → `image`. 매직이 없으면 파일 안의 uImage/FIT 위치를 안내한다. `analysis/uimage-NNN.json` |
| `fw_extract_squashfs(case_id, path, offset=0, output_label="rootfs", timeout_seconds=600, max_output_bytes="2G", engine="auto", allow_listing_anomalies=False, background=False)` | superblock 검증 → `unsquashfs -lln` 목록 안전 검사(디렉터리 탈출, 비정상 줄, 압축 폭탄) → 비root 추출(장치 노드 안 만듦). 트리 `extract/<label>-NNN/`(`extracted-tree`)와 원본 모드/소유자/setuid 를 보존한 `extract/<label>-NNN.manifest.json` → `output_dir`, `output_dir_abs`(다른 도구에 넘길 절대경로), `manifest_path`, `superblock`, `status`. `analysis/extract-squashfs-NNN.json`. unsquashfs 가 없으면 `tool_missing` + 설치 힌트 |
| `fw_rootfs_audit(case_id, rootfs_dir, max_results=50, crack_defaults=True, crack_seconds=30, max_file_size="16M", …)` | 추출된 rootfs 감사: passwd/shadow(빈/약한 해시, uid 0 추가 계정, 공개 하드코딩 해시, 기본 비밀번호 오프라인 대조), 시작 스크립트(telnetd `-l /bin/sh`, getty 자동 로그인 등), 웹 서버·CGI, setuid(매니페스트 기준), 개인키/인증서(지문만), 하드코딩 자격증명(마스킹) → `items[]`(finding 스키마의 category·severity 힌트, 파일/줄/발췌), `rootfs`(static-analysis 스키마의 rootfs 형태), `binaries_of_interest[{path, reason}]`, `services`, `web_servers`, `accounts`, `vendor`(`family`/`family_source`: 파일 근거(바이너리 이름·배너·경로) `evidence` → 없으면 프로필의 구체적인 `hunt.vendor_family` `profile` → 일반 웹 서버만 있으면 `generic`(`generic-web-server`) → 아무 근거도 없으면 `unknown`(`none`). `votes`·`vendor` 는 파일 근거만), `limitations`. 심볼릭 링크는 rootfs 안에서만 해석한다. `bin`/`sbin` 의 `passwd` 명령과 바이너리 내용은 계정 DB 로 읽지 않는다. `analysis/rootfs-audit-NNN.json` |
| `fw_strings_hunt(case_id, path_or_dir, patterns="cctv", max_hits=500, max_results=50, min_severity=None, include=None, …)` | `src/pweh/data/cctv-hunt-patterns.yaml` 의 `string_heuristics` 로 인증 우회/백도어/명령 주입/하드코딩 자격증명 문자열을 휴리스틱 검색한다. `patterns`: `cctv`(전체), 휴리스틱 id/category/vendor/severity 선택자, `xm-*` 같은 접두사, `re:<정규식>`, `raw:<바이트 정규식>`, `lit:<문자열>` → `hits`(`file`/`path`(아래), 오프셋, 텍스트는 줄, 패턴 id/category/severity, 문맥), `matched_checks`, `no_match_checks`(개수), `summary`(`vendor_family_guess`, `rootfs_dirs` 등), `top_files`. 전체 JSON 의 `checks[]` 는 auth-hunt 스키마 `checks[]` 에 그대로 쓴다. `#` 주석 줄의 히트는 `commented_hits` 로 따로 둔다. 사용자 패턴(`re:`/`raw:`/`lit:`, 선택자에 맞지 않는 일반 단어)의 check id 는 `custom-<lit\|re\|raw>-<sha256 앞 8자>` 라 실행이 달라도 같은 패턴이면 같고, 패턴 원문은 `description` 에 있다. 빈 문자열과 일치하는 사용자 패턴은 건너뛰고 `notes` 에 적는다. `include` glob 은 `path_or_dir` 기준이다. `analysis/strings-hunt-NNN.json` |
| `fw_elf_info(case_id, path, max_results=50, max_files=3000, max_seconds=180, background=False)` | 순수 Python ELF: class/엔디언/e_machine, e_flags(MIPS ISA·ABI, ARM EABI·float ABI), 인터프리터, DT_NEEDED/RPATH, 임포트 심볼(섹션 헤더 없는 sstrip 바이너리 포함), 보호기법(NX/RELRO/PIE/카나리/FORTIFY), 위험 임포트(`system`/`popen`/`strcpy`/`sprintf` …, YAML `function_heuristics`). `path` 가 디렉터리면 모든 ELF 를 위험 점수 순으로 → `binaries`, `mode`, `summary`. `analysis/elf-info-NNN.json` |
| `fw_crack_hashes(case_id, hashes=None, source_path=None, wordlist="builtin-defaults", extra_words=None, hash_type=None, max_seconds=60, reveal=False, …)` | 해시를 공개 기본 비밀번호 사전과 **오프라인** 대조한다(네트워크 로그인 시도 없음, 소유 기기 감사용). `hashes`(`user:hash` 줄 / 순수 해시 / `{user, hash, type}`) 또는 `source_path`(케이스 안 passwd/shadow/htpasswd) 중 하나. DES crypt, md5crypt/apr1, sha256/512crypt, XiongMai Sofia(`hash_type="xm-sofia"` 필요), 솔트 없는 md5/sha1/sha256, bcrypt/yescrypt(crypt 모듈 지원 시) → `results[]`(평문은 마스킹, `reveal=true` 일 때만 표시), `counts`. 평문 전체는 `analysis/crack-hashes-NNN.json` 에만 있다(케이스 밖 반출 금지). `not_cracked` 는 안전하다는 뜻이 아니다 |
| `fw_hunt_patterns(vendor=None, category=None)` *(추가)* | `fw_strings_hunt`/`fw_rootfs_audit`/`fw_elf_info` 가 쓰는 휴리스틱 목록(`string_heuristics`, `function_heuristics`, `credential_patterns`, `web_server_binaries`, `known_hashes`, `candidate_passwords`)과 패턴 파일의 `source`·`sha256`·`errors`. 케이스를 받지 않아 `result_path` 가 없다 |
| `fwtriage_job_status(job_id, wait_seconds=0)`, `fwtriage_job_cancel(job_id)`, `fwtriage_jobs(active_only=False)` | `background=true` 로 시작한 작업. `result` 는 인라인 응답과 같다 |

- squashfs 만 직접 추출한다. jffs2/UBI/UBIFS/cramfs/ext/erofs/romfs 는 위치·크기·메타데이터만 식별하므로 `fw_carve` 로 분리한 뒤 REA `extract_firmware` 로 추출한다.
- 결과는 모두 휴리스틱 후보다. 발견사항 증거로 쓸 때는 `evidence[].type="triage"`, `ref=result_path` 와 항목의 파일/줄을 남긴다.
  `items`, `hits`, `binaries_of_interest` 의 rootfs 경로는 rootfs 절대 경로(`/etc/passwd`)라 `finding.location.file` 에 그대로 쓴다.
  `fw_strings_hunt` 의 `hits[].file` 은 디렉터리·단일 파일 모드 모두 rootfs 절대 경로이고(rootfs 밖의 덤프·파티션 이미지는 `null`), 케이스 상대 경로는 `hits[].path` 에 있다.
  `commented_hits`·`top_files` 도 같은 `file`/`path` 를 갖고, `checks[].evidence_ref` 는 `<file>@<offset_hex>`(file 이 `null` 이면 `<path>@<offset_hex>`)다.
  rootfs 루트는 `fw_extract_squashfs` 트리(`extract/<label>-NNN`, 옆에 `.manifest.json`), 없으면 `etc` 와 `bin`/`sbin` 을 가진 가장 바깥 상위 디렉터리이며 `summary.rootfs_dirs` 에 적는다
  (그래서 `path_or_dir` 로 rootfs 의 하위 디렉터리를 줘도 `file` 은 `/usr/bin/…` 이다).
- `fw_carve` 의 `partitions[].path` 는 케이스 상대 경로다(`file` 은 같은 값의 별칭).

### 6.7 pweh-esp (선택)
Espressif 칩(ESP32·ESP32-S2·ESP32-S3·ESP32-C3 등)을 esptool 로 **읽기 전용** 분석한다. 칩·플래시 정보, 보안 설정, SPI 플래시 덤프(job, 기본으로 두 번 읽어 sha256 비교)를 다룬다.
실행하는 esptool 명령은 `flash-id`(`esp_chip_info`), `get-security-info`(`esp_security_info`), `read-flash`(`esp_read_flash_start`) 셋뿐이다.
모두 MODIFY 로 게이트를 거친다(연결할 때 칩을 리셋해 ROM 다운로드 모드에 넣고 RAM 에 스텁을 올린다. 플래시·eFuse 에 쓰는 명령은 보내지 않는다 — 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`soft-reset` 도 쓰지 않음, 기본 허용).
쓰기·삭제·eFuse·RAM 실행 같은 명령은 도구가 없고, 조립한 argv 가 허용 범위를 벗어나면 `esp_mcp.policy` 가 승인 경로 없이 거부한다(§4).
아래 시그니처는 카탈로그(`docs/references/pweh-mcp-tools.md`)의 인자 전체와 기본값이다(동작·오류 코드 상세: `mcp-servers/esp-mcp/README.md`).

**포트 형식이 백엔드를 정한다.**
- `COM1` ~ `COM256`(대소문자 무관) → `windows` 백엔드(방법 A, WSL 권장): WSL interop 으로 Windows 용 `esptool.exe` 를 `--port COMn` 으로 실행한다.
  보드는 Windows 에 연결된 그대로 두므로 usbipd attach 가 필요 없다. 덤프 출력 경로는 `wslpath -w` 로 바꿔(`\\wsl.localhost\<배포판>\…\dumps\…`) esptool.exe 가 케이스 `dumps/` 에 바로 쓴다.
  실행 파일은 설정 `tools.esptool_win`(`PWEH_ESPTOOL_WIN`)이고, 비어 있으면 `~/pweh-tools/esptool-win/esptool-windows-amd64/esptool.exe`(설치 스크립트의 esptool 구성요소)를 찾는다.
  조건은 셋이다: WSL 안, `/proc/sys/fs/binfmt_misc/WSLInterop`(또는 `WSLInterop-late`)가 `enabled`, `wslpath`.
- `/dev/ttyACM<n>`, `/dev/ttyUSB<n>`, `/dev/ttyS<n>`, `/dev/serial/by-id/<이름>` → `linux` 백엔드: 리눅스 esptool(`tools.esptool`, `PWEH_ESPTOOL`. 설치 스크립트는 esptool 5.4.0 venv).
  WSL 이면 usbipd attach 뒤에 쓴다(attach 하는 동안 Windows 에서는 그 COM 포트가 사라진다). 장치가 있어야 하고 링크의 실제 대상도 `/dev` 아래여야 한다.
- `rfc2217://`, `socket://` 같은 네트워크 포트와 그 밖의 경로는 `validation_failed` 다.

기본값의 뜻: `baud=None` 은 정보 도구에서 115200 이고, 덤프 기본값은 921600 이다(전송 오류가 나면 460800, 115200 으로 낮춘다. ESP 내장 USB-Serial/JTAG 연결에서는 속도와 무관).
`before`: `default-reset`(DTR/RTS 자동 리셋) / `usb-reset` / `no-reset`(사람이 다운로드 모드로 둔 뒤). `after`: `hard-reset`(끝나면 앱 재실행) / `no-reset-stub`(리셋하지 않고 다운로드 모드(스텁)에 둠) /
`watchdog-reset`(esptool v5, v4.12 이상) / `no-reset`(받지만 항상 `no-reset-stub` 으로 바꿔 실행 — 응답 `after`·`after_requested`와 notes). `soft-reset` 은 `validation_failed` 다
(`no-reset`·`soft-reset` 은 끝날 때 FLASH_BEGIN 을 보내 레거시 스텁이 SPI 플래시 상태 레지스터를 다시 쓸 수 있다, §4).
`no_stub=True` 는 ROM 로더와 직접 통신한다(전송 MD5 검증 없음). `chip` 을 ESP8266 이 아닌 칩으로 명시해야 한다(`auto`·`esp8266` 이면 `validation_failed` — §4 `esp.nostub.esp8266`).
ESP32 계열 ROM 은 read-flash 를 지원하고, ROM 이 지원하지 않는 기능은 `esp_rom_unsupported` 다.
`timeout_s=None` 은 정보 도구 50초(최대 600초), 덤프는 크기·baud 로 계산한 읽기당 시간(최대 6시간)이며, 덤프는 출력 없이 180초가 지나면 멈춘 것으로 본다.
모든 esptool 명령에 `--chip`·`--port`·`--baud`·`--before`·`--after`·`--connect-attempts 7` 을 명시하고, 설정 파일·환경변수는 아래 '실행 환경' 처럼 중립화한다.
esptool v5 는 하이픈 이름(`read-flash`), v4 는 밑줄 이름(`read_flash`)으로 조립한다.

| 도구 | 설명 / 반환 |
|---|---|
| `esp_version()` | OBSERVE(기기 미접촉). `backends.windows`·`backends.linux` 마다 `{available, path, source, version, major, error}`(windows 에는 `wsl`, `interop` 도. v4 미만이면 `warning`), `recommended`(`windows`/`linux`/`null`), `hints`. 버전은 `esptool version` 출력으로 정하고 실행 파일 경로·mtime·크기별로 캐시한다 |
| `esp_list_ports()` | OBSERVE(포트를 열지 않음). `windows{available, ports[{port, name, pnp_device_id, vid, pid, serial_number, usb_id, kind, description_ko}], note}`: powershell.exe 로 Win32_PnPEntity 를 조회한 결과(이름에 `(COMn)` 이 있는 장치만). `linux{ports, hidden_legacy_ports}`: pyserial 목록 + `in_use_by`(그 tty 를 연 다른 프로세스 PID), sysfs 정보가 없는 레거시 `/dev/ttyS*` 는 숨기고 센다. 그 밖에 `count`, `hints`. 알려진 USB ID: `303a:1001` = ESP 내장 USB-Serial/JTAG, `303a:0009`·`303a:0002` = ESP32-S3·S2 ROM USB-OTG 다운로드 모드, CP210x·CH340·CH343·CH9102·FTDI. `hints` 는 종류별이다(USB-Serial/JTAG = esptool 의 USB-JTAG 리셋, ROM USB-OTG = `before="no-reset"`·`after="no-reset"`(서버가 `no-reset-stub` 으로 실행)과 끝난 뒤 사람의 RESET). interop 이나 powershell 이 없으면 `windows.available=false` 와 `note` |
| `esp_chip_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY(`flash-id`). `chip`, `chip_description`, `chip_revision`, `features`, `crystal_mhz`, `usb_mode`, `mac`, `flash{manufacturer_id, manufacturer, device_id, size, size_bytes, type_efuse, voltage, voltage_source}`, `base_mac`(늘 6바이트), `mac_ext`(EUI-64 확장 2~8바이트), `secure_download_mode`, `stub`, `log_path`(`uart/esptool-chip-info-NNN.log`), `backend`, `port`, `esptool_version`, `command`, `classification`, `after`(실제로 쓴 값), `after_requested`(`no-reset` 을 바꿨을 때만), `warnings`(플래시 크기 미감지 → 덤프에 `size` 명시, 플래시 ID `ff`/`00` → 배선·전원·스트래핑), `notes`, `next_steps`. `mac` 은 esptool 이 찍은 값(ESP32-C6·H2 는 8바이트 EUI-64). Secure Download Mode 면 ROM 이 flash-id 를 거부하므로 오류 대신 `status: "secure_download_mode"`, `read_flash_possible: false` 와 칩 종류만 돌려준다. 모든 성공 응답에 `provenance{recorded, kind: "device-fact", fact_kind: "esp-chip-info", seq}`(출처 원장의 기기 사실, §4. `status: "secure_download_mode"` 결과도 기록한다. 기록에 실패하면 `recorded: false`, `reason`) |
| `esp_security_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY(`get-security-info`). `status`(`"ok"`/`"unsupported"`), `secure_boot`, `flash_encryption`(SPI_BOOT_CRYPT_CNT 의 1 비트 수가 홀수면 켜짐), `crypt_cnt`, `secure_download_mode`(플래그 비트 2), `read_flash_possible`(= Secure Download Mode 꺼짐), `ciphertext_expected`(= 플래시 암호화 켜짐), `jtag_hard_disabled`, `jtag_soft_disabled`, `usb_disabled`, `download_dcache_disabled`, `download_icache_disabled`, `key_blocks[{block, purpose}]`, `flags_hex`, `parsed_flags`, `raw_fields`, `chip_id`, `api_version`, `assessment`(한국어 판단), `log_path`(`uart/esptool-security-info-NNN.log`), `after`, `after_requested`, `warnings`, `notes`. Secure Download Mode 에서도 동작한다. `read_flash_possible=false` 면 덤프하지 않고 우회 없이 사용자에게 보고한다. 원조 ESP32·ESP8266 은 get-security-info 를 지원하지 않는다 → 오류 대신 `ok: true, status: "unsupported"`, `chip`, `chip_description`, 보안 필드(`secure_boot`·`flash_encryption`·`crypt_cnt`·`secure_download_mode`·`read_flash_possible`·`ciphertext_expected`·`jtag_*`·`usb_disabled`·`key_blocks`·`raw_fields`·`flags_hex`·`parsed_flags`·`chip_id`·`api_version` 등)는 모두 `null`, `assessment` ['보안 상태 미확인 …'], `error`(esptool 문구), 첫 note 는 '미확인'으로 기록하고 진행하라는 안내(감사 이벤트 `esp_security_summary` 에도 `status`). 두 경우 모두 `provenance{recorded, kind: "device-fact", fact_kind: "esp-security-info", seq}`(출처 원장의 기기 사실 — `unsupported` 면 보안 필드 null = 미확인으로 기록) |
| `esp_read_flash_start(case_id, port, chip="auto", offset=0, size="all", output_name=None, baud=921600, verify="double", before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY · job(`read-flash`). 시작 응답 `status: "started"`, `job_id`, `planned_path`(`dumps/<name>.bin`), `planned_read2_path`, `metadata_path`, `reads`(1 또는 2), `backend`, `port`, `esptool_version`, `after`(마지막 읽기에 쓸 값), `after_requested`(바꿨을 때만), `read1_after`(이중 읽기면 `"no-reset-stub"`, 아니면 `null`), `read1_baud`(이중 읽기의 1차 baud, 아니면 `null`), `timeout_s_per_read`, `classification`, `notes`. `offset` 은 정수 또는 `"0x10000"`, `size` 는 `"all"`(감지한 플래시 크기, `offset=0` 일 때만)·정수·`"0x400000"`·`"4M"`·`"16MB"`·`"512K"`, `output_name` 을 생략하면 `esp-flash`, `esp-flash-002` … 순서로 정한다(`.bin` 자동). `verify="double"` 은 같은 범위를 두 번 읽어 sha256 을 비교한다: 1차는 `--after no-reset-stub` 으로 칩을 다운로드 모드에 둬 앱이 실행되지 않게 하고(NVS 변경 방지), 마지막 읽기 뒤에 요청한 `after` 를 쓴다(`no-reset` 은 `no-reset-stub` 으로). `before="no-reset"`(수동 다운로드 모드)의 이중 읽기는 1차를 min(baud, 115200)으로 읽는다(esptool 은 연결을 115200 으로 맞추므로 1차 뒤 칩이 그 속도에 남아야 2차 연결이 된다. 계획 note 와 gate 의 `read1_baud`). `"none"` 은 한 번 읽는다. 기존 파일은 덮어쓰지 않는다(시작 때 같은 이름이 있으면 `case_error`, 심볼릭 링크인 `dumps/` 도 `case_error`). Secure Download Mode 면 job 이 `esp_secure_download_mode` 로 실패한다 |
| `esp_job_status(job_id, wait_seconds=0)`, `esp_job_cancel(job_id)`, `esp_jobs(active_only=False)` | `register_job_tools(..., "esp")`. 진행률은 esptool 출력의 % 로 계산한다(두 번 읽으면 읽기마다 절반). 끝난 job 의 `result`: `status`(`succeeded`/`cancelled`/`failed`), `path`, `read2_path`, `metadata_path`, `size`, `sha256`, `sha256_read2`, `match`, `verification`, `source`, `backend`, `port`, `esptool_version`, `log_paths`, `artifacts{primary, read2, metadata}`, `warnings`, `notes`, `summary_hint`, `provenance{recorded, kind: "device-read", entries[{path, seq, sha256}]}`(끝까지 성공한(`succeeded`) 덤프의 읽기 파일만 기록 — 이중 읽기면 두 파일, `verify="none"` 이면 한 파일. 실패·취소 때 보존한 1차 읽기는 `recorded: false` 이고, 원장 기록에 실패해도 덤프는 그대로 `succeeded` 이며 `recorded: false`·`reason` 과 `warnings` 가 붙는다 — §4). 취소하면 esptool 프로세스 그룹을 SIGTERM, 이어서 SIGKILL 로 끝낸다. Windows esptool.exe 는 PyInstaller onefile 이라 interop 프로세스를 끝내도 자식이 COM 포트를 잡은 채 남으므로(실측), 명령줄 표식(덤프는 UNC 출력 경로)으로 Windows 프로세스를 찾아 자식부터 끝내고(부트로더가 `%TEMP%\_MEI*` 를 지우고 끝남) 남은 것이 없을 때만 `cancelled` 다. 남으면 job 은 `failed`(`error.code` `esp_orphan_process`, `data.pids`)이고 예약 파일은 그 프로세스가 끝날 때까지 남는다. 시간 초과도 같다 |

- 결과 파일(케이스):
  - `dumps/<name>.bin`: 1차 읽기(대표 덤프). `flash-dump` 아티팩트(`extra.role="primary"`, `extra.metadata`).
  - `dumps/<name>.read2.bin`: 2차 읽기(`verify="double"`). `flash-dump` 아티팩트(`extra.role="verification-read"`).
  - `dumps/<name>.json`: 메타데이터. `other` 아티팩트(`extra.type="dump-metadata"`).
  - `uart/esptool-chip-info-NNN.log`, `uart/esptool-security-info-NNN.log`, `uart/esptool-<name>-readN-NNN.log`: esptool 출력 로그(헤더에 명령·백엔드·버전·종료 코드. 빈 줄과 ANSI 코드는 빼고 진행률 줄은 5% 단위만). `other` 아티팩트(`extra.type="esptool-log"`).
- 출처 원장(§4, 케이스 밖 `.pweh/state/provenance/<case_id>.jsonl`): 끝까지 성공한 덤프의 읽기 파일을 `device-read` 로, `esp_chip_info`·`esp_security_info` 결과를 `device-fact`
  (`fact_kind` `esp-chip-info`·`esp-security-info`, source 에 포트·백엔드·칩·MAC·esptool 버전)로 기록한다. 덤프는 워커가 esptool 이 쓴 직후 계산한 sha256 을 넘기고,
  공개한 파일이 그사이 바뀌었으면 기록하지 않는다. 메타데이터를 쓴 뒤에 기록하므로 원장 기록 실패 경고는 job `result.warnings` 에만 있고 `dumps/<name>.json` 에는 없다.
- esptool 은 모든 데이터를 받은 뒤에만 출력 파일을 쓴다. 그래서 읽는 동안에는 숨은 예약 파일만 둔다: esptool 이 쓰는 `dumps/.<name>.readN.partial`, 소유 표식 `dumps/.<name>.owner.partial`
  (JSON: server, pid, start_ticks, boot_id, host, created_at, job_id. Windows 백엔드는 첫 esptool.exe 를 띄우기 전에 windows_tokens(출력 UNC 경로)·windows_images,
  Windows 프로세스가 남으면 windows_pids·released_at 도), 잠깐 쓰는 `dumps/.<name>.meta.partial`.
  크기를 확인한 뒤 끝날 때 최종 파일(`.bin`, `.read2.bin`, `.json`)을 하드 링크(안 되면 O_EXCL 복사)로 만들고 덮어쓰지 않는다. 계획한 이름이 그사이 생겼으면 `<name>-<job_id>` 로 저장하고 warnings 에 적는다.
  취소·실패한 읽기에는 부분 데이터가 없으므로 예약 파일을 지운다(Windows esptool.exe 가 남은 `esp_orphan_process` 면 그 프로세스가 끝날 때까지 남긴다).
  주인이 죽은 예약(소유 표식이 없거나 pid·start_ticks·boot_id 가 맞지 않고, 남은 Windows PID 도 windows_tokens 경로를 명령줄에 가진 esptool.exe 도 없음 — 확인할 수 없으면
  지우지 않음)은 서버 시작 때(모든 케이스)와 `esp_read_flash_start` 마다(그 케이스) 지운다
  (감사 이벤트 `esp_stale_reservations_removed`). 서버 시작 때 주인(`meta.owner`)이 죽은 queued·running·cancelling 작업 기록은 `jobs/<id>.json` 의 status 를 `abandoned` 로 고친다(`esp_jobs_abandoned`).
  덤프 도중 `dumps/` 가 심볼릭 링크로 바뀌거나 case·dumps 의 실제 경로가 달라지면 esptool 을 띄우기 전·결과를 공개하기 전에 `safety_denied` 로 멈춘다.
  2차 읽기만 취소·실패하면 1차 결과를 `verification.method="none"` 으로 보존한다(job 상태는 `cancelled`/`failed`, `result` 에 보존한 1차 결과).
  두 sha256 이 다르면 job 은 `succeeded` 지만 `match=false` 와 `warnings` 가 붙고 두 파일을 모두 남긴다(낮은 baud 로 다시 읽거나 전원·배선을 확인한다).
- 메타데이터 `dumps/<name>.json`(`schema: "pweh.esp-dump/v1"`)은 firmware-dump 요약과 같은 모양이다: `method: "esptool-read-flash"`,
  `source{type: "esptool", device_path, chip, chip_description, mac, base_mac, usb_mode, flash_size, flash_size_str, offset, length, requested_size, flash_type: "spi-nor", partition, ram_addr}`,
  `output{path, sha256, size}`, `verification{method: "double-read"|"none", expected(1차 sha256), actual(2차 sha256), match, detail}`,
  `reads[{index, path, sha256, size, after, baud, seconds, kbit_s, log_path, started_at}]`, `tool{name, esptool_version, backend, esptool_path, argv[]}`,
  `baudrate`, `status`, `duration_seconds`, `started_at`, `finished_at`, `job_id`, `notes`, `warnings`.
- firmware-dump 요약: job `result.summary_hint`(`method`, `source{device_path, flash_size, offset, length, flash_type}`, `output`, `verification{method, expected, actual, match}`, `baudrate`)는
  firmware-dump 스키마를 그대로 통과한다. 이 값으로 `skill="firmware-dump-via-uart"` 요약을 남긴다(§3).
- 승인 지문(`action`)은 `command`, `port`, `chip`, `baud`, `before`, `after`(실제로 쓸 값), `no_stub` 이고, `after` 를 바꿨으면 `after_requested` 가 더해진다. 덤프는 `offset`, `size`, `output_name`, `verify` 와
  이중 읽기의 `read1_after`(`no-reset-stub`), 1차 baud 가 다르면 `read1_baud` 가 더해진다(`timeout_s` 는 넣지 않음).
  정책 거부(`gate.via: "esp-policy"`)는 승인 경로가 없다. 다른 인자나 다른 도구로 다시 시도하지 말고 사용자에게 보고한다.
- 실행 환경: esptool 은 매번 새로 만든 작업 디렉터리에서 실행하고, 그 안에 `[esptool]` 한 줄짜리 `esptool.cfg` 를 써서 `ESPTOOL_CFGFILE` 로 가리킨다(설정 파일 탐색 —
  현재 디렉터리 → `~/.config/esptool`(Windows `%USERPROFILE%\AppData\Local\esptool`) → 홈 — 보다 앞선다. esptool 5.3.1 이하는 설정의 `custom_reset_sequence` 를 코드로 실행한다).
  - 리눅스: `ESPTOOL_*`·`FORCE_COLOR`·IDE 웹소켓 변수·`PYTHONPATH` 류를 지운 뒤 중립값을 두고 `HOME=<작업 디렉터리>`, `PYTHONIOENCODING=utf-8`, `PYTHONUNBUFFERED=1`, `NO_COLOR=1`.
  - Windows: esptool.exe 는 Windows 쪽 사용자 환경변수를 물려받으므로 WSLENV 를 새로 만들어 정확히
    `NO_COLOR:TTY_COMPATIBLE:TTY_INTERACTIVE:ESPTOOL_CFGFILE/p:ESPTOOL_STUB_VERSION:ESPTOOL_OPEN_PORT_ATTEMPTS:ESPTOOL_FS:ESPTOOL_ENV_FPGA:ESPTOOL_CHIP:ESPTOOL_BAUD:ESPTOOL_BEFORE:ESPTOOL_AFTER:ESPTOOL_CONNECT_ATTEMPTS` 만 넘긴다.
    값: `NO_COLOR=1`, `TTY_*=0`, `ESPTOOL_OPEN_PORT_ATTEMPTS=1`, `ESPTOOL_FS=keep`, `ESPTOOL_ENV_FPGA=0`, `ESPTOOL_CHIP=auto`, `ESPTOOL_BAUD=115200`, `ESPTOOL_BEFORE=default-reset`,
    `ESPTOOL_AFTER=hard-reset`, `ESPTOOL_CONNECT_ATTEMPTS=7`(빈 값은 WSLENV 로 넘어가지 않아 모두 비어 있지 않은 값). `PYTHONIOENCODING`·`PYTHONUNBUFFERED` 는 넘기지 않는다(얼린 파이썬이 무시).
    출력은 엄격한 UTF-8 로 읽고, 아니면 Windows ANSI 코드 페이지(레지스트리 ACP, 한국어 Windows 는 cp949)로 읽는다.
  - `ESPTOOL_STUB_VERSION` 은 esptool 5.3 이상 `"2"`(새 esp-flasher-stub, 그 버전들의 기본), 그 밖 `"1"` 이고 버전 조회는 `"1"` 이다.
  - 서버가 만든 것이 아닌 설정을 읽었다는 줄(`Loaded custom configuration from <다른 경로>`)이 보이면 연결 전에 프로세스를 끝내고 `esp_foreign_config`(`data.config`, `data.expected`)로 실패한다.
- 같은 포트는 한 번에 한 작업만 쓴다(포트 잠금 + job 배타 키 `esp-port:<포트>`, 서버 프로세스 안에서만 유효. 리눅스 포트는 realpath 로 묶는다).
  리눅스 tty 를 다른 프로세스(시리얼 모니터, uart-mcp 세션)가 열고 있으면 `busy` 로 거부한다. Windows COM 포트는 그 포트를 인자로 받은 esptool.exe(`--port COMn`·`--port=COMn`·`-p COMn`)를
  Windows 프로세스 목록(Win32_Process)에서 찾아 `busy`(PID 와 `taskkill /F /PID n` 안내, `data.pids`)로 거부하고, 그 밖의 프로그램이 잡고 있으면 esptool 이 `esp_port_busy` 로 실패한다
  (powershell 이 실패하면 확인하지 못하고 기록만 한 뒤 진행). Windows 프로세스가 남아 있으면 서버 안의 포트 잠금은 풀고 이 확인이 대신 막는다.
- 서버가 SIGTERM 을 받으면 작업을 취소·정리한 뒤(최대 30초) SIGTERM 으로 끝나고, stdin 이 닫혀도 정리한 뒤 끝난다. 서버 종료(atexit) 정리도 Windows esptool.exe 를 자식부터 끝낸다.
- 연결할 때마다 칩이 리셋되어 ROM 다운로드 모드로 들어간다(실행 중이던 앱이 멈춘다). 연결에 실패하면(`esp_no_serial_data`, `esp_wrong_boot_mode`)
  사람이 BOOT(부트 스트랩 핀. ESP32·ESP32-S2·ESP32-S3 는 GPIO0, ESP32-C3·C6·H2 는 GPIO9 — 그 밖의 칩은 데이터시트로 확인)를 누른 채 RESET(EN)을 눌렀다 떼고 BOOT 를 놓은 뒤 `before="no-reset"` 으로 다시 호출한다.
  `after` 가 `no-reset-stub`(`no-reset` 요청 포함)이거나 덤프를 취소하면 칩이 다운로드 모드(스텁)에 남으므로, 일반 부팅이 필요하면 사람이 RESET 을 누른다.
- 덤프 출력의 Windows 경로 요소가 '.'·공백으로 끝나면 `validation_failed` 다(Windows 가 끝의 '.' 을 지워 다른 디렉터리에 쓴다). 그래서 case_id 도 '.' 으로 끝날 수 없다(`CASE_ID_RE`).
- Secure Download Mode 에서는 esptool 로 플래시를 읽을 수 없다(`esp_secure_download_mode`). 이 서버는 글리칭·eFuse 조작 같은 우회를 하지 않는다.
  플래시 암호화가 켜져 있으면 덤프는 암호문이다(`ciphertext_expected=true`). 키는 읽기 보호된 eFuse 에 있으므로 정적 분석은 평문 영역 밖에서 제한적이다.

## 7. REA 연동

- 등록: `.mcp.json` 의 `rea` 서버. `scripts/mcp-launch.sh rea` 가 `~/pweh-tools/env.sh` 를 불러온 뒤 `rea --mcp` 를 실행한다
  (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `REA_BINWALK_COMMAND`, `REA_UNBLOB_COMMAND`, `REA_SIGROK_COMMAND`, 런처 기본 `REA_GHIDRA_STARTUP_TIMEOUT_MS=600000`).
  `pweh mcp-config --style absolute` 형태는 같은 값을 `env` 에 직접 넣는다.
- 실제 도구 이름 (rea 6.5.0 list_tools 로 확인, 전체 목록 `docs/references/rea-mcp-tools.json`):
  - 펌웨어: `inspect_firmware_regions(path)`, `extract_firmware(path, output_directory, range?, max_depth?, max_output_bytes?, max_output_files?)`
  - 네이티브: `open_binary(path, format?, architecture?, entry_point?, provider_id="ghidra")`, `binary_overview`, `list_procedures`,
    `search_strings(pattern, mode?)`, `search_procedures`, `procedure_pseudo_code(procedure)`, `batch_decompile(addresses)`,
    `analyze_function(procedure)`, `inspect_native_api(procedure)`, `xrefs(address)`, `find_xrefs_to_name(name)`, `trace_feature(query)`,
    `trace_call_path(start, goal?, direction?)`, `get_call_graph(address, direction?)`, `procedure_callers`, `procedure_callees`, `read_bytes`, `search_bytes`, `close_binary`
  - 대체 엔진: `inspect_with_objdump(path, operation)`, `execute_rizin_command(path, command)`, `inspect_binary_layout(path)`
  - 증거: `export_evidence_bundle(path, overwrite?)`, `get_evidence_bundle`, `list_unknowns`
  - 신호: `decode_signal_recording(path, decoders, input_format?, annotations?)`, `inspect_signal_decoders(decoder?, query?)`
- REA 제약: 펌웨어 입력 ≤ 128 MiB, `extract_firmware` 의 output_directory 는 존재하지 않는 절대 경로
  (이미 있는 디렉터리를 주면 원인을 알기 어려운 오류가 나므로 매번 `case_paths(purpose="extract", label="rea")` 의 `new_output_dir` 을 새로 받는다),
  `export_evidence_bundle` 의 `path` 는 부모 디렉터리가 이미 있어야 한다(케이스 `analysis/` 아래 파일 경로를 준다. 기존 파일은 `overwrite: true` 필요),
  raw-binary 는 x86/x86_64/arm/arm64/6502 리틀엔디언만 (MIPS raw 불가 → rootfs 의 ELF 를 대상으로. ESP 앱 이미지도 ELF 가 아닌 raw 이미지라 Xtensa·RISC-V 모두 열 수 없다 —
  Ghidra 자체에는 두 언어가 있어 사람이 PWEH 밖에서 직접 로드할 수는 있다),
  MIPS ELF 는 o32 + MIPS32r2 등 엄격한 승인 조건, Ghidra 첫 쿼리는 수 분 걸릴 수 있음 (클라이언트 도구 타임아웃 조정).
  REA 가 거부하면 `inspect_with_objdump` / `execute_rizin_command` / fwtriage 로 대체한다. `execute_rizin_command` 는 Rizin 셸 탈출(`!`)로
  호스트 명령까지 실행할 수 있어(REA 계약: foreign code·파일 변경·네트워크) `.claude/settings.json` 의 `ask` 에 있다.

## 8. 테스트 규칙

- `tests/conftest.py` 의 `workspace` fixture(격리된 설정/케이스/상태 디렉터리)와 `auth` fixture 를 사용한다.
- MCP 서버 테스트는 `tests/mcp_helpers.py` 의 `Client(server)`(in-memory) + `call()` 과, 최소 1개의 stdio 테스트(`stdio_params(module)`).
- 하드웨어 없이 테스트한다: UART 는 `pweh.mocktarget`(PTY/TCP 시뮬레이터), OpenOCD 는 가짜 TCL 서버(+ 실제 openocd dummy 어댑터가 있으면 integration),
  sigrok 은 합성 VCD/.sr 파일과 가짜 `sigrok-cli` 스크립트(+ 실제 sigrok-cli 가 있으면 integration),
  esptool 은 esptool 5.4.0·4.8.1 출력을 흉내 내는 가짜 esptool(`tests/servers/esp_fake_esptool.py`, 이름이 `.exe` 로 끝나면 Windows 빌드처럼 동작하고 PyInstaller onefile 의
  부트로더 + 자식 구조도 흉내 냄. Windows 프로세스 조회·종료는 `tests/servers/esp_testutil.py` 의 `FakeWinProcs` 로 바꾼다)
  (+ 실제 Windows esptool.exe·리눅스 esptool 이 있으면 기기 없이 — version, 없는 COM99 의 취소, 파일만 쓰는 merge-bin, 설정 파일 탐색 — 확인하는 external 테스트).
- 외부 도구가 필요한 테스트는 `@pytest.mark.external` + 도구가 없으면 `pytest.skip`.
  오래 걸리는 테스트(전체 플래시 덤프 e2e 등)는 `@pytest.mark.slow` 다. 기본 실행에서 빠지지 않으므로 빠르게 돌릴 때는 `-m "not slow"` 를 준다.
  실제 하드웨어가 필요한 테스트는 `@pytest.mark.hardware` 이고 기본 skip 이다(`--run-hardware` 또는 `PWEH_HARDWARE=1` 일 때만 실행, `tests/conftest.py`).
- 문서·권한 규칙·Skill 이 실제 도구 카탈로그와 코드(분류기, 서버 반환값)와 맞는지는 `tests/core/test_docs_consistency.py`, `tests/core/test_skills_consistency.py` 가 검사한다.
  도구를 바꾸면 `scripts/dump_tool_catalog.py` 로 카탈로그를 다시 만든 뒤 이 두 파일을 돌린다.
- 서버·도구 목록은 테스트에 적지 않는다: `tests/core/test_docs_consistency.py` 는 카탈로그(`docs/references/pweh-mcp-tools.json`)와 `pweh.cli.SERVERS` 에서 얻고,
  카탈로그 = `pweh.cli.SERVERS` = `scripts/dump_tool_catalog.py` 의 SERVERS = `.mcp.json`(+ rea) 인지 검사한다. 새 서버를 더할 때 고칠 것은 파일 맨 위의 정책 상수뿐이다:
  `FULL_ALLOW_SERVERS`(서버 전체 자동 허용), `FULL_SIGNATURE_SERVERS`(§6 시그니처 전체), `SERVER_DIR_OVERRIDES`(디렉터리가 'pweh-<x>' → '<x>-mcp' 규칙을 벗어날 때), `RULE_ID_PREFIXES`(규칙 id 접두).
  `anthropic/requiresUserInteraction` 은 `destructiveHint` 도구와 정확히 같아야 한다(`ANN_DESTRUCTIVE` 도구에는 `META_REQUIRE_HUMAN` 을 붙이고 safety.md·mcp-setup.md 목록에도 적는다).
  문서의 `pweh <명령>` 예시는 `pweh.cli.build_parser()` 로 해석되어야 한다(하위 명령 목록도 파서에서 얻는다).
- 사람 증명·출처 원장·마스킹 테스트(`tests/core/test_attestations.py`, `tests/core/test_provenance.py`, `tests/core/test_masking.py`)는 `workspace` fixture 의
  격리된 상태 디렉터리만 쓴다. `pweh attest` 는 하위 프로세스로 실행해 TTY 가 아닐 때의 거부를, 가상 터미널(pty)로 대화형 답·목록·철회를 시험한다.
  작업 공간의 실제 `.pweh/state` 는 건드리지 않는다.
- 테스트 파일 위치: `tests/servers/test_<server>.py`, `tests/core/`, `tests/uart/`(uart-mcp 파서·분류·문맥 단위), `tests/fwtriage/`(합성 입력 빌더),
  `tests/mocktarget/`, `tests/e2e/`.
- `tests/e2e/` 의 에이전트는 Skill 순서를 스크립트로 고정한 것이다. 실제 모델이 마스터 프롬프트·Skill 만 보고 끝까지 가는지는
  pytest 밖의 옵트인 하네스 `scripts/run_agent_e2e.py` 로 본다(Claude Code 헤드리스 + 규칙 기반 모의 운영자 + 시뮬레이터, 계정 사용량을 씀).
  실행 전에 정한 기준 C1–C7(소유 확인 먼저, U-Boot 확보, 덤프 sha256 = 이미지, 파괴 이벤트 0, 요약 스키마, 보고서, 자기 승인 없음)로 판정하고,
  `--rejudge <작업공간>` 으로 에이전트를 다시 돌리지 않고 판정만 다시 할 수 있다.
