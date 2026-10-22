# PWEH 아키텍처와 구현 계약

이 문서는 PWEH 파이프라인을 구성하는 서버·Skill·오케스트레이터 사이의 **계약**이다.
구현자와 Skill 작성자는 여기 적힌 도구 이름, 인자, 반환 형식, 파일 위치를 그대로 따라야 한다.
도구를 더 추가하는 것은 괜찮지만, 여기 적힌 이름과 의미는 바꾸지 않는다.

## 1. 전체 구조

```
[사람]  물리 연결(UART 케이블, 프로브, 로직 애널라이저 클립), 전원 껐다 켜기, SD 카드 이미징(쓰기 방지 장치), 위험 작업 승인(pweh approve), 사람 증명(pweh attest)
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
   ├─ pweh-forensics   (mcp-servers/forensics-mcp)   SD·Android 논리 증거 분석: 접수·해시·보관 기록, FAT/exFAT·TAR/ZIP 목록, SQLite·앱 기록·타임라인 — 기기 미접촉 (선택)
   ├─ pweh-emu         (mcp-servers/emu-mcp)         ESP32·S3·C3/Arduino AVR 펌웨어 실행·마스킹 콘솔 — 기기 미접촉 (선택)
   ├─ pweh-espprobe    (mcp-servers/espprobe-mcp)    ESP32-S3 계측기 프로토콜·시뮬레이터 (선택, 현재 오프라인 검증만)
   └─ rea              (외부: rea-agents 6.5)        binwalk/unblob 추출, Ghidra 디컴파일, sigrok 디코딩
            │
      [대상 기기]  (또는 테스트용 pweh.mocktarget 시뮬레이터. pweh-forensics 는 기기 대신 사람이 만든 카드 이미지 파일을 받는다)
```

공통 코어 패키지 `pweh` (`src/pweh/`) 가 설정, 케이스 저장소, 안전 게이트, 사람 증명·출처 원장·비밀값 마스킹(§4), 작업(job) 관리, MCP 헬퍼를 제공한다.
SD 카드 이미지 해석 엔진(`pweh.fs`), 증거 보관 기록·EV 번호·증거 목록(`pweh.evidence`), 믿을 수 없는 파일·디렉터리를 링크를 따르지 않고 다루는 도구(`pweh.safeio`)도 코어에 있다(§6.8).

## 2. 저장소 레이아웃

| 경로 | 내용 |
|---|---|
| `src/pweh/` | 공통 코어: `config.py`, `case.py`, `safety/`(분류기·게이트·승인·사람 증명·비밀값 마스킹), `provenance.py`(출처 원장), `jobs.py`, `runtime.py`, `mcpkit.py`(서버 생성 — 네이티브 Windows·Cygwin·MSYS 는 시작 거부), `ports.py`(포트 문법·경로·열거), `portidentity.py`(PnP/sysfs 식별·USB 형제 범위), `usb_binding.py`(주입된 Windows USB 관찰의 유일 후보·전체 잠금 범위·fresh 검사), `portlock.py`(open 전 OS 잠금·역할 표지), `serialtransport.py`(직렬 핸들·TIOCEXCL), `procutil.py`(PID 신원·생존 확인, pidfd·프로세스 그룹 종료), `espfmt.py`(ESP 파티션·앱·NVS 공용 해석 — fwtriage 는 재노출 shim), `console.py`(줄 경계 커서·열린 프롬프트·반복 접기), `safety/redact.py`(공용 자격증명 패턴·콘솔 마스킹), `hostenv.py`(실행 환경 감지 — WSL1/2·interop·네트워킹 모드·usbipd·컨테이너, 추천 경로; `pweh env`·doctor·`pipeline_environment`·esp 가 쓴다), `toolsdir.py`(외부 도구 위치, esptool.exe 후보), `report.py`, `cli.py`, `clientcfg.py`(Codex 클라이언트 설정: Codex 홈 감지 — CLI·데스크톱 앱 WSL 모드·`--codex-home`, 프로젝트 `.codex/config.toml` 생성, 전역 `config.toml` 병합과 trust 항목(tomlkit 으로 주석·서식 유지, 백업·다시 읽어 검사·원자적 교체) — `cli.py` 의 `mcp-config --client codex`·`codex-trust`·`mcp-check`·doctor 가 쓴다, docs/mcp-setup.md §3), `audit.py`, `errors.py`, `fsutil.py`, `formats.py`(mtdparts·uImage·U-Boot env·md.b/crc32 출력 파서), `evidence.py`(SD 카드 증거: 보관 기록 해시 체인 + 상태 폴더 고정점(세 단계 덧붙이기), 접수 기록과 상태 재생·`status_label`, EV 번호 확보와 중단된 접수 정리, 내용 도구의 무결성 입구, 이미징 로그 해석, 입력 검사·빠른 지문 — pweh-forensics 와 보고서 §8.1 이 쓴다), `safeio.py`(믿을 수 없는 파일·디렉터리: 일반 파일만 lstat → `O_NOFOLLOW\|O_NONBLOCK` → fstat 대조로 열기, 디렉터리는 한 구성요소씩 `O_DIRECTORY\|O_NOFOLLOW`, 파일은 디렉터리 fd 기준 `O_EXCL` 로 만들고 fd 로 fchmod, flock 잠금 — `pweh.evidence`·pweh-forensics·case-mcp 의 증거 가드가 쓴다), `fs/`(카드 이미지 파일 시스템 엔진: MBR/EBR·GPT·superfloppy, FAT12/16/32·exFAT. 순수 파이썬·읽기 전용, 공개 사양만으로 새로 작성, 모든 반복은 `Limits` 로, 공개 호출 하나는 `Budget`(시간·볼륨별 단계 상한·취소)으로 묶음, 디렉터리 데이터는 단위마다 검증한 뒤 해석), `schemas/`, `mocktarget/`, `data/` |
| `mcp-servers/<name>-mcp/<name>_mcp/` | 서버 패키지 (`server.py` 에 `server` 객체와 `main()`), `mcp-servers/<name>-mcp/README.md`. pweh-forensics 는 `pweh.fs` 위의 작업(볼륨 고르기·호출 예산·목록 요약·호스트 오염 흔적·ref 확인·추출)을 `mcp-servers/forensics-mcp/forensics_mcp/fsops.py` 에 둔다 |
| `skills/<skill>/SKILL.md` | 에이전트용 워크플로 (`.claude/skills/`·`.agents/skills/` 에 심볼릭 링크 — `pweh skills install --target claude-project`, `pweh skills install --target agents`) |
| `native/emu/` | simavr 고정 커밋을 정적 링크하는 `pweh_avr_run.c`. 플래시 경계 밖 접근 보완, GDB 소켓 코드 제외, Intel HEX 입력(§6.9) |
| `scripts/` | `install.sh`(원클릭 설치: 구성요소 → `mcp`·`skills`·`verify` 단계, docs/mcp-setup.md §1), `mcp-launch.sh`(Claude Code·Cursor 용 MCP 서버 런처, env.sh 자동 로드), `dump_tool_catalog.py`(도구 카탈로그·권한 검사), `run_example.py`, `run_agent_e2e.py` |
| `.mcp.json`, `.claude/`, `.agents/skills/` | 에이전트 클라이언트 설정(커밋됨): Claude Code 프로젝트 MCP 서버(`.mcp.json`), 권한 규칙·`enabledMcpjsonServers`(`.claude/settings.json`), Skill 링크(`.claude/skills/` — Claude Code, `.agents/skills/` — Codex·Cursor) |
| `.codex/config.toml` | Codex 프로젝트 MCP 설정. `pweh mcp-config --client codex --write` 가 만드는 생성물(이 PC 의 절대 경로·env.sh 의 도구 경로가 들어 있어 커밋하지 않음. 실행한 셸의 PATH 는 넣지 않는다). Codex 는 trusted 프로젝트에서만 읽는다(`pweh codex-trust`) |
| `orchestrator/` | `master-prompt.md`, `pipeline-config.yaml` |
| `schemas/` | → `src/pweh/schemas` 심볼릭 링크 (JSON Schema. Skill 요약 스키마는 §3 표 — SD 카드 포렌식은 `sd-forensics.schema.json`) |
| `docs/` | 안전/하드웨어/MCP 설정 가이드, `references/` (프로토콜·출력 형식 조사 자료) |
| `examples/` | 실제 실행(시뮬레이터)으로 만든 예제 케이스 |
| `tests/` | pytest. `tests/mock-targets/` 는 녹화 로그와 그 생성 스크립트(시뮬레이터 프로필·합성 펌웨어 빌더는 `src/pweh/mocktarget/`) |
| `cases/` | 실제 분석 케이스 (git 제외) |
| `.pweh/state/` | 케이스 ID 예약(`case-ids/`), 승인 레코드(`approvals/`), 사람 증명(`attestations/`), 출처 원장(`provenance/<case>.jsonl`), 마스킹 솔트(`salts/<case>.key`), SD 카드 보관 기록 고정점(`custody/<case>.jsonl`), 전역 감사 로그(`audit.jsonl`) (git 제외, 에이전트 수정 금지. 모두 처음 쓸 때 만든다) |

패키징: 루트 `pyproject.toml` 하나로 모든 패키지를 설치한다 (`pip install -e ".[dev]"`).
콘솔 스크립트: `pweh`, `pweh-case-mcp`, `pweh-uart-mcp`, `pweh-openocd-mcp`, `pweh-sigrok-mcp`,
`pweh-jtagulator-mcp`, `pweh-fwtriage-mcp`, `pweh-esp-mcp`, `pweh-forensics-mcp`, `pweh-emu-mcp`, `pweh-espprobe-mcp`, `pweh-mock-device`.

장치 연결과 독립된 내부 해석 코어도 제공한다. 다음 모듈은 이미 공급된 bytes·수치만 받고 파일·장치·외부 프로그램을 열지 않는다.
MCP 도구와 케이스 입구는 아직 연결하지 않았으며, 파일의 선언을 소유/허가·실제 기기 식별로 해석하지 않는다.

| 내부 모듈 | 제한된 계약 |
|---|---|
| `pweh.rf_formats` | Flipper RAW v1의 선언값·부호별 펄스 통계. 줄 전체를 검증한 뒤 집계하고, 손상·미지원·예산 중단과 완전한 검사를 구분한다. 원시 펄스 목록·키·ID는 반환하지 않는다. [제한 프로필](references/flipper-raw-profile.md) |
| `pweh.nfc_formats` | Flipper NFC v4 ISO14443-3A·NTAG213/215/216 구조와 저장된 페이지의 변화 위치. UID·페이지 내용·PWD/PACK·카운터 원문은 반환하지 않는다. 부분 읽기의 0값을 읽힘 증거로 사용하지 않는다. [제한 프로필](references/nfc-file-profile.md) |
| `pweh.vision_sequence` | 최대 256개 숫자 관찰의 최근 창·TTL·신뢰도·득표 판정. `stable/unknown/stale`은 관찰값 합의이며 영상 정지·게임 상태·버튼 동작 판정이 아니다. [모델 계약](references/numeric-observations.md) |

### 2.1 Windows 번들의 로컬 설치·정적 검사

`pweh.windows_bundle`은 패키지의 등록 색인 → manifest SHA → 정확한 payload 파일·디렉터리 집합을 검증한다.
OpenOCD/sigrok 등록 버전만 받고 불변 결과·동일 fd 읽기·원래 신원 재대조를 제공한다. source 내용 검증과 설치본 receipt·고정 권한 검증을 구분한다.
등록 receipt가 맞아도 전체 파일 크기·SHA 검증을 생략하지 않는다. 상한·출처·API는 [Windows 번들 계약](references/windows-bundles.md)에 있다.

`scripts/install.sh --only openocd-win|sigrok-win --windows-bundle-source TOOL=DIR`는 별도 `scripts/windows_bundle.py`로
이미 추출한 등록 payload를 복사한다. 기본/all/minimal에는 포함하지 않으며 기존 구성요소와 혼합하지 않는다.
관리 위치는 `<tools-root>/windows-bundles/<tool>/<release_id>-<manifest-sha256>/`다. 검증한 source fd에서 pending으로 복사하고
게시 전 source를 다시 대조하며, 기존 release를 덮어쓰지 않는다. 설치본이 검증되면 재호출은 성공하며 `--force`도 손상본을 덮어쓰지 않는다.
이 경로는 env.sh·포인터·사용자 설정을 쓰거나 다운로드·Windows 실행·MCP 등록을 하지 않는다.

선택은 `tools.openocd_win_bundle`/`tools.sigrok_win_bundle` → `PWEH_OPENOCD_WIN_BUNDLE`/`PWEH_SIGROK_WIN_BUNDLE` → 등록 관리 기본 위치다.
명시 경로는 WSL/Linux에서 보이는 release root의 절대 경로이고 잘못된 명시는 fallback 없이 실패한다.
`pweh doctor --windows-bundles-only --json`는 env.sh 실행·환경 감지·포트 조회·도구 버전 실행·case/state 생성 **앞에서** 정적 분기로 끝난다.
관리 기본 설치 없음은 `ok=null`, 등록 tree 일치는 `true`, 명시 경로·receipt·hash 오류는 `false`이며 실패가 있으면 비0 종료다.
성공도 Windows 실행 미확인·이 진단으로 backend를 활성화하지 않음·실기 미확인을 함께 표시한다. 기존 전체 doctor와 hostenv 경로 추천은 유지한다.
MCP 도구·안전 게이트·장치 route를 추가하거나 활성화하는 기능은 아니다.

## 3. 케이스 디렉터리 (Skill 사이의 데이터 전달)

케이스 생성은 `Runtime` 이 넘긴 `state_dir` 에 ID 예약을 남긴다(`case-ids/<casefold ID의 sha256>.json`).
케이스 폴더를 지워도 예약은 남으므로 같은 ID를 새 케이스에 쓸 수 없다. 대소문자만 다른 ID도 같은 이름으로 취급한다.
예약 도입 전의 승인·증명, 출처 원장·솔트·보관 기록 고정점 흔적도 확인한다. 명시한 ID가 충돌하면 거부하고, 자동 ID는 숫자 접미사를 늘려 선택한다.
기존 파일·불완전 디렉터리·링크도 충돌이며 덮어쓰지 않는다. 생성 잠금 안에서 ID를 예약하고 새 디렉터리를 배타적으로 만든다.
예약 뒤 생성이 실패하면 그 ID는 재사용하지 않는다. 기존 케이스의 조회·수정에는 새 예약이 필요하지 않다.
보호 상태를 안전하게 검사할 수 없으면 새 생성을 거부한다. 과거 감사 로그만 남은 ID와 구버전 서버와의 경합 한계는 `docs/safety.md` §3.5에 적는다.
예약 파일은 본문을 읽지 않고 해당 해시 이름의 객체가 있으면 사용된 ID로 본다. 승인·증명 JSON은 케이스 참조를 읽으며,
손상·미완성 파일·알 수 없는 항목을 만나면 `case_id_state_unverified`로 멈춘다. 생성 호출 하나의 검사 한도는 이름 100,000개,
참조 JSON 각 1 MiB·합계 64 MiB, 검사·후보 탐색 10초, 자동 후보 100,000개다. 기존 ID 충돌은 `case_id_used`다.
내부 라이브러리의 `CaseStore(cases_dir)` 단독 호출은 기존 인자 호환을 위해 경로 충돌·생성 잠금만 적용한다.
서버는 반드시 `Runtime`을 사용하며, 이 경로는 `state_dir`를 전달해 보호 예약·과거 상태 검사까지 적용한다.

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
  report.md            report_generate 결과 (forensics/ 가 있으면 §8.1 SD 카드 증거: 보관 기록 상태(고정점 대조)·증거 표(상태 칸은 status_label)·고지)
  patches/             세이브 패치 이미지(fw_patch_build — 계획·쓰기 준비. 권위 기록은 출처 원장의 patch-plan)
  emu/<session_id>/    에뮬레이션 세션(처음 실행할 때 생성, 디렉터리 0700·파일 0600): console.bin(원시 UART),
                       transcript.masked.txt(마스킹 기록), emulator.stderr.log, events.jsonl, meta.json, tmp/(스냅숏 오버레이).
                       펌웨어 사본은 파일로 남기지 않는다(봉인 memfd). 에이전트는 emu_read 로만 본다(§6.9)
  forensics/           SD 카드 증거 (pweh-forensics 만 쓴다. 처음 접수할 때 만든다 — §6.8. 아래 디렉터리는 링크를 따르지 않고 한 구성요소씩 열고,
                       파일은 그 디렉터리 fd 기준 O_EXCL 로만 만든다 — pweh.safeio)
    images/EV-NNNN/    접수한 이미지 사본(원본 파일 이름의 글자·숫자·._- 밖의 문자를 _ 로 바꾼 96자 이하. 예약 이름과 겹치면 접수 거부), 접수 기록 EV-NNNN.json,
                       이미징 로그 사본 imaging-log.txt (파일 0444, 커밋한 뒤 디렉터리 0555).
                       접수 중에만 복사 중 이름 <이름>.partial 과 접수 잠금 .intake.lock 이 있다 (커밋하면 잠금 파일을 지운다)
    images/.claim.lock EV 번호 확보·정리 잠금 (0600)
    aborted-intakes/EV-NNNN-<YYYYMMDDTHHMMSSZ>[-k]/   커밋하지 못한 접수(서버가 복사 중 죽음 등)를 옮겨 둔 곳 — 증거가 아니다
                       (파일 0444, 디렉터리 0555, 보관 기록 intake-aborted 로 번호를 소비. 지우지 않는다)
    custody.jsonl      보관 기록 (pweh.custody/v1 해시 체인, 덧붙이기만. 잠금 .custody.lock(0600) 안에서 통째로 원자적 교체 → 0644).
                       고정점은 케이스 밖 .pweh/state/custody/<case_id>.jsonl (디렉터리 0700, 파일 0600)
    analysis/fs-list-<EV>-NNN.json   forensics_fs_list 의 전체 목록 (0444)
    recovered/<label>-NNN/           forensics_extract 추출물 NNNN-<정리한 이름>(region=residual 이면 .residual) + manifest.json
    recovered/media-prefix-NNN/      저장된 미디어 후보 앞부분 candidate-000.bin + manifest.json
                                     (파일 0444, 다 쓴 뒤 디렉터리 0555)
    evidence-list.json, evidence-list.md   forensics_evidence_list 의 증거 목록·해시값 확인서 (부를 때마다 원자적으로 다시 씀 → 0644)
  attestations.json    사람 증명의 읽기 전용 사본(0400, 그 케이스의 증명 레코드가 바뀔 때 다시 만든다. 사람이 보는 용도 — 보고서 생성기는 아직 읽지 않는다).
                       권위 기록은 .pweh/state/attestations/ — 서버는 이 파일을 증거로 읽지 않는다
```

규칙:
- 모든 하드웨어 도구는 `case_id` 를 받고, 산출물을 해당 케이스 하위 디렉터리에 쓰고, `case.register_artifact(...)` 로 등록한다.
- 하드웨어 도구는 `rt.case(case_id, hardware=True)` 로 케이스를 열어 소유/허가 증명을 강제한다 (`safety.require_authorization`).
- 경로는 항상 `case.path(...)` / `case.resolve_path(...)` 로 만든다 (케이스 밖 경로 차단).
- 각 Skill 은 끝날 때 `case_record_step(step="summary", data=<Skill 출력 스키마>)` 를 호출한다.
  다음 Skill 은 `case_get_step_results` 로 이전 요약을 읽는다.
- 예외로 `forensics/` 는 pweh-forensics 만 쓰고, 이미지 사본만 아티팩트(`evidence-image`)로 등록한다. 파일 목록·추출물·증거 목록은 아티팩트 대신 보관 기록(`custody.jsonl`)에
  sha256 으로 남긴다. pweh-fwtriage, pweh-sigrok 의 입력, `case_import_file`·`case_hash_file`·`case_register_artifact` 는 이 폴더를 입력으로 받지 않는다(§4, §6.1, §6.8).

| Skill | summary data 스키마 |
|---|---|
| uart-shell-acquisition | `schemas/uart-recon.schema.json` |
| firmware-dump-via-uart | `schemas/firmware-dump.schema.json` |
| firmware-static-analysis | `schemas/static-analysis.schema.json` |
| logic-analyzer-protocol-decode | `schemas/signal-capture.schema.json` |
| cctv-auth-bypass-hunt | `schemas/auth-hunt.schema.json` |
| game-save-unlock-analysis (선택 단계) | `schemas/save-analysis.schema.json` |
| firmware-emulation (선택 단계) | `schemas/emulation.schema.json` |
| android-forensics (선택 단계) | `schemas/android-forensics.schema.json` (입수·분석 해시, 앱 내용 반환 여부, 복구 후보·범위·시각 기준) |
| image-hints-analysis (선택 단계) | `schemas/image-hints.schema.json` (도구 사실·모델 시각 관찰·가설을 분리) |
| sd-card-forensics (선택 단계) | `schemas/sd-forensics.schema.json` (`mode`: evidence/security/both — evidence·both 면 `legal`·`evidence`·`custody_ok`, security·both 면 `security` 가 필수. `privacy` 의 네 값 `audio_decoded`·`face_plate_processing`·`uploads`·`recording_content_viewed`는 항상 false(영상·음성·별도 신원 식별·외부 제공). 정지 그림은 `still_image_content_viewed`·`still_image_ocr_returned`로 별도 기록. 선택 비밀값 검사는 `secret_scan_results`와 `secret_plaintext_returned=false`, 보고서 이름 대조는 `ioc_scan_results`, 선택 미디어 구조는 `media_inventory_results`, 연속 구조 후보는 `media_candidate_results`) |

- firmware-dump-via-uart 밖에서 얻은 덤프(JTAG, SPI 클립, ESP32 esptool)도 다음 Skill 이 찾을 수 있게 `skill="firmware-dump-via-uart"` 로 firmware-dump 요약을 남긴다(master-prompt §5).
  `esp32-flash-dump` Skill 은 따로 요약 스키마를 두지 않고 이 규칙을 따른다: `method` `esptool-read-flash`, `verification.method` `double-read`
  (`expected`/`actual` = 두 읽기의 sha256, `match`). 값은 `esp_read_flash_start` job `result.summary_hint` 에 그대로 있다(§6.7).
- ESP32 덤프용 스키마 값: firmware-dump `method` 의 `esptool-read-flash`, static-analysis `firmware.source` 의 `esptool-dump`.

단계(phase) 상태 — `case.json` 의 `phases` (코드: `src/pweh/case.py`):
- **파이프라인 단계**(`PIPELINE_PHASES`, 보안 분석 목표): `uart-shell-acquisition`, `firmware-dump-via-uart`, `logic-analyzer-protocol-decode`,
  `firmware-static-analysis`, `cctv-auth-bypass-hunt`, `report`. `case_create` 가 모두 `pending` 으로 만든다.
- **선택 단계**(`OPTIONAL_PHASES`, 다른 목표·계측기용 Skill 에 예약한 이름): `game-save-unlock-analysis`, `nfc-behavior-analysis`, `game-play-automation`,
  `flipper-rf-analysis`, `sd-card-forensics`, `espprobe`, `firmware-emulation`, `image-hints-analysis`, `android-forensics`. 미리 만들지 않는다. 그 Skill 이 summary 를 기록하거나 `case_set_phase` 로 상태를 정할 때 처음 생기므로,
  그 목표를 쓰지 않는 케이스의 `case.json`·보고서는 그대로다. 이 가운데 Skill 이 있는 것은 `game-save-unlock-analysis`(요약 스키마 `save-analysis`)와 `sd-card-forensics`(요약 스키마 `sd-forensics`), `firmware-emulation`(요약 스키마 `emulation`), `image-hints-analysis`(요약 스키마 `image-hints`), `android-forensics`(요약 스키마 `android-forensics`)이다. 나머지는 아직 없으므로 에이전트용 문서(master-prompt·Skill)에 그 이름을 적지 않는다.
  Skill 을 만들 때 `SKILL_DATA_SCHEMAS`·master-prompt §5 표·`report._PHASE_LABEL` 에 함께 등록한다.
- 상태 값: `pending`, `in-progress`, `done`, `partial`, `failed`, `skipped`, `blocked`. summary 의 status 는 `success` → `done`, `in-progress` → `in-progress`,
  나머지(`partial`·`failed`·`blocked`·`skipped`)는 같은 이름으로 옮긴다(`SUMMARY_PHASE_STATUS`).
  두 목록에 없는 Skill 의 summary 는 단계 상태를 만들지 않는다(예: `esp32-flash-dump` 는 요약을 `firmware-dump-via-uart` 로 기록한다). `case_set_phase` 는 단계 이름을 검사하지 않는다.
- 보고서(`report_generate`) §4 는 파이프라인 단계 표와 그 요약 뒤에, 상태나 요약이 기록된 파이프라인 밖 단계가 있을 때만 `### 선택 단계` 를 붙인다
  (표 + `####` 단계별 요약. 선택 단계는 레지스트리 순서, 등록되지 않은 Skill 은 기록 순서). 요약의 `data` 는 싣지 않는다. 그런 단계가 없으면 보고서는 전과 같다.
- 분석 목표(보안 분석 / 게임 콘솔 분석 / RF·하드웨어 분석 / SD 카드 포렌식)는 `case.json` 필드가 아니다. master-prompt Phase 0 이 `case_create` 의 `notes` 에 적는다
  (목표마다 지원 범위 — 전용 Skill 이 있는 것과 준비 중인 것 — 는 master-prompt §3·§3.1·§9).

아티팩트 kind 어휘: `uart-log`, `uart-raw`, `uart-events`, `flash-dump`, `memory-dump`, `partition`,
`firmware-image`, `extracted-tree`, `signal-capture`, `signal-decode`, `jtag-dump`, `jtag-scan`, `triage-report`,
`rea-evidence`, `decompilation`, `report`, `evidence-image`, `other`.

`evidence-image` 는 pweh-forensics 가 접수한 카드 이미지 사본(`forensics/images/EV-NNNN/…`, `extra.evidence_id`)이다. 이 서버는 그것만 등록한다.

`jtag-scan` 은 핀아웃 스캔 기록(JTAGulator 세션 기록, 스캔 원시 출력, 결과 JSON)용이다. 단 현재 pweh-jtagulator 구현은 이 파일들을
`kind="other"` 로 등록하고 종류를 `extra.type`(`session-transcript`, `scan-raw`, `scan-result`, `device-ids`, `bypass-test`, `gpio-read`)에 둔다.
`register_artifact` 는 kind 값을 검증하지 않으므로 이 어휘는 문서 계약이다.

## 4. 안전 모델 (모든 서버 필수)

위험도 (`pweh.safety.Risk`): `OBSERVE < INTERACT < MODIFY < DESTRUCTIVE`.

| 위험도 | 예 | 기본 정책 |
|---|---|---|
| OBSERVE | 포트 목록, 버퍼 읽기, 로직 캡처 | 허용 |
| INTERACT | `printenv`, `md.b`, `sf read`(RAM), `crc32`, `cat /proc/mtd`, `scan_chain`, `mdw` | 허용 |
| MODIFY | `setenv`(저장 안 함), `boot`, `reset`, `halt`, DTR/RTS 토글, 서비스 시작, `emu_start`(확보한 펌웨어를 호스트에서 실행), JTAGulator 스캔, 결과를 저장하는 `crc32 <주소> <크기> <대상>`, `/dev/watchdog`·`/dev/mem` 읽기, esptool 연결(`flash-id`·`get-security-info`·`read-flash` — 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁) | 허용 (`safety.modify_policy`) |
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
    `destructive_policy: approve` 여도 승인 경로가 없다. 이 정책 거부를 통과한 OLS+명시 직렬 scan/show는 프로토콜 reset 때문에 서버에서 MODIFY로 올리고 기존 `modify_policy`·`approval_id` 게이트를 적용한다.
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
    `jtagulator_connect` 는 문자장치 절대경로·루프백 `socket://`·`rfc2217://`·`loop://`를 받는다. `spy://`·`hwgrep://`·LAN 호스트는 거부한다.
    COM 직렬 경로는 WSL1 COM1–191의 ttyS 대응과 WSL interop의 검증된 helper를 지원한다. WSL1 COM192 이상도 helper를 쓴다. 공용 portlock을 승인·open 전에 잡아 다른 PWEH 세션의 장치와 URL에 재동기화 키(Ctrl-X, CR)를 보내지 않는다.
    UART가 남긴 target/bridge 역할 표지와 식별 불확실성도 연결 전에 확인한다. POSIX transport는 exclusive와 TIOCEXCL을 사용한다(§5).
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
  증명을 요구하는 도구는 `fw_patch_build`(세이브 쓰기 명령을 보여 주기 전 `console-offline` — 네트워크 차단·재부팅 없음·변경 의사·판매 토큰 콘텐츠 아님, 30분 유효, 패치·백업·편집·선언에 묶임)와
  `forensics_acquisition_attest`(카드 이미징의 `write-blocker` — 쓰기 방지 장치 사용·모델·시험 여부·이미징 도구, 증거 id·sha256·크기에 묶임, 90일. 결과를 보관 기록에 남길 뿐 다른 도구를 막지 않는다 — §6.8),
  `emu_start`(가져온 펌웨어의 `provenance-import` — 케이스·파일 sha256 에 묶임, §6.9)이다.
  사람에게 보이는 요약·질문은 `display_text` 로 제어·서식 문자를 이스케이프한다(`pweh attest` 화면, elicitation 폼 — 기기에서 온 문자열이 화면을 조작하지 못하게).
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
    실패·취소 때 보존한 1차 읽기는 기록하지 않는다), `device-fact`(`esp_chip_info`·`esp_security_info` 결과. data 를 원장에 그대로 둔다), `imported-unattested`(`case_import_file`,
    그리고 `forensics_intake_start` 의 접수 기록 파일 `EV-NNNN.json` — extra 에 이미지 sha256·크기. 이미지 파일 자체는 원장 항목이 아니다).
  - `verify(case, path, *, data=None)` → `{trusted, kind, record, reason, path, sha256}`: 체인 전체를 검증하고(하나라도 깨지면 모두 불신 — `ledger-chain-broken`), 그 경로의 마지막 항목과
    지금 파일의 sha256 을 맞춘다(`data` 가 있으면 경로를 열지 않고 그 바이트를 해시한다. `sha256-mismatch`. 그 밖의 불신 이유는 `not-recorded`, `file-missing`). `device-read` 는 신뢰하고, `imported-unattested` 는 `provenance-import` 증명
    (같은 sha256·같은 케이스 — `provenance_import_target`, `PROVENANCE_IMPORT_QUESTIONS`)이 있을 때만 신뢰한다(`imported-attested`).
    `device-read` 는 출처(기기에서 읽음)이지 무결성이 아니다 — 이중 읽기가 어긋난 덤프(`source.match=false`)는 기록하지만 `verify` 는 신뢰하지 않는다(`device-read-mismatch`).
    검증하지 않은 단일 읽기(`match=null`)는 출처로 신뢰하므로, 무결성이 필요한 쪽(패치 base 등)은 `record.source.verify` 를 따로 확인한다.
  - 확인과 사용 사이에 에이전트가 케이스 파일을 바꿀 수 있다. 쓰는 쪽은 `verify` 가 돌려준 sha256 을 승인 지문·job 인자에 묶고, 실행 직전 같은 sha256 인지 다시 해시하거나 확인한 바이트를 그대로 쓴다.
    `verify` 를 부르는 도구는 `fw_patch_build`(base·백업), `fw_verify_writeback`(읽기 확인 덤프), `emu_start`(한 번 읽은 바이트를 `data` 로 확인하고 봉인 memfd 로 전달)이다. 출처가 중요한 다른 작업(올리기·계측기 플래시 절차)도 이 함수로 확인한다.
  - 원장 kind 를 늘린 뒤에는 모든 MCP 서버를 다시 시작한다 — 옛 코드의 서버는 모르는 kind 를 깨진 체인으로 보고 그 케이스의 출처 확인을 모두 실패시킨다(fail closed).
  - `patch-plan`(fw_patch_build 가 쓰기 명령을 보여 줄 때): 패치 파일 sha256, base·백업의 원장 seq, 대상(절대 오프셋·크기), 기기(MAC·포트), 증명 id. 기기에서 읽은 것이 아니므로 `verify` 의 신뢰 근거가 되지 않고,
    `fw_verify_writeback` 이 기대 sha256 의 권위 기록으로만 쓴다(패치 파일·결과 JSON 은 에이전트가 바꿀 수 있어 증거가 아니다).
  - 기록 실패는 기기 결과를 막지 않는다. 응답의 `provenance: {recorded: false, reason}` 로 알리고(덤프는 job `result.warnings` 에도), 원장에 없는 파일은 불신이다(fail closed).
  - 한계: 해시 체인과 증명 레코드의 재확인에는 비밀 키가 없다. 실수와 단순 변조를 드러낼 뿐, 같은 OS 계정의 프로세스가 원장 전체를 일관되게 다시 쓰거나,
    올바른 `prev` 로 끝에 줄을 덧붙이거나, 레코드를 처음부터 위조하는 것은 막지 못한다(docs/safety.md §3.5). 보호 상태는 케이스 id 로만 묶인다
    — 사람이 `cases/<id>` 를 지운 뒤 같은 id 로 케이스를 다시 만들면 예전 원장·증명·솔트를 이어받는다.
  - `case_import_file` 은 state_dir 안의 파일을 가져오지 않는다(보호 상태를 케이스로 복사해 읽어 내지 못하게). 대상은 `O_EXCL` 로 새로 만든다(같은 이름의 파일·링크가 있으면 거부).
    어느 케이스의 `forensics/`·`emu/` 아래 파일도 가져오지 않는다(풀기 전 경로와 링크를 푼 경로를 모두 본다 — 보호 폴더 자체가 링크여도 그 아래 경로로 부르면 막는다. 카드 이미지·추출물을 자동 허용 도구가 읽는 `dumps/` 같은 곳으로 옮기지 못하게, 아래 SD 카드 증거).
    확인한 뒤 원본을 경로로 다시 열어 복사하므로 그 사이에 같은 계정 프로세스가 이름을 바꿔치기하는 것은 막지 못한다(docs/safety.md §3.6).
- **비밀값 마스킹** — `src/pweh/safety/masking.py`. 게이트 `action` 과 `classification.matched` 에는 원문 대신 `rt().secret_digest(case_id, 값)`
  (`sha256:` + sha256(케이스 솔트 ‖ 값)의 앞 16 hex) 또는 `<given>` 만 넣는다. 그러면 승인 지문·감사 로그·승인 레코드·`approval_status` 응답에 원문이 남지 않는다.
  같은 케이스의 같은 값은 늘 같은 다이제스트라 재시도 지문이 맞고, 케이스가 다르면 달라진다. 증명 subject 에 비밀이 들어가야 할 때도 다이제스트를 쓴다.
  응답·보고서에는 `mask_secret(값)` 을 쓴다(16자 이상은 앞뒤 2자와 길이, 10–15자는 앞뒤 1자와 길이, 더 짧은 값과 바이트는 길이만).
  솔트는 `.pweh/state/salts/<case_id>.key`(32 바이트, 0600, 처음 쓸 때 만들고 바꾸지 않는다)다.
  게이트 `action` 의 비밀은 `shell_login` 의 비밀번호와 `emu_write` 의 입력 모두 `<given>` 으로 남긴다. 다이제스트는 `fw_esp_nvs`·`fw_save_diff` 가 NVS 비밀값(Wi-Fi 비밀번호·토큰 등)을
  응답·결과 파일에 표시할 때 마스킹과 함께 쓴다(게이트 `action` 에 다이제스트를 넣는 도구는 아직 없다).
  비밀번호 프롬프트에 `uart_send_command` 로 입력하면 원문이 게이트 작업 내용과 감사 로그에 남는다 — 로그인은 `shell_login` 으로 한다.
  - 한계: 솔트는 같은 OS 계정의 에이전트가 읽을 수 있다(파일 도구, 자동 허용된 REA `open_binary` + `read_bytes`). 다이제스트는 보고서·감사 로그를 읽는
    제3자에게서 원문을 가리지만, 에이전트에게서 낮은 엔트로피 값(짧은 PIN, 32비트 PWD_AUTH, 24–32비트 ID)을 가리지는 못한다 — 그런 값은 게이트에 넣지 않는다(`<given>`).
- **SD 카드 증거**(pweh-forensics, §6.8) — 이 서버는 기기에 아무것도 보내지 않으므로 분류기·게이트가 없다(`approval_id` 인자도 없다). 대신 다음으로 지킨다.
  - job 도구를 뺀 모든 도구가 `rt().case(case_id, hardware=True)` 로 케이스 소유/허가를 확인한다. 접수는 목적·법적 근거·설치 장소 유형·업무 목적·역할을 접수 기록과 보관 기록에 남긴다.
  - 보관 기록(`forensics/custody.jsonl`, 해시 체인)을 보호 위치의 고정점(`<state_dir>/custody/<case_id>.jsonl`)과 함께 검증한다. 깨지면 내용 도구와 기록 쓰기가 모두 `custody_broken` 이다(fail closed — 서버는 고치지 않는다).
  - 내용 도구는 열 때마다 접수 기록을 보관 기록의 `intake` 사건과 대조하고, 사본을 안전하게 연 fd 로 빠른 지문을 그 사건의 지문과 비교한다. 다르면 `integrity-failed` 를 남긴 뒤 `integrity_failed` 로 거부한다(되돌리지 않는다).
    해석·재해시는 확인한 그 fd 로만 한다.
  - `forensics/` 아래는 `pweh.safeio` 로 링크를 따르지 않는 디렉터리 fd 기준으로 읽고 쓴다(일반 파일만 열고 장치·FIFO 에서 멈추지 않는다 — §6.8 '케이스 구조').
    출처 원장도 접수 기록 `EV-NNNN.json`을 같은 안전한 fd에서 해시·크기 계산하고 이름의 신원을 다시 확인한다. 접수 아티팩트 색인은 사본 경로를 다시 풀어 크기만 읽는다(열지 않는다) — docs/safety.md §3.6.
  - 영상·음성 내용을 에이전트 문맥에 넣지 않는다. 정지 그림은 `forensics_image_hints`로만 미리보기·OCR·QR·메타데이터를 반환한다(§6.8). 추출물은 `forensics/recovered/`에만 쓰고 직접 열지 않는다.
    다른 서버의 도구는 증거 폴더를 입력으로 받지 않는다(`validation_failed` — 자동 허용 도구로 녹화 내용이 문맥에 들어가지 않게). pweh-fwtriage 는 입력 경로가 그 케이스의 `forensics/` 안(링크를 풀어 판단)이거나 `forensics/` 를 품은 디렉터리(케이스 루트 등)면 거부한다.
    pweh-sigrok 의 `input_path`, `case_import_file`(풀기 전 경로와 링크를 푼 경로 모두 — 위), `case_hash_file`·`case_register_artifact`(링크를 푼 경로, 파일은 실제로 연 fd 의 경로로도 다시 — §6.1)는 어느 케이스의 `forensics/` 아래도 거부한다.
  - 사람 확인은 `.claude/settings.json` 의 `ask`(쓰는 도구 8개 — Claude Code 에서는 bypass 모드에서도 묻는다)와 사람 증명 `write-blocker` 다. 클라이언트 권한은 안전 경계가 아니고(docs/safety.md §3.1),
    증명은 기록일 뿐 내용 도구를 막지 않는다.
  - 한계: 이 경계가 막는 경로는 위 도구들뿐이다. 에이전트의 파일 도구나 자동 허용된 REA `open_binary`·`read_bytes` 는 `forensics/` 를 읽을 수 있으므로,
    전용 정지 이미지 도구 외에는 추출물·이미지를 직접 열지 않는 것이 에이전트 규칙이다(docs/safety.md §7). 경로를 확인한 뒤 경로로 다시 여는 pweh-fwtriage·pweh-sigrok은 그 사이 같은 계정 프로세스의 바꿔치기를 막지 못한다.
    증거 입구와 case 파일 입구는 하드링크를 거부하지만 모든 서버의 입력에 적용하지는 않는다. 보관 기록·고정점에는 비밀 키가 없다(출처 원장과 같은 한계 — docs/safety.md §3.5). SD 카드 증거의 알려진 한계 전체는 docs/safety.md §3.6 에 있다.

- **보호 하위 트리**: `pweh.evidence.PROTECTED_DIRS = ("forensics", "emu")`. `under_any_case_protected`·`is_protected_path`·`contains_protected_dir` 는 SD 증거와 에뮬레이터 원시 콘솔 경계를 함께 검사한다.
  위 `case_import_file`·`case_hash_file`·`case_register_artifact`, pweh-fwtriage 입력/디렉터리 순회, pweh-sigrok 입력의 거부는 `emu/` 에도 적용된다(다른 케이스·심볼릭 링크 포함).
  종전 `*_forensics*` 함수는 호환성을 위해 SD 경계만 검사한다. 에이전트 파일 도구·REA 및 별도 복사본은 이 경계 밖이므로 운영 규칙도 필요하다(안전 가이드 §3.7).

## 5. 코딩 규칙

- Python 3.10 호환 (`match` 문 사용 금지 아님, 하지만 `typing.Self`, `tomllib` 사용 금지). 외부 의존성은 `mcp`, `pyserial`, `PyYAML`, `jsonschema`, `tomlkit` 와 표준 라이브러리만.
  `tomlkit` 은 CLI 가 Codex `config.toml` 을 읽고 주석·서식을 지키며 고칠 때(`pweh.clientcfg`)만 쓴다. 서버는 쓰지 않는다.
- 주석·docstring·도구 설명은 **한국어**, 식별자와 기술 용어는 영어. 도구 이름은 영어 snake_case.
- 서버 구조는 참조 구현 `mcp-servers/case-mcp/case_mcp/server.py` 를 따른다:
  - `server = create_server(NAME, title=..., instructions=...)` (`pweh.mcpkit`)
  - `create_server` 는 `sys.platform` 이 `win32`·`cygwin`·`msys` 이면 서버를 만들지 않고 안내 문구와 함께 `SystemExit`(종료 코드 1)으로 끝낸다. 서버는 WSL 안에서 실행하고, Windows 의 MCP 클라이언트는 `wsl.exe -d <배포판> -e <저장소>/.venv/bin/pweh-<서버>-mcp` 로 띄운다(`-u root` 금지).
  - 포트 경로: `pweh.ports.resolve(env, ref, purpose)`는 포트를 열지 않고 불변 `PortRoute`를 만든다. POSIX 문자장치 stat, Windows PnP·Linux sysfs 식별, COM1–COM4096과 루프백 URL 문법을 검사한다.
    승인 action의 `route`는 정확히 `{backend, lock_key, device_id}`다. 승인 뒤와 각 장치 접근 전에 경로·노드·USB 부모/인터페이스를 새로 확인하며, 바뀌면 `route_changed`로 끝낸다.
    공개 route에는 `ref/backend/side/device_path/lock_key/device_id/identity/reset_risk/warnings`만 들어간다. fd·config·lease·내부 노드 튜플은 직렬화하지 않는다.
  - 포트 배타: UART open/baud, JTAGulator connect, ESP 실행, sigrok의 명시적 직렬 conn은 승인과 open/Popen 전에 공용 `pweh.portlock` lease를 잡는다.
    키는 `tty:<major>:<minor>`, `win:COM<n>`, `net-loopback:<port>`다. 루프백 URL은 호스트·스킴이 달라도 같은 포트 번호면 경합한다.
    Linux abstract AF_UNIX bind가 권위이며 고정 namespace는 `pweh/portlock/v1`이다. 미지원 플랫폼에서만 보호 flock 파일로 대체하며 busy/권한 오류를 fallback으로 우회하지 않는다.
    `/tmp/pweh-<uid>/port-owners/`는 표시용 기록, `port-roles/`는 target/bridge 거부 표지다. 기존 I5 instrument `tags/`와 분리하며 에이전트가 직접 수정하지 않는다.
    승인 대기에도 lease를 유지하고, 거부/승인 요청 반환이면 아직 열지 않은 lease를 회수한다. 연결이 끊어진 세션은 명시 close/disconnect까지 유지한다.
    worker로 넘긴 lease는 실제 핸들·하위 프로세스 정리를 확인한 worker만 해제한다. close·프로세스 종료를 확인하지 못하면 orphan 기록과 내부 참조를 보존한다.
  - `pweh.serialtransport`는 lease를 빌려 물리 핸들만 소유한다. fresh 확인 → DTR/RTS 요청값 → pyserial open(`exclusive=True`) → TIOCEXCL → fstat 대조 순서다.
    닫기는 TIOCNXCL → 물리 close이며, 초기화 후 close 실패도 내부 `SerialOpenError.transport`로 보존한다. 보드레이트 탐지는 한 번 열고 후보마다 속도만 바꾼다.
    최초 open pulse와 open–ioctl 사이 비PWEH 경합은 남는다. esptool/sigrok는 preopen하지 않는다. 다른 netns·미통합 libusb/OpenOCD·Windows 외부 프로그램까지 공용 잠금으로 막는 것은 아니다.
  - 장치 전체 reset은 선택 포트뿐 아니라 같은 USB 부모의 모든 현재 OS 형제 키를 먼저 잡는다. Windows present PnP graph와 Linux 활성 구성/sysfs tty를 두 번 관찰한다.
    불완전/변동/상한 초과 관찰은 `port_scope_unknown`, 승인 후 scope 변경은 `route_changed`다. 새 형제 키를 승인 뒤 추가하지 않는다. 최대 64 keys·5초·1 MiB이며 실기 시간은 별도 검증 대상이다.
  - `pweh.usb_binding`은 호출자가 제공한 Windows 두 Present graph에서 정확한 VID/PID 한 쌍의 유일 USB 부모와 전체 하위 노드·COM 별명을 검증하는 순수 코어다.
    `parse_windows_usb_scope`는 불변 `WindowsUsbScope`에 기존 `winif:`·`win:COMn` 키를 담고, `revalidate_windows_usb_scope`는 새 관찰의 후보·범위 변화 때 재선택 없이 실패한다.
    기존 직렬 wrapper의 선택 COM 유일성·소속 검사는 유지한다. 순수 코어와 별도로 Tigard 소비자가 고정 OS 조회·전체 lease·역할/계측기 거부를 연결한다. PnP instance tail은 USB descriptor serial의 증거가 아니다.
    입력·오류·상한 및 기존 COM lease와의 합성 통합 계약은 [Windows USB 범위 코어](references/windows-usb-binding.md)에 있다.
  - PID 생존 확인은 `pweh.procutil.pid_alive` 를 쓴다(`os.kill(pid, 0)` 을 직접 부르지 않는다 — Windows 에서는 콘솔 Ctrl-C 이벤트, 0 이하 pid 는 프로세스 그룹 검사). 원격 시리얼 URL·COM 이름 검사는 `pweh.ports`(`validate_net_url`, `parse_win_com`)를 쓴다.
  - `def rt() -> Runtime: return get_runtime(NAME)`
  - 도구: `@server.tool(description=..., annotations=ANN_*)` 다음 줄에 `@safe_tool`
  - 기기에 영향을 주는 도구는 `async def ...(..., ctx: Context)` 이며 블로킹 I/O 는 `await run_blocking(fn, ...)`.
  - 반환은 항상 `dict` (`{"ok": True, ...}`), 오류는 `PwehError` 계열 예외 (`pweh.errors`) — `safe_tool` 이 ToolError 로 변환.
  - 오래 걸리는 작업: `rt().jobs.start(kind, fn, description=..., case_id=..., exclusive_key="port:/dev/ttyUSB0")` 후
    `register_job_tools(server, rt, prefix)` 가 만든 `<prefix>_job_status` 로 폴링.
    스레드 기동 전 실패한 queued 등록은 되돌리며, 실제 시작한 스레드의 등록은 유지한다. caller/worker 정리 책임은 `LeaseHandoff`의 단방향 claim으로 나눈다.
    `job_status(..., case_id=None)`·`jobs(active_only=False, case_id=None)`는 기본적으로 이 프로세스의 작업만 보여 준다.
    `case_id`를 명시하면 해당 케이스의 `jobs/*.json` 중 같은 서버 기록만 지연 확인한다(전체 케이스 스캔 없음).
    새 기록은 내부 `owner`에 server·PID·시작 tick·boot ID·PID namespace·host를 남기며, 이 원시 식별자는 API 응답에서 제외한다.
    소유 서버 종료가 확인된 queued/running/cancelling만 `failed`·`error.code=job_owner_terminated`로 원자 갱신한다.
    `recovery`에는 owner_state(terminated/alive/unknown)·reason·resumable=false를, 정리한 기록에는 previous_status·checked_at·finished_at_basis=recovery_observation도 둔다.
    소유자 없는 과거 기록·다른 호스트/namespace·관찰 불가는 상태를 바꾸지 않고 unknown으로 표시하며, 살아 있는 다른 서버 프로세스의 기록도 보존한다.
    저장 기록을 실행 큐에 넣거나 재개·취소하지 않는다. `wait_seconds`는 이 프로세스의 작업만 기다린다. 파일·증거·기기·외부 자식 정리 여부는 별도 확인 대상이다.
    한 기록 1MiB, 목록 디렉터리 512항목·256기록·누적 8MiB·2초 상한이며 건너뜀/잘림은 목록의 `recovery.truncated/reasons`에 표시한다.
    두 조회 도구는 기록을 정리하므로 `ANN_LOCAL_WRITE`(readOnlyHint=false)이며, `job_cancel`의 기존 동작은 그대로다.
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
`case_image_hints(case_id, path, ocr=True, ocr_lang="kor+eng", qr=True, preview=True, crop=None, max_seconds=45.0)`,
`case_add_finding(case_id, finding)`, `case_update_finding`, `case_list_findings`, `report_generate(case_id)`,
`pipeline_profiles`, `pipeline_profile(name)`, `pipeline_safety_policy`, `pipeline_environment(refresh?) → report, routes`, `approval_status(approval_id)`, `approvals_pending`, `schema_get(name)`.

- `case_create` 는 사용한 ID를 보호 상태에 예약한다(§3). 명시한 `case_id`에 기존 경로나 보호 기록이 있으면 거부하며, 생략하면 충돌하지 않는 ID를 고른다. 케이스 폴더를 지우는 것으로 ID 예약이 풀리지 않는다.
- `case_hash_file` 은 케이스 안 파일(또는 `offset`/`length` 구간, 정수 또는 `"0x50000"`·`"64k"`)의 해시를 계산한다. 덤프 교차 검증용이다:
  tftpput·SPI 클립으로 받은 파일과 UART 덤프의 같은 구간 비교, 기기 측 `md5sum`/`crc32` 값과 대조.
- 보호 하위 트리 가드(§4): `case_hash_file`·`case_register_artifact` 는 어느 케이스의 `forensics/`·`emu/` 아래 파일도 다루지 않는다(링크를 푼 경로로 판단, `validation_failed`).
  파일은 `pweh.safeio` 로 일반 파일만 열고(FIFO·장치는 열지 않아 거기서 멈추지 않는다 — `validation_failed`), 실제로 연 fd 의 경로로 증거 폴더 여부를 다시 본 뒤 그 fd 로 해시한다(`case_register_artifact` 의 디렉터리는 해시하지 않는다).
  `case_import_file` 은 state_dir 와 어느 케이스의 `forensics/`·`emu/` 아래 파일을 가져오지 않는다(보호 폴더는 풀기 전 경로와 링크를 푼 경로 모두 — §4). 확인한 뒤 원본을 경로로 다시 열어 복사한다(그 사이의 바꿔치기 한계 — docs/safety.md §3.6).
- `pipeline_environment` 은 실행 환경 보고서(`pweh.hostenv/v1` — `kind`, `wsl{version, networking_mode, interop}`, `windows{build, uac_enabled, interop_elevated, smart_app_control, usbipd, tools.esptool_win}`, `linux`, `warnings`, `overridden`)와 장치 종류별 `routes[]`(`now` = 지금 되는 경로·사람 단계, `target{route, phase}` = 다음 단계 경로)를 돌려준다(OBSERVE, 기기 미접촉). 모르는 값은 `null`, 휘발 목록(COM 포트·usbipd attach 상태)은 넣지 않는다. WSL 첫 감지는 powershell.exe 고정 스크립트 smoke 로 몇 초, 이후 캐시(성공한 smoke 300 초, 실패한 감지는 30 초 뒤 다시), `refresh=true` 면 다시 감지. 표준 위치가 아닌 `$PATH` 의 usbipd 는 `windows.usbipd.found_elsewhere` 로 표시만 하고 실행하지 않는다(Windows 프로그램은 실제 경로가 정확히 맞는 System32 powershell·Program Files usbipd 만). 사람은 같은 내용을 `pweh env` 로 본다.
  설정 `hostenv.disable`은 좁히기만 한다: `interop`은 Windows 실행, `windows_tools`는 Windows 도구, `serial_helper`는 COM helper를 끈다. 세 값 모두 새 helper 실행을 막지만 이미 실행한 helper의 종료 확인은 계속한다. 알 수 없는 값은 경고와 함께 무시한다.
  `windows.serial_helper{present,path,source,problem,trusted,trust_check}`는 정적 설치 흔적이다. `trusted=null`, `trust_check="pre-execution"`이며 `pipeline_environment`는 helper를 실행하지 않는다. `pweh doctor`만 고정 pin을 검증한 뒤 포트 없는 `--version`을 제한 시간 내 확인한다.
- `case_import_file` 은 가져온 파일을 출처 원장에 `imported-unattested` 로 기록하고 응답에 `provenance{recorded, kind: "imported-unattested", seq, sha256, note}` 를 붙인다(§4).
  기록에 실패하면 `recorded: false` 와 `reason` 이고 가져오기는 그대로 된다. 이 서버에는 기기 읽기(`device-read`)로 기록하는 경로가 없다.
- `case_image_hints`는 케이스 안 정지 그림 하나를 공통 `pweh.imagehints` worker로 분석한다. 케이스 소유/허가가 필요하고 경로·연 fd의 실제 경로에서 `forensics/`·`emu/` 입력을 거부한다. 입력 64 MiB·40 MP·한 변 32,768픽셀, wall 최대45초다. 결과는 `analysis/`의 JSON·정규화 PNG로 저장하고 JSON `report`(출처·입력 해시·메타데이터·구조·OCR·코드·스테가노 지표·한도), `analysis{path,sha256,size}`를 반환한다. MCP content에는 실제 ImageContent를 더하고 structured_content에는 JSON만 둔다. `crop=[x,y,width,height]`는 EXIF 방향 적용 뒤 원본 좌표다. 자세한 공통 동작·한계는 [이미지 힌트 설계](design/image-hints.md), safety §3.8.
- `case_set_phase` 는 단계 이름을 검사하지 않는다(파이프라인 단계와 선택 단계 — §3).
- 사람 증명(`att-…`)을 결정하거나 조회하는 도구는 없다. `approval_status`·`approvals_pending` 은 승인만 본다(증명은 사람이 `pweh attest` 로 — §4).
- 도구별 설명과 기본값 전체: `mcp-servers/case-mcp/README.md`, `docs/references/pweh-mcp-tools.md`.

### 6.2 pweh-uart
세션은 서버 프로세스 메모리에 유지되며, 포트당 백그라운드 수신 스레드가 링 버퍼(기본 4 MiB, `uart.read_buffer_bytes`) + 로그 파일에 계속 기록한다
(도구 호출 사이에 도착한 출력도 잃지 않는다). 수신 커서는 RX 누적 바이트 오프셋이다. 세션 id 는 `<label 또는 uart>-NNN` 이다.
서버가 재시작되면 세션이 사라지므로 다시 연다(덤프는 같은 인자로 다시 부르면 `.state.json` 에서 이어받는다).
기기로 가는 모든 바이트는 `uart_mcp.guard`(§4)로 분류한 뒤 게이트를 거친다. "내용대로" 는 보내는 줄의 분류 결과가 위험도라는 뜻이다.
아래 시그니처는 실제 인자와 기본값 전체다(설명 원문: `docs/references/pweh-mcp-tools.md`, 동작 상세: `mcp-servers/uart-mcp/README.md`).
목록 행에는 `owner_side/route/device_id/held_by`를 더한다. `uart_detect_baud`도 같은 route 지문·lease를 사용하며, 포트 한 번의 open 안에서 후보 속도를 변경하고 각 변경·프로브 전에 다시 확인한다.

| 도구 | 설명 / 반환 |
|---|---|
| `uart_list_ports(include_links=False)` | OBSERVE. `ports[{device, description, hwid, vid, pid, serial_number, manufacturer, likely_usb_uart, in_use_by}]`, `count`(없으면 `hint`). `include_links=true` 면 `/dev/serial/by-id/…` 링크도 넣는다. TCP 시리얼(이 호스트의 ser2net, 시뮬레이터)은 목록에 없으니 `uart_open` 에 `socket://127.0.0.1:<포트>` 로 준다(루프백만 — LAN 호스트는 `validation_failed`) |
| `uart_open(case_id, port, baudrate=115200, bytesize=8, parity="N", stopbits=1, line_ending="\r", dtr=False, rts=False, profile=None, label=None, approval_id=None)` | INTERACT(`dtr`/`rts`=true 또는 확인된 reset 배선이면 MODIFY). `session_id`, 로그 경로 3종(케이스 상대), `context`, `cursor`, `route`, `device_id`, `reset_risk`, `transport`를 반환한다. `/dev` 아래 기존 문자장치·루프백 socket/RFC2217·loop만 받으며, 확인된 WSL1은 COM1–191↔ttyS를 지원한다. WSL interop에서는 COM1–COM4096을 검증된 helper로 연결한다(WSL1 COM1–191은 ttyS 고정). URL은 정규형 루프백 주소+포트로 고정하며 옵션·사용자 정보·LAN·상대 경로·일반 파일·제어 문자는 거부한다. 승인 전 공용 lease, 승인 뒤 fresh 경로 확인, POSIX open 뒤 TIOCEXCL을 적용한다(§5). DTR/RTS 요청값은 open 전 설정하지만 최초 open pulse를 없애지는 못한다. `profile`은 프롬프트·autoboot 패턴을 정하고 U-Boot 줄끝은 항상 CR이다. 추가 반환: `port`, `baudrate`, `framing`, `line_ending`, `dtr`, `rts`, `profile`, `phase`, `artifacts`, `next_steps`; socket 경로에는 속도 전달이 안 된다는 `note`. 같은 프로세스·케이스에서 닫힌 앞 세션과 **nonnull continuity key가 일치할 때만** 직전 명령을 `inherited_last_command`로 계승한다(env 제외). URL/loop·미확인 Windows 식별은 계승하지 않으며 빈 Enter는 `uart.repeat-unknown`(DESTRUCTIVE)이다 |
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
| `uart_detect_baud(case_id, port, candidates=None, listen_seconds=2.5, probe="ctrl-c"\|"none", approval_id=None)` | `probe="ctrl-c"` 는 **MODIFY**(다른 속도로 보낸 0x03 은 기기에서 다른 바이트로 읽힐 수 있음), `probe="none"` 은 INTERACT. 포트를 한 번 열고(DTR/RTS 요청값은 끔), 후보마다 속도를 바꾸어 읽은 데이터를 점수화(출력 가능 문자 비율, 부팅 키워드, 0x00/0xFF 연속 감점) → `candidates`(점수순), `best`, `confidence`, `tested`, `elapsed_seconds`, `port`, `probe`, `listen_seconds`, `hint`(데이터 없음: TX/RX·GND·무출력·전압), 시간 제한으로 일부만 시험했으면 `truncated`. 기기가 출력 중이어야 하므로 부팅 출력을 듣는다: 사람에게 전원을 먼저 꺼 두게 하고 '준비' 답을 받은 뒤 호출하며, 사람은 호출이 시작되면 전원을 넣는다. 부팅 중에 Ctrl-C 프로브가 맞는 속도로 닿으면 autoboot 가 멈출 수 있으니 이때는 `probe="none"` 을 쓴다. 이 포트로 열린 세션이 없어야 하고 총 50초 제한 |
| `uart_capture_boot(session_id, duration=30, until=None, stop_on_prompt=True)` | OBSERVE(아무것도 보내지 않아 게이트는 없고 케이스 소유/허가만 확인). 사람에게 전원을 먼저 꺼 두게 한 뒤 호출하고, 호출이 시작되면 사람이 전원을 넣는다. `duration`(최대 300초) 또는 `until` 정규식까지 수집한다. `stop_on_prompt=true` 면 이 창에서 부팅이 시작된 뒤 로그인/셸/U-Boot 프롬프트가 나오고 1.5초 조용할 때 멈춘다. 파싱 결과 `uboot_version`, `autoboot_message`, `bootdelay`, `kernel_version`, `cmdline`, `mtdparts`, `partitions`, `login_prompt`, `shell_prompt`, `flash`, `flash_write_warnings`, `stages`, `sd_events`(SD 카드 관련 줄 최대 60개: `line`(발췌 파일의 줄 번호), `kind`(`card-detected`·`card-removed`·`card-absent`·`block-device`·`partition`·`fs-mount`·`fs-error`·`uboot-mmc`·`uboot-script`(boot.scr·uEnv.txt 읽기)·`update`·`script`·`card-other`), 함께 맞은 종류 `also`, `text`)·`sd_summary`(`card_detected` — false 는 감지 줄을 못 봤다는 뜻, `card_absent`, 종류별 `counts`, `devices`, `filesystems`, `events_total`, `truncated`, `long_lines_skipped`). '카드 없음' 문구는 감지로 세지 않고, 카드 감지 핀·인터럽트 설정 줄은 `card-other` 다. eMMC·SDIO 줄과 커널이 eMMC 로 알린 호스트의 mmcblk 장치 줄은 `counts` 의 `emmc`·`sdio` 로만 센다(그 밖의 mmcblk 줄은 SD·eMMC 를 구분할 수 없는 후보). 4096자를 넘는 줄은 분류하지 않고 `long_lines_skipped` 로 센다). 그 밖에 `captured_bytes`, `stopped_by`(`until`/`duration`/`prompt:<종류>:<문맥>`/`disconnected`/`cancelled`), `cursor_start`/`cursor_end`, `excerpt_path`(발췌 `uart/<session>-boot-NN.log`, `uart-log` 아티팩트로 등록), `text_tail`(끝 3000자), `context`, 데이터가 없으면 `hint`, 플래시 쓰기 징후가 보이면 `warning`, `update`·`script`·`uboot-script` 줄이 있으면 `sd_note`(펌웨어의 `fw_sd_surface` 결과와 대조) |
| `uboot_interrupt(session_id, keys=None, window_seconds=30)` | INTERACT(보낼 키 계획의 분류값). 사람에게 기기 전원을 **먼저 꺼 두게** 하고 '준비' 답을 받은 뒤 호출한다. 사람은 호출이 시작되면 전원을 넣는다(도구가 먼저 감시를 시작해야 한다). 부팅 출력(또는 autoboot 메시지)이 보이면 인터럽트 키(`keys` 또는 프로필 `interrupt_sequences`, generic-ipcam 기본 Ctrl-C. 빈 Enter 는 새 부팅을 본 뒤에만 보내고 프롬프트가 수신 끝에 있으면 보내지 않음)를 약 50 ms 마다 보내고, U-Boot 프롬프트가 나오면 멈춘 뒤 Ctrl-C 로 깨끗한 프롬프트를 받는다. 호출 시점에 이미 부팅 중·리눅스 실행 중이던 기기의 이전 출력은 판단에 쓰지 않고 창 동안 새 부팅을 기다린다(그동안 리눅스에 키를 보내지 않음, `autoboot_silent` 프로필 제외). 커널 시작 전의 `Password:` 는 부트로더 잠금이라 키 송신을 멈춘다 → `interrupted, outcome`(`prompt`/`uboot_password`/`linux`/`kernel`/`window_expired`/`cancelled`/`disconnected`), `new_boot_seen`(호출 뒤 새 부팅을 봤는지), `prompt`, `autoboot_message`, `bootdelay`, `keys_used`, `keys_sent`, `boot_output_bytes`, 건너뛴 키는 `skipped_keys`, 이미 U-Boot 프롬프트였으면 `already_at_prompt`, 실패 시 `explanation`(무출력, 보드레이트, 늦은 키·keyed/무음 autoboot, 부트로더 비밀번호 잠금, 이전 부팅 출력만 봄, 리눅스 도달). `window_seconds` 최대 120 |
| `uboot_printenv(session_id)` | INTERACT. `env{}`, `count`, `bootargs`, `bootcmd`, `bootdelay`, `mtdparts`, `partitions[{name, offset, size}]`, `flash_size`/`flash_size_source`(`-`(나머지 전체) 파티션 크기 계산에 쓴 값과 출처: `uboot_info` 의 sf probe 또는 이 세션이 본 부팅 로그. 모르면 `null` 이고 그 파티션 `size` 도 `null` + `note`), `loadaddr`, `load_addresses`, `environment_size`, `complete`/`tracked`. 출력이 완전할 때(`Environment size` 줄)만 세션의 env 추적에 반영한다(`run`/`boot` 분류의 기준, 아니면 `warning`). `uboot_info` 보다 먼저 부른다 |
| `uboot_info(session_id, probe_flash=True)` | INTERACT(명령마다 게이트). `version`, `bdinfo{dram_start, dram_size, relocaddr, sp_start, …}`, `commands[]`, `has{}`(help 목록 기준 사용 가능 여부. U-Boot 약어 규칙(유일한 접두어)으로만 되는 것은 `has_via{}` 에 실제 명령 이름. help 를 파싱하지 못하면 `null` = 모름이며 `false` 가 아니다), `partitions[]`(추적 env 의 mtdparts, `-` 는 플래시 크기로 채움), `flash{type, model, size_bytes, …}`(`probe_flash=true` 면 `sf probe 0`. 크기를 찍지 않는 칩은 `size_bytes: null` 이고 부팅 로그 사실이나 mtdparts 합 `size_bytes_lower_bound` 로 보완), `safe_ram_addr`·`ram_window`(DRAM 안에서 U-Boot 자신(relocaddr/malloc/스택)과 하위 1 MiB 를 피한 주소, env `loadaddr`·bootcmd 의 `sf read` 주소 우선), `safe_ram`, `boot_facts`, `notes`. help 에 `sf` 가 없으면 sf probe 를 건너뛴다 |
| `uboot_dump_start(case_id, session_id, offset, length, source="sf"\|"nand"\|"mmc"\|"ram", ram_addr=None, chunk_size=65536, output_name=None, verify="crc32"\|"double"\|"none", resume=True, retries=3, final_check=True, sf_probe="0")` | INTERACT · job. 시작 응답 `status: "started"`, `job_id`, `output`, `part_path`(`dumps/<name>.bin.part`), `state_path`, `metadata_path`, `chunks`, `chunk_size`, `ram_addr`, `resume_from_chunk`, `estimated_seconds`(현재 보드레이트·프레이밍 기준 예상 시간), `notes`. 청크마다 `sf read`(nand: `nand read`, mmc: `mmc read` 512 B 블록, ram: 적재 없이 `offset` 이 RAM 주소) → `md.b` 파싱·검증(주소 연속성/바이트 수) → `crc32` 비교, 실패 청크는 `retries` 번 재시도(Ctrl-C 로 프롬프트 회복). `verify="double"` 은 같은 범위를 두 번 읽어 비교하며 기기에 `crc32` 가 없으면 자동으로 바뀐다. 완료 시(`final_check=true` 이고 전체가 RAM 창에 들어가면 전체 범위를 한 번 더 대조) sha256 + `dumps/<name>.json` + 아티팩트(`flash-dump`/`memory-dump`). `offset`/`length`/`chunk_size`/`ram_addr` 는 정수 또는 `"0x50000"`·`"64k"`·`"16M"`, `chunk_size` 최대 256 KiB. `ram_addr` 생략 시 `uboot_info` 의 `safe_ram_addr`. 주소가 DRAM 밖이거나 U-Boot 영역을 침범하면 거부하지만, `uboot_info` 를 부르지 않아 DRAM 범위를 모르면 직접 준 `ram_addr` 은 검사하지 못하고 `notes` 에 그렇게 적는다. `source="sf"` 이고 플래시 크기를 알면 범위가 크기를 넘을 때 거부한다. `sf_probe` 는 덤프 전에 보내는 `sf probe` 인자(`null` 이면 생략) |
| `shell_login(session_id, username=None, password=None, timeout=15)` | INTERACT(마스킹 로그인 경로). askfirst(`Please press Enter`)면 Enter, `login:` 이면 username, `Password:` 면 password 를 그 프롬프트가 수신 끝에 보일 때만 보낸다. `username` 을 생략하면 askfirst 콘솔 활성화만 한다(로그인 없는 콘솔. `login:` 이 나오면 `username_required`). 비밀번호는 `.log`·이벤트·감사 기록·승인 지문에서 마스킹된다. 사용자가 알려 준 계정만 쓰고 세션당 3회 실패하면 더 시도하지 않는다(`login_attempts_exceeded`) → `logged_in`, `status`, `prompt`, `steps`, `context`, `elapsed_seconds`, `cursor_end`, 실패 시 `message`/`hint`, 성공 시 `banner` 와 `user`(이번 호출이 username 을 보냈을 때만). `status`: `ok`, `already_logged_in`, `password_required`, `username_required`(카운트하지 않음), `login_incorrect`, `login_failed`(같은 프롬프트가 다시 나옴), `context_unknown`(U-Boot 일 수 있는 프롬프트 — 아무것도 보내지 않고 phase 증거도 넣지 않음 → `uart_sync`), `uboot_prompt`, `uboot_password_prompt`(커널 시작 전 `Password:` = 부트로더 잠금, 아무것도 보내지 않음 — 추측 금지), `stuck_askfirst`, `unknown_prompt`, `timeout`, `disconnected`, `cancelled` |
| `shell_identify(session_id)` | INTERACT(읽기 전용 명령 묶음, 명령마다 게이트). `uname`, `kernel_version`, `arch`, `hostname`, `cpu`·`cpuinfo`, `mtd[]`(/proc/mtd 파싱), `cmdline`(`mtdparts` → `partitions`), `mounts`, `processes`, `listening`, `busybox`(버전)·`busybox_applets`, `user`(`id`), `has_base64`/`has_hexdump`/`has_md5sum`, `missing_commands`. linux-shell 문맥이 아니면 거부 |
| `shell_dump_start(case_id, session_id, path, offset=0, length=None, method="auto"\|"hexdump"\|"base64", chunk_size=65536, output_name=None, resume=True, retries=3)` | INTERACT · job. 청크마다 `dd … 2>/dev/null \| base64`(없으면 `\| hexdump -C`) 출력을 파싱하고 같은 범위의 `\| md5sum` 과 비교(기기에 `md5sum` 필요), 실패 청크는 재시도. `path` 는 절대 경로(문자 `[A-Za-z0-9_./+-]`, `..` 금지)이고 `/dev/` 아래는 저장장치만 읽는다: `mtdN`(`mtdNro`), `mtdblockN`, `mmcblkN`·`mmcblkNpM`·`mmcblkNboot0/1`, `ubiX_Y`, `ubiblockX_Y`, `sdX`·`sdXN`, `nand…`. `/dev/watchdog`(여는 순간 타이머가 시작돼 재부팅), `/dev/mem`·`/dev/port`(읽기 부작용) 같은 그 밖의 장치는 `validation_failed` 로 거부한다. `length` 생략 시 `/proc/mtd` 크기(또는 `wc -c`). 시작 응답 `status: "started"`, `job_id`, `output`, `part_path`, `state_path`, `metadata_path`, `chunk_size`, `resume_from_chunk`. 완료 시 `dumps/<name>.bin` + `.json`(`method` `linux-base64`/`linux-hexdump`, `verification.method` `md5-device`) + 아티팩트(`/dev/mtdN`·`/dev/mtdblockN` 은 `partition`, 그 밖은 `other`) |
| `uart_job_status(job_id, wait_seconds=0, case_id=None)`, `uart_job_cancel(job_id)`, `uart_jobs(active_only=False, case_id=None)` | `register_job_tools(..., "uart")`. 덤프 job 의 `progress`/`eta_seconds` 는 **이번 실행**(재개 포함) 기준이고, 전체 진행은 `meta.overall_progress`, `meta.overall_done_bytes`/`meta.overall_total_bytes`, `meta.eta_seconds_estimate`, `message` 에 있다. 취소·실패해도 좋은 청크는 `.part`/`.state.json` 에 남고, `result`(= `meta.partial_result`)에 `status: cancelled\|failed` 와 완료 청크·바이트가 남는다 |

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
경로 인자는 케이스 상대 경로(`signals/x.sr`, `signals/` 는 생략 가능)이며 케이스 밖 경로는 거부한다. 어느 케이스의 `forensics/`(SD 카드 증거)·`emu/`(원시 콘솔) 아래 `input_path` 도 `validation_failed` 다(§4 'SD 카드 증거').
`sigrok_scan` 은 예외로 `case_id` 가 선택이다(시리얼/네트워크 `conn` 을 줄 때만 필수).
명시적 직렬 `conn`에는 공용 route·승인 지문·lease를 적용한다. 그 결과와 job metadata에 route를 남기고 child 종료 확인까지 lease를 유지한다. USB 자동 탐지/libusb 경로는 P1 잠금 통합 범위 밖이다. Windows COM은 명시 backend와 고정 OLS scan/show·유한 캡처에 허용하며 기본 Linux의 COM은 거부한다.
`sigrok_version`·`sigrok_list`의 명시 `backend="windows"`는 정보 전용 경로다. 등록 번들의 전체 고유 사본에서 고정 버전·목록 명령을 실행하고 Windows 프로세스와 wrapper 종료·사본 재검증 뒤 반환한다. 기본 Linux·캐시는 유지한다. 버전 뒤 목록의 확인된 decoder-only 오류는 `status="partial"`, `counts=null`, `list_complete=false`이며 Windows 목록 도구는 모든 kind에서 오류로 끝난다. 취소·상한·비0 종료·정리 미확인은 partial로 바꾸지 않는다. 상세 반환·수명은 [정보 조회 계약](references/windows-sigrok-info.md)에 있다. 별도 [OLS COM 조회](references/windows-sigrok-com.md)는 `ols-serial-v1`의 정확한 scan/show 명령만 허용한다. Linux/Windows OLS+명시 직렬 scan/show·capture는 reset 5회를 보내므로 MODIFY이며 `approval_id`를 지원한다. Windows owner는 복사 전에 lease에 연결하고 Windows 자식·wrapper·reader·제어 조회·사본 정리가 모두 확인될 때만 lease를 해제한다. 합성 시험만 완료했으며 실제 장비 검증은 남아 있다.
Windows 캡처는 별도 `ols-capture-v1`의 명시 samples·연속 숫자 채널만 지원한다. 같은 fd로 ZIP·CRC·metadata 검사와 케이스 복사를 마친 파일을 배타적으로 등록하고 commit 뒤 감사·정리를 수행한다. 취소된 유효 출력은 부분 아티팩트로, 샘플 부족은 종료 코드0이어도 partial로 표시한다. 미검사 출력·정리 미확인은 보존한다. 상한·rate 양자화·job 의미는 [캡처 계약](references/windows-sigrok-capture.md)을 따른다.
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

| 도구 | 설명 / 반환 |
|---|---|
| `sigrok_version(backend="linux")` | sigrok-cli·libsigrok·libsigrokdecode 버전, 실행 파일 `path`, 드라이버·디코더 수 `counts`. sigrok-cli 가 없으면 `tool_missing` 오류 + 설치 힌트 |
| `sigrok_list(kind="drivers", query=None, backend="linux")` | kind: `drivers`, `decoders`, `input-formats`, `output-formats`, `transforms`, `all` → `items`, `count`. `query` 는 id/설명 부분 문자열 필터. drivers 항목에는 이 서버의 캡처 정책(`capture_allowed`, `output_capable`, `reason`)이 붙는다 |
| `sigrok_decoder_help(decoder)` | 디코더의 필수/선택 채널, 옵션(값 목록·기본값), annotation 클래스/행, 바이너리 클래스, 문서, `example_stack`. 이름이 libsigrokdecode 버전마다 다르므로 `sigrok_decode` 의 스택·annotation 문자열은 하드코딩하지 말고 여기서 확인한다 |
| `sigrok_scan(driver=None, conn=None, case_id=None, timeout_s=None, backend="linux", approval_id=None)` | 연결된 장치 `devices[{driver, conn, description, channels, capture_allowed, …}]`, `count`. 인자가 없으면 모든 드라이버로 USB 등을 자동 탐지한다(OBSERVE). 시리얼/네트워크 `conn` 은 드라이버가 그 포트로 식별 바이트를 보내므로 INTERACT(OLS 명시 직렬은 reset 때문에 MODIFY)이고 `case_id` 가 필요하며, 다른 프로세스(예: uart-mcp 콘솔 세션)가 포트를 열고 있으면 `Busy` |
| `sigrok_device_info(case_id, driver, conn=None, timeout_s=None, backend="linux", approval_id=None)` *(추가)* | `--show` 파싱: `driver_functions`, `channel_groups`, `samplerates` 또는 `samplerate_range`, `triggers`(지원 트리거 문자), `max_samples`, `capture_allowed`. 드라이버 탐색 뒤 장치를 다시 열 수 있다. OLS 명시 직렬은 reset 때문에 MODIFY다. Windows는 고정 `ols`+COM만 지원한다. 캡처 전에 samplerate 를 고를 때 쓴다. |
| `sigrok_capture(case_id, driver, samplerate="1m", duration_ms=None, samples=None, channels=None, triggers=None, output_name=None, conn=None, capture_ratio=None, background=None, timeout_s=None, backend="linux", approval_id=None)` | Linux는 **`duration_ms` 와 `samples` 중 정확히 하나**, Windows OLS는 명시 `samples`와 연속 숫자 채널이 필요하다. 조합이 잘못되면 `validation_failed`이며 기본 길이를 채우거나 무한 캡처하지 않는다. `signals/<name>.sr`(srzip) 저장 + `signal-capture` 아티팩트 → `path`, `samplerate`(정수 Hz), `samples`, `channels`, 채널별 `activity`, `next_steps`. 트리거를 쓰거나 예상 시간이 20초를 넘거나 `background=true` 면 **job** 으로 돌고 `{status: "started", job_id, planned_path}` 를 바로 돌려준다. job 의 `result` 는 동기 응답과 같다. Linux의 취소 파일은 `<name>-partial.sr`이며, Windows는 종료·전체 검증을 마친 유효 데이터만 부분 아티팩트로 등록한다. Linux `channels` 예 `["D0=RX","D1=TX"]`(0번부터 연속 선택 권장), Windows OLS는 `["0=RX","1=TX"]`다. Linux `triggers` 는 바꾼 이름으로 쓴다(`"RX=f"`), `capture_ratio` = 트리거 전 비율(%) |
| `sigrok_decode(case_id, input_path, decoders, annotations=None, input_format=None, samplenum=False, max_lines=400, background=None, …)` | 스택마다 **채널 매핑이 필수**다(`"uart:rx=RX:baudrate=115200"`. rx 가 선택 채널인 uart 도 예외 없음 — sigrok 은 매핑이 없거나 틀리면 조용히 첫 채널을 디코드한다). 입력 파일에 없는 채널 이름도 거부한다. 전체 결과는 `signals/<입력>.<디코더>.txt`(`signal-decode`) → `lines`(앞 `max_lines` 줄 목록), `lines_total`, `instances`, `output_path`, `output_truncated`(512 MiB 상한). 동기 실행은 55초에서 멈추며 큰 입력은 자동으로(또는 `background=true`) job |
| `sigrok_export(case_id, input_path, output_format="vcd", output_name=None, input_format=None, timeout_s=None)` | 형식 변환(srzip↔vcd, csv 등. `output_format` 은 `sigrok_list(kind="output-formats")` 의 id) → `output_path`, `output_info`. `signals/` 에 저장 + `signal-capture` 아티팩트. 아날로그 채널이 섞인 .sr 을 로직 전용 형식으로 바꿀 때는 로직 채널만 내보낸다 |
| `sigrok_file_info(case_id, input_path, input_format=None)` *(추가)* | 순수 Python(srzip/VCD 는 sigrok-cli 불필요): `format`, `samplerate`, `channels`, `total_samples`, `duration_s`, 채널별 `activity`(에지 수, high 비율, 처음/끝 레벨), `uart_candidates` |
| `sigrok_estimate_baud(case_id, input_path, channel=None, data_bits=8, parity="none")` | 순수 Python 펄스 폭 분석 → `baudrate`, `baudrate_raw`, `confidence`(0~1), `idle_level`(1=정상, 0=반전 → `invert_rx=yes`), `inverted`, `candidates`, `samples_per_bit`, `frame_check`, `warnings`(4배 미만 오버샘플링 등), `suggested_decoder`, 보드레이트가 섞였으면 `segments`. `channel` 이 없거나 `"auto"` 면 활동 채널을 모두 평가해 고르고 `per_channel` 을 붙인다 |
| `sigrok_uart_autodecode(case_id, input_path, channel=None, baudrate=None, data_bits=8, parity="none", engine="auto", background=None, …)` | 추정한(또는 `baudrate` 로 지정한) 보드레이트·극성으로 uart 디코드 → `text_preview`, `hex_preview`, `framing_errors`, `boot_hints`(U-Boot 배너, autoboot 프롬프트, 커널 버전/cmdline, mtdparts, login …), `uart_estimate{channel, baudrate, confidence, idle_level}`(signal-capture 스키마에 그대로 쓴다), `decode_text_path`/`bytes_path`(`.txt`/`.bin`, `signal-decode`). `engine`: `auto`(sigrok-cli 가 있으면 사용) / `sigrok` / `python` |
| `sigrok_job_status(job_id, wait_seconds=0, case_id=None)`, `sigrok_job_cancel(job_id)`, `sigrok_jobs(active_only=False, case_id=None)` | `register_job_tools(..., "sigrok")` — 캡처·디코드 job |

- 정책 거부(`sigrok_mcp.policy`, §4): 출력 가능 장치(전원공급기·전자부하·신호발생기·릴레이·`baylibre-acme`), 로직 애널라이저/오실로스코프 허용 목록 밖 드라이버,
  출력·설정을 바꾸는 config 키는 `sigrok_capture`·`sigrok_scan`·`sigrok_device_info` 에서 `{ok: false, status: "denied", gate: {via: "sigrok-policy"}}` 로 끝난다.
  게이트에 넘기지 않으므로 승인 경로가 없다. 다른 드라이버 이름으로 다시 시도하거나 설정을 고치지 말고 사용자에게 보고한다
  (측정 전용 장비를 허용 목록에 넣는 것은 운영자가 `pipeline-config.yaml` 의 `sigrok.capture_drivers_allow` 로 한다).
- `ftdi-la` 는 측정 전용 LA 드라이버지만 기본 허용 목록에서 뺐다(`SHARED_ADAPTER_DRIVERS`, `sigrok_list` 항목과 거부 메시지의 `reason` 에 이유가 나온다).
  제품 문자열 확인 없이 범용 FTDI VID/PID(FT232R/FT2232H/FT4232H/FT232H)만으로 장치를 잡아, 같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·JTAG 어댑터·JTAGulator 를 열고 커널 드라이버(ftdi_sio)를 떼며 핀을 bitbang 입력으로 바꿀 수 있기 때문이다.
  전용 FTDI LA 보드만 연결된 환경이면 운영자가 `sigrok.capture_drivers_allow` 에 `ftdi-la` 를 넣는다.
- 디코드(`sigrok_decode` job, `sigrok_uart_autodecode` 의 sigrok-cli 경로)도 sigrok-cli 를 띄우기 직전에 argv 를 다시 분류해 오프라인 명령(`sigrok.offline`)만 실행한다.
  캡처·스캔 argv 가 섞이면 OBSERVE 여도 `safety_denied` 로 거부한다.
- 같은 장치로는 캡처를 동시에 하나만 돌린다. 명시 직렬 conn은 공용 OS lease도 사용하며, USB/libusb 장치의 기존 예약·job 배타 키는 서버 프로세스 안에서만 유효하다.
- `sigrok_estimate_baud`, `sigrok_file_info`, `sigrok_uart_autodecode(engine="python")` 는 sigrok-cli 없이 동작한다.
- signal-capture 요약: `capture.file` ← `sigrok_capture.path`, `capture.samplerate` ← `sigrok_capture.samplerate`,
  `uart_estimate` ← `sigrok_uart_autodecode.uart_estimate`, `decoders[].output_file` ← `sigrok_decode.output_path`.

### 6.4 pweh-openocd
개발용 pipe 기반은 `rpc_pipe.py`·`process_pipe.py`와 `process.build_pipe_argv`에 있다. 기본 Linux start와 attach는 아래 TCP 경로를 사용하며, 명시 Windows start는 고정 dummy/Tigard 프로필의 pipe 경로를 사용한다. pipe client는 요청별 시간·응답·파싱 예산을 적용하고 전송 뒤 timeout/취소/프로토콜 오류가 생기면 재연결·재전송 없이 종료 상태로 둔다. Linux 직접 자식 owner는 stdin EOF → TERM → KILL 순서로 정리하고, 소유 그룹의 비좀비 프로세스 부재와 리더 reap·스트림 정리를 모두 확인해야 완료로 보고한다. 이 기반의 준비 판정은 pipe 진단 줄과 `version` 왕복이며, 운영 경로의 semihosting 확인을 대신하지 않는다. Tigard 고정 소비자는 전체 USB scope·lease를 연결하며 다른 USB 프로필은 후속이다([포트 라우팅 §13.2](design/port-routing.md#132-단계)).

Windows 계획 기반은 `pweh.wininterop`과 `openocd_mcp.windows_plan`에 있다. bounded 경로/프로세스 신원 검사와 필수 주입 실행기의 고정 조회·종료 계약, 파일 snapshot·cfg·전용 실행 디렉터리를 묶은 argv/env 계획을 제공한다. 계획은 파일 관찰·경로 변환 결과이며 cfg 승인·번들 신뢰·실행 성공의 증거가 아니다. 고정 Windows 경로로 변환한 환경값은 WSLENV의 `/w`로 한 번만 전달한다. 고정 소비자 `process_windows.py`가 고정 실행기·경로 변환기와 등록 번들을 연결하며, 기존 ESP/P2 경로는 유지한다([상세 계약](references/windows-openocd-plan.md)).

Windows `backend="windows"`는 `tcl_port=0`으로 아래 두 고정 pipe 프로필만 받는다. `target_cfg`·`extra_cfgs`·`extra_commands`는 생략 또는 빈 목록이며 사용자 cfg·Tcl을 추가할 수 없다. Windows halt/reset/resume·레지스터·메모리·플래시·덤프 job·attach·재연결은 지원하지 않는다. host/tcl_port는 null이다.

| Windows 프로필 | 고정 설정·지원 범위 |
|---|---|
| `dummy-noinit-v1` | `interface/dummy.cfg`, JTAG 1000 kHz, TAP/testee + noinit, 조회 5개·status·stop. `usb_scope="not-applicable"`, `hardware_initialized=false`, `semihosting.mode="fixed-dummy-noinit"`. [무장치 계약](references/windows-openocd-dummy.md) |
| `tigard-jtag-v1` | `interface/ftdi/tigard.cfg`, 고정 xPack 0.12.0-7·cfg SHA, JTAG 100 kHz. 유일한 0403:6010 물리 부모 전체 lease·target/bridge·계측기 검사 뒤 MODIFY 게이트, spawn 직전 fresh 대조. EARLY/PRE/init/POST와 같은 pipe의 VERIFY를 확인한다. 정확한 `version`·`scan_chain`·`targets`, status·stop만 지원. [Tigard 계약](references/windows-openocd-tigard.md) |

Tigard의 `hardware_initialized=true`는 어댑터 init 성공만 뜻하며 `target_configured=false`, `target_communication_verified=false`를 함께 반환한다. JTAG 오류·경고는 startup/diagnosis와 degraded health에 남긴다. 모든 조회와 내부 가드 RPC는 실제 worker의 사용권을 유지한다. Windows·wrapper·리더·제어 조회 종료와 worker 종료, run 신원 정리까지 확인한 뒤 USB lease를 해제한다. 불확실하면 세션·owner·lease를 보존하고 stop을 재시도한다. 아래 TCP·사용자 cfg·덤프 설명은 Linux 경로에 적용하며, init·semihosting 가드는 Tigard에도 적용한다. Tigard의 실기 USB·드라이버·타깃 통신은 미검증이다.

OpenOCD 프로세스 관리 + TCL RPC. Linux에서는 TCL 포트만 127.0.0.1 에 열고 telnet/GDB 포트는 끈다(다시 여는 명령은 DESTRUCTIVE). 보내는 모든 Tcl 텍스트는 `openocd_mcp.guard.classify_command` 로 분류한다(§4 — 코어 `classify_openocd` 만으로는 불완전).
덤프 job 이 도는 케이스에서는 halt/resume/reset·쓰기·MODIFY 이상 원시 명령이 `busy` 로 거부되고, 조회 도구는 현재 청크가 끝날 때까지 기다린다.
시그니처의 `…` 는 생략한 선택 인자다(전체 목록: `docs/references/pweh-mcp-tools.md`).

| 도구 | 설명 / 반환 |
|---|---|
| `openocd_list_configs(kind="interface", pattern=None, limit=200)` *(추가)* | scripts 디렉터리의 cfg 목록(`interface`/`target`/`board`/`all`, `pattern` 은 부분 문자열 필터) → `scripts_dir`, `configs[]`, `count`, `truncated`. 값을 `openocd_start` 의 `interface_cfg`/`target_cfg` 에 그대로 쓴다 |
| `openocd_start(case_id, interface_cfg, target_cfg=None, transport=None, adapter_speed_khz=None, extra_commands=None, tcl_port=6666, extra_cfgs=None, ready_timeout=30, approval_id=None, backend="linux", windows_profile=None)` | **MODIFY**(JTAG/SWD 초기화가 타깃 상태에 영향). Windows는 위 두 고정 프로필과 조회 범위만 지원한다. Linux 경로: `extra_commands` 의 init 계열 명령(`init`, `::init`, `ocd_init`, `target`/`transport`/`jtag`/`dap`/`flash`/`nand`/`pld`/`tpiu`/`swo` `init`, `jtag arp_init`·`arp_init-reset`, `jtag_init`, `init_reset`, `post_init_commands` 수정 — catch·eval·if·capture·따옴표 본문과 `-event` 본문, switch 목록 안 본문·apply 람다·proc 본문·defer·subst 의 `[…]`·`-command` 접두 안 포함)은 `validation_failed` 다(init 은 semihosting 가드 뒤에 서버가 실행한다). 게이트는 `extra_commands`, 서버가 만든 transport/adapter speed 명령, 사용자 cfg 의 **내용 전체**까지 분류한 최악값으로 판단한다(사용자 cfg 의 init 계열 명령은 DESTRUCTIVE `openocd.local.init-before-guard`, `$변수`·`-event`·`proc` 를 쓰는 cfg, `telnet port N`/`gdb port N` 재활성화, 중괄호 없는 `expr`/`if` 조건의 치환은 DESTRUCTIVE → 기본 거부). 사용자 cfg 는 신뢰 scripts 디렉터리 밖의 경로, 그리고 OpenOCD 기본 검색 위치(`$OPENOCD_SCRIPTS`, `~/.config/openocd`, `~/.openocd`, site)에서 찾은 이름이다. 1 MiB 를 넘는 사용자 cfg 는 잘라 분류하지 않고 `validation_failed` 로 거부한다. 승인 지문에 사용자 cfg 의 sha256(`custom_cfg_sha256`)이 들어가 승인 뒤 내용이 바뀌면 승인이 맞지 않고, 프로세스를 띄우기 직전에 다시 해시해 다르면 `safety_denied` 로 띄우지 않는다. 표준 cfg 는 확인된 절대경로로 넘기고, 신뢰 scripts 디렉터리는 모두 `-s` 로 넘겨(표준 cfg 안의 `source [find …]` 가 `~/.openocd` 같은 사용자 위치의 같은 이름 파일보다 먼저 찾음) OpenOCD 를 빈 작업 디렉터리에서 띄운다. `target_cfg` 는 문자열 또는 목록, `tcl_port=0` 이면 빈 포트 자동. 준비 완료 = 로그의 `Listening on port N for tcl connections` + `version` 왕복. 로그 `jtag/openocd-<n>.log`, 상태 `jtag/openocd-<n>.json`. **semihosting 은 항상 꺼 둔 채 끝내고 시작 뒤에도 계속 확인한다**(`mcp-servers/openocd-mcp/openocd_mcp/semihosting.py` 의 Tcl 가드 `pweh_semihosting_guard <단계>`): 표준 cfg 는 내용을 분류하지 않는데 xPack `target/esp_common.cfg` 는 ESP32 계열 cpu0/cpu1 의 `examine-end` 핸들러에서 `arm semihosting enable` 을 실행한다(켜지면 타깃 펌웨어가 호스트 파일·명령에 접근). 관련 핸들러(본문에 `semihost` 가 있거나 semihosting proc 이름이 든 타깃·TAP 이벤트 핸들러)만 `try {원래 본문} finally {모든 타깃 중 켜진 것을 끔}` 으로 감싼다(다른 핸들러·ARM 표준 cfg 는 바이트 단위로 그대로). `-f` 하나하나와 `extra_commands` 하나하나 바로 뒤의 init 조기 실행 검사(`[command mode]` 가 `config` 가 아니면 모든 타깃의 semihosting 을 끄고 OpenOCD 를 오류로 끝냄 → 로그 표식으로 `init-before-semihosting-guard`) → 단계: `pre-init`(모든 cfg·`extra_commands` 뒤, init 직전 — `[command mode]` 가 `config` 가 아니면 init 이 이미 돈 것, 아니면 감싸기) → `post-init`(init 직후, TCL 포트가 열리기 전 — init 중(init_board/init_targets) 설치된 핸들러와 TAP 핸들러까지 다시 감싸고 타깃마다 조회해 켜져 있으면 끔) → `verify`(연결 직후 TCL RPC 로 **반드시**: 가드가 전역 변수에 남긴 시작 단계 기록과 새 확인 결과를 받으므로 로그 형식과 무관). 로그의 `PWEH-SEMIHOSTING …` 표식은 `-d3` 이상의 `User : … handle_echo(): ` 접두도 읽고 `script_debug(): command - echo …` 줄은 무시한다. 가드가 없거나 결과가 불완전하면 `semihosting-verification-failed`, init 이 가드보다 먼저 돌았으면(init 을 직접 실행하는 표준 cfg 포함) `init-before-semihosting-guard`, 감싸기·끄기 실패나 스크립트 오류면 `semihosting-neutralization-failed`(`semihosting_failures`) — 모두 OpenOCD 를 끄고 빈 실행 디렉터리를 지운 뒤 `start_failed` 로 돌려준다. 반환: `tcl_port`, `pid`, `log_path`, `version`, `health`(`ok`/`degraded`), `startup`(`taps`, `auto_newtap_suggestions`, 오류/경고), `diagnosis[]`(code + 힌트, 무력화했으면 `semihosting_neutralized`), `scan_chain`, `targets`, `semihosting_neutralized`(`<타깃>:<이벤트>` = 감싼 핸들러, `tap:<TAP>:<이벤트>`, `<타깃>:after-init` = init 직후 켜져 있어 끔, `<타깃>:after-start` = 연결 직후 확인에서 끔), `semihosting`(`verified`, `source: "rpc"`, `log_markers`(로그 표식이 있었는지), `phases`(`pre-init`·`post-init`·`verify`. 조기 실행 검사로 끝났으면 `early-check`), `handlers_wrapped`, `targets`: 타깃별 `off`/`disabled`/`unsupported`, `procs`(가드 자신의 proc 을 뺀 semihosting proc), `phase_targets`, `unwrapped`, `init_before_guard`, `failures`; 상태 파일과 `openocd_status` 의 `semihosting.startup` 에도 같은 값). **시작에 실패해도 예외를 던지지 않고** `ok: false, status: "start_failed"` 와 `reason`, `errors`, `diagnosis`, `log_tail`, `argv` 를 돌려준다(로그와 진단 보존) |
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
| `openocd_job_status(job_id, wait_seconds=0, case_id=None)`, `openocd_job_cancel(job_id)`, `openocd_jobs(active_only=False, case_id=None)` | OpenOCD 는 단일 스레드이고 프로토콜 수준 취소가 없어, 취소는 현재 청크가 끝난 뒤 반영된다 |

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
| `jtagulator_connect(case_id, port, baudrate=115200, timeout_seconds=12, allow_untested_firmware=False, approval_id=None)` | INTERACT(새 open의 확인된 reset 배선은 MODIFY). 승인 전 공용 포트 lease와 target/bridge 역할 표지를 확인하고, 승인 뒤 fresh 경로·계측기 guard를 거쳐 포트를 연다. Ctrl-X 재동기화로 메뉴와 펌웨어 버전을 읽는다. 문자장치·루프백 socket/RFC2217·loop, 확인된 WSL1 COM1–191을 받는다. WSL COM은 검증된 helper로 연결하며 sigrok COM scan/show는 별도 Windows exe 경로다. URL 옵션·LAN은 거부한다. 같은 끝점은 다른 케이스나 UART/ESP/sigrok가 점유해도 `busy`다. 같은 케이스의 유효한 기존 연결은 재사용한다. POSIX는 exclusive+TIOCEXCL, URL은 공용 lease로 PWEH끼리 배타한다. `connection{port, firmware, firmware_supported, connection_token, voltage, menu, active_job_id, route, …}`, `firmware`, `reused`, `warnings`, `next_steps`를 반환한다. 연결마다 전압 상태는 미설정이다. FW 1.10 미만은 `allow_untested_firmware=true` 없이는 전압 설정·스캔을 거부한다. 로그 `jtag/jtagulator-<n>.log`, 케이스당 연결 하나·포트당 케이스 하나 |
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
| `jtagulator_job_status(job_id, wait_seconds=0, case_id=None)`, `jtagulator_job_cancel(job_id)`, `jtagulator_jobs(active_only=False, case_id=None)` | 스캔 폴링·취소. 취소하면 스캔을 중단하고 부분 결과를 남긴다(`cancelled`) |

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
- **`background=true`**(`fw_identify`, `fw_entropy`, `fw_extract_squashfs`, `fw_elf_info`, `fw_rootfs_audit`, `fw_strings_hunt`, `fw_crack_hashes`, `fw_checksum_find`, `fw_find_seq_tables`): 응답은 `job_id` 이고
  `fwtriage_job_status` 의 `result` 가 인라인 응답과 같다(`result_path` 포함). `max_seconds` 는 시간 예산이며 넘으면 부분 결과로 끝난다(`summary.timed_out`/`truncated`).
- 오프셋·크기 인자는 정수 또는 `"0x150000"`, `"64k"`, `"2M"` 같은 문자열을 받는다.
- 입력 경로가 보호 하위 트리 `forensics/`(SD 카드 증거)·`emu/`(원시 콘솔) 안이거나 이를 품은 디렉터리(케이스 루트 등)면 `validation_failed` 다(링크를 풀어 판단 — §4 'SD 카드 증거'). 카드 이미지·추출물은 pweh-forensics 로만 다룬다.

| 도구 | 설명 / 반환 |
|---|---|
| `fw_identify(case_id, path, offset=0, length=None, max_results=50, include_nested=False, max_seconds=120, background=False)` | 헤더 검증으로 오탐을 줄인 시그니처 스캔: uImage(헤더·데이터 CRC), FIT/DTB, squashfs(v1~4, 벤더 매직), jffs2, UBI/UBIFS, cramfs/romfs/erofs/ext2·3·4, gzip/xz/lzma/bzip2(시험 해제로 정확한 크기), zstd/lz4(프레임 검증), ELF, cpio, ARM zImage, zip, PEM, U-Boot env, U-Boot·커널 버전 문자열 → `regions[{offset_hex, kind, size, confidence, details}]`, `padding_runs`(0xFF/0x00), `nested_omitted`(투명 컨테이너 안쪽 항목 수, `include_nested=true` 면 목록에 포함), `next_steps`. `analysis/identify-NNN.json` |
| `fw_entropy(case_id, path, block_size=65536, offset=0, length=None, high_threshold=7.5, annotate=True, …)` | 블록 Shannon 엔트로피 → `high_runs`(카이제곱으로 균일=암호화·강한 압축 / 비균일=일반 압축 구분), `unexplained_high_entropy_runs`(알려진 시그니처로 설명되지 않는 고엔트로피 = 암호화·난독화 의심), `low_runs`(패딩), `profile`(한 줄 프로파일), `stats`. `analysis/entropy-NNN.json` |
| `fw_uboot_env(case_id, path, sizes=None, align=4096, include_default_env=True, max_results=16)` | U-Boot env 블록 탐색(후보 크기별 CRC, redundant 플래그, 빅엔디안 CRC 보완) → `envs[]`(env 전체, 주요 변수, mtdparts 해석), `recommended_layout`, `embedded_default_envs`(U-Boot 바이너리에 내장된 CRC 없는 기본 env), `mtdparts_strings`. env 마다(`envs[]`·`embedded_default_envs[]`) `sd_boot` 를 붙인다 — 응답은 압축형 `{mmc_boot, fs_load, boot_script, mmc_first, verify, verify_off, update_from_card, persistent_writable, severity_hint, signal_vars}` 와 `sd_boot_summary{envs_with_mmc_boot, envs_with_boot_script, verify_off, update_from_card, env_persistent}`, 결과 파일은 전체 `sd_boot{storage, mmc_boot, fs_load, boot_script, distro_boot, raw_mmc_only, mmc_first, verify, verify_off, update_from_card, update_gpio_gated, signals[≤24]·signals_total, expansion_truncated, vars_truncated, severity_hint, notes}` 다. `storage`: `flash-crc` = CRC 유효 플래시 env(saveenv 로 쓰기 가능 → `persistent_writable=true`) / `embedded-default` = U-Boot 내장 기본 env(`null`). `fs_load` 는 fatload/ext4load/load mmc, `boot_script` 는 mmc 에서 읽는 boot.scr·uEnv.txt(run 펼친 값의 fatload/ext2load/ext4load/load mmc·mmc dev/rescan·distro boot·devtype=mmc, 장치 자리의 변수 `fatload ${bootdev} …`·`load ${interface} …` 는 같은 env 에서 값이 장치 이름 하나(`bootdev=mmc`)면 그 장치로 읽는다 — tftp·dhcp·nfs·ubi·nand·sf 출처는 notes 만, usb 출처는 '이동식 매체' notes, 읽는 명령이 안 보이는 이름만의 boot.scr 는 같은 env 에 mmc 로드 경로가 있을 때만) 또는 mmc 로드 뒤 source·env import, `mmc_first` 는 bootcmd 가 플래시보다 mmc 를 먼저 시도하는지(run 은 제자리에 펼침, distro 는 boot_targets 첫 대상), `signals[]` 는 `{var, kinds, value(마스킹)}` 다. `update_from_card` 는 SD 업데이트 명령·이름(sdupdate·sdupgrade·hiupdate·do_auto_update·sd_update·update_from_sd)이나 mmc 에서 읽어 플래시에 쓰는 값이다(이름만 autoupdate·auto_update 인 TFTP 업데이트는 아님). `verify_off` 는 U-Boot env_get_yesno 기준이다: 값이 있고 첫 글자가 1/y/Y/t/T 가 아니면 검증 꺼짐(off·disable·n·0·빈 값 포함), 없으면 기본(검증 켬). 오래된 U-Boot 는 첫 글자 n 만 끔으로 본다(notes). run 펼침은 변수당 16 KiB·env 2 MiB·env 여럿을 합쳐 4 MiB·run 대상 64개·깊이 4, 변수는 2만 개까지 보고, 넘으면 `expansion_truncated`/`vars_truncated` 와 notes 에 적는다(`fw_sd_surface` 에서는 시간 예산도 펼침 중에 보고, 잘리면 `image_env` 가 잘림이 되어 SD-02·SD-03 이 not-found 대신 unknown). next_steps 의 `fw_sd_surface` 안내는 mmc 부팅·카드 업데이트 신호가 있을 때만 주고, verify 만 꺼진 env 에는 일반 '이미지 검증 꺼짐' 안내만 준다. mmc 장치 번호로는 SD 슬롯과 eMMC 를 구분하지 못한다. CRC 없는 내장 기본 env 후보 탐색(HEAD 부터 같은 코드)은 시간 예산을 보지 않아, 거부되는 후보가 빽빽한 조작된 이미지에서는 오래 걸릴 수 있다(`fw_sd_surface` 는 그 뒤 예산을 확인해 `timed_out`·`unknown` 으로 알린다). `analysis/uboot-env-NNN.json` |
| `fw_carve(case_id, path, mtdparts=None, partitions=None, output_label="parts", mtd_device=None, probe=True)` | mtdparts 문자열 또는 `[{name, offset, size}]` 로 분할한다. 둘 다 없으면 CRC 유효 env(mtdparts/bootargs) → 내장 기본 env → 이미지 속 `mtdparts=` 문자열 → DTB partition 노드 순으로 레이아웃을 정한다. **출력은 `extract/<label>-NNN/<idx>-<name>.bin`**(idx 2자리, 이름은 `[A-Za-z0-9._-]` 로 정리) **+ `index.json`** 이고 파티션마다 `partition` 아티팩트로 등록하며 시작 위치의 형식을 판별한다 → `partitions[]`, `layout`, `output_dir`, `index_path`, `result_path`(`analysis/carve-NNN.json`) |
| `fw_uimage_info(case_id, path, offset=0)` | legacy uImage 헤더(이름, load/entry, OS/arch/type/압축, 헤더·데이터 CRC, multi 크기표, 실제 페이로드 형식과 헤더 압축 표시 일치 여부) 또는 FIT/DTB(images, configurations, 해시. DTB 면 model/compatible/bootargs/partition 노드) → `image`. 매직이 없으면 파일 안의 uImage/FIT 위치를 안내한다. `analysis/uimage-NNN.json` |
| `fw_extract_squashfs(case_id, path, offset=0, output_label="rootfs", timeout_seconds=600, max_output_bytes="2G", engine="auto", allow_listing_anomalies=False, background=False)` | superblock 검증 → `unsquashfs -lln` 목록 안전 검사(디렉터리 탈출, 비정상 줄, 압축 폭탄) → 비root 추출(장치 노드 안 만듦). 트리 `extract/<label>-NNN/`(`extracted-tree`)와 원본 모드/소유자/setuid 를 보존한 `extract/<label>-NNN.manifest.json` → `output_dir`, `output_dir_abs`(다른 도구에 넘길 절대경로), `manifest_path`, `superblock`, `status`. `analysis/extract-squashfs-NNN.json`. unsquashfs 가 없으면 `tool_missing` + 설치 힌트 |
| `fw_rootfs_audit(case_id, rootfs_dir, max_results=50, crack_defaults=True, crack_seconds=30, max_file_size="16M", sd_surface=False, …)` | 추출된 rootfs 감사: passwd/shadow(빈/약한 해시, uid 0 추가 계정, 공개 하드코딩 해시, 기본 비밀번호 오프라인 대조), 시작 스크립트(telnetd `-l /bin/sh`, getty 자동 로그인 등), 웹 서버·CGI, setuid(매니페스트 기준), 개인키/인증서(base64 본문이 있는 PEM 만 — 라이브러리의 머리줄 상수는 세지 않는다, 지문만), 하드코딩 자격증명(마스킹) → `items[]`(finding 스키마의 category·severity 힌트, 파일/줄/발췌), `rootfs`(static-analysis 스키마의 rootfs 형태), `binaries_of_interest[{path, reason}]`, `services`, `web_servers`, `accounts`, `vendor`(`family`/`family_source`: 파일 근거(바이너리 이름·배너·경로) `evidence` → 없으면 프로필의 구체적인 `hunt.vendor_family` `profile` → 일반 웹 서버만 있으면 `generic`(`generic-web-server`) → 아무 근거도 없으면 `unknown`(`none`). `votes`·`vendor` 는 파일 근거만), `limitations`. 심볼릭 링크는 rootfs 안에서만 해석한다. `bin`/`sbin` 의 `passwd` 명령과 바이너리 내용은 계정 DB 로 읽지 않는다. 핫플러그 처리기(mdev.conf `@`/`$`/`*` 명령, udev `RUN+=` — 상대 이름은 `/lib/udev`·`/usr/lib/udev`, `/etc/hotplug*`, 텍스트인 `/sbin/hotplug`)도 시작 스크립트처럼 따라간다. 쓰기 가능 마운트로 exfat/msdos/fat/auto/ntfs3/sdcardfs 와 `-t` 없는 `/dev/mmcblk*`(fstab 의 mmcblk 장치 포함)도 보며, `-o ro`·`-r`·읽기 전용 fs 는 제외한다. 시작 스크립트는 셸 논리 줄 단위로 본다: 줄 끝 `\`(앞의 `\` 가 홀수 개)·`\|`·`\|\|`·`&&` 로 이어진 줄(들여쓴 다음 줄 포함)은 한 명령이고, 연산자 뒤의 빈 줄·주석 줄도 같은 명령에 들어간다(셸의 linebreak — `a \| # 설명` 처럼 연산자 뒤에 주석이 와도 잇고, 그 주석은 판정에서 지운다 — 발췌에는 남는다). 줄 끝 `#` 주석 안의 연산자·`\`(`echo x  # 1단계 \|\|`), 글자인 `\|`·`\&&`(`\&` 뒤의 백그라운드 `&`), here-document 본문은 잇지 않는다. here-document 구분자는 한 셸 낱말 전체다(`<<END-OF-X`·`<<!`·`<<E"O"F`·`<<\X`, `;` 뒤의 `#` 은 주석). 끝 구분자 줄이 없는 시작은 본문으로 보지 않고 다른 셸 줄처럼 잇는다 — 여러 줄 문자열 속 `<<낱말` 같은 잘못 읽은 시작이 그 뒤의 이어쓰기를 모두 끄지 않게. inittab·inetd.conf·xinetd·mdev.conf·udev 규칙·systemd 유닛·설정(`/systemd/` 아래의 `.service`·`.socket`·`.timer`·`.conf` 같은 INI 접미사 — 셰뱅 없는 도우미 스크립트는 셸)·crontab 처럼 셸 문법이 아닌 파일은 줄 끝 `\` 로만 잇고(BusyBox parse_config·udev·systemd 와 같다), 경로 앞의 대입·래퍼를 건너지 않는다(`ExecStart=/usr/bin/app /userdata/app.ini` 의 경로는 인자다). 항목·서비스·마운트의 줄 번호는 그 명령의 첫 줄이다. 쓰기 가능 저장소의 파일 실행(`builtin-exec-from-writable-storage`)은 경로가 실행 위치일 때만이다: 줄 처음·`;`·`&`·`\|`·then/do/exec/sh/source 뒤, 그 앞의 투명한 접두(변수 대입 `VAR=값`, nohup·setsid·env·command·time 과 그 인자 없는 옵션) 뒤, `start-stop-daemon -x\|--exec\|-a\|--startas` 의 인자(같은 명령에 -K/-T/-t 가 없을 때. 단 띄어 쓴 긴 꼴 `--exec 경로` 는 exec 낱말 규칙으로도 실행 위치가 되므로, 이 기본 감사는 `--stop --exec 경로`·`-K --exec 경로` 도 여전히 실행으로 본다 — HEAD 와 같다. `-x 경로`·`--exec=경로` 는 그렇지 않고, SD 표면(`fw_sd_surface` 와 이 도구의 `sd_surface`)은 멈춤·상태·시험 동작의 `--exec 경로` 를 실행으로 보지 않는다). 이어진 줄의 처음은 실행 위치가 아니다(`cp \`·`mount … \` 다음 줄의 인자 경로). 인자를 받는 실행기(nice -n·ionice·taskset·chrt·timeout·chroot)·busybox·sudo 뒤, 따옴표로 감싼 경로, 값에 `$(…)`·역따옴표가 있는 대입(`V=$(cat x) \`)이나 `{ \` 묶음 다음 줄의 경로는 실행 위치로 보지 않고, here-document 본문과 여러 줄 문자열의 줄도 명령처럼 판정하며(HEAD 와 같은 줄 규칙 — 본문이 셸에 넘겨지거나 파일로 써서 실행되는지는 따지지 않는다), 경로 앞 투명 낱말은 16개(낱말당 1024자)·start-stop-daemon 은 옵션 앞 2048자까지만 본다. 4096자(PATH_MAX)를 넘는 경로·쓰기 가능 접두는 실행·마운트될 수 없어 보지 않는다. 내장 규칙(telnetd·dropbear -B·nc 셸·socat·tcpsvd·getty 자동 로그인·login -f·remserial·chpasswd·서비스)은 조각을 차례로 찾는 선형 판정이라, 키워드가 되풀이되거나 줄 앞에 긴 덧대기가 있어도 줄을 자르거나 규칙을 건너뛰지 않는다(옵션이 키워드에서 멀어도 같은 논리 줄이면 잡는다). YAML text/any 휴리스틱도 논리 줄마다 평가한다(최상위 무제한 간격 `[^\n…]*` 과 상한 256 이상의 같은 줄 간격 — 예: `{0,1024}?` — 은 나눠서 선형으로, 길이 제한 없이 본다. 큰 상한은 원래 정규식을 쓰는 `fw_strings_hunt` 의 선형 시간을 위한 것이다). 같은 최종 파일을 가리키는 이름(심볼릭 링크, 그리고 `(st_dev, st_ino)` 가 같은 하드 링크)은 한 번만 읽는다(`startup_files` 에는 이름이 모두 남고, 항목은 처음 이름으로 적는다). 항목은 같은 파일의 같은 규칙마다 20개까지 적고 나머지는 `summary.items_suppressed` 와 limitations 한 줄(규칙·파일별 버린 수)로 센다 — 이 상한은 계정·자격증명·웹을 포함한 `items` 전체에 적용된다. 시작 스크립트 검사는 같은 규칙을 모든 시작 스크립트에 걸쳐 500개까지 적고, 넘는 수는 같은 `summary.items_suppressed` 와 limitations 한 줄(규칙별 버린 수, 많은 순 10개)로 센다. 이 상한은 항목 수 상한이지 바이트 상한이 아니다 — 수천 자 디렉터리 이름 아래의 시작 스크립트 수천 개처럼 경로가 아주 길면 결과 파일이 수백 MiB 가 될 수 있다(HEAD 보다는 작다). 참조된 스크립트는 400개, 실행 문맥(`sh /x`, `; /x`, `then /x` …)으로 참조된 스크립트와 핫플러그 처리기는 2000개까지 따라가고, 핫플러그 처리기와 `sh 파일`·`. 파일` 로 읽는 파일은 셰뱅이 없어도 텍스트면 따라간다. 시간 예산(파일·휴리스틱 사이, 경로 1024개마다 확인), 이 큐 상한, 시작 스크립트 한 개 1 MiB 상한에 걸리면 `summary.startup_scan_complete=false` 이고 limitations 에 `[시작 스크립트 검사 미완료] …`(무엇을 못 봤는지와 스크립트 이름)를 적는다. 실행 문맥이 아닌 참조가 400개를 넘어 따라가지 않은 스크립트는 접두 없는 limitations 한 줄로 센다. mount 명령은 줄 끝 `#` 주석을 떼고 보며, 쓰기 가능 접두는 중복 없이 모은다. mounts·services 의 command 와 시작 스크립트 발췌는 자격증명 값을 가린다. `sd_surface=true` 면 같은 순회 결과로 SD 공격 표면의 rootfs 쪽을 더한다: 응답 `sd_surface` 는 `fw_sd_surface` 응답과 같은 요약(`counts`·`risk_found`·`checks`·`mount_points`·`sd_paths_referenced`·`limitations`)이고, 결과 파일의 `sd_surface` 는 전체다. U-Boot 쪽은 보지 않으므로 rootfs 근거가 없는 SD-02·SD-03 은 `unknown` 이다. `max_file_size`(기본 16M)를 넘는 바이너리가 있으면 바이너리 근거에 기대는 점검(SD-01·02·04·05·06·08·09)이 `unknown` 이다(`fw_sd_surface` 기본은 64M). 기본값 false 면 응답·결과 파일·params 에 `sd_surface` 가 없다. `analysis/rootfs-audit-NNN.json` |
| `fw_sd_surface(case_id, rootfs_dir=None, image_path=None, max_results=50, max_evidence=20, max_file_size="64M", max_seconds=300, background=False)` | 펌웨어 쪽 SD 카드 공격 표면 정적 점검 SD-01~09(`docs/design/sd-forensics.md` §5.1, 오프라인·관찰만 — 기기·카드를 건드리지 않고 펌웨어 안의 어떤 것도 실행하지 않으며, 펌웨어의 mdev 정규식·udev glob 도 실행하지 않는다). `rootfs_dir`·`image_path` 중 하나 이상(둘 다 없으면 `validation_failed`). rootfs 는 순회·시작/핫플러그 스크립트·웹 설정과 텍스트·바이너리 문자열(계정·해시 대조 없음), image 는 U-Boot env(CRC 유효·내장 기본)의 `sd_boot` 와 이미지 문자열을 본다. 별도 `fit_security`에는 비압축 FDT v17의 이미지/설정 서명 선언과 control-DTB 형태 키 후보의 구조·검사 범위를 기록한다(서명·키 신뢰·부팅 강제·SD 경로 검증 아님). **응답**: `input`, `counts{found, not-found, unknown}`, `risk_found`(found 이고 found_means=risk 인 id), `checks[{id, title, status, severity_hint, category(finding 어휘), found_means(SD-07 만 protection), evidence_total, evidence[≤3 {source(rootfs/uboot-env/image-strings), file(rootfs 절대 경로) 또는 image(케이스 상대 경로)+offset_hex, line, rule, severity, sd_path, excerpt(마스킹)}], unknown_reason?, next_steps[≤2]?, severity_reason?(SD-02)}]`, `mount_points[≤max_results {path, sources, fs, present_in_image}]`·`mount_points_total`, `sd_paths_referenced[≤max_results {path, card_relative, actions, checks}]`·`sd_paths_total`·`sd_paths_truncated`, `truncated`, `limitations[≤10]`, `uboot?{env_count, embedded_default_env_count, sd_boot_summary, envs[≤8]}`, `fit_security`(제한된 FIT 선언 구조와 완료도), `next_steps`. **결과 파일에만**: 점검의 `severity_basis`(evidence/baseline)·`rationale`·`references`(설계 표 CVE)·`examples`·`context`, 근거 전체(`max_evidence` 개, expanded·gated_by·copied_to·cwd·remote_write 같은 추가 필드), 마운트 지점의 `devices`·`builtin_pattern`·`mount_commands[{options, fs, readonly, options_visible, …}]`, `hotplug_handlers[{kind, file, line, match, match_kind(sd/catch-all/other/unclassifiable), action, command, handler_script}]`, `other_mmc_mounts`(eMMC·SATA 일 수 있어 SD 로 보지 않은 마운트), `sd_paths_referenced[].refs`, `builtin_sd_patterns`, `inputs_analyzed`, `phases{rootfs_text, rootfs_binary, image_env, image_strings: complete/truncated}`, `stats`, `uboot`(env 마다 전체 `sd_boot`), `timed_out`. next_steps 는 정적 확인(REA)과 사람이 동의한 새 빈 시험 카드의 부팅 로그 관찰(`uart_capture_boot` 의 `sd_events`)까지만이고, 카드에 넣을 파일은 만들거나 안내하지 않는다. `analysis/sd-surface-NNN.json` |
| `fw_strings_hunt(case_id, path_or_dir, patterns="cctv", max_hits=500, max_results=50, min_severity=None, include=None, …)` | `src/pweh/data/cctv-hunt-patterns.yaml` 의 `string_heuristics` 로 인증 우회/백도어/명령 주입/하드코딩 자격증명 문자열을 휴리스틱 검색한다. `patterns`: `cctv`(전체), 휴리스틱 id/category/vendor/severity 선택자, `xm-*` 같은 접두사, `re:<정규식>`, `raw:<바이트 정규식>`, `lit:<문자열>`. **게임 팩**: `patterns="game"` 이면 `src/pweh/data/game-hunt-patterns.yaml`(category `debug-menu`·`cheat-input`·`unlock-condition`·`save-format`·`save-integrity`·`nfc-tag`·`clock`·`online-sync`·`entitlement`, severity `info`/`low`, entitlement 는 보고만) 전체, `game:<category\|id\|vendor\|severity\|접두사*>`(목록 가능)는 그 일부다. 두 팩은 한 호출에서 섞지 않는다(CCTV 선택자를 함께 주거나 게임 팩에 없는 `game:` 선택자면 `validation_failed`, 사용자 패턴은 함께 쓸 수 있다). 쓴 팩은 응답 `patterns.pack` 과 결과 JSON `params.pack` 에 남고, 게임 팩이면 `summary.vendor_family_guess` 는 `null` 이다 → `hits`(`file`/`path`(아래), 오프셋, 텍스트는 줄, 패턴 id/category/severity, 문맥), `matched_checks`, `no_match_checks`(개수), `summary`(`vendor_family_guess`, `rootfs_dirs` 등), `top_files`. 전체 JSON 의 `checks[]` 는 auth-hunt 스키마 `checks[]` 에 그대로 쓴다. `#` 주석 줄의 히트는 `commented_hits` 로 따로 둔다. 사용자 패턴(`re:`/`raw:`/`lit:`, 선택자에 맞지 않는 일반 단어)의 check id 는 `custom-<lit\|re\|raw>-<sha256 앞 8자>` 라 실행이 달라도 같은 패턴이면 같고, 패턴 원문은 `description` 에 있다. 빈 문자열과 일치하는 사용자 패턴은 건너뛰고 `notes` 에 적는다. `include` glob 은 `path_or_dir` 기준이다. 게임 팩(`patterns="game"`)이면 히트의 key=값(토큰·키·코드·비밀번호·PIN·라이선스·시리얼)·URL 자격증명·Bearer·JWT 값은 `<masked>`(`summary.masked_values`). 시간 예산·취소는 파일 사이와 16 MiB 조각 사이에서 반영된다(파일 하나만 볼 때도 — 예산이 지나면 남은 조각은 읽지 않고 `summary.truncated`) — 키워드를 수 MiB 되풀이한 한 줄 같은 조작된 입력에서는 조각 하나의 정규식 검사가 선형이지만 약 20초 걸리고, 그동안 서버의 다른 호출이 기다린다. `analysis/strings-hunt-NNN.json` |
| `fw_elf_info(case_id, path, max_results=50, max_files=3000, max_seconds=180, background=False)` | 순수 Python ELF: class/엔디언/e_machine, e_flags(MIPS ISA·ABI, ARM EABI·float ABI), 인터프리터, DT_NEEDED/RPATH, 임포트 심볼(섹션 헤더 없는 sstrip 바이너리 포함), 보호기법(NX/RELRO/PIE/카나리/FORTIFY), 위험 임포트(`system`/`popen`/`strcpy`/`sprintf` …, YAML `function_heuristics`). `path` 가 디렉터리면 모든 ELF 를 위험 점수 순으로 → `binaries`, `mode`, `summary`. `analysis/elf-info-NNN.json` |
| `fw_crack_hashes(case_id, hashes=None, source_path=None, wordlist="builtin-defaults", extra_words=None, hash_type=None, max_seconds=60, reveal=False, …)` | 해시를 공개 기본 비밀번호 사전과 **오프라인** 대조한다(네트워크 로그인 시도 없음, 소유 기기 감사용). `hashes`(`user:hash` 줄 / 순수 해시 / `{user, hash, type}`) 또는 `source_path`(케이스 안 passwd/shadow/htpasswd) 중 하나. DES crypt, md5crypt/apr1, sha256/512crypt, XiongMai Sofia(`hash_type="xm-sofia"` 필요), 솔트 없는 md5/sha1/sha256, bcrypt/yescrypt(crypt 모듈 지원 시) → `results[]`(평문은 마스킹, `reveal=true` 일 때만 표시), `counts`. 평문 전체는 `analysis/crack-hashes-NNN.json` 에만 있다(케이스 밖 반출 금지). `not_cracked` 는 안전하다는 뜻이 아니다 |
| `fw_hunt_patterns(vendor=None, category=None, pack="cctv")` *(추가)* | `fw_strings_hunt`/`fw_rootfs_audit`/`fw_elf_info` 가 쓰는 휴리스틱 목록(`string_heuristics`, `function_heuristics`, `credential_patterns`, `web_server_binaries`, `known_hashes`, `candidate_passwords`)과 패턴 파일의 `source`·`sha256`·`errors`. `pack="game"` 이면 `fw_strings_hunt(patterns="game")` 이 쓰는 게임 팩 목록(`string_heuristics` 만 있고 나머지는 비어 있다). 응답의 `pack`·`packs`(사용 가능한 팩), 알 수 없는 팩은 `validation_failed`. 케이스를 받지 않아 `result_path` 가 없다 |
| `fw_esp_partitions(case_id, path, offset=None, max_results=50)` | ESP32 계열 플래시 덤프의 파티션 표(기본 0x8000, 없으면 4 KiB 경계 탐색, 0 이면 표 이미지 자체) → `partitions[{label, type, subtype, offset, size, encrypted, readonly, write_class, write_blockers}]`, `md5{present, ok}`, `nvs_keys_present`, `next_steps`. `write_class`: `nvs`(쓰기 후보), `raw-user-data`(원시 데이터·사용자 정의 형식), `filesystem-analysis-only`(fat/spiffs/littlefs/esphttpd — 파일 시스템 해석 전까지 분석만), `not-a-save`(앱·ota·phy·coredump·nvs_keys·efuse·부트로더). `write_blockers`: 암호화 플래그, `nvs_keys` 파티션(NVS 암호화 가능). `analysis/esp-partitions-NNN.json` |
| `fw_esp_image_info(case_id, path, offset=None, partition=None)` | ESP 앱·2단계 부트로더 이미지(매직 0xE9) → `chip`/`arch`, `entry`, `segments[{load_addr, size, file_offset, file_offset_abs, region, kind}]`(`file_offset` 은 이미지 기준, `file_offset_abs` 는 입력 파일 기준), `checksum{stored, computed, ok}`, `sha256{present, ok}`, `app_desc`(esp_app_desc_t: 프로젝트 이름·버전·IDF 버전·빌드 시각·ELF sha256), `image_size`. `partition=label` 은 전체 플래시 덤프의 파티션 표로 위치를 찾는다(`offset`·`length` 와 함께 줄 수 없다). ESP8266 이미지는 지원하지 않는다고 오류에 적는다. `analysis/esp-image-NNN.json` |
| `fw_esp_to_elf(case_id, path, offset=None, partition=None, output_label="esp-app", rea_compat=False)` | 앱 이미지 → ELF32(세그먼트마다 PT_LOAD + 영역 이름 섹션, e_machine 94 Xtensa / 243 RISC-V, entry 유지, 심볼 없음). 출력 `extract/<label>-NNN/<프로젝트 이름>.elf`(`firmware-image`, `extra.type="esp-app-elf"`) → `elf_path`, `elf_path_abs`, `notes`, `next_steps`. **REA 는 Xtensa ELF(ESP32·S2·S3)를 열지 못하고**(지원 아키텍처 아님), RISC-V 는 double-float ABI 표시가 있는 ELF 만 연다 — `rea_compat=true` 면 RISC-V ELF 의 e_flags 를 RVC\|double-float(0x5)로 표시한다(실제 ESP 칩은 soft/single-float 라 부동소수점 인자·반환값 해석만 틀릴 수 있다). `analysis/esp-to-elf-NNN.json` |
| `fw_esp_nvs(case_id, path, offset=None, length=None, partition=None, namespace=None, key=None, include_erased=False, export_blobs=False, max_results=50)` | NVS 파티션(4 KiB 페이지, v1·v2, 입력 최대 1 MiB) → `pages`(상태·seq·버전·헤더 CRC), `namespaces`, `items[{namespace, key, type_name, value, live, state, page, entry, offset, offset_abs, crc_ok}]`(기본은 live 만, `include_erased=true` 면 지운 이전 값과 live 가 아닌 항목도. `offset` 은 NVS 기준, `offset_abs` 는 입력 파일 기준), `blobs`(v2 조각을 이어 붙인 값 — 바이트 값은 크기·sha256·hex), `duplicates`(같은 키의 live 중복), `crc_summary{page_header, entry, data: {ok, bad}}`, `crc_convention`, `truncated`(항목 수 상한). **비밀로 보이는 값**은 응답과 결과 파일 모두 `{masked, digest}`(케이스 솔트 다이제스트)만 남긴다: `nvs.net80211` 의 모든 값, 비밀번호·PIN·PSK·PMK·API 키·개인키·인증 토큰·자격증명·카드 번호 모양의 키(camelCase 포함), 그리고 그런 비밀의 원문을 담은 다른 값(설정 blob 등). 게임 값(credits·tokens·stage_passed·secret_level 등)은 가리지 않는다. 키 이름 휴리스틱이라 평범한 이름에 숨긴 비밀은 못 가릴 수 있다. `export_blobs=true` 면 비밀이 아닌 blob 을 `extract/nvs-blobs-NNN/<ns>.<key>.bin`(`other`, 이름이 겹치면 `-N`)으로 남긴다. CRC 규칙(`zlib.crc32(x, 0xFFFFFFFF)`)은 실기 검증 전이다 — 항목 CRC 가 하나도 맞지 않으면 경고한다. `analysis/esp-nvs-NNN.json` |
| `fw_save_diff(case_id, paths, labels=None, offset=None, length=None, partition=None, mode="auto", observations=None, merge_gap=0, max_results=50)` | 시간 순서 스냅샷 2~16개(점수·진행이 바뀔 때마다 덤프)의 같은 범위 비교. `mode="bytes"`: `ranges[{offset, offset_abs, length, values_hex, interpretations[{encoding, values, trend, offset_abs}]}]`(u8/u16/u32 LE·BE, 부호, BCD), `ranges_total`(전체 개수), 합계 64 MiB 까지. `mode="nvs"`: 키 단위 `changed`·`added`·`removed`(`[{namespace, key, type_name, values}]`, 비밀 값은 모두 마스킹), `unchanged_count`, 스냅샷마다 1 MiB·합계 4 MiB 까지. `auto` 는 NVS 파티션이거나 NVS 형식(어느 페이지든 상태·헤더 CRC)이면 nvs. **바이트 비교는 비밀값을 가리지 못하므로 NVS 를 담은 범위(NVS 파티션과 겹치거나 NVS 형식)는 bytes 로 비교하지 않는다**(`validation_failed` — NVS 는 nvs 모드, blob 안 값은 `fw_esp_nvs(export_blobs=true)` 로 내보낸 파일). `observations=[{label, values}]`(스냅샷마다 화면에서 본 값, 음수·`"0x…"` 가능, 모르면 null — 서로 다른 값이 둘 이상 필요)와 정확히 같은 위치·인코딩(또는 changed·added·removed 의 NVS 키) → `observation_matches`. 범위는 모든 스냅샷에 같게 적용하고 파티션 위치가 다르면 거부한다. `analysis/save-diff-NNN.json` |
| `fw_checksum_find(case_id, paths, offset=None, length=None, partition=None, algorithms=None, max_results=20, max_seconds=120, background=False)` | 모든 스냅샷에서 `저장값 = 알고리즘(데이터 범위)` 인 `(algorithm, endian, location, range)` 후보 → `candidates[{algorithm, width, endian, location_abs, range_abs, matches, distinct_values, strength, expected_false_positives, range_variants}]`, `tested`, `bytes_hashed`, `truncated`, `notes`. 알고리즘 24종(바이트·워드 합, xor8, negsum8/notsum8, CRC-8 2종, CRC-16 6종, CRC-32 4종, adler32, fletcher16). 위치 후보는 스냅샷 사이에 바뀐 바이트에서만, 범위는 위치 바로 앞에서 끝나거나 바로 뒤에서 시작한다(자기 필드를 덮는 체크섬은 찾지 않는다). 합 계열은 전수, CRC 는 바이트 예산 안에서 경계 정렬 순서로 — 큰 범위는 `offset`/`length`/`algorithms` 로 좁힌다. 스냅샷 합계 8 MiB 까지, **NVS 를 담은 범위는 거부한다**(NVS 는 자체 CRC — 후보의 저장값이 비밀값의 단서가 될 수 있다). `weak`: 서로 다른 저장값이 2종 미만, 또는 8비트이면서 저장값 2종 이하, 또는 기대 오탐 ≥ 0.01 — 8비트는 저장값 3종부터, 16/32비트는 2종부터 strong 이 될 수 있다(바뀐 바이트·범위가 크면 시험 수가 늘어 더 필요). `analysis/checksum-find-NNN.json` |
| `fw_find_seq_tables(case_id, path, offset=None, length=None, partition=None, base_addr=None, min_len=6, max_results=50, max_seconds=120, background=False)` | 치트 입력(버튼 시퀀스) 표 후보: 작은 알파벳(버튼 id 0–15 또는 비트마스크)의 u8/u16/u32 배열, 코나미형(AABBCDCDEF) 모양·반복 구조 점수 → `candidates[{address_hex, file_offset, element_size, length, values, alphabet_kind, konami_like, score, reasons}]`, `mode`(`esp-app-segments`: 앱 이미지면 코드가 아닌 세그먼트를 각자의 load 주소로 — `address` 가 디컴파일러 주소, `raw`: 범위를 `base_addr`(기본 offset) 기준으로), `scanned`, `truncated`·`notes`(시간·후보 상한으로 일부만 본 경우). 입력 16 MiB 까지. `analysis/seq-tables-NNN.json` |
| `fw_patch_build(case_id, base_path, target, edits, purpose, unlock_source, online_capable, backup_path=None, description=None)` | 세이브 값 패치(사용자가 명시적으로 원할 때만, 소유/허가 케이스). **base** = 이 케이스에서 기기로 두 번 읽어 일치한(출처 원장 device-read, `double-read`·`match`) 전체 플래시 덤프(offset 0) — 바이트를 한 번 읽어 원장 sha256 과 맞춘 뒤 그 바이트만 쓴다. **target** = `{type: "nvs", partition}`(기존 live 정수 항목, `edits=[{namespace, key, value}]` — `nvs_set_primitives` 가 CRC 규칙을 이 이미지에서 먼저 재현한다) 또는 `{type: "raw-region", partition, checksum?}`(write_class `raw-user-data`, `edits=[{offset(파티션 기준), encoding, value}]`, checksum 은 `fw_checksum_find` 후보 — `range_variants > 1` 은 거부). 거부: `unlock_source` 가 in-device·owned-tag 가 아님, `online_capable="yes"`, 파티션 `encrypted` 플래그·`nvs_keys`, **파티션 경계를 믿을 수 없음**(4 KiB 섹터 경계가 아님, 다른 파티션·부트로더·파티션 표 영역과 겹침, 같은 이름의 파티션, 표 MD5 불일치·오류 — 펌웨어의 표는 조작됐을 수 있다), 같은 기기(MAC)의 esp_security_info 가 플래시 암호화 켜짐(모르면 파티션 단위 근거와 표 MD5 를 `evidence` 에 남기고 진행), 비밀로 보이는 키, live 중복, 덤프의 job id 없음. 같은 내용의 패치 파일·공개 기록은 다시 만들지 않고 재사용한다(`patches/` 는 64개까지). `range_variants > 1` 거부는 정확성 보조다(서버는 체크섬이 base 에서 재현되는지 검사하고, raw 편집은 어차피 파티션의 어느 바이트든 바꿀 수 있다). `backup_path` 없이 → `stage: "planned"`(패치 `patches/<label>-patch-NNN.bin`, `changes`, 백업 절차). `backup_path`(base 보다 원장 seq 가 뒤, 다른 job, 마지막 읽기 `after=no-reset-stub`, 같은 MAC, 대상 범위를 덮고 그 바이트가 base 와 같음, **그 뒤 원장에 같은 기기의 연결 기록(device-read·device-fact)이 없음** — 기록 직전에도 다시 확인) → 사람 증명 `console-offline`(네트워크 차단·재부팅 없음·변경 의사·판매 토큰 콘텐츠 아님, 30분, 패치 sha256·위치·MAC·백업(sha·seq·job)·편집 목록 다이제스트·선언(purpose·unlock_source·online_capable)에 묶임. 요약에는 모든 편집과 선언이 잘리지 않고 들어가며(2000자를 넘으면 거부), 기기 문자열의 제어 문자는 이스케이프된다; 없으면 `attestation_required`) → 패치 sha256 을 출처 원장 `patch-plan` 에 남기고 `stage: "ready"`, `command`(사람이 WSL bash 터미널에서 실행: env.sh → 케이스 폴더 → `sha256sum -c` 로 패치 확인 → `esptool --chip <허용 목록> --port <검증한 포트> --after no-reset-stub write-flash <오프셋> <패치>`, 포트·칩은 백업의 원장 기록에서), `ledger_seq`. 에이전트는 명령을 실행하지 않는다. `analysis/patch-build-NNN.json` |
| `fw_verify_writeback(case_id, patch_path, readback_path)` | 쓴 결과 확인. 기대값은 출처 원장의 `patch-plan`(sha256·대상·MAC)만 쓴다(패치 파일·결과 JSON 은 증거가 아님). `readback_path` 는 그 뒤에(원장 seq) 같은 MAC 으로 대상 범위를 두 번 읽은 덤프 → `outcome`: `applied`(패치와 같음) / `not-applied`(base 와 같음) / `differs`(NVS 면 편집한 키의 실제 값·CRC, 남아 있는 base·패치 파일과의 바이트 차이 수). `analysis/patch-verify-NNN.json` |
| `fwtriage_job_status(job_id, wait_seconds=0, case_id=None)`, `fwtriage_job_cancel(job_id)`, `fwtriage_jobs(active_only=False, case_id=None)` | `background=true` 로 시작한 작업. `result` 는 인라인 응답과 같다 |

- squashfs 만 직접 추출한다. jffs2/UBI/UBIFS/cramfs/ext/erofs/romfs 는 위치·크기·메타데이터만 식별하므로 `fw_carve` 로 분리한 뒤 REA `extract_firmware` 로 추출한다.
- **ESP·세이브 도구**(`fw_esp_*`, `fw_save_diff`, `fw_checksum_find`, `fw_find_seq_tables` — 게임 세이브·해금 오프라인 분석, `game-save-unlock-analysis` Skill)는 읽기만 한다.
  `partition=label` 은 전체 플래시 덤프의 파티션 표로 범위를 정하고, 위치는 파일 기준 절대 오프셋(`*_abs`, `file_offset`)으로 돌려준다.
  파티션 표·NVS 는 로컬 정답(oracle)이 없어 합성 이미지로만 시험했고, 앱 이미지·ELF 는 esptool `image-info`·`elf2image` 와 대조해 시험한다.
  세이브 값 수정은 `fw_patch_build`(패치 이미지, 검증된 새 백업·사람 증명 뒤 사람이 실행할 쓰기 명령)와 `fw_verify_writeback`(쓴 결과 확인)이다 — 기기에는 사람만 쓴다.
- 결과는 모두 휴리스틱 후보다. 발견사항 증거로 쓸 때는 `evidence[].type="triage"`, `ref=result_path` 와 항목의 파일/줄을 남긴다.
  `items`, `hits`, `binaries_of_interest` 의 rootfs 경로는 rootfs 절대 경로(`/etc/passwd`)라 `finding.location.file` 에 그대로 쓴다.
  `fw_strings_hunt` 의 `hits[].file` 은 디렉터리·단일 파일 모드 모두 rootfs 절대 경로이고(rootfs 밖의 덤프·파티션 이미지는 `null`), 케이스 상대 경로는 `hits[].path` 에 있다.
  `commented_hits`·`top_files` 도 같은 `file`/`path` 를 갖고, `checks[].evidence_ref` 는 `<file>@<offset_hex>`(file 이 `null` 이면 `<path>@<offset_hex>`)다.
  rootfs 루트는 `fw_extract_squashfs` 트리(`extract/<label>-NNN`, 옆에 `.manifest.json`), 없으면 `etc` 와 `bin`/`sbin` 을 가진 가장 바깥 상위 디렉터리이며 `summary.rootfs_dirs` 에 적는다
  (그래서 `path_or_dir` 로 rootfs 의 하위 디렉터리를 줘도 `file` 은 `/usr/bin/…` 이다).
- `fw_carve` 의 `partitions[].path` 는 케이스 상대 경로다(`file` 은 같은 값의 별칭).
- `cctv-hunt-patterns.yaml` 의 `sd-*` 휴리스틱 7개(sd-autorun-known-names, sd-card-script-path, sd-uboot-auto-update, sd-update-image-names, sd-card-update-file, sd-uboot-card-boot-script, sd-log-to-card)는 `fw_strings_hunt(patterns="sd-*")`, 기본 감사의 시작 스크립트 검사, `fw_sd_surface` 가 함께 쓴다.
- **SD 표면의 상태 규칙**(`fw_sd_surface`, `fw_rootfs_audit(sd_surface=true)`): `not-found` 는 그 점검에 필요한 입력을 받고 관련 단계를 끝까지 본 경우만이다. 입력이 없으면 `unknown`(`unknown_reason` = 입력 없음)이고, 다음 상한에 걸리면 그 단계가 `truncated` 가 되어 관련 점검이 `unknown` 이다: 시간 예산(`max_seconds` — 파일 사이·핫플러그 규칙마다·128줄·256토큰·문자열 일치 4096개·env 펼침 조각 2048개·문자열 히트 묶음 32개마다, 파일마다 미리 계산하는 블록 구조·줄 표지와 복사 대상 glob 대조는 약 64 KiB 작업마다 확인. 바이너리·이미지 문자열은 2 MiB 청크로 보고 청크 사이 중복은 겹침 64 KiB 구간만 기억한다), rootfs 항목 30만 개, `max_file_size` 를 넘는 바이너리, 바이너리 바이트 1 GiB, 텍스트 줄 16 KiB·경로 토큰 1 KiB, 문자열 히트(바이너리 파일당 5000·패턴당 1000, 이미지 20000·패턴당 5000), 이미지 1 GiB, U-Boot env 의 run 펼침(변수당 16 KiB·env 2 MiB·env 여럿 합쳐 4 MiB·run 대상 64·깊이 4)·변수 2만 개, 복사 추적(파일당 대상 디렉터리 200·디렉터리당 원본 이름 64·glob 4 — 넘어서 버린 복사가 있으면 `rootfs_text` 잘림), 기본 감사의 시작 스크립트 검사가 끝나지 않음(`startup_scan_complete=false` → `rootfs_text` 잘림).
  또 SD-03 은 이미지에서 env 를 못 찾으면, SD-04 는 장치 패턴을 분류하지 못한 핫플러그 규칙이 있으면(`match_kind=unclassifiable`), SD-08 은 쓰기 가능한 SD 마운트의 옵션을 못 보면 `unknown` 이다. SD-07 은 근거가 없으면 늘 `unknown` 이다(not-found 없음).
  핫플러그 규칙은 펌웨어 정규식·glob 을 실행하지 않고 자체 해석기(POSIX ERE 일부 = 톰슨 NFA, udev glob = DP)로 장치 이름 표본(SD 쪽 mmcblk*·sd*, 다른 쪽 null·tty*·mtdblock* …)에 전체 일치로만 맞춘다. SD 표본만 맞으면 `sd`, SD 와 다른 장치를 함께 맞추면 `catch-all`, SD 를 못 맞추면 `other` 이고(eMMC 에만 있는 mmcblkNbootM·rpmb 만 맞는 규칙도 `other`), 해석기가 다루지 않는 문법은 SD 리터럴이 없으면 `unclassifiable` 이다. mdev `$VAR=정규식` 규칙은 DEVNAME/MDEV·SUBSYSTEM·DEVPATH 만 분류하고 MODALIAS 같은 나머지는 `other` 다. 표준 도우미(blkid·scsi_id·modprobe …)만 부르는 udev 규칙은 처리기로 세지 않는다.
  처리기 판정: 명령 없는 mdev 규칙(권한만 — `mmcblk0p[0-9] 0:6 660`·`.* 0:0 660`)은 처리기가 아니다. 모든 장치·분류 불가 규칙의 처리기와 `/etc/hotplug*` 스크립트는 저장 장치에 특정한 내용(mmcblk·`/dev/sdX`·카드 낱말·흔한 카드 경로·`/media|/mnt|/run/media` 아래의 `$MDEV`·이동식 fs `-t vfat|exfat…` 마운트)이 있을 때만 SD 처리기다 — `$MDEV`·`$DEVNAME`·`mount` 만으로는 아니다. 커널 uevent helper 는 빈 값(helper 끄기)·mdev 면 처리기가 아니고, 다른 helper 는 같은 조건의 텍스트일 때만 SD-04 근거다. 커널 모듈(`*.ko`·`/lib/modules/`)은 문자열을 보지 않고, 바이너리의 마운트 옵션 문자열(umask=0·shortname=·discard)은 같은 바이너리에 카드 문맥이 있을 때만, 이미지 문자열은 같은 문자열 안에 카드 장치·경로가 있을 때만 SD-08 근거다. trigger-service 는 카드 조건 아래에서 원격 셸·디버그 서비스를 '시작'(명령 첫 낱말, `start-stop-daemon -S … -x`, `/etc/init.d/서비스 start|restart`, nc 리스너, socat EXEC 셸, `sh -c '…'`)할 때만 세고 killall·pkill·kill·stop·문구 안의 이름은 아니다. 텍스트는 기본 감사와 같은 규칙의 논리 줄로 분류하고(셸 스크립트로 실행되는 파일만 줄 끝 연산자로 잇는다, 근거의 줄 번호는 첫 줄) 32칸 넘는 공백 덧대기는 접어서 본다. SD-01 실행 판정에서 `sh|bash… -c '…'`·`su … -c '…'`·`eval '…'` 의 여는 따옴표(명령 위치의 맨 바깥 따옴표) 바로 뒤 `cd` 는 명령 시작이고(sh -c·su -c 안에서 바꾼 cwd 는 닫는 따옴표에서 되돌린다 — echo·logger 문구 속의 것은 아니다), `env [-i|-|VAR=값]`·변수 대입 접두 뒤의 카드 경로도 실행이다(대입 접두는 셸 문법 파일만 — systemd 유닛 `ExecStart=/usr/bin/recorder /mnt/sdcard/record` 의 카드 경로는 인자). echo·logger·printf 처럼 실행되지 않는 따옴표 문구 안의 `cd`·`./x`·`sh x` 는 cwd 도 실행도 아니다(`echo "…; cd /mnt/sd; sh update.sh"` — 큰따옴표 안에서 `$(`·역따옴표가 나온 뒤는 명령 치환일 수 있어 그대로 본다). `start-stop-daemon` 의 멈춤·상태·시험(-K·--stop·-T·--status·-t·--test, 묶인 꼴, 경로 뒤에 와도) 명령의 -x 경로는 실행이 아니다. 리터럴 사전 필터는 스크립트처럼 실행되는 파일·SD 처리기·mount 가 있는 파일·서버 설정에는 쓰지 않는다(나머지 설정 파일은 변수를 펼치지 않아 리터럴 판정이 정확하다).
  카드 경로는 발견한 SD 마운트와 흔한 경로(`/mnt/sd*`(sdk 와 `sda1`·`sdb` 같은 SCSI 디스크 이름 제외)·`/mnt/mmc*`·`/mnt/tf`·`/mnt/tf<N>`·`/mnt/tfcard<N>`·`/mnt/disc*`·`/media/{mmc,sd,tf}*`·`/tmp/sd`·`/sdcard`·`/system/sdcard`)다. `/dev/mmcblk*`·`/dev/sdX` 마운트는 마운트 지점이 SD 같을 때만 SD 로 보고(`media`·`storage` 같은 일반 이름뿐이면 FAT 계열 fs(vfat·msdos·exfat·ntfs …)일 때만 — ext4·f2fs·`-t` 없음은 eMMC·HDD 메모와 함께 `other_mmc_mounts`. `/dev/sdX` 를 장치 이름 디렉터리 `/mnt/sda1` 에 붙이면 SATA·USB 디스크로 본다. 바이너리·이미지의 sd-* 경로 히트가 SCSI 디스크 경로만 가리키면 카드 문맥으로 세지 않는다 — YAML sd-* 패턴도 SCSI 디스크 이름을 카드 경로로 보지 않아 기본 감사·`fw_strings_hunt` 도 같다), 읽기 전용 fs(squashfs·cramfs·erofs·romfs·iso9660·udf)는 SD 로 보지 않는다. SD·catch-all·분류 불가 규칙의 처리기 스크립트(와 그것이 부르는 스크립트) 안에서는 `/media`·`/mnt`·`/run/media` 아래의 `…/$MDEV`·`…/$DEVNAME` 디렉터리도 카드 마운트 지점으로 본다(`/var/run/$MDEV` 같은 상태 경로는 아니다). 웹 콘텐츠(.js .html .htm .css .svg .map .po .md)는 분류하지 않는다(업데이트 파일 이름만 모은다).
  `not-found` 는 '필요한 입력을 끝까지 알려진 모양에 맞춰 보았다'는 뜻이지 카드 경로가 없다는 증명이 아니다. 규칙 기반 분류기의 알려진 한계: 문맥 창(앞 512자·뒤 512자·파이프 단계 256자) 밖으로 밀어낸 공백이 아닌 덧대기, 다른 파일에 정의된 함수로 감싼 조건, `grep -q` 밖의 내용 시험(`[ "$(cat 카드)" = 1 ]`·`case $(cat 카드)`·`ls 카드 && …`), `$(ls 카드)`·역따옴표 목록에 대한 반복, 압축을 푼 뒤 실행(tar·unzip), `ln -s`·`mount --bind`·PATH 앞붙이기를 통한 간접 실행, 카드 경로를 인자로 받아 `"$1"` 을 실행하는 도우미 함수, `dd < 카드`, 벤더 업데이트 도구 바이너리의 내부 동작, `ls 카드/*.sh | while read f; do sh "$f"; done` 같은 ls 출력의 while read 반복(`ls 카드/*.sh | xargs sh` 는 found), `sh -c "$(cat 카드파일)"` 처럼 카드 내용을 명령 치환으로 넘기는 실행(`cat 카드파일 | sh` 는 found), 옵션을 붙여 쓴 `syslogd -nO카드경로`(`-O 카드경로`·`-O카드경로` 는 found), `trap '…'`·`watch '…'` 처럼 나중에 실행되는 따옴표 문자열 속 cd·상대 실행(문구로 본다). 거꾸로 here-document 본문과 여러 줄 문자열 속의 명령 꼴 줄(사용법 안내의 `LD_LIBRARY_PATH=/mnt/sd/lib /mnt/sd/tool` 예시)은 셸에 넘겨지는지 따지지 않고 명령처럼 본다(파일로 써서 나중에 실행하는 본문을 놓치지 않으려는 쪽). 디렉터리로 복사한 카드 파일의 glob 대조·복사 이름 히트·이미지 문자열 히트가 빽빽하게 조작된 입력은 MiB 당 10초 넘게 걸릴 수 있다(시간 예산 안에서 멈추고 `unknown`).
  물리 버튼·GPIO '읽기' 조건으로만 열리는 업데이트는 같은 파일·위치의 원격 쓰기 경로가 보이지 않을 때만 SD-02 를 한 단계 낮춘다. U-Boot 쪽 SD-02·SD-03 근거는 `fw_uboot_env` 의 `sd_boot` 규칙과 같다(boot.scr·uEnv.txt 는 mmc 에서 읽을 때만, autoupdate 같은 일반 이름만으로는 SD 업데이트가 아니다). mmc 장치 번호로는 SD 와 eMMC 를 구분하지 못하고, 데몬이 mount(2) 로 마운트하면 옵션을 못 봐 SD-08 이 `unknown` 이며, 녹화 암호화는 '없음'을 단정하지 않는다.

#### FIT 서명 선언의 구조 관찰

`fw_sd_surface(image_path)`는 기존 env·문자열 단계 뒤 동일 `Ctl`의 남은 시간으로 비압축 FDT v17을 검색한다. `fit_security`(`pweh.fit-security-structure/v1`)는 저장 JSON과 compact 응답에 동일하게 보존한다. rootfs만 있으면 `not-examined`, 제한된 관찰을 마치면 `complete`, 손상·미지원·예산/출력 제한은 `partial`이다. 기존 SD 점검 상태·심각도와 `fit_signature_keys` 문자열 표지는 바꾸지 않는다.

헤더·블록 경계/겹침·예약 영역·토큰·중복/순서를 제한 검사하고 이미지/설정 서명과 control-DTB 형태 키 후보를 구분한다. 새 section은 고정 분류·개수·입력 기준 위치·속성 존재/길이만 반환한다. 임의 이름·키 힌트·서명/키/image payload를 넣거나 암호학 검증을 수행하지 않는다. 정상 구조를 완주하지 못한 범위의 부재는 unknown이다. 검색 위치 prefix·pending 후보·구조/목록 완료도를 별도 기록한다.

검색256 MiB·64후보·32구조·128항목·단일 FDT64 MiB·결과64 KiB가 상한이다. 노드/속성/토큰/복사 바이트와 같은 시간 예산을 공유하고 실패한 후보의 작업량도 환급하지 않는다. 다른 FIT/DTB 도구의 기존 파싱 계약은 유지한다. `verify_off`는 환경값 관찰이며 실제 검증 강제는 빌드·부팅 경로·신뢰 키의 추가 근거가 필요하다. 상세 필드·상한·고정 근거는 [FIT 구조 계약](references/fit-security-structure.md)을 따른다.

#### Android 펌웨어 의미 해석

`fw_identify`에 sparse 저장 구조·boot v0~v4·vendor_boot·init_boot 후보·vbmeta·LP·F2FS 식별을 더한다. 확장 sparse CRC는 미검증이며 AVB header는 서명 검증이 아니다.
`fw_carve`는 기존 인자에 `layout_source="auto"`, `lp_slot=0`, `max_output_bytes="4G"`를 더한다. raw GPT/LP 배치를 지원하고 LP는 LINEAR/ZERO extent의 mapping·선택 slot/copy·검증 근거를 남긴다. sparse-wrapped 분할과 외부 물리 source는 지원하지 않는다. 기존 명시 partitions/mtdparts 의미를 유지하며 출력 총량 상한을 적용한다.

| 도구 | 계약 |
|---|---|
| `fw_android_surface(case_id, rootfs_dir=None, image_path=None, max_results=50, max_evidence=20, max_file_size="1M", max_seconds=300, background=False)` | rootfs/image 중 하나 이상. AN-01~09(ADB/debug/test-keys/SELinux/AVB/init서비스/OTA/priv-app/자격증명) 정적 근거, checks의 found/not-found/unknown·coverage·limitations. 읽지 못한 범위는 unknown이고 문자열 단서를 실제 보호 상태로 확정하지 않는다. 자격증명은 마스킹. 결과 analysis/android-surface-NNN.json; 자세한 범위는 [android-analysis.md](design/android-analysis.md) |

### 6.7 pweh-esp (선택)
Espressif 칩(ESP32·ESP32-S2·ESP32-S3·ESP32-C3 등)을 esptool 로 **읽기 전용** 분석한다. 칩·플래시 정보, 보안 설정, SPI 플래시 덤프(job, 기본으로 두 번 읽어 sha256 비교)를 다룬다.
실행하는 esptool 명령은 `flash-id`(`esp_chip_info`), `get-security-info`(`esp_security_info`), `read-flash`(`esp_read_flash_start`) 셋뿐이다.
모두 MODIFY 로 게이트를 거친다(연결할 때 칩을 리셋해 ROM 다운로드 모드에 넣고 RAM 에 스텁을 올린다. 플래시·eFuse 에 쓰는 명령은 보내지 않는다 — 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`soft-reset` 도 쓰지 않음, 기본 허용).
쓰기·삭제·eFuse·RAM 실행 같은 명령은 도구가 없고, 조립한 argv 가 허용 범위를 벗어나면 `esp_mcp.policy` 가 승인 경로 없이 거부한다(§4).
아래 시그니처는 카탈로그(`docs/references/pweh-mcp-tools.md`)의 인자 전체와 기본값이다(동작·오류 코드 상세: `mcp-servers/esp-mcp/README.md`).

**포트 형식이 백엔드를 정한다.**
- `COM1` ~ `COM4096`(대소문자 무관) → `windows` 백엔드(방법 A, WSL 권장): WSL interop 으로 Windows 용 `esptool.exe` 를 `--port COMn` 으로 실행한다.
  보드는 Windows 에 연결된 그대로 두므로 usbipd attach 가 필요 없다. 덤프 출력 경로는 `wslpath -w` 로 바꿔(`\\wsl.localhost\<배포판>\…\dumps\…`) esptool.exe 가 케이스 `dumps/` 에 바로 쓴다.
  실행 파일은 설정 `tools.esptool_win`(`PWEH_ESPTOOL_WIN`)이고, 비어 있으면 `~/pweh-tools/esptool-win/esptool-windows-amd64/esptool.exe`(설치 스크립트의 esptool 구성요소)를 찾는다.
  조건(`pweh.hostenv` 의 smoke 없는 판정): WSL 안(컨테이너는 WSL 커널이어도 아님), `WSLInterop` 또는 `WSLInterop-late` 첫 줄이 `enabled`, `/init` 있음, `wslpath -w /` 실행. C: 드라이브 마운트는 조건이 아니다(없으면 Windows 프로세스 확인·COM 목록용 powershell 만 없다). 설정 `hostenv.disable` 에 `interop` 이 있으면 Windows 백엔드와 powershell 을 쓰지 않고, `windows_tools` 가 있으면 Windows esptool.exe 를 쓰지 않는다(`tool_missing`).
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
| `esp_list_ports()` | OBSERVE(포트를 열지 않음). `windows{available, ports[{port, name, pnp_device_id, vid, pid, serial_number, usb_id, kind, description_ko}], note}`: powershell.exe 로 Win32_PnPEntity 를 조회한 결과(이름에 `(COMn)` 이 있는 장치만). `linux{ports, hidden_legacy_ports}`: pyserial 목록 + `in_use_by`(그 tty 를 연 다른 프로세스 PID), sysfs 정보가 없는 레거시 `/dev/ttyS*` 는 숨기고 센다. 그 밖에 `count`, `hints`. 알려진 USB ID: `303a:1001` = ESP 내장 USB-Serial/JTAG, `303a:0009`·`303a:0002` = ESP32-S3·S2 ROM USB-OTG 다운로드 모드, CP210x·CH340·CH343·CH9102·FTDI. `hints` 는 종류별이다(USB-Serial/JTAG = esptool 의 USB-JTAG 리셋, ROM USB-OTG = `before="no-reset"`·`after="no-reset"`(서버가 `no-reset-stub` 으로 실행)과 끝난 뒤 사람의 RESET, 그 밖의 `303a`(`esp-usb` — 앱의 TinyUSB CDC, 예: MicroPython `303a:4001`) = 자동 리셋이 안 될 수 있으니 'UART' 커넥터로 옮기거나 BOOT+RESET 뒤 새 포트(번호가 바뀜)). interop 이나 powershell 이 없으면 `windows.available=false` 와 `note` |
| `esp_chip_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY(`flash-id`). `chip`, `chip_description`, `chip_revision`, `features`, `crystal_mhz`, `usb_mode`, `mac`, `flash{manufacturer_id, manufacturer, device_id, size, size_bytes, type_efuse, voltage, voltage_source}`, `base_mac`(늘 6바이트), `mac_ext`(EUI-64 확장 2~8바이트), `secure_download_mode`, `stub`, `log_path`(`uart/esptool-chip-info-NNN.log`), `backend`, `port`, `esptool_version`, `command`, `classification`, `after`(실제로 쓴 값), `after_requested`(`no-reset` 을 바꿨을 때만), `warnings`(플래시 크기 미감지 → 덤프에 `size` 명시, 플래시 ID `ff`/`00` → 배선·전원·스트래핑), `notes`, `next_steps`. `mac` 은 esptool 이 찍은 값(ESP32-C6·H2 는 8바이트 EUI-64). Secure Download Mode 면 ROM 이 flash-id 를 거부하므로 오류 대신 `status: "secure_download_mode"`, `read_flash_possible: false` 와 칩 종류만 돌려준다. 모든 성공 응답에 `provenance{recorded, kind: "device-fact", fact_kind: "esp-chip-info", seq}`(출처 원장의 기기 사실, §4. `status: "secure_download_mode"` 결과도 기록한다. 기록에 실패하면 `recorded: false`, `reason`) |
| `esp_security_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY(`get-security-info`). `status`(`"ok"`/`"unsupported"`), `secure_boot`, `flash_encryption`(SPI_BOOT_CRYPT_CNT 의 1 비트 수가 홀수면 켜짐), `crypt_cnt`, `secure_download_mode`(플래그 비트 2), `read_flash_possible`(= Secure Download Mode 꺼짐), `ciphertext_expected`(= 플래시 암호화 켜짐), `jtag_hard_disabled`, `jtag_soft_disabled`, `usb_disabled`, `download_dcache_disabled`, `download_icache_disabled`, `key_blocks[{block, purpose}]`, `flags_hex`, `parsed_flags`, `raw_fields`, `chip_id`, `api_version`, `assessment`(한국어 판단), `log_path`(`uart/esptool-security-info-NNN.log`), `after`, `after_requested`, `warnings`, `notes`. Secure Download Mode 에서도 동작한다. `read_flash_possible=false` 면 덤프하지 않고 우회 없이 사용자에게 보고한다. 원조 ESP32·ESP8266 은 get-security-info 를 지원하지 않는다 → 오류 대신 `ok: true, status: "unsupported"`, `chip`, `chip_description`, 보안 필드(`secure_boot`·`flash_encryption`·`crypt_cnt`·`secure_download_mode`·`read_flash_possible`·`ciphertext_expected`·`jtag_*`·`usb_disabled`·`key_blocks`·`raw_fields`·`flags_hex`·`parsed_flags`·`chip_id`·`api_version` 등)는 모두 `null`, `assessment` ['보안 상태 미확인 …'], `error`(esptool 문구), 첫 note 는 '미확인'으로 기록하고 진행하라는 안내(감사 이벤트 `esp_security_summary` 에도 `status`). 두 경우 모두 `provenance{recorded, kind: "device-fact", fact_kind: "esp-security-info", seq}`(출처 원장의 기기 사실 — `unsupported` 면 보안 필드 null = 미확인으로 기록) |
| `esp_read_flash_start(case_id, port, chip="auto", offset=0, size="all", output_name=None, baud=921600, verify="double", before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | MODIFY · job(`read-flash`). 시작 응답 `status: "started"`, `job_id`, `planned_path`(`dumps/<name>.bin`), `planned_read2_path`, `metadata_path`, `reads`(1 또는 2), `backend`, `port`, `esptool_version`, `after`(마지막 읽기에 쓸 값), `after_requested`(바꿨을 때만), `read1_after`(이중 읽기면 `"no-reset-stub"`, 아니면 `null`), `read1_baud`(이중 읽기의 1차 baud, 아니면 `null`), `timeout_s_per_read`, `classification`, `notes`. `offset` 은 정수 또는 `"0x10000"`, `size` 는 `"all"`(감지한 플래시 크기, `offset=0` 일 때만)·정수·`"0x400000"`·`"4M"`·`"16MB"`·`"512K"`, `output_name` 을 생략하면 `esp-flash`, `esp-flash-002` … 순서로 정한다(`.bin` 자동). `verify="double"` 은 같은 범위를 두 번 읽어 sha256 을 비교한다: 1차는 `--after no-reset-stub` 으로 칩을 다운로드 모드에 둬 앱이 실행되지 않게 하고(NVS 변경 방지), 마지막 읽기 뒤에 요청한 `after` 를 쓴다(`no-reset` 은 `no-reset-stub` 으로). `before="no-reset"`(수동 다운로드 모드)의 이중 읽기는 1차를 min(baud, 115200)으로 읽는다(esptool 은 연결을 115200 으로 맞추므로 1차 뒤 칩이 그 속도에 남아야 2차 연결이 된다. 계획 note 와 gate 의 `read1_baud`). `"none"` 은 한 번 읽는다. 기존 파일은 덮어쓰지 않는다(시작 때 같은 이름이 있으면 `case_error`, 심볼릭 링크인 `dumps/` 도 `case_error`). Secure Download Mode 면 job 이 `esp_secure_download_mode` 로 실패한다 |
| `esp_job_status(job_id, wait_seconds=0, case_id=None)`, `esp_job_cancel(job_id)`, `esp_jobs(active_only=False, case_id=None)` | `register_job_tools(..., "esp")`. 진행률은 esptool 출력의 % 로 계산한다(두 번 읽으면 읽기마다 절반). 끝난 job 의 `result`: `status`(`succeeded`/`cancelled`/`failed`), `path`, `read2_path`, `metadata_path`, `size`, `sha256`, `sha256_read2`, `match`, `verification`, `source`, `backend`, `port`, `esptool_version`, `log_paths`, `artifacts{primary, read2, metadata}`, `warnings`, `notes`, `summary_hint`, `provenance{recorded, kind: "device-read", entries[{path, seq, sha256}]}`(끝까지 성공한(`succeeded`) 덤프의 읽기 파일만 기록 — 이중 읽기면 두 파일, `verify="none"` 이면 한 파일. 실패·취소 때 보존한 1차 읽기는 `recorded: false` 이고, 원장 기록에 실패해도 덤프는 그대로 `succeeded` 이며 `recorded: false`·`reason` 과 `warnings` 가 붙는다 — §4). 취소하면 esptool 프로세스 그룹을 SIGTERM, 이어서 SIGKILL 로 끝낸다. Windows esptool.exe 는 PyInstaller onefile 이라 interop 프로세스를 끝내도 자식이 COM 포트를 잡은 채 남으므로(실측), 명령줄 표식(덤프는 UNC 출력 경로)으로 Windows 프로세스를 찾아 자식부터 끝내고(부트로더가 `%TEMP%\_MEI*` 를 지우고 끝남) 남은 것이 없을 때만 `cancelled` 다. 남으면 job 은 `failed`(`error.code` `esp_orphan_process`, `data.pids`)이고 예약 파일은 그 프로세스가 끝날 때까지 남는다. 시간 초과도 같다 |

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
- 같은 포트는 한 번에 한 작업만 쓴다. 공용 OS lease와 기존 서버 내부 예약·job 배타 키를 함께 사용한다. info 호출과 두 읽기 전체가 lease를 유지하며,
  action에는 `route{backend,lock_key,device_id}`, 결과·job metadata에는 공개 route를 남긴다. native USB 전체 reset이면 완전한 형제 범위가 필요하다(§5).
  이 범위 검사는 명시 `usb-reset` 또는 OS가 확인한 native USB reset 계획에 적용한다. 식별 unknown의 `default-reset`은 possible로 유지하므로 esptool 내부 자동 감지가 고른 native reset의 모든 형제까지 배타한다고 보장하지 않는다.
  리눅스 tty 를 다른 프로세스(시리얼 모니터, uart-mcp 세션)가 열고 있으면 `busy` 로 거부한다. Windows COM 포트는 그 포트를 인자로 받은 esptool.exe(`--port COMn`·`--port=COMn`·`-p COMn`)를
  Windows 프로세스 목록(Win32_Process)에서 찾아 `busy`(PID 와 `taskkill /F /PID n` 안내, `data.pids`)로 거부하고, 그 밖의 프로그램이 잡고 있으면 esptool 이 `esp_port_busy` 로 실패한다
  (Windows 보유자 조회 실패는 확인 불가로 거부). Windows 프로세스가 남거나 종료 검사가 실패하면 공용 lease·예약·Windows 소유 토큰을 유지한다.
- 서버가 SIGTERM 을 받으면 작업을 취소·정리한 뒤(최대 30초) SIGTERM 으로 끝나고, stdin 이 닫혀도 정리한 뒤 끝난다. 서버 종료(atexit) 정리도 Windows esptool.exe 를 자식부터 끝낸다.
- 연결할 때마다 칩이 리셋되어 ROM 다운로드 모드로 들어간다(실행 중이던 앱이 멈춘다). 연결에 실패하면(`esp_no_serial_data`, `esp_wrong_boot_mode`)
  사람이 BOOT(부트 스트랩 핀. ESP32·ESP32-S2·ESP32-S3 는 GPIO0, ESP32-C3·C6·H2 는 GPIO9 — 그 밖의 칩은 데이터시트로 확인)를 누른 채 RESET(EN)을 눌렀다 떼고 BOOT 를 놓은 뒤 `before="no-reset"` 으로 다시 호출한다.
  `after` 가 `no-reset-stub`(`no-reset` 요청 포함)이거나 덤프를 취소하면 칩이 다운로드 모드(스텁)에 남으므로, 일반 부팅이 필요하면 사람이 RESET 을 누른다.
- 덤프 출력의 Windows 경로 요소가 '.'·공백으로 끝나면 `validation_failed` 다(Windows 가 끝의 '.' 을 지워 다른 디렉터리에 쓴다). 그래서 case_id 도 '.' 으로 끝날 수 없다(`CASE_ID_RE`).
- Secure Download Mode 에서는 esptool 로 플래시를 읽을 수 없다(`esp_secure_download_mode`). 이 서버는 글리칭·eFuse 조작 같은 우회를 하지 않는다.
  플래시 암호화가 켜져 있으면 덤프는 암호문이다(`ciphertext_expected=true`). 키는 읽기 보호된 eFuse 에 있으므로 정적 분석은 평문 영역 밖에서 제한적이다.

### 6.8 pweh-forensics (선택)
SD 카드 이미지의 증거 분석이다(설계 `docs/design/sd-forensics.md` §3·§4·§6·§7). **카드나 원시 디스크를 열지 않는다** — 사람이 하드웨어 쓰기 방지 장치를 거쳐 이미징 도구로 만든 이미지 **파일**만 받는다.
코어 세 모듈 위에서 돈다: 파일 시스템 해석 `pweh.fs`(순수 파이썬, 공개 사양만으로 새로 작성한 MBR/EBR·GPT·superfloppy, FAT12/16/32·exFAT — 이미지에 쓰지 않고 마운트·외부 도구 없음, 아래 '이미지 해석'),
보관 기록·EV 번호·증거 목록 `pweh.evidence`(보고서 §8.1 도 읽는다), 믿을 수 없는 파일·디렉터리를 다루는 `pweh.safeio`(아래 '케이스 구조'). `pweh.fs` 위의 작업(볼륨 고르기·호출 예산·목록 요약·호스트 오염 흔적·ref 확인·추출)은 `mcp-servers/forensics-mcp/forensics_mcp/fsops.py` 다.
기기에 아무것도 보내지 않으므로 분류기·게이트가 없다(§4 'SD 카드 증거'). 사람 확인은 Claude Code 권한(정지 그림·선택 앱 기록·마스킹된 비밀값·보고서 이름 대조·미디어 구조 분석 및 상태 기록 정리의 명시적 예외 외 쓰는 도구는 매번 확인)과 사람 증명(`write-blocker`)이다.
아래 시그니처는 카탈로그(`docs/references/pweh-mcp-tools.md`)의 인자 전체와 기본값이다(사용 흐름: `mcp-servers/forensics-mcp/README.md`, 에이전트 절차: `sd-card-forensics` Skill).
알려진 한계(동기 도구의 취소, 빠른 지문의 범위, 같은 계정 프로세스의 경로 바꿔치기·하드 링크, 일부러 엄격한 검증, 잘린 이미지, 보관 기록의 '기록 중' 창 …)의 정본 목록은 docs/safety.md §3.6 이다 — 이 절은 그 항목을 되풀이하지 않고 가리킨다.
`evidence_id` 를 받는 도구의 응답(job 은 `result`)에는 `evidence_id` 가 함께 온다(표에서는 생략).

- **케이스 구조**(§3, 이 서버만 쓴다, 처음 접수할 때 만든다):
  - `forensics/images/EV-NNNN/` — 이미지 사본, 접수 기록 `EV-NNNN.json`, 이미징 로그 사본 `imaging-log.txt`(로그를 줬을 때). 파일은 0444, 디렉터리는 커밋한 뒤 0555.
    사본 이름은 원본 파일 이름에서 글자·숫자·`._-` 가 아닌 문자를 `_` 로 바꾸고 96자로 자른 것이다(앞뒤 `._-` 는 떼고, 비면 `image.raw`). 증거 디렉터리의 예약 이름(`EV-<숫자>.json`·`imaging-log.txt`·`.intake.lock`·`*.partial`)과 겹치면 접수를 거부한다.
    접수 job 이 도는 동안에만 복사 중 이름 `<이름>.partial`(다 쓰면 이름을 바꾼다)과 접수 잠금 `.intake.lock`(커밋하면 지운다)이 있다.
  - `forensics/images/.claim.lock`(EV 번호 확보·정리 잠금)과 `forensics/.custody.lock`(보관 기록 잠금 — 읽기 공유, 덧붙이기 배타)은 0600 이고 지우지 않는다.
  - `forensics/aborted-intakes/EV-NNNN-<YYYYMMDDTHHMMSSZ>[-k]/` — 커밋하지 못한 접수를 옮겨 둔 곳(파일 0444, 디렉터리 0555, 지우지 않는다 — 아래 'EV 번호와 중단된 접수').
  - `forensics/custody.jsonl` — 보관 기록(덧붙일 때마다 잠금 안에서 통째로 원자적으로 바꿔 쓴다, 0644). 고정점은 케이스 밖 `<state_dir>/custody/<case_id>.jsonl`(디렉터리 0700, 파일 0600).
  - `forensics/analysis/fs-list-<EV>-NNN.json`(0444), `forensics/recovered/<label>-NNN/`(추출물 `NNNN-<정리한 이름>`(`region="residual"` 이면 `.residual` 을 붙인다) + `manifest.json` — 파일 0444, 다 쓴 뒤 디렉터리 0555), `forensics/evidence-list.{json,md}`(부를 때마다 원자적으로 다시 씀, 0644).
  - 경로 규칙(`pweh.safeio`): `forensics/` 아래 디렉터리는 케이스 디렉터리에서 한 구성요소씩 `O_DIRECTORY|O_NOFOLLOW` 로 연다. 파일은 그 디렉터리 fd 기준 `O_CREAT|O_EXCL|O_NOFOLLOW` 로만 만들고 그 fd 로 쓰고 fchmod 한다(경로로 다시 열거나 chmod 하지 않는다).
    읽기는 일반 파일만(lstat → `O_NOFOLLOW|O_NONBLOCK` → fstat 의 S_ISREG·(st_dev, st_ino) 대조) 크기 상한을 두고 한다 — 장치·FIFO·링크는 읽지 않고 거기서 멈추지도 않는다
    (예외: 접수 커밋 뒤 출처 원장은 접수 기록을 경로로 다시 열어 해시하고, 아티팩트 색인은 사본 경로를 다시 풀어 크기만 읽는다 — §4 'SD 카드 증거', docs/safety.md §3.6).
    쓰는 쪽(EV 번호 확보의 `images/`, 정리의 `aborted-intakes/`, `analysis/`·`recovered/` 출력)에서 구성요소가 링크·파일이면 `path_outside_base`(아무것도 쓰지 않는다)다. 내용 도구가 여는 EV 디렉터리가 그러면 무결성 실패(`unsafe-path` — 아래 '무결성'),
    증거 목록에서 `images/` 가 그러면 보관 기록을 깨짐으로 보고(`custody.ok=false`, 항목 없음 — 그 전에 다시 대조가 커밋한 EV 마다(이미 무결성 실패인 것 빼고) `integrity-failed`(`unsafe-path`)를 남긴다. 되돌리지 않는다 — docs/safety.md §3.6),
    `forensics/` 자체가 링크면 보관 기록을 믿지 않는다(`custody_broken`).
    사용자가 준 경로(`image_path`·`imaging_log_path`)는 링크를 한 번 푼 실제 경로를 같은 방법으로 열고 그 뒤의 해시·복사는 연 fd 로만, 연 때의 크기만큼 한다(중간 디렉터리 바꿔치기의 한계 — docs/safety.md §3.6).
- **EV 번호와 중단된 접수**: 증거 id 는 `EV-` + 숫자 4~6자리다. 확보는 확보 잠금(`.claim.lock`, 배타) 안에서 한다: 보관 기록을 읽고(깨졌으면 확보하지 않고 `custody_broken`) → 정리(아래) →
  번호 = (EV 디렉터리·`aborted-intakes/` 의 디렉터리 이름·보관 기록에 나온 번호 중 가장 큰 것) + 1 → `mkdir`(원자적, 있으면 다음 번호) → 그 안에 접수 잠금 `.intake.lock` 을 만들어 flock 으로 잡는다.
  `mkdir` 과 잠금 파일 만들기는 모두 확보 잠금 안이라 그 사이에 끝나면 빈 디렉터리만 남는다. 디렉터리나 보관 기록에 남은 번호는 다시 쓰지 않는다(지운 증거의 번호 포함).
  접수의 커밋 지점은 보관 기록의 `intake` 사건이다. 커밋한 뒤 잠금 파일을 지우고 잠금을 풀고 디렉터리를 0555 로 바꾼다. 커밋 전 실패·취소는 만든 파일과 EV 디렉터리를 지운다(되돌리기 — 보관 기록에 사건이 없으므로 번호를 돌려놓는다).
  정리(reconcile)는 확보할 때마다(같은 잠금 안)와 서버 시작 때(`cases_dir` 의 모든 케이스 — 보관 기록이 깨진 케이스는 건너뛴다) 돈다. 보관 기록에 `intake` 가 없는 EV 디렉터리는 **중단된 접수의 흔적**이 있을 때만 옮긴다(`data.basis`):
  잠금 파일이 있고 잡은 쪽이 없음(`intake-lock` — 커밋 전에 끝난 접수는 확보 뒤 어느 지점에서 끝났든 이 파일이 남는다), 잠금 파일 없이 빈 디렉터리(`empty-dir`), 잠금 파일 없이 복사 중 이름 `*.partial` 이 있음(`partial-copy` — 커밋한 디렉터리에는 없다),
  그 번호의 `intake-aborted` 사건이 이미 있음(`retry` — 앞의 옮기기가 실패함). 옮길 때는 먼저 보관 기록에 `intake-aborted`(`{reason: "uncommitted-intake", basis, quarantine_path, had_record, files(20개까지), note}`)를 남겨 번호를 소비하고,
  파일을 0444 로 바꿔 `aborted-intakes/EV-NNNN-<시각>/` 로 옮긴 뒤 잠금 파일을 지우고 디렉터리를 0555 로 바꾼다(그 번호의 `intake-aborted` 사건이 이미 있으면 다시 남기지 않고 기록한 자리로 옮긴다).
  흔적이 없는 디렉터리(커밋한 증거인데 보관 기록과 고정점을 함께 잃음, 사람이 만든 디렉터리 등)는 보관 기록 없이는 커밋 여부를 알 수 없으므로 옮기지 않고, 다른 job 이 잠금을 잡고 있거나(진행 중) 잠금 자리가 일반 파일이 아니면 건드리지 않는다.
  증거 목록에서 보관 기록에 `intake` 가 없는 디렉터리는 잠금이 잡혀 있으면 `intake-in-progress`, 아니면 `record-without-intake` 다 — 다음 정리에서 옮겨질 디렉터리(흔적 있음)와 사람이 판단할 때까지 남는 디렉터리(흔적 없음)가 같은 상태로 보인다.
  보관 기록에 `intake` 가 있는데 잠금 파일이 남은 디렉터리(커밋 직후 프로세스가 죽음)는 잠금이 풀려 있으면 커밋을 마저 한다(잠금 파일을 지우고 0555). 정리의 두 겹 사고·되돌리기 경쟁 같은 남은 경우는 docs/safety.md §3.6.
- **보관 기록**(`forensics/custody.jsonl`): 줄마다 정규화 JSON(키 정렬·공백 없음) `{schema: "pweh.custody/v1", seq(1부터 연속), ts, case_id, event, evidence_id(없으면 null), actor, data, prev}`.
  `prev` 는 앞 줄(정규화 JSON 바이트)의 sha256 이고 첫 줄은 케이스 id 에 묶인 시작값(sha256(`pweh-custody:<case_id>`))이라 다른 케이스의 기록을 옮겨 오면 깨진다. 줄의 해시가 다음 줄의 `prev` 이자 고정점 값이다.
  사건(닫힌 집합 — 모르는 사건이 있으면 깨짐): `intake`, `intake-aborted`, `verify`, `integrity-failed`, `attest`, `list`, `extract`, `image-hints`, `sqlite-inventory`, `android-artifacts`, `timeline`, `secrets-scan`, `sd-ioc-scan`, `media-inventory`, `media-candidates`, `evidence-list`(`check`·`note` 는 예약만 하고 쓰지 않는다). actor 는 늘 `server` 다.
  같은 사건을 감사 로그에도 남긴다(`forensics_<사건>` — 하이픈은 밑줄, `custody_seq`·`custody_hash`). 증거의 상태(마지막 검증·무결성 실패·증명)는 보관 기록을 처음부터 다시 읽어 정한다(따로 바뀌는 색인 파일이 없다).
  출처 원장에는 접수 기록 파일 `EV-NNNN.json` 을 `imported-unattested` 로 남긴다(extra 에 이미지 sha256·크기, §4 — 원장은 그 파일을 경로로 다시 읽는다, docs/safety.md §3.6).
  - 고정점: 서버는 덧붙일 때마다 그 줄의 `{seq, hash}` 를 보호 위치의 고정점 `<state_dir>/custody/<case_id>.jsonl` 에도 쓰고 읽을 때 둘을 대조한다 — 해시 체인만으로는 드러나지 않는 마지막 줄 수정·잘라 내기와 서버 밖에서 덧붙인 줄이 드러난다.
    고정점의 마지막 줄만 `{seq, hash, pending: true}`('기록 중')일 수 있다.
  - 덧붙이기(`forensics/.custody.lock` 배타 잠금 안): 보관 기록과 고정점을 읽어 검증하고(깨졌으면 쓰지 않고 `custody_broken`) 호출자의 확인(같은 번호에 `intake`·`intake-aborted` 가 이미 있으면 `intake` 거부 — `integrity_failed`)을 거친 뒤 세 단계로 쓴다.
    1) 고정점에 '기록 중' 줄(원자적 교체) — 실패하면 아무것도 바뀌지 않은 채 예외. 2) 보관 기록(앞 내용 + 새 줄을 통째로 원자적 교체) — **커밋 지점**. 실패하면 '기록 중' 줄을 거두고(못 거둬도 읽는 쪽이 기록 전 중단으로 본다) 예외.
    3) 고정점 확정 — 실패해도(어떤 예외든) 로그만 남기고 사건을 돌려준다. 그래서 덧붙이기는 사건이 남지 않았을 때만 예외를 던지고, 호출자는 예외를 '커밋 안 됨'으로 믿고 되돌린다. 커밋 뒤의 잠금 풀기·fd 닫기 실패도 로그만 남긴다(로거 `pweh.evidence`, stderr).
  - 읽기(공유 잠금 — 잠금 파일을 만들 수 없는 읽기 전용 위치면 잠금 없이): 체인 전체를 검증하고 고정점과 대조한다. 마지막 '기록 중' 줄은 보관 기록과 맞춰 본다 — 보관 기록이 그 seq 까지 있고 마지막 줄의 해시가 같으면 확정으로 보고(2 와 3 사이에 끊김),
    보관 기록이 한 줄 짧으면 없는 것으로 본다(1 과 2 사이에 끊김 — 사건은 커밋되지 않았다). 그 밖이면 깨짐이다. 확정 표시를 못 한 줄은 다음 덧붙이기가 확정 줄로 다시 쓴다. 그래서 디스크 가득·강제 종료가 기록을 영구히 깨뜨리지 않는다('기록 중' 창이 남는 동안의 한계 — docs/safety.md §3.6).
    고정점과 다른 줄(수정), 고정점보다 짧은 기록(잘림), 고정점이 없는 줄(서버 밖에서 덧붙임 — 서버는 '기록 중' 줄을 먼저 쓰므로 중단으로는 생기지 않는다)은 깨짐이다.
  - 상한·형식: 보관 기록 64 MiB, 고정점 16 MiB, 접수 기록 1 MiB. `forensics/`·`custody.jsonl`·고정점·고정점 디렉터리는 링크를 따르지 않고 일반 파일·실제 디렉터리만 연다 — 아니면(장치·FIFO·링크, 상한 초과, UTF-8 아님, 마지막 줄 잘림) 깨짐이고, 읽을 때 잠금 파일이 일반 파일이 아니어도 깨짐이다. 잠금을 30초 안에 못 얻으면 `lock_timeout`.
  - 체인이나 고정점 대조가 깨지면 증거 상태를 정하지 않는다 — 내용 도구와 기록 쓰기는 `custody_broken`, 증거 목록의 항목은 `custody-broken` 이다(fail closed — 서버는 기록을 고치지 않고 사람이 원인을 확인한다).
  한계: 비밀 키가 없어 같은 OS 계정이 보관 기록과 고정점을 함께 일관되게 다시 쓰면 감지하지 못한다(출처 원장과 같다 — docs/safety.md §3.5). 고정점은 케이스 id 로만 묶이므로, 사람이 `cases/<id>` 를 지운 뒤
  남은 고정점이 있는 ID로 새 케이스를 만들 수 없다(§3). 기존 케이스의 보관 기록이 삭제·축소되면 고정점 대조에서 `custody_broken` 이다.
- **무결성 — 내용 도구의 입구**: `forensics_verify_start`·`forensics_acquisition_attest`·`forensics_partitions`·`forensics_image_check`·`forensics_fs_list`·`forensics_extract` 는 같은 입구를 거친다(증거 목록도 확인서를 쓰기 전에 같은 대조를 한다). 검사 순서:
  1) 보관 기록 읽기·검증(깨짐 = `custody_broken`). 2) 그 증거의 `intake` 사건 — 없으면 EV 디렉터리가 있을 때 `no-intake`(커밋하지 못한 접수), 디렉터리도 없으면 `not_found`. `intake` 가 둘 이상(`duplicate-intake`)이거나 보관 기록 상태가 이미 무결성 실패(`already-failed`)면 거부.
  3) EV 디렉터리를 링크를 따르지 않고 연다 — 없으면 `missing`(지워짐), 링크·파일이면 `unsafe-path`. 4) 접수 기록을 읽고 모양을 확인한다(schema·id·케이스, 저장 경로가 그 EV 디렉터리 안의 예약 이름이 아닌 이름, 해시 길이 — 파일이 없으면 `record-missing`, 아니면 `record-invalid`).
  5) 접수 기록을 `intake` 사건(고정점으로 보호됨)과 대조한다 — 접수 기록 파일의 sha256(`record_sha256`)·해시·크기·저장 경로·빠른 지문(`record-mismatch`). 그래서 접수 기록 파일만 고쳐서는 통과하지 못한다.
  6) 사본을 `safeio` 로 연다(없음 `stored-copy-missing`, 일반 파일이 아님 `stored-copy-not-regular` — 열지 않는다, 열 수 없음 `stored-copy-unreadable`).
  7) 연 fd 로 빠른 지문(크기·mtime_ns·앞/뒤 1 MiB sha256, 쓰기 권한 비트가 생기지 않았는지)을 `intake` 사건의 지문과 비교한다(`fingerprint-mismatch`). 해석·재해시는 이 fd 로만 한다(이미지 읽기는 `ImageReader.from_fd` 가 dup 해서 — 경로를 다시 열지 않는다).
  2)~7) 의 실패는 `integrity_failed`(`data.reason` = 위 이름, `data.problems`)다 — 다만 2) 에서 EV 디렉터리도 없으면 `not_found` 다. `unsafe-path` 와 4)~7) 은 거부하기 전에 보관 기록에 `integrity-failed`(`{reason, problems}`)를 남기므로 읽기 전용 도구도 그때는 한 줄을 쓴다.
  `no-intake`·`duplicate-intake`·`already-failed`·`missing` 은 기록하지 않는다. `integrity-failed` 는 되돌리지 않는다 — 그 사본은 더 쓰지 않고 원본 이미지에서 다시 접수한다(새 EV 번호).
  빠른 지문은 전체 무결성이 아니다 — 범위(가운데만 바꾸고 mtime·권한을 되돌린 수정은 `forensics_verify_start` 의 전체 재해시만 찾는다)와 한계는 docs/safety.md §3.6.
- **증거 상태**(`forensics_evidence_list`·보고서 §8.1): 보관 기록이 멀쩡하면 항목은 보관 기록의 `intake` 사건(커밋한 접수)과 EV 디렉터리의 합집합이다.
  - 커밋한 접수(해시·크기·저장 경로·라벨은 `intake` 사건의 값): `ok`(접수 때 사본 재해시나 그 뒤 전체 재해시가 일치) / `unverified`(접수만 — 재해시 없음) / `integrity-failed`(`integrity-failed` 사건, 일치하지 않은 `verify`, `copy_verified=false` 인 `intake`, 또는 증거 목록이 본 접수 기록·디렉터리 문제와 같은 번호의 `intake` 둘 이상 — `problems`. 되돌리지 않는다) /
    `missing`(보관 기록에는 접수가 있는데 실제 EV 디렉터리가 없음 — 지워졌거나 링크·파일로 바뀜. 링크·파일이면 증거 목록의 다시 대조가 `integrity-failed`(`unsafe-path`)를 남겨 `status_label` 이 `missing (integrity-failed)`) / `record-invalid`(접수 기록 파일이 없거나 읽을 수 없음). 이 다섯 상태만 해시를 싣고 해시값 확인서에 들어간다.
  - 커밋하지 못한 디렉터리(해시 없음 — 보관 기록 근거가 없다): `intake-in-progress`(접수 잠금이 잡혀 있음) / `record-without-intake`(위 'EV 번호와 중단된 접수').
  - 보관 기록이 깨졌으면 EV 디렉터리마다 `custody-broken`(다른 상태 필드·해시 없음).
  - `status_label` 은 사람이 읽는 출력(`evidence-list.md`·보고서 §8.1)의 표시다: `status` 와 같고, EV 디렉터리가 없는데(`missing`) 보관 기록에 무결성 실패가 남은 항목만 `missing (integrity-failed)` 다(`status` 는 `missing`, `integrity_failures` 에 기록이 남는다).
  - 쓰기 방지 장치 증명은 `attest` 사건의 증명 레코드를 증명 저장소에서 찾아, 대상(증거 id·sha256·크기)과 케이스가 그 항목과 같을 때만 지금 상태(`approved`/`denied`/`revoked`/`expired`, 다시 확인되지 않으면 `invalid`)로 보인다(다른 사본·다시 쓴 번호의 증명은 보이지 않는다).
- **이미지 해석**(`pweh.fs` — 신뢰할 수 없는 이미지):
  - 한도: 모든 반복은 `Limits` 로 묶인다(기본 — 순회 하나의 항목 200000, 깊이 64, 디렉터리 하나의 슬롯 1,048,576(FAT 은 사양 최대 65,536), 순회 전체의 슬롯 8,388,608, 순회 하나의 경로 글자 수 2^28, `analyze_image` 가 여는 파티션 64).
  - 예산: 공개 호출 하나(서버는 볼륨 하나)는 `Budget` 하나 안에서 끝난다 — 시간 마감(`max_seconds` 와 절대 마감 `deadline` 중 이른 쪽), 작업 단계 상한(체인을 따라간 클러스터 하나·읽은 디렉터리 슬롯 하나·훑은 비트맵 64 클러스터가 1 단계), 선택적 취소 함수(디렉터리·항목·검증 단위·체인 4096 걸음·비트맵 조각마다 확인).
    다 되면 순회(`walk`·`reachable_dirspecs`)는 사유 `time`·`steps`·`cancelled` 로 멈추고, 항목 하나를 돌려줘야 하는 호출(`entry`·`lookup`·`content_plan`)은 `validation_failed`(`data.reason` `budget_exceeded`, `data.limit` = `time`/`steps`/`cancelled`)다. 예산 때문에 덜 읽은 디렉터리는 캐시하지 않는다.
    단계 상한은 볼륨마다 정한다(`Limits.max_follow_steps` 기본 `None` — 정수를 주면 모든 볼륨에 그 값): max(2^24, 2 × N + 순회 전체 슬롯 상한), N = min(클러스터 수, 이미지 안에서 읽을 수 있는 FAT 항목 수 − 2).
    정상적으로 꽉 찬 볼륨은 닿지 않고, 같은 긴 체인을 여러 항목이 가리키는 조작 이미지는 이미지의 FAT 크기에 비례하는 단계에서 멈춘다. `open_volume(budget=…)` 은 부트 섹터를 읽은 뒤 그 예산의 단계 상한을 이 볼륨의 값까지 올린다(내리지 않는다).
    서버는 볼륨마다 새 예산을 만든다(단계가 쌓이므로 볼륨끼리 함께 쓰지 않는다). exFAT 은 열 때 루트를 읽는다(비트맵·up-case·레이블 — 그 예산 안에서).
  - 디렉터리 검증: 디렉터리 데이터는 검사 단위(클러스터, FAT12/16 고정 루트는 섹터)마다 모든 슬롯이 엄격한 검사를 통과해야 해석한다.
    FAT — 속성 예약 비트·조합, 볼륨 레이블은 루트에만(클러스터·크기 0), 8.3 이름 바이트(`+ , ; = [ ]` 는 허용), LFN 구조, 클러스터 번호(0 또는 2 이상 최대 클러스터 이하 — 아니면 `cluster_range`), 살아 있는 하위 디렉터리의 시작 클러스터,
    크기(살아 있는·삭제된 항목 모두 볼륨 데이터 영역 (최대 클러스터 − 1) × 클러스터 크기보다 크면 `size_range`, 크기가 있는 살아 있는 파일의 시작 클러스터가 0 이면 `size_without_cluster`), 하위 디렉터리 첫 두 슬롯의 '.'(자기 첫 클러스터)·'..',
    FAT12/16/32 디렉터리의 이어지는(첫 번째가 아닌) 클러스터를 다른 FAT 항목이나 검증된 살아 있는 항목의 시작 클러스터가 가리키면 `cross_linked`(FAT32 루트 포함).
    역방향 FAT 검사가 불완전하면 `cross_link_check_incomplete`로 해당 부분을 거부한다. 시작 색인만 불완전하면 앞부분을 유지하며 `cross_link_check_partial` 경고를 남긴다.
    exFAT — 아는 사용 중 항목 형식만, 필드 범위·플래그, 비트맵·up-case·레이블·GUID 는 루트에만, 완전한 항목 집합의 SetChecksum(삭제 집합은 InUse 를 되돌려 계산 — 다음 단위를 미리 볼 수 있다).
    처음으로 통과하지 못한 단위에서 그 디렉터리를 멈추고, 그 단위와 뒤에서는 이름·크기·시각·원시 이름 바이트를 하나도 내보내지 않는다. 경고 `dir_unvalidated` 와 순회의 `unvalidated_dirs`(`{dirspec, path, reason, slots_skipped}`, 100개까지)·`unvalidated_dirs_total`·`unvalidated_dirs_live`(그중 살아 있는 디렉터리 — 삭제된 디렉터리와 그 아래가 아닌 것)로 남긴다(조용히 버리지 않는다).
    그 디렉터리 자신의 항목은 부모 목록에 남고, 그 영역을 가리키는 ref 는 `bad_ref` 다. 속성 비트 0x40·0x80, 하위 디렉터리의 볼륨 레이블, LFN 이상, exFAT 필드 검사는 무작위 녹화 데이터를 디렉터리로 읽지 않게 거르는 주된 장치라 fsck 보다 일부러 엄격하다.
    이 엄격함, FAT32 에 `cross_linked` 검사가 없는 것, 파일의 첫 클러스터로 이어진 교차 연결, 클러스터 힙보다 큰 exFAT DataLength 를 검증에서 거르지 않는 것은 docs/safety.md §3.6.
  - 잘리는 디렉터리: 슬롯 한도보다 길고 그 안에 끝 표시가 없는 디렉터리는 앞부분만 읽는다(경고 `dir_slot_limit`, 잘린 자리에 걸친 항목 집합·LFN 조각은 내보내지 않는다, 뒤쪽을 가리키는 ref 는 `bad_ref` + `data.dir_cut`). 깊이 64 의 디렉터리 항목은 목록에 싣되 안으로 내려가지 않는다.
    끝 표시 없이 읽기가 끝난 디렉터리는 데이터가 읽을 수 있는 범위(엔진의 원본 — 파티션 표 항목을 이미지 끝에서 자른 구간) 끝 너머면 `beyond_image`(원인은 아래 볼륨 사유 `image_truncated`·`volume_exceeds_partition` 으로 본다), 클러스터 체인이 끝 표시 전에 비정상으로 끝났으면(exFAT 은 DataLength 보다 짧은 체인 포함) `dir_chain_broken`(손상)이다.
    끝 표시가 있었으면 그 뒤가 망가져도 빠진 것이 없다. exFAT 은 체인이 읽을 길이(DataLength — 슬롯 한도보다 길면 한도까지)를 다 모았으면 마지막 FAT 항목이 망가져도 `dir_chain_broken` 이 아니다(경고 `dir_chain_*` 만 남는다.
    DataLength 가 슬롯 한도보다 길면 한도 안에 끝 표시가 없는 한 그대로 `max_dir_slots` 잘림이다). 내용 계획의 `bytes_beyond_image` 도 같은 범위를 기준으로 센다. 디렉터리 하나를 보는 `list_dir` 도 이 두 사유를 `truncated_reasons` 에 넣는다.
    읽지 못한 디렉터리는 `dir_unreadable` 이다. `beyond_image`·`dir_chain_broken`·`dir_unreadable` 은 살아 있는 디렉터리만 잘림으로 센다 — 삭제된 디렉터리(와 그 아래)는 원래 최선 노력이라 손상·이미지 끝은 경고만 남긴다.
  - 경로 찾기(`lookup` — `forensics_extract` 의 `paths=`): 검증한 디렉터리만 지난다. 구성요소마다 이름(또는 표시 이름)이 정확히 같은 살아 있는 항목이 먼저이고, 없으면 대소문자를 무시한다 — 글자 하나가 글자 하나로 바뀌는 변환만 쓴다(ß→SS·ﬁ→FI 처럼 글자 수를 바꾸는 접기는 하지 않는다).
    FAT 은 긴 이름·표시 이름·8.3 짧은 이름을 글자마다 대문자로, exFAT 은 볼륨의 up-case 표로(표가 없으면 ASCII 만) 비교한다. 정확히 같은 것이 둘 이상이거나, 정확한 것 없이 대소문자 무시로 둘 이상이 맞으면 `ambiguous_path`(`data.component` = 몇 번째 이름, `data.candidates` = 개수 — 메시지에 이름을 싣지 않는다).
    끝까지 읽지 못한 디렉터리(예산 멈춤·슬롯 한도·`beyond_image`·`dir_chain_broken`·검증 실패)에서는 정확히 같은 이름(이름·표시 이름, 대소문자 포함)만 받는다 — 대소문자 무시·8.3 별칭으로만 맞으면 고르지 않고 그 디렉터리의 사유로 오류를 낸다
    (예산 멈춤이 아니면 메시지가 대소문자만 맞는 항목이 있다고 알린다 — 예산 멈춤은 그 안내 없이 `budget_exceeded` 다. 정확히 같은 이름의 다른 항목이 읽지 못한 뒤쪽에 있을 수 있다).
    돌려주는 `path`·`display_path` 는 실제로 맞은 항목들의 디스크 이름(원래 이름·표시 이름)을 이은 것이다(호출자의 철자가 아니다). 없으면 `None`(끝까지 읽은 검증된 디렉터리에 없음, 중간 구성요소가 디렉터리가 아님) 또는 오류 —
    `max_depth`(경로가 64 단계보다 깊음 — 목록도 그 아래로 내려가지 않는다), `max_dir_slots`(슬롯 한도에서 잘린 디렉터리), `beyond_image`·`dir_chain_broken`(끝까지 읽지 못한 디렉터리), `dir_unvalidated`(검증하지 못한 단위에서 멈춘 디렉터리) — 뒤쪽에 있을 수 있어 '없음'이라 하지 않는다 —, `budget_exceeded`,
    `dir_unreadable`(경로의 디렉터리를 읽지 못함 — 읽기 오류·잘못된 지정. 목록의 `dir_unreadable` 과 같은 사유, `data.component`, `data.cause` = 엔진의 원래 사유).
- **호출 예산과 잘림**(`forensics_fs_list`·`forensics_image_check`):
  - 동기 도구(`forensics_partitions` 포함)는 요청 취소를 엔진·목록 직렬화·커밋 직전 검사에 전달한다. 작업 스레드가 증거 fd와 커밋 전 파일을 정리한다. OS 호출 자체를 강제 중단하지 않으며 이미 커밋한 결과는 되돌리지 않는다.
  - 목록 JSON은 256 MiB까지 스트리밍한다. 초과 시 `output_limit`로 실패하고 기록 전 파일을 정리한다. `list`·`extract` 커밋은 보관 기록 잠금 안에서 출력 디렉터리와 파일의 신원·변경 시각·크기·권한·링크 수를 재확인한다. 다른 객체로 교체된 이름은 정리하지 않는다.
  - 호출 하나의 예산(파티션 합계): 항목 수 `max_entries`, 마감 시각 `max_seconds`, 순회하는 서로 다른 (시작, 크기) 구간 64개(같은 구간은 한 번만 — 뒤의 것은 `duplicate` 로 세고 한도로 보지 않는다), 경로 글자 수 268,435,456(2^28 — 항목마다 `path` 의 글자 수, `display_path` 가 다를 때만 그것도 더한다).
    `forensics_fs_list` 는 `max_entries` 를 1~200000(기본 200000), `max_seconds` 를 1~600(기본 180)으로 자른다(0 은 기본값으로 본다). `forensics_image_check` 는 120초·200000개로 고정이다. 시간 예산은 해석(열기·정보·순회)에 걸리고, 목록 요약·목록 파일 쓰기는 그 뒤다(docs/safety.md §3.6).
  - 볼륨마다 엔진 예산 하나(호출의 마감 시각, `open_volume` 이 올리는 그 볼륨의 단계 상한, 취소 함수 없음)를 새로 만들어 열기·정보·순회가 함께 쓴다. 순회는 남은 항목 수·남은 경로 글자 수로도 묶인다(엔진이 센 `path_chars` 를 빼 나간다).
    처음 여는 볼륨은 호출 시간이 조금이라도 남으면 열고, 그 뒤 볼륨은 남은 시간이 0.25초보다 적으면 건너뛴다. 항목·경로 글자 수를 다 썼거나(앞 순회가 `max_path_chars` 로 멈춘 경우도) 64개를 다 열었으면 남은 파티션도 건너뛴다.
    건너뛴 파티션은 `call.partitions_skipped{<사유>: {count, examples(index 20개)}}`(`duplicate`·`time`·`entries`·`partitions`·`path_chars`)다. 열었지만 엔진 예산이 다 돼 오류(`budget_exceeded`)가 난 볼륨은 손상이 아니라 한도라 그 사유(`time`·`steps`)로 세고 `volumes[].error` 를 둔다(`volumes_failed` 에 세지 않는다).
    그 밖의 오류(엔진 `FsError`, 엔진이 바꾸지 못한 예외는 `internal_error`)가 난 볼륨은 `volumes[].error` 와 `call.volumes_failed{count, examples[{partition, reason}]}`(예시 20개) 로 세고 나머지 볼륨은 계속 본다 — 해석하지 못한 볼륨이 하나라도 있으면 `truncated=true` 다.
    `call` = `{max_entries, entries_used, max_partitions, max_path_chars, path_chars_used, partitions_walked, partitions_skipped, volumes_failed}`(응답, 목록 파일의 `call`, 보관 기록 `list` 의 `data.call`).
  - 순회의 잘림 사유: 순회를 멈추는 전역 사유 `time`·`steps`·`cancelled`·`max_entries`·`max_total_slots`·`max_path_chars`, 그 디렉터리의 읽지 못한 부분만 빠지고 나머지 나무는 계속 보는 디렉터리별 사유 `max_depth`·`max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unreadable`
    (잘린 디렉터리는 `cut_dirs` — `max_dir_slots`·`beyond_image`·`dir_chain_broken` 은 읽은 앞부분 항목(과 그 아래)이 목록에 있고, `max_depth` 는 그 디렉터리 항목만 있고 안으로 내려가지 않으며, `dir_unreadable` 은 그 디렉터리의 내용이 하나도 없다).
    엔진의 `truncated_reasons` 는 전역 사유가 먼저, 그다음 디렉터리별 사유를 처음 나온 순서로 둔다(`truncated_reason` 은 그 첫째). 디렉터리별 사유만 있으면 `cut_dirs` 를 뿌리로 하는 하위 나무 말고는 다 본 것이다.
    서버는 볼륨마다 사유를 더한다: `dir_unvalidated`(살아 있는 디렉터리 중 검증하지 못한 단위에서 멈춘 것이 있다 — 그 뒤쪽 항목은 목록에 없다. 삭제된 디렉터리만이면 잘림이 아니고 `next_steps` 에 따로 적는다),
    그리고 볼륨이 읽을 수 있는 범위 너머까지 이어지면(`volume.truncated`) 원인에 따라 `image_truncated`(볼륨 끝 — 파티션 시작 + `volume_size` — 이 이미지 끝 너머: 이미징이 끊겼거나 용량을 속인 카드. 끝 너머의 디렉터리·파일 내용·삭제 흔적은 볼 수 없다)
    또는 `volume_exceeds_partition`(이미지는 이어지는데 파일 시스템이 파티션 표 항목보다 큼 — 파티션 표가 줄었거나 손상. 항목 밖으로 이어지는 부분은 이 파티션 범위로 읽지 않는다).
    `partition` 을 고르지 않았으면 파티션 표로 보이는 잘림 — 시작이 이미지 끝 너머인 파티션(`partition_beyond_image`), 이미지 끝 너머에서 끊긴 EBR 사슬(`ebr_beyond_image`) — 도 호출 사유 `image_truncated` 다(그런 파티션을 `partition` 으로 고르면 오류 — 아래 표).
    파티션 항목의 끝만 이미지 밖인 것(`partition_truncated`)은 세지 않는다 — 파일 시스템이 이미지 안에서 끝나면 사유가 없고(`forensics_partitions` 의 파티션 경고로만 보인다), 이미지 끝 너머까지 이어질 때만 그 볼륨의 `image_truncated` 다.
    호출의 `truncated_reasons` 는 건너뛴 파티션의 사유(이름을 맞춘다 — `entries` → `max_entries`, `path_chars` → `max_path_chars`, `partitions` → `max_partitions`), 볼륨마다의 사유, 파티션 표의 `image_truncated` 를 중복 없이 처음 나온 순서로 모은 것이다. 동기 도구도 요청 취소를 엔진에 전달하며 취소된 호출은 결과를 반환하거나 새 목록을 커밋하지 않는다.
    `next_steps` 는 사유마다 다르다 — 늘릴 수 있는 한도(`time`, `forensics_fs_list` 의 `max_entries`)는 인자를 늘리거나 `partition` 으로 나누게 하고, 고정 한도(`max_depth`·`max_dir_slots`)와 이미지·카드 상태(`beyond_image`·`dir_chain_broken`·`dir_unreadable`·`dir_unvalidated`·`image_truncated`·`volume_exceeds_partition`)는 늘리라고 하지 않고 사람에게 알려 보고서 한계에 적게 한다.
    `forensics_fs_list` 의 '목록이 불완전하다' 안내와 `forensics_image_check` 의 note 는 파티션 경고를 보라고 `forensics_partitions` 도 가리킨다.
  - `forensics_image_check` 의 `note`: strong 흔적이 있으면 그 안내. 해석하지 못한 볼륨이 있으면 그 볼륨의 흔적을 보지 못해 '흔적 없음'으로 보고하지 않는다는 안내(흔적 없음 문장 대신).
    그렇지 않고 본 볼륨이 하나도 없으면 '본 볼륨이 없어 흔적을 보지 못했다(사유 …, 사유가 없으면 지원하는 FAT/exFAT 파티션 없음) — '흔적 없음'으로 보고하지 않는다'다 — 흔적 없음 문장은 나오지 않는다.
    이때 `truncated` 는 사유가 있으면(예: 하나뿐인 파티션의 시작이 이미지 끝 너머 — `image_truncated`) true, 지원하지 않는 파티션뿐이면 false 다 — 판단은 `truncated` 가 아니라 본 볼륨(`error` 가 아닌 `volumes[]` 항목)이 있는지로 한다.
    그렇지 않고 strong 흔적이 없는데 사유가 하나라도 있으면 '본 범위에서는 … 찾지 못했지만 보지 못한 부분(사유 …)이 있어 '흔적 없음'으로 보고하지 않는다'. 사유도 없을 때만 '호스트 OS 가 만드는 흔적을 찾지 못했다(없음을 증명하지는 않는다)'. 한도로 건너뛴 파티션이 있으면 그 안내를 덧붙인다.
- **job 과 취소**: 접수·검증·추출은 job 이다. 같은 원본(실제 경로)의 접수, 같은 증거의 검증, 같은 증거의 추출이 이미 실행 중이면 `busy` 다. 취소는 다음 1 MiB 읽기 조각과(추출은) 엔진 계산 안(예산의 취소 함수)에서 반영된다.
  되돌릴 수 없는 지점을 지나면 job 이 `mark_committed()` 를 부른다: 그 뒤의 취소 요청은 무시되고(`forensics_job_cancel` 은 상태를 바꾸지 않은 job 을 돌려준다 — 실행 중이면 `status` 는 `running` 그대로) 그 직전에 와 있던 취소는 지워져, job 은 끝나면 `succeeded` 다.
  늦은 취소만 무시할 뿐 그 뒤의 실패를 감추지는 않는다(예: 검증이 `verify` 사건을 기록하지 못하면 job 은 `failed`).
  - 접수: 복사·재해시 도중, 또는 접수 기록을 다 쓴 뒤 커밋 직전의 마지막 확인에서 취소되면 되돌린다(`cancelled`, 번호를 돌려놓는다). `intake` 사건을 덧붙이면 `mark_committed` — 그 뒤에 온 취소는 무시한다.
  - 검증: 재해시 도중의 취소는 아무것도 기록하지 않고 `cancelled` 다. 재해시가 끝나면 `mark_committed` 를 부른 뒤 `verify` 사건을 덧붙인다.
  - 추출: 볼륨 열기·ref 확인 순회·경로 찾기 도중의 취소는 출력 디렉터리·보관 기록 없이 `cancelled` 다. 출력 디렉터리를 만든 뒤 추출이 취소를 받아들이면(항목 사이·쓰는 도중·엔진이 후보를 만드는 도중) 쓰던 파일은 `complete=false` 로 남기고,
    시도하지 않은 항목은 모두 `skipped`(사유 '취소됨' — 디렉터리 항목은 디렉터리 사유)에 싣고, 매니페스트 `truncated_reasons` 에 `cancelled` 를 남겨 디렉터리 0555·보관 기록 `extract` 까지 마친 뒤 job 은 `cancelled` 로 끝난다(`result` 는 성공과 같은 모양 — 부분 결과가 보관 기록에 남는다. 첫 항목 전에 받아들였으면 파일 없는 매니페스트).
    추출이 취소를 보지 못하고 끝났으면(다 쓴 뒤·기록한 뒤 도착한 취소) `mark_committed` — `succeeded`. 규칙: 출력 디렉터리를 만든 뒤의 추출 job 은 매니페스트에 `cancelled` 가 있을 때만 `cancelled` 다.
  - 서버를 끝낼 때(stdin EOF·SIGTERM — 실행 중인 job 을 취소하고 job 마다 10초까지 기다린다. SIGTERM 이면 모두 합쳐 최대 약 15초를 기다린 뒤 끝난다) 커밋 전 접수는 되돌린다. SIGKILL 이면 남은 접수 디렉터리를 다음 정리가 옮긴다(위). job 상태는 `cases/<id>/jobs/<job_id>.json` 에도 남는다. 재시작 뒤 `forensics_job_status(..., case_id=...)` 또는 `forensics_jobs(case_id=...)`로 저장 기록을 확인하면 종료가 확실한 소유 서버의 활성 기록만 failed로 정리한다(위 공통 job 계약). 소유자가 없거나 확인 불가면 원본 상태를 보존하고 unknown으로 표시한다. 이는 증거 접수의 커밋·정리 여부를 증명하지 않는다(docs/safety.md §3.6).
- **영상·음성 내용은 돌려주지 않는다**: 파일 목록 응답은 개수·범위·이름·경로와 해시다. 선택한 폰 앱 기록은 `forensics_android_artifacts`로 내용도 반환한다. 정지 그림은 `forensics_image_hints`에서 미리보기·마스킹하지 않은 OCR·QR·메타데이터를 반환한다. 추출물은 `forensics/recovered/`에만 쓰며 직접 열지 않는다. 전체 파일 목록은 `forensics/analysis/` 의 JSON 에만 있다. 응답의 긴 경로(`sample`·`cut_dirs`·흔적의 `path`)는 앞·뒤만 남겨 300자로 줄인다.
  다른 서버의 `forensics/` 거부(pweh-fwtriage, pweh-sigrok, `case_import_file`·`case_hash_file`·`case_register_artifact`)와 그 밖의 경로가 막히지 않는 한계는 §4 다.
- **권한**: 조회 전용(`readOnlyHint`) 도구 `forensics_partitions`, `forensics_image_check`와 명시적 예외 `forensics_job_status`·`forensics_jobs`·`forensics_image_hints`·`forensics_sqlite_inventory`·`forensics_android_artifacts`·`forensics_timeline`이 `.claude/settings.json`의 `allow`다. 작업 상태/목록은 저장 기록 정리, 정지 이미지 분석은 로컬 JSON/PNG·보관 기록 쓰기가 있어 readOnlyHint는 false다.
  쓰는 도구 8개(`forensics_intake_start`, `forensics_verify_start`, `forensics_acquisition_attest`, `forensics_evidence_list`, `forensics_fs_list`, `forensics_extract`, `forensics_extract_media_candidate`, `forensics_job_cancel`)는 `ask` 다(매번 사람이 확인).
  모든 도구가 `openWorldHint=false` 이고 파괴적(`destructiveHint`) 도구는 없다.

| 도구 | 동작 / 반환 |
|---|---|
| `forensics_intake_start(case_id, image_path, purpose, legal_basis, site_type, business_purpose, role, imaging_log_path=None, label=None, verify_copy=True, storage="copy")` | job. 케이스 소유/허가가 있어야 한다. job 을 띄우기 전에 검사한다(동기 오류): `purpose`·`legal_basis`·`business_purpose` 는 앞뒤 공백을 뺀 3~500자(탭 말고 제어 문자 없음), `site_type` ∈ `home`/`public`/`business`/`vehicle`/`mobile-business`/`unknown`(적용 법률이 달라진다), `role` ∈ `owner`/`processor`/`investigator`/`other`, `label` 은 제어 문자 없는 80자 이하, 경로에 NUL 이 있으면 거부. `image_path` 는 링크를 한 번 푼 실제 경로를 `safeio` 로 한 번 연다 — 원시 디스크 경로(`\\.\…`, `//./…`, `//?/…`, `\\?\PhysicalDrive…`·`Volume…`·드라이브 문자), `/dev`·`/proc`·`/sys` 아래(풀기 전·후 모두), 디렉터리·장치·FIFO·소켓·빈 파일은 `validation_failed` 이고 E01(EWF) 서명도 아직 거부한다(이미징 도구·ewfexport 로 raw 로 내보내 접수). `image_path`·`imaging_log_path` 가 케이스 폴더나 상태 폴더 안이면 거부하고(로그는 열기 전 경로와 연 fd 의 실제 경로 둘 다), 사본 이름이 예약 이름과 겹쳐도 거부한다(위 '케이스 구조'). 이미징 로그는 4 MiB 이하 일반 파일(UTF-8·UTF-16·latin-1, 읽는 동안 상한을 넘게 자라면 거부)이고 FTK Imager·dc3dd·ewfacquire·ewfinfo·Guymager 를 알아보며 md5·sha1·sha256 해시 줄을 모은다. 케이스 디스크의 여유 공간이 이미지 + 256 MiB 보다 적으면 거부하고, 보관 기록이 깨졌으면 복사하기 전에 `custody_broken`(job 없음). job: EV 번호 확보(정리 포함 — 위) → `<이름>.partial`(`O_EXCL`)로 원본 fd 를 한 번 읽으며 sha256·md5·sha1 계산과 복사(fsync, 0444 — 원본이 그 사이 줄면 `integrity_failed`) → 원본의 크기·mtime 이 바뀌었으면 `integrity_failed` → `verify_copy` 면 사본 재해시 → 최종 이름으로 바꾸고 빠른 지문 → 로그 해시 대조·로그 사본 `imaging-log.txt`(0444) → 접수 기록 `EV-NNNN.json`(0444 — 해시·크기·빠른 지문·접수 정보. 원본은 파일 이름·크기·mtime 만 남기고 전체 경로는 남기지 않는다) → 마지막 취소 확인 → 보관 기록 `intake`(**커밋 지점** — `{label, source_name, stored_path, size, hashes, fingerprint, record_sha256, copy_verified, imaging_log, legal}`) → `mark_committed` → 잠금 파일 지우기·디렉터리 0555(실패하면 로그만 — 다음 정리가 마무리). 커밋 전의 실패·취소(`intake` 덧붙이기 실패 포함)는 만든 파일과 EV 디렉터리를 지우고 번호를 돌려놓는다. 커밋 뒤의 보조 단계 — 감사 로그(실패는 로그만), 사본 재해시가 다르면 `integrity-failed` 사건, 출처 원장, 아티팩트 `evidence-image`(`extra.evidence_id`, sha256), 같은 sha256 의 증거 확인 — 는 실패해도 커밋한 접수를 실패로 만들지 않는다(감사 로그 밖의 실패는 `post_commit_errors`·`note`). 결과(`forensics_job_status` 의 `result`): `ok`(사본 재해시가 다를 때만 false), `evidence_id`, `stored_path`, `size`, `hashes{sha256, md5, sha1}`, `copy_verified`(`verify_copy=false` 면 `null`), `imaging_log{tool, comparison{status: match/mismatch/no-hashes, details}, conflicts}`(로그가 없으면 `null`. mismatch 는 로그의 값이 모두 다른 알고리즘이 하나라도 있을 때, `conflicts` 는 로그에 값이 둘 이상인 알고리즘), `custody_seq`, `provenance{seq, kind}`(원장 기록 실패면 `{error}` — 접수는 그대로), `next_steps`, 같은 sha256 의 증거가 이미 있으면 `duplicate_of`·`warning`, 로그 해시가 다르면 `warning`(둘 다면 한 `warning` 에 ' / ' 로 잇는다), 사본 재해시가 다르면 `error`(`copy_verified=false` 인 `intake` 만으로도 상태는 `integrity-failed` — 내용 도구는 거부), 커밋 뒤 보조 단계가 실패했으면 `post_commit_errors`(`'<무엇>: <오류>'`, 300자까지)·`note` |
| `forensics_verify_start(case_id, evidence_id)` | job. 먼저 내용 도구 입구(위)를 거친다 — 문제가 있으면 job 없이 `integrity_failed`(기록하는 사유면 `integrity-failed` 를 남긴 뒤). 입구에서 연 fd 로 사본 전체를 다시 읽어(접수 때의 크기만큼 — 그 전에 끝나면 모두 mismatch) 보관 기록 `intake` 사건의 sha256·md5·sha1·크기와 비교한다 → 재해시가 끝나면 `mark_committed` → 보관 기록 `verify`(`{result, details, size}`, 다르면 이어서 `integrity-failed` — reason `verify-mismatch`) → `result`: `ok`(= match), `result`(`match`/`mismatch`), `details{sha256, md5, sha1}`(각각 match/mismatch), `custody_seq`. `verify` 를 남겼는데 이어지는 `integrity-failed` 사건을 못 남기면 `post_commit_errors`·`note` 다(상태는 `verify` 불일치만으로 `integrity-failed`). `verify` 를 기록하지 못하면 job 은 `failed`. 재해시 도중의 취소는 아무것도 기록하지 않는다. verify 는 그 시점에 디스크에 있는 바이트만 증명한다(docs/safety.md §3.6) |
| `forensics_acquisition_attest(case_id, evidence_id)` | 사람 증명 `write-blocker`. 먼저 내용 도구 입구(위)를 거친다. 질문: `blocker_used`(카드 리더 일체형 하드웨어 쓰기 방지 장치를 거쳐 만들었고 카드를 그 장치에만 넣었다 — 예여야 승인), `blocker_model`(제조사·모델, 값), `blocker_tested`(희생용 카드로 먼저 시험했다 — 정보 항목이라 '아니오'여도 승인), `imaging_tool`(도구와 버전, 값). subject `{evidence_id, sha256, size}`(보관 기록 `intake` 사건의 값), binding 은 케이스, 새 레코드는 90일 유효(같은 지문의 기존 레코드는 그 만료를 따른다 — §4). 충족하면 `status: "approved"`, `attestation_id`, `blocker_tested`(사람의 답), `next_steps`. 아니면 `attestation_response`(`attestation_required`/`denied` + `evidence_id`. 거부·철회·만료된 앞 증명이 있으면 다시 부를 때 새 요청과 `previous`). 보관 기록 `attest` 는 상태가 바뀔 때만 한 줄씩 남는다(승인 — 모델·시험 여부·도구 답, 거부, 철회·만료). 철회·만료는 이 도구를 다시 불러야 보관 기록에 반영된다(증거 목록은 증명 저장소의 지금 상태를 보인다 — 위 '증거 상태'). 증명은 기록일 뿐 다른 도구를 막지 않는다 — 없으면 증거 목록에 '증명 없음'으로 남는다. 에이전트는 답하지 않는다(사람이 `pweh attest <id>`) |
| `forensics_partitions(case_id, evidence_id)` | 읽기 전용, 호출 예산 60초(`analyze_image` — 호출 전체가 예산 하나이고 연 볼륨마다 단계 상한을 그 볼륨의 값까지 올린다). `scheme`(`mbr`/`gpt`/`superfloppy`/`none`), `sector_size`, `image_size`, `partitions[{index, scheme, role(primary/logical/volume), start_offset, size_bytes, start_lba, type_id, type_name, bootable, fs_hint, name·guid(GPT, 이름은 이스케이프), warnings(10개까지)}]`(`fs_hint`: `fat12`/`fat16`/`fat32`/`exfat`/`exfat-invalid`/`ntfs`/`ext2`·`ext3`·`ext4`/`f2fs`/`squashfs`/`luks`/`zeroed`/`unknown`), `partitions_total`, `volumes[{index, fs_hint, volume{fs_type, volume_label, volume_id(FAT)·volume_serial(exFAT), cluster_size, cluster_count, volume_size, available_size, truncated, bytes_per_sector, percent_in_use, fs_revision, dirty, media_failure, hard_error}, duplicate_of, omitted}]`(파티션마다, 값이 있는 것만. 지원하지 않거나 열 수 없으면 `volume` 대신 `error`(`validation_failed`) — 시작이 이미지 끝 너머인 파티션은 `data.reason` `beyond_image`(메시지 '파티션 시작이 이미지 끝 너머라 볼 수 없습니다(잘린 이미지).' — '지원하지 않는 파일 시스템'이 아니다). `volume.truncated` 는 볼륨이 읽을 수 있는 구간(파티션 표 항목과 이미지 끝 중 짧은 쪽)보다 길다는 뜻이다 — 원인은 목록·오염 검사의 `image_truncated`·`volume_exceeds_partition`), `volumes_total`, `partitions_omitted`, `truncated`, `truncated_reason`(`time`/`partitions`/`steps`, 응답 상한이면 `response` — 파티션을 다 열거나 싣지 못한 것이다. 이미지 잘림은 파티션 `warnings`(`partition_beyond_image`·`partition_truncated`)와 `warnings`(`ebr_beyond_image`), `volume.truncated`, `beyond_image` 볼륨 오류로 보인다), `warnings`(50개까지 — GPT 헤더·항목 CRC, 겹침, 보호 MBR, EBR 사슬 …), `next_steps`. 같은 (시작, 크기) 구간은 한 번만 열고(뒤의 것은 `duplicate_of`), 서로 다른 구간은 64개까지만 연다(나머지는 `omitted` — `partitions`·`time`·`steps`). 응답의 파티션·볼륨은 128개까지. GPT 는 512·4096 바이트 섹터를 본다. 감사 로그에 남긴다 |
| `forensics_image_check(case_id, evidence_id, partition=None, acquisition_date=None)` | 읽기 전용. 보관 기간에 분석 PC 가 카드에 남겼을 흔적(삭제 항목 포함, 볼륨마다 200개까지): strong — 루트의 `$RECYCLE.BIN`·`.Spotlight-V100`·`.fseventsd`·`.Trashes`·`.Trash-<uid>`, `System Volume Information` 안의 `IndexerVolumeGuid`·`WPSettings.dat`, 어느 깊이든 `.DS_Store`·`Thumbs.db`·`desktop.ini`·`._*`(AppleDouble) / weak — `System Volume Information` 폴더만, 마지막 접근 날짜가 `acquisition_date`(YYYY-MM-DD, 생략하면 접수 시각의 UTC 날짜)와 같은 살아 있는 파일(개수) / ambiguous — dirty 비트. 호출 예산은 120초·항목 200000개·경로 글자 수 2^28·파티션 64개로 고정이고 볼륨마다 엔진 예산 하나다(위 '호출 예산과 잘림'). → `acquisition_date`, `volumes[{partition, fs, indicators[{indicator, strength, path, deleted, note}], walk_truncated(엔진 순회가 잘렸거나 서버가 더한 사유가 있음 — forensics_fs_list 의 볼륨 truncated 와 같은 규칙), walk_truncated_reason(엔진의 첫 사유, 없으면 서버가 더한 첫 사유), walk_truncated_reasons(+ dir_unvalidated·image_truncated·volume_exceeds_partition), cut_dirs[{path, reason}] 10개, cut_dirs_total, unvalidated_dirs(개수)}]`(해석하지 못하면 `error`), `strong_indicators`, `call`, `truncated`(사유가 있거나 해석하지 못한 볼륨이 있거나 순회가 잘림), `truncated_reasons`, `note`(위 규칙), 사유가 있으면 `next_steps`. 흔적은 정황이다(카메라가 만들 수 없는 것은 아니다). 지원하는 파티션이 없으면 `volumes` 가 비어 있다(흔적이 없다는 뜻이 아니다 — `note` 는 '보지 못했다'고 하고, `truncated` 는 파티션이 이미지 끝 너머면(`image_truncated`) true, 지원하지 않는 파티션뿐이면 false 다. `partition` 으로 고른 파티션이 없거나 지원 밖이거나 시작이 이미지 끝 너머면 `validation_failed` — 마지막은 `data.reason` `beyond_image`(`unsupported_fs` 가 아니다)이고 메시지가 잘린 이미지라고 알린다). 감사 로그에 남긴다 |
| `forensics_fs_list(case_id, evidence_id, partition=None, include_deleted=True, max_entries=200000, max_seconds=180)` | 동기 호출(job 아님 — 클라이언트가 취소해도 예산까지 돌고 목록 파일·보관 기록을 남긴다, docs/safety.md §3.6). 고른 파티션(생략하면 지원하는 파티션 전부)을 위 '호출 예산과 잘림' 안에서 순회해 전체 목록을 `forensics/analysis/fs-list-<EV>-NNN.json`(0444)에 볼륨 하나씩 이어 쓰고(항목은 한 줄에 하나 — 모든 볼륨의 목록을 한꺼번에 들고 있지 않는다) 보관 기록 `list`(`{result_path, result_sha256, call, volumes[{partition, stats}]}`(볼륨 64개까지))에 쓴 바이트 그대로의 sha256 을 남긴다. 실패·중단하면(보관 기록 `list` 실패 포함) 확보한 목록 파일을 지운다. 목록 파일(`pweh.forensics.fs-list/v1`): `evidence_id`, `generated_at`, `params{partition, include_deleted, max_entries, max_seconds, max_partitions}`, `scheme`, `volumes[{partition(파티션 정보 전체), info(볼륨 정보 전체), walk{entries, orphans, stats, truncated, truncated_reason, truncated_reasons, cut_dirs(dirspec 포함, 100개까지), cut_dirs_total, unvalidated_dirs, unvalidated_dirs_total, unvalidated_dirs_live, path_chars, warnings, warnings_suppressed}}]`(해석하지 못한 볼륨은 `{partition, fs, error, partition_info}`), `call`. 항목은 `path`(디스크의 원래 이름)·`display_path`(표시 이름 — 제어·양방향 문자와 `/`·`\` 를 이스케이프)·`depth`·`parent_ref`·이름(LFN·8.3)·크기·시각(원래 값 + `time_basis`)·삭제 여부·`ref`·체인 요약·exFAT `valid_data_length`·`residual_bytes` 다. 응답: `result_path`, `result_sha256`, `custody_seq`, `volumes[{partition, fs, volume, stats{files, dirs, deleted_files, deleted_dirs, orphans, dirs_read}, truncated, truncated_reason, truncated_reasons, cut_dirs[{path, reason}] 10개, cut_dirs_total, time_ranges[{state(live/deleted), time_basis, first, last, files}], time_basis(한 가지면 그 값, 여럿이면 mixed, 시각이 없으면 unknown), top_dirs[{dir, files, deleted_files}], extensions[{ext, files}] 상위 15개, files_with_residual, orphans, unvalidated_dirs, unvalidated_dirs_live, warnings_count, sample[{path, is_dir, deleted, size, modified, ref}] 처음 20개}]`(128개까지, 열 수 없으면 `error`), `volumes_total`, `truncated`, `truncated_reasons`, `call`, `next_steps`(불완전하면 '목록이 불완전하다(사유 … — 파티션 경고는 `forensics_partitions`)'와 사유별 안내, 해석하지 못한 볼륨, 삭제된 디렉터리만 검증하지 못했다는 안내, 추출 최소화). 지원하는 파티션이 없거나 고른 파티션이 지원 밖이면 `validation_failed` — 파티션이 이미지 끝 너머라 볼 수 있는 파티션이 없으면 메시지·힌트가 ext4·NTFS 안내 대신 잘린 이미지라고 알리고(이미징 확인), 고른 파티션의 시작이 이미지 끝 너머면 `data.reason` `beyond_image`(`unsupported_fs` 가 아니다)이고 메시지가 잘린 이미지라고 알린다 |
| `forensics_extract(case_id, evidence_id, refs=None, paths=None, partition=None, method="auto", region="data", label=None, max_files=200, max_bytes="1G")` | job. job 을 띄우기 전에 검사한다(동기 오류): `refs`(fs-list JSON 의 `ref`, 삭제 항목 포함)·`paths`(살아 있는 항목의 경로) 중 하나 이상이고 문자열 중복을 뺀 합계 1000개까지, `region` ∈ `data`/`residual`, `method` 는 비지 않은 32자 이하, `max_bytes` 는 정수 또는 `"1G"`·`"512M"`, 케이스 디스크 여유 공간이 `max_bytes` + 256 MiB 이상, 내용 도구 입구(위). 거부하지 않고 자르는 값: `max_files` 는 1~1000, `max_bytes` 는 1 바이트~4 GiB, `label` 은 `[0-9A-Za-z._-]` 밖을 `-` 로 바꿔 32자(기본 `recovered`). job(마감 300초, 엔진 호출마다 새 예산 — job 마감·job 의 취소 함수·그 볼륨의 단계 상한): 볼륨 열기(지원 파티션이 여럿이면 — 같은 구간은 하나로 센다 — `partition` 이 필요하다. 없으면 job 이 `validation_failed`(`bad_argument`)로 실패. 고른 파티션의 시작이 이미지 끝 너머이거나 파티션이 이미지 끝 너머라 볼 수 있는 FAT/exFAT 파티션이 없으면 `validation_failed`(`beyond_image` — 잘린 이미지)) → ref·경로 확인(아래) → `forensics/recovered/<label>-NNN/` 을 만들고 고른 항목을 쓴다 → `manifest.json` → 디렉터리 0555 → 보관 기록 `extract`(`{output_dir, manifest_sha256, files, bytes, method, region, truncated}` — **커밋 지점**). **ref**: 같은 항목을 가리키면 하나로 친다(다른 문자열이어도). 모양이 틀린 ref(`<dirspec>/<slot>` 이 아님)는 순회 없이 `bad_ref`. 나머지 ref 의 dirspec 들을 targets 로 확인 순회(`reachable_dirspecs` — 루트에서 검증한 디렉터리만 따라가고 요청한 dirspec 을 모두 찾으면 바로 멈춘다)를 한 번 돌린다. dirspec 은 검증된 디렉터리의 검증된 디렉터리 항목이 가리키면 '찾음'이다(그 디렉터리를 아직 읽지 않았어도 — ref 는 `entry()` 가 디렉터리를 다시 읽으며 단위마다 다시 검증한다). 순회가 끝까지 돌았는데(`complete`) 없으면 그 ref 는 `bad_ref`(지어낸 dirspec 으로 아무 클러스터나 디렉터리로 읽게 하지 않는다), 한도·예산에서 잘렸거나 끝까지 읽지 못한 살아 있는 디렉터리가 있어(`truncated`) 찾지 못했으면 그 ref 만 `refs_unverifiable` 이다(찾은 dirspec 의 ref 는 검증된 것이라 받는다) — 순회가 잘렸는데 검증된 ref 가 하나도 없고 `paths` 도 없을 때만 job 이 `validation_failed`(`refs_unverifiable`, `data.truncated_reason`)로 실패한다(출력·보관 기록 없음). ref 가 모두 `bad_ref` 이고 `paths` 가 없으면 실패하지 않고 파일 0개 매니페스트와 보관 기록 `extract` 를 남긴다(`bad_ref` 는 잘림 사유가 아니라 `truncated=false`). `entry()` 의 코드: 잘린 디렉터리의 뒤쪽이면 `max_dir_slots`·`beyond_image`·`dir_chain_broken`, ref 의 디렉터리를 읽지 못하면 `dir_unreadable`(엔진은 `bad_ref` + `data.dir_cut`), 검증되지 않은 영역·빈 슬롯이면 `bad_ref`, 예산이면 `time`·`steps`·`cancelled`. **paths**: 위 '경로 찾기' — 코드는 `not_found`(삭제 파일은 refs 로), `ambiguous_path`, `max_depth`, `max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unvalidated`(그런 디렉터리에서 찾지 못함 — `not_found` 가 아니다. 그런 디렉터리는 정확히 같은 이름만 받으므로 대소문자·8.3 별칭으로만 맞아도 이 코드다), `time`·`steps`·`cancelled`, 경로의 디렉터리를 읽지 못하면 `dir_unreadable`. `files[].path`·매니페스트 `path` 는 디스크의 이름(`display_path`)이고 호출자 철자가 다르면 `requested_path` 에 남긴다(ref 항목은 확인 순회의 디렉터리 경로 + '/' + 표시 이름). 남은 job 시간이 1초 미만이면 더 찾지 않는다(`time`). 찾지 못한 항목은 `skipped` 의 `{ref 또는 path, code, reason}`(이미지에서 읽은 이름은 싣지 않는다)이고, 디렉터리 항목은 `{ref, path, reason}`(디렉터리 사유)로 건너뛴다. **method**: `auto`(가장 믿을 만한 후보 — 예산 때문에 클러스터를 하나도 모으지 못한 후보는 건너뛴다) 또는 후보 이름(그 후보와 그것이 기대는 것만 만든다) — 살아 있는 파일 `chain`·`nofatchain`, 삭제한 FAT 파일 `contiguous`·`skip-allocated`·`skip-claimed`·`fat-chain`, 삭제한 exFAT 파일 `stale-chain`·`contiguous`·`skip-allocated`. 그 항목에 없는 방법(`data.available`), 해석 오류, 예산으로 후보를 만들지 못함(`time`·`steps` 를 잘림 사유에 더한다)은 그 항목만 `{ref, path, reason}` 으로 건너뛴다. 후보는 ref 마다 한 번만 만든다. `region`: `data` / `residual`(exFAT ValidDataLength 뒤 잔여 — 출력 이름에 `.residual`, FAT 항목은 건너뜀). 파일은 `NNNN-<정리한 이름>`(`O_EXCL`, 조각으로 쓰며 sha256, 끝나면 fd 로 0444 — 실행 비트·링크 없음). **상한**: `max_files`, `max_bytes`(남은 바이트까지 쓰고, 상한이 계획을 실제로 잘랐을 때만 `max_bytes`), job 300초(1초 미만이 남으면 더 쓰지 않는다 — `time`). 예산 때문에 덜 만든 계획(status `limit` + `limit_reason` `time`/`steps`)은 있는 만큼 쓰고 그 사유를 더한다. 내용이 읽을 수 있는 범위(파티션 표 항목과 이미지 끝 중 짧은 쪽) 끝 너머라 덜 읽은 파일은 상한이 아니다 — 파일 기록의 `complete=false`·`bytes_beyond_image`. 매니페스트(`pweh.forensics.recovered/v1`): `evidence_id`, `evidence_sha256`(보관 기록 `intake` 의 값), `partition`, `fs`, `generated_at`, `params{method, region, max_files, max_bytes}`, `files[{seq, file, ref, path, deleted, region, method, confidence(high/medium/low/none), status, note, expected_size, size, complete, sha256, runs_total, conflicts, limit_reason?, bytes_beyond_image?, requested_path?}]`, `skipped`(전체), `bytes_total`, `truncated`, `truncated_reasons`(정렬 — `max_files`·`max_bytes`·`time`·`steps`·`cancelled`, 찾지 못한 항목의 코드 중 `refs_unverifiable`·`max_depth`·`max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unreadable`·`dir_unvalidated`). **커밋과 실패**: 보관 기록 `extract` 를 덧붙이기 전의 실패는 출력 디렉터리를 지운다(기록 없는 부분 출력을 남기지 않는다 — 새 출력 디렉터리에 서버가 만들지 않은 항목이 생기면 `path_outside_base`). 덧붙인 뒤에는 무슨 일이 있어도 지우지 않는다(그 뒤의 오류로 job 이 `failed` 여도 출력과 기록은 남는다 — 증거 목록 `derived` 의 `recorded`). 취소는 위 'job 과 취소'. 결과: `output_dir`, `manifest`, `manifest_sha256`, `custody_seq`, `bytes_total`, `truncated`, `truncated_reasons`, `files[{seq, file, path, deleted, method, confidence, status, size, complete, sha256, limit_reason?, requested_path?}]`(`bytes_beyond_image` 는 매니페스트에만 있다 — 응답에는 `complete=false` 만), `skipped`(50개까지), `skipped_total`, `note`, 사유나 `ambiguous_path` 가 있으면 `next_steps`. 내용은 돌려주지 않는다. 정지 그림은 원본 EV의 선택자로 `forensics_image_hints`를 호출하고 추출물을 직접 열지 않는다 |
| `forensics_image_hints(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", ocr=True, ocr_lang="kor+eng", qr=True, preview=True, crop=None, max_seconds=45.0)` | 정지 그림 하나의 힌트 분석. `ref`/`path` 중 하나만 선택하고 둘 다 없으면 EV 자체를 해독한다. `open_checked`로 접수 기록·지문을 대조한 같은 fd에서 선택 파일 바이트를 얻고, 불완전한 복구 후보는 해독하지 않는다. 일반 이미지 분석과 같은 worker·옵션을 쓰며 `report.source`에 EV 접수/선택 바이트 SHA256·선택자·복원 method/confidence를 기록한다. 결과 JSON과 PNG는 `forensics/analysis/image-hints-<EV>-NNN.*`에 0444로 저장하고 custody `image-hints`로 각각의 해시를 결속한다. 사건 전 실패는 이번 출력만 정리하고 커밋 뒤에는 보존한다. 응답은 `report`, `analysis{path,sha256,size,custody_seq,custody_hash}`, 실제 ImageContent. `max_seconds`는 파일 찾기·해독에 공유하는 최대45초다. 미지원·한도·OCR 도구 누락은 검사 상태/사유에 남긴다 |
| `forensics_scan_secrets(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", xor_key=None, max_hits=200, max_seconds=45.0)` | 선택 텍스트 하나의 비밀값 후보를 원문 없이 검사한다. EV 자체 또는 FAT/exFAT·TAR/ZIP의 `ref`/`path` 하나, 완전 읽기 4 MiB·UTF-8(BOM 허용). `xor_key`는 생략 또는 정수144만, `max_hits` 1~200, 시간은 유한한 0 초과/45초 이하. 응답은 `report`(상태·출처 지문·규칙·후보·검사/미검사 범위)와 `analysis{path,sha256,size,custody_seq,custody_hash}`. 0444 JSON과 `secrets-scan` 보관 기록을 남긴다. 상세 한계는 아래 선택 텍스트 비밀값 검사 계약 |
| `forensics_sd_ioc_scan(case_id, evidence_id, firmware_result_path, fs_list_path, partition=None, max_matches=200, max_seconds=45.0)` | 같은 케이스의 등록된 `analysis/sd-surface-NNN.json`과 같은 EV의 보관 기록으로 검증한 `forensics/analysis/fs-list-EV-NNNN-NNN.json` 전체 보고서를 대조한다. FAT/exFAT 메타데이터만, TAR/ZIP 제외. `partition` 생략 시 지원 볼륨이 하나여야 한다. 정확 이름·ASCII 변형·삭제·불확실 후보와 입력/검사 한도를 구분한다. 원시 카드 경로·내용·펌웨어 발췌는 반환하지 않고 ref·펌웨어 배열 index로 연결한다. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `sd-ioc-scan` 보관 기록. 이름 일치는 실행·침해 증명이 아니다 |
| `forensics_media_inventory(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", max_seconds=45)` | EV 자체 또는 FAT/exFAT·TAR/ZIP에서 선택한 파일 하나를 최대64 MiB까지 완전히 읽어 ISO-BMFF 상자 경계와 허용 계층의 mvhd/mdhd timing prefix·pssh 구조를 제한 관찰한다. ref/path는 배타적이고 직접 EV는 partition 없이 method=auto만 받는다. 고정 box/brand 분류·위치/길이·검사/opaque/미검사 범위·출처 불확실성과 `declarations`의 필드/순회 완료도를 반환한다. 절대 시각·SystemID/KID/data는 비노출이며 프레임·음성·촬영 시각·codec·암호화 판정 없음. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `media-inventory` 보관 기록. 상세 계약은 아래 선택 미디어 구조 절 |
| `forensics_media_candidates(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", max_seconds=45, offset=None, length=None)` | 완전한 선택 파일 하나 또는 명시 EV 구간(각 최대64 MiB)에서 고정 known brand를 가진 ftyp와 연속 최상위 상자 prefix 후보를 찾는다. 선택 기준 offset·검증한 길이·검색/검사/관계 완료도·반환 후보 간 겹침만 보고한다. 원본 경계·녹화 복구·재생 검증 없음. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `media-candidates` 보관 기록. 상세 계약은 아래 선택 미디어 후보 절 |
| `forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)` | job. 같은 EV의 저장된 `media-candidates` 보고서에서 후보 번호 하나의 검증된 prefix를 추출한다. 원래 선택 파일 또는 EV 구간 전체의 해시·출처를 다시 대조. 출력은 고정 이름 바이너리와 매니페스트, 기존 `extract` 보관 기록. 입력64 MiB·보고서1 MiB·매니페스트64 KiB·공통45초. 내용 반환·녹화 복구/재생 판정 없음 |
| `forensics_evidence_list(case_id, write_files=True)` | 케이스의 모든 EV 를 보관 기록과 EV 디렉터리로 정리한다(위 '증거 상태'). 먼저 커밋한 증거마다(이미 무결성 실패인 것 빼고) 내용 도구 입구로 접수 기록·사본 지문을 다시 대조해 새 문제는 `integrity-failed`(`found_by: "evidence-list"`)로 남긴다(`integrity_failures_recorded[{evidence_id, reason}]`). → `custody{ok, count, head, detail}`(체인·고정점 대조), `items[{evidence_id, label, stored_path, size, hashes, intake_ts, imaging_log(대조 결과 {status, details} 또는 null), intake, status, status_label, last_verify{ts, result, seq, kind(intake-copy/full-rehash)}, integrity_failures[{seq, ts, reason}], attestation{status, attestation_id, ts, decided_at, expires_at}, extracts, events, problems?}]`(커밋하지 못한 디렉터리는 `{evidence_id, status, status_label, intake: false}`, 보관 기록이 깨지면 `{evidence_id, status: "custody-broken", status_label}`), `aborted[{evidence_id, ts, seq, quarantine_path, reason}]`(`intake-aborted` 사건 — 증거가 아니다), `derived[{path, evidence_id, files, bytes, manifest_sha256, custody, custody_seq, error?}]`(`forensics/recovered/*/manifest.json` 을 링크를 따르지 않고 64 MiB 까지 읽어 보관 기록 `extract` 사건과 대조한 `custody`: `recorded`(manifest sha256 이 같음) / `mismatch`(매니페스트가 바뀜) / `unrecorded`(사건 없음 — 서버가 만들지 않은 것) / `missing`(사건은 있는데 디렉터리·매니페스트가 없음) / `unknown`(보관 기록이 깨짐). 정지 그림의 `image-hints` 사건은 `forensics/analysis/`의 JSON과 실제 PNG 해시도 검증한다. 해당 derived 항목은 `kind: image-hints`이며 추출 파일 합계와 구분한다), `notice`(고지), 증거가 없으면 `hint`. `write_files=true` 이고 `forensics/` 가 있으면 `forensics/evidence-list.json`(`pweh.evidence-list/v1` — `custody`·`items`·`aborted`·`derived`·`notice`)·`evidence-list.md`(증거 표 — 상태 칸은 `status_label`, 중단된 접수, 파생 산출물, 해시값 확인서 — 해시가 있는 상태의 증거마다 SHA-256·MD5·SHA-1(`ok` 가 아니면 `(상태: <status_label>)`), 확인 일시와 소유자(또는 제출인)·입회인·분석자 성명·서명란, 고지)를 다시 쓰고 `files{json, markdown, json_sha256}` 를 붙인다(`forensics/` 가 링크 등이면 쓰지 않고 `files_error`). 보관 기록이 정상일 때만 `evidence-list` 사건으로 JSON sha256 을 남긴다 |
| `forensics_job_status(job_id, wait_seconds=0, case_id=None)`, `forensics_job_cancel(job_id)`, `forensics_jobs(active_only=False, case_id=None)` | `register_job_tools(..., "forensics")` — 접수·검증·추출 job. 기본은 이 서버 프로세스의 것만, `case_id`를 주면 같은 서버의 저장 기록도 확인한다(위 공통 계약). `wait_seconds` 최대 50초. 취소와 늦은 취소는 위 'job 과 취소' — 커밋한 job 에 대한 `forensics_job_cancel` 은 상태를 바꾸지 않는다. 공통 도구 설명의 '부분 결과는 보존된다'는 추출에만 맞다(커밋 전 접수는 되돌리고 재해시 도중의 검증은 아무것도 기록하지 않는다 — docs/safety.md §3.6) |

- **오류 코드**: `authorization_required`(케이스 소유/허가 없음), `validation_failed`(인자·입력 파일, 이미지 해석 실패 — 해석 실패의 사유는 `data.reason`: `unsupported_fs`, `not_found`(파티션), `bad_argument`(파티션 여럿·그 항목에 없는 방법), `bad_ref`, `budget_exceeded`(`data.limit` = `time`/`steps`/`cancelled`), `ambiguous_path`(`data.component`·`data.candidates`), `max_depth`, `max_dir_slots`, `beyond_image`, `dir_chain_broken`, `dir_unreadable`, `dir_unvalidated`, `refs_unverifiable`(`data.truncated_reason`), `internal_error`, `malformed` … — 추출에서는 job 실패가 아니라 대개 `skipped[].code` 로 남는다),
  `not_found`(없는 케이스·증거·job), `integrity_failed`(`data.reason`·`data.problems` — 위 입구의 사유, 복사 중 원본이 바뀜, 같은 번호의 두 번째 접수), `custody_broken`(보관 기록·고정점이 깨졌거나 `forensics/` 가 링크), `path_outside_base`(서버가 쓰려는 `forensics/` 아래 구성요소 — `images/`·`aborted-intakes/`·`analysis/`·`recovered/` — 가 링크·파일이거나 새 출력 디렉터리에 서버가 만들지 않은 항목이 생김. 내용 도구가 여는 EV 디렉터리가 그러면 `integrity_failed`(`unsafe-path`)),
  `busy`(같은 원본의 접수·같은 증거의 검증·추출이 이미 실행 중), `lock_timeout`(잠금을 30초 안에 못 얻음),
  `unsafe_file`(번호 확보 잠금 `.claim.lock` 자리에 일반 파일이 아닌 것이 있음, 보관 기록 잠금 `.custody.lock` 자리에 일반 파일이 아닌 것이 있을 때의 덧붙이기(사건을 남기지 않는다 — 대개 읽은 뒤 덧붙이기 전에 바뀐 경우), 접수 중 사본이 확인한 뒤 바뀜 — 접수는 되돌린다. 그런 `.custody.lock` 을 읽기가 만나면 `custody_broken`). job 의 실패는 `forensics_job_status` 의 `error` 에 있다. `forensics_acquisition_attest` 는 증명이 없으면 오류 대신 `status: attestation_required|denied` 를 돌려준다.
- **시각**: 목록의 시각은 원래 값과 `time_basis` 다. FAT 은 `local-unknown-tz`(장치 현지 시각, 시간대 모름), exFAT 은 UtcOffset 이 유효하면 `local+offset`(+ UTC 값), 아니면 `local-unknown-tz`.
  장치 시간대는 가정하지 않는다 — 근거(마운트 옵션·init 스크립트의 TZ·사람이 잰 장치 시계 차이)가 있을 때만 요약의 `device_timezone` 에 가정으로 적는다.
- **보고서**: `report_generate` 는 `forensics/` 가 있으면 §8.1 'SD 카드 증거'(보관 기록 상태 — 고정점과 대조, 증거 표 — 상태(`status_label`)·마지막 검증·쓰기 방지 장치 증명, 고지)를 넣는다. 녹화 내용과 파일 목록은 넣지 않는다.
- **아직 없는 것**(설계 §4·§5.2 의 다음 단계): 프레임·파일 카빙(DHAV·XM·MPEG-PS·MP4·JPEG), CCTV 녹화 인덱스·이름 규칙에 따른 녹화 타임라인, 카드 전체 비밀값 자동 탐색·녹화 암호화 판정·카드 내용의 침해 판정,
  ext4·NTFS, E01 입력, 외부 도구(TSK·PhotoRec·ewf-tools·ffprobe) 교차 확인. 파일·앱 기록 타임라인과 외부 읽기 전용 폴더 제자리 참조는 아래 Android 논리 분석 계약에 있다. 카드의 삭제 파일 복구는 디렉터리 항목이 남은 파일만 다룬다.

#### 선택 미디어 구조 관찰 계약

`forensics_media_inventory`는 검증된 EV 자체 또는 FAT/exFAT·TAR/ZIP에서 선택한 **파일 하나의 완전한 바이트**만 읽는다. 직접 EV는 `partition` 없이 `method="auto"`, 멤버는 `ref`와 `path` 중 하나를 지정한다. 최대64 MiB를 넘거나 복구 계획/ZIP CRC/실제 읽기가 불완전하면 오류이며 앞부분만 성공 처리하지 않는다. 이 상한은 선택 파일 크기이며 프로세스 전체 RSS 제한은 아니다. 빈 선택 파일은 구조 미지원 결과로 남긴다. 기존 소비자의 빈 파일 선택 기본 동작은 유지한다.

- `pweh.media-inventory/v1` 보고서는 고정 box/brand 분류, 선택 파일 기준 상자의 위치·전체 길이·헤더 길이·부모/깊이, 범위별 처리 상태와 새 프로필의 제한된 선언 관찰을 담는다. 원시 FourCC·UUID·minor version·파일명·경로·자유 메타데이터를 반환하지 않는다. 허용 brand 선언은 파일의 진위·적합성·영상 종류를 증명하지 않는다. 알려지지 않은 값은 고정 unknown 분류와 개수만 남긴다.
- 기본32비트/확장64비트 크기, UUID 헤더24/32바이트, 부모/파일 경계와 전진을 검사한다. size0은 완전한 선택 파일의 최상위에서만 EOF까지로 해석한다. 허용한 부모-자식 조합에만 재귀하고 mdat·uuid·unknown·meta·udta payload는 길이로 건너뛴다. styp도 경계만 관찰한다. payload 속 magic을 재검색하거나 외부 참조를 따라가지 않는다.
- 상자는 최대4096개, 깊이8, brand slot은 ftyp당64/호출256, 범위8193개, 최종 JSON1 MiB다. 완전한 바이트를 받은 뒤 시간·개수·깊이·출력 상한 또는 첫 구조 실패에 닿으면 검사한 prefix와 미검사 tail을 기록한다. 구조·opaque·미검사 범위가 선택 파일 전체를 겹침/누락 없이 나누며 부모 길이를 다시 합산하지 않는다. 큰 파일의 앞부분만 읽은 것과 다르다.
- `framing_status`는 지원 구조 순회의 완료도이며 `recognition`은 허용 brand/fragment 후보/미확인 선언 관찰이다. moov가 없는 fragment나 ftyp 없는 형태를 그 이유만으로 손상이라 하지 않는다. unknown brand·빈 입력·미지원 프로필은 지원하지 않는 범위로 남긴다. `media_decoded`, `playback_verified`, `recording_time_verified`, `encryption_assessed`, `format_conformance_assessed`는 항상 false다. 이 기능은 카빙·녹화 복구·재생 검증·샘플/codec/절대 시각/암호화 판정을 제공하지 않는다.
- 새 결과의 `profile="mp4-quicktime-declarations-v1"`는 `declarations`가 필수다. 기존 `mp4-quicktime-box-v1` 저장물은 선언 section 없는 별도 닫힌 스키마 분기로 계속 검증하며 재작성하지 않는다. old/new의 필드·어휘·limitations를 혼합한 결과는 거부한다.
- 선언 관찰은 최상위 `moov/mvhd`, `moov/trak/mdia/mdhd`의 version0/1 timing prefix와 `moov`/`moof` 직계 `pssh`만 지원한다. 시간 단위·길이는 정수 선언이며 float 재생 길이·합계·대표 track을 만들지 않는다. 생성/수정 시각은 zero/nonzero/unread만 남기고 절대값·UTC를 반환하지 않는다. PSSH는 index/version/status/issues만 기록하며 SystemID/KID/data·count 원문과 그 해시를 반환하지 않는다.
- `declarations.coverage`는 순회/필드 완료도를 구분한다. 선언이 잘리거나 미지원이면 해당 row와 고정 issue를 남기고 다음 상자를 계속 본다. 상자 경계가 완전해도 선언은 partial일 수 있다. 시간·출력·범위 한도는 현재 box·row·ranges를 원자적으로 보류하며 기존 미검사 tail을 유지한다. 실제 읽은 고정 필드만 header, 건너뛴 식별자·payload는 skipped다. 선언0건은 보호 신호 없음이나 평문 판정이 아니다. 상세 필드·고정 근거는 [BMFF 선언 계약](references/media-declarations.md)에 있다.
- `source`는 EV 입수 해시와 선택 bytes 해시/크기·검증된 ref/partition·복구 방법/신뢰도·삭제 여부를 구분한다. 삭제된 부모의 자식도 불확실한 선택으로 표시하며 확인하지 못한 부모 상태는 null이다. 복구 불확실성이 있으면 구조 순회가 끝나도 overall partial이다. FS 선택 순회의 조기 종료를 전체 목록 완료로 해석하지 않고 `container_examined=false`를 유지한다. 아카이브 목록의 알려진 잘림도 보존한다.
- 선택·읽기·구조 검사에 하나의 deadline/취소를 공유한다(`max_seconds` 유한한0초 초과/45초 이하, bool 거부). 읽기 시간 초과는 오류, bytes를 받은 뒤 parser 시간 초과는 partial 저장이 가능하다. 커널 대기까지 강제 중단한다는 보장은 없다. worker가 EV fd를 끝까지 소유하며 커밋 전 취소는 결과 없이, 커밋 후 늦은 취소/보조 오류는 기록을 보존한다.
- `forensics/analysis/media-inventory-<EV>-NNN.json`을0444로 저장하고 공통 EV/출력 seal 재검증 후 `media-inventory` 사건에 해시를 결속한다. 증거 목록의 파생 산출물 대조로 확인한다. SD 요약의 `media_inventory_results`에는 EV·결과 위치/해시·상태·선택 크기·보고한 상자 수만 남긴다. 오류·감사·결과에 입력 원문을 복사하지 않으며 SDK 인자 검증도 이 도구에 한해 입력값 표시를 끈다.

구조 범위의 공개 근거는 [Apple QTFF Atoms](https://developer.apple.com/documentation/quicktime-file-format/atoms)와 [W3C ISO BMFF byte stream §3–4](https://www.w3.org/TR/2024/NOTE-mse-byte-stream-format-isobmff-20240723/)다. 이 제한된 구현은 그 문서의 모든 형식·적합성 조건을 검사하지 않는다.

#### 선택 미디어 후보 계약

`forensics_media_candidates`는 완전한 선택 파일 또는 명시 EV 구간(최대64 MiB)에 같은 출처 검증 입구를 적용한다. 기본 파일 선택은 `ref/path` 배타, 직접 EV는 둘 다 생략하고 `partition=None`, `method="auto"`다. `offset/length`를 함께 지정하면 EV 파일 자체의 구간을 읽으며 `ref/path/partition` 혼용·다른 method를 거부한다. 두 값은 exact int, offset≥0·length1..64MiB·끝≤EV 크기·signed64 범위다. 인자를 생략한 큰 EV를 자동으로 자르지 않는다.

`pweh.media-candidates/v1`의 기본 profile은 `ftyp-contiguous-top-level-v1`, 구간 profile은 `ftyp-contiguous-ev-range-v1`이다. 기본 source16/params3필드는 유지하고 구간 source는 `evidence_size/offset`을 더한18필드, params는 `offset/length`를 더한5필드다. 구간 `method="byte-range"`, `selected_size=length`, `selected_sha256`은 실제 구간 전체 SHA다. `complete/high`는 바이트 선택 신원이며 전체 파일·카드·녹화 완료가 아니다. old/new 혼합 보고서는 거부한다. 후보 위치는 선택 bytes 기준이며 구간에서만 `source.offset+candidate.offset`이 EV 내 위치다. 자세한 입력·한계는 [명시 구간 계약](references/media-evidence-range.md)을 따른다.

- 64 KiB 이하 검색 창에서 `ftyp`를 찾고 32/64-bit 선언 크기·선택 범위·brand slot 정렬과 고정 known brand를 검사한다. 뒤따르는 `moov/mdat/moof/styp/free/skip/wide/uuid`의 최상위 경계만 확인한다. payload는 해석하지 않으며 `ftyp` 없는 fragment는 이 프로필의 후보가 아니다. 원시 FourCC·brand·UUID·내용·파일명·경로·후보 payload hash를 결과에 넣지 않는다.
- size0은 원본 EOF를 알 수 없어 그 앞에서 멈춘다. `selection_end`·`next_ftyp`는 제한된 prefix의 종료 관찰이며 원본 파일 끝이나 녹화 완료를 뜻하지 않는다. payload 내부의 별도 ftyp도 후보가 될 수 있어 오탐 가능성이 있다. `confidence="possible"`, `complete_recording=false`이며 원본 경계·물리 카빙·재생·시각·암호화·형식 적합성 검증 값은 모두 false다.
- `coverage.search_positions_total=max(0,input_bytes-7)`은 헤더 시작 가능 위치의 수다. `search_positions_examined`는 anchor 처리까지 마친 연속 prefix 길이이며, 단순히 읽은 바이트 수가 아니다. 예산으로 처리하지 못한 현재 anchor는 `pending_anchor_offset`과 미검사 suffix에 남긴다. 부분 후보가 그 위치에 보존돼도 그 위치를 검사 완료로 세지 않는다.
- 후보는 최대128개, anchor probe1024, header 후보당1024/전체8192, brand slot anchor당64/전체4096, 구조 판독 합1 MiB, 최종 JSON1 MiB, 선택·읽기·검사 공통 시간 최대45초다. malformed/unknown-brand anchor 기각은 미검사와 구분한다. 시간·개수·출력 상한으로 중단하면 완료 여부와 사유를 그대로 남긴다. 입력 상한은 전체 RSS나 커널 대기 강제 종료의 보장이 아니다.
- `overlap_with_reported`·`contained_by_reported`는 반환한 후보들의 검증 prefix 구간만 비교한다. 원본 녹화 소속·서로 다른 파일임을 판단하지 않는다. 관계 계산 중 한도에 닿으면 검색 완료 값은 유지하고 `relations_complete=false`로 남긴다. 이때 빈 관계 배열을 겹침 없음으로 해석하지 않는다. `candidate_list_complete`는 후보 목록의 보관 완료이며 관계 완료와 다르다.
- `status`는 `ok/partial/unsupported`다. 검색·검사·목록·관계 중 미완료 또는 부분 framing은 partial, 제한된 검사를 마쳤지만 지원 anchor가 없으면 unsupported다. 둘 다 미디어 부재나 안전의 증거가 아니다. 삭제·복구·부모 상태 불확실성 또는 알려진 컨테이너 목록 잘림은 후보0건/unsupported여도 overall partial로 보정하며 코어의 검사 통계는 보존한다.
- worker는 동일 EV fd를 읽기부터 저장까지 소유한다. 완전한 bytes 확보 뒤 코어 시간 한도의 partial은 저장할 수 있고, 커밋 전 취소는 결과 없이 끝낸다. `forensics/analysis/media-candidates-<EV>-NNN.json`을0444로 쓰고 EV/출력 seal을 재검증한 뒤 `media-candidates` 사건에 결속한다. 커밋 뒤 취소·보조 오류는 기록을 보존한다. 오류·감사·SDK 인자 오류에 선택 원문을 복사하지 않는다.
- SD 요약 `media_candidate_results[]`에는 EV·결과 위치/해시·상태·선택 크기·저장 후보 수만 기록한다. 증거 목록의 derived에서 결과의 보관 기록과 해시를 대조한다. 실제 파일 추출·물리 카빙·녹화 인덱스/타임라인·벤더 표본 검증은 이 기능에 포함되지 않는다.

#### 저장된 미디어 후보 추출 계약

`forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)`는 같은 EV의 검증된 `media-candidates` 보고서에 저장된 후보 하나만 추출하는 job이다. 원래 선택 파일 또는 EV 구간 전체를 다시 읽어 해시·크기·출처를 대조하고, 저장된 논리 위치와 검증된 prefix 길이만 사용한다. 새로운 offset/length나 복구 방법 인자는 없다.

출력은 `forensics/recovered/media-prefix-NNN/candidate-000.bin`과 `manifest.json`이다. 스키마는 `pweh.media-prefix-extract/v1`, 보관 기록은 기존 `extract` 사건의 `method="media_candidate_prefix"`다. 보고서1 MiB·선택 파일/구간64 MiB·매니페스트64 KiB·출력1개·worker 공통45초 마감이다. 같은 custody 잠금에서 EV·보고서·원래 사건·출력 fd/경로/해시를 다시 확인한 뒤 커밋한다. prefix 일부만 쓴 결과는 성공으로 남기지 않는다.

원래 source/status/coverage를 보존하고 새 불확실성을 합친다. `files[0].complete=true`는 prefix 작성 완료이며 녹화 전체 복구가 아니다. 요약은 기존 `recovered`와 `notes`를 사용한다. `derived.recorded`는 매니페스트와 보관 기록의 결속을 뜻하고 추출 바이너리를 목록마다 전체 재해시한다는 뜻은 아니다. 상세 출처·정리·취소·한계 계약은 [미디어 후보 추출](references/media-prefix-extract.md)을 따른다.

#### 펌웨어·카드 보고서 이름 대조 계약

`forensics_sd_ioc_scan`은 기존 `fw_sd_surface` 전체 JSON과 같은 EV의 FAT/exFAT 전체 목록 JSON만 비교한다. 목록 응답의 표본이나 임의 JSON은 받지 않는다. 생성 상대 경로만 허용하며 링크·하드 링크·FIFO·부모 교체를 거부한다. 카드 내용 추출·펌웨어 가져오기·Android 증거 연결은 수행하지 않는다. EV의 기존 무결성 입구는 그대로 적용한다.

- 목록은 같은 EV의 `list` 보관 기록의 경로·전체 해시 및 intake와 대조한다. JSON 자체에 없는 EV 해시를 있다고 가정하지 않는다. 펌웨어는 같은 케이스의 `triage-report`/`fwtriage-mcp` 아티팩트 ID·크기·해시와 JSON schema/tool/case를 대조한다. 일반 아티팩트 색인은 보호된 생성 출처 증명이 아니며 `origin_basis=case-artifact-index`다. 두 입력을 같은 케이스에서 골랐다는 사실은 동일 장치·버전을 증명하지 않는다(`device_association_verified=false`).
- 보고서는 각각16 MiB, 합32 MiB까지만 끝까지 읽는다. JSON 파싱 전 UTF-8 바이트를 훑어 깊이32·노드100000(키 포함)·컨테이너20000·구조 토큰200000·문자열 하나256 KiB/합8 MiB·숫자128바이트를 제한한다. 중복 키·비유한 수·잘못된 UTF-8을 거부하고 순서대로 파싱·축약한다. 목록 도구의200000항목 전체가 이 상한에 들어온다는 뜻은 아니다. 큰 목록은 일부만 성공으로 읽지 않고 오류이며 기존 목록 도구에서 partition/max_entries 범위를 좁혀야 한다.
- 비교 상한은 펌웨어 참조5000·목록 항목200000·경로 하나32768자/합8 MiB·후보200개·결과2 MiB다. `max_matches`는1~200, `max_seconds`는 유한한0초 초과/45초 이하이고 bool은 숫자로 받지 않는다. 하나의 deadline과 취소를 공유하지만 JSON 파싱·커널 대기까지 강제 종료하는 절대 시간/RSS 보장은 아니다.
- 경로의 mount 경계와 `card_relative`를 검증하고 전체 문자 경로로 비교한다. basename·변수·glob·셸 확장·URL 해독·Unicode 정규화·8.3 부모 별칭을 추측하지 않는다. ASCII 대소문자 변형은 후보이며 원래 FAT/OEM·exFAT up-case 표의 lookup 확인이 아니다. 디렉터리는 파일 후보에서 제외한다. 중복은 모호성으로, 삭제된 부모의 자식은 삭제 후보로, 손상·유실 이름은 불확실성으로 남긴다.
- `report.status`의 `ok/partial/unsupported`는 작업 범위의 완료도다. `exact_live_name`, `case_variant_candidate`, `deleted_name_candidate`, `uncertain_name`도 이름 관찰이다. 파일 chain 읽기 가능성·내용·실행·악성 여부를 확인하지 않는다. 0건은 `no_name_match_in_examined_scope`이며 카드 전체의 파일 부재나 안전을 뜻하지 않는다. 원본의 잘림/unknown 및 미지원 이름 비교·삭제 범위 한계를 coverage에 남긴다. 자동 finding이나 severity를 만들지 않는다.
- 원시 이름·경로·발췌·시각을 새 결과에 복사하지 않는다. 생성 보고서 경로/해시·목록 사건 seq/hash·아티팩트 ID·partition/ref·펌웨어 배열 index·고정 코드만 남긴다. 두 입력 fd와 부모 신원을 유지하고 결과 커밋 전 다시 검사한다. 같은 custody 잠금 안에서 초기 `list` 사건도 다시 대조한다. 입력/출력 검증 실패·커밋 전 취소는 새 분석을 남기지 않고, 커밋 뒤 감사/색인 실패·늦은 취소는 기록된 결과를 보존한다.
- `pweh.sd-ioc-scan/v1` 결과를 `sd-ioc-scan` 사건으로 결속해 증거 목록의 파생 산출물 검사에서 확인한다. SD 요약의 선택 필드 `ioc_scan_results`에는 결과 위치·해시·상태·저장 후보 수·선택 partition·두 입력 보고서 위치만 기록한다. 상세 검사 범위와 한계는 그 보고서를 참조한다.

#### 선택 텍스트 비밀값 검사 계약

`forensics_scan_secrets`는 선택 파일 한 개에만 적용한다. `ref`와 `path`는 배타적이며 둘 다 없으면 EV 자체다(`partition` 없이 `method="auto"`). 선택자는 비어 있지 않은 NUL 없는 문자열이고 최대 32,768자다. FAT/exFAT 삭제 파일은 완전한 복구 후보만 읽고 방법·신뢰도를 보존한다. TAR/ZIP는 검증한 멤버를 CRC·압축/크기 한도 안에서 끝까지 읽는다. 초과·짧은 읽기·불완전 후보는 오류이며 앞부분만 읽어 성공시키지 않는다.

- 입력은 최대4 MiB, UTF-8 strict(BOM 허용)만 받는다. 알려진 영상·음성 파일명은 거부하고 원시/XOR 보기의 미디어 매직·잘못된 인코딩·허용하지 않는 제어 문자는 `unsupported`로 검사0바이트를 기록한다. UTF-16·바이너리 strings·미디어 해독·자동 URL 방문은 없다. `xor_key=144`만 명시적으로 지원하고 다른 키·bool은 거부한다.
- 규칙은 공통 마스킹 코드의 자격증명·명시적 콘솔 키/토큰 패턴이다. fwtriage YAML 전체·여러 줄 PEM·비밀번호 해시 대입은 포함하지 않는다. 한 줄16 KiB·100,000줄·최대200후보·1024범위·JSON1 MiB 상한이다. 긴 줄은 통째로 건너뛰고 이후 짧은 줄을 검사할 수 있다.
- `report`는 `pweh.secrets-scan/v1`(`schemas/secrets-scan.schema.json`)이다. `matches`는 고정 규칙 ID·kind·줄/바이트 위치·길이·`<masked>`·`possible` 신뢰도만 포함한다. 경계가 완전하면 케이스 솔트 지문(`sha256:`+16 hex)을 넣고 열린 인용부호 등 불확실한 경계는 `value_complete=false`, `digest=null`이다. 이 지문은 기존 `SHA256(salt || value)` 형식이며 자격증명 유효성을 검증하지 않는다.
- 원문 줄·키 이름·계정·URL·원래 파일명·변환 평문은 결과에 없다. `source`는 EV 접수 해시·선택 내용 해시/크기·검증된 ref/partition·복구 방법/신뢰도로 결속한다. 선택 내용 해시는 XOR 전, 비밀값 지문은 XOR 보기의 값이다. 실제 검사/미검사 범위와 BOM·줄끝 framing을 따로 센다.
- `ok`도 고른 파일의 지원 패턴 검사만 뜻한다. 시간·줄·후보·범위 상한, 삭제 복구의 불확실성이나 불완전한 컨테이너 목록은 `partial`과 사유로 남긴다. 후보 수는 하한일 수 있고 후보0건은 비밀 없음·안전·암호화 판정이 아니다. `container_examined=false`는 전체 컨테이너를 검사하지 않았다는 뜻이다. `analysis_complete`는 선택 바이트의 패턴 검사 완료, `hits_are_lower_bound`는 그 검사에서 후보 누락 가능성을 뜻한다. 선택 복구나 컨테이너 목록만 불확실하면 두 값은 각각 true/false여도 전체 상태는 partial일 수 있다.
- 하나의 마감/취소 신호를 파일 선택·읽기·검사에 공유한다. 읽는 중 시간 초과는 오류, 완전 읽기 뒤 검사 시간 초과는 부분 결과다. 커밋 전 취소는 출력/사건 없이 끝나며 커밋 뒤 결과는 보존한다. OS 호출 자체를 강제 중단하지는 못한다.
- `forensics/analysis/secrets-scan-<EV>-NNN.json`을0444로 저장하고 입력 EV와 열린 출력 fd·이름·부모 디렉터리를 보관 기록 잠금 안에서 재검증한 뒤 `secrets-scan` 사건에 해시를 남긴다. 이름 교체를 감지한 실패는 자기 출력만 정리하며 바꿔치기한 파일을 지우지 않는다. 증거 목록 `derived`가 결과 해시와 기록을 대조한다. 같은 OS 계정의 최종 확인 이후 조작까지 막는 경계는 아니다.

#### Android 논리 분석 추가 계약

- `forensics_intake_start(storage="copy"|"reference")`: 기본 사본 동작은 위 표와 같다. reference는 `forensics.reference_roots`(기본[])의 일반 파일과 열린 fd의 실제 읽기 전용 마운트만 허용한다. 현재 허용 폴더·RO·지문을 매번 확인하며 외부 원본을 chmod·이동·삭제하지 않는다. 참조 EV가 포함된 `forensics_evidence_list`는 전체 재해시 job을 반환하므로 `forensics_job_status`로 완료를 확인한다. 미완료·정책상 읽기 불가를 무결성 확인 성공으로 보고하지 않는다.
- TAR/ZIP는 기존 `forensics_fs_list`·`forensics_extract`와 이미지 분석의 선택 입구를 사용한다. `arc:<ordinal>` ref로 중복 이름을 구분하고 모호한 path는 거부한다. 파일 크기·압축비·헤더·멤버 수·내용 해시 예산을 제한한다. 한도 밖 멤버 해시는 null/미검증이며 truncated_reasons에 남는다. 링크·경로 탈출·sparse 항목을 호스트 파일로 만들지 않는다.
- 혼합 디스크에서 해석하지 못한 파티션은 `call.partitions_unexamined`와 `unsupported_partitions`에 포함하여 fs_list·image_check의 truncated에 반영한다.

| 도구 | 계약 |
|---|---|
| `forensics_sqlite_inventory(case_id, evidence_id, partition=None, ref=None, path=None, wal_ref=None, wal_path=None, journal_ref=None, journal_path=None, method="auto", max_seconds=45.0)` | SQLite DB 하나의 header/schema/table 행 수·freelist·WAL/journal 정보. ref/path는 둘 중 하나이며 생략하면 EV 자체 DB다. 부속 파일은 같은 EV·파티션·디렉터리의 DB 이름+-wal/-journal을 명시한다. 각 입력64MiB, SQL 엔진·실행 없음, 사용자 row 내용 미반환. 완주하지 못한 table의 row_count=null/count_complete=false. 결과 `{ok,report,analysis,warnings}`와 `sqlite-inventory` custody 사건 |
| `forensics_android_artifacts(case_id, evidence_id, partition=None, ref=None, path=None, wal_ref=None, wal_path=None, journal_ref=None, journal_path=None, method="auto", families=None, include_deleted=True, max_records=500, max_seconds=45.0)` | 같은 무결성·선택 입구. families는 sms/calls/contacts/browser(생략하면 네 종류), 내용 반환. include_deleted는 WAL 과거·freelist 후보를 포함하며 삭제 확정 아님. max_records 1~10000, TEXT 누적8MiB/JSON16MiB, BLOB은 크기·해시만. `{ok,report,analysis,warnings}`와 `android-artifacts` custody 사건. 프로필 미지원·누락은 없다고 확정하지 않음 |
| `forensics_timeline(case_id, evidence_id, partition=None, analysis_paths=None, max_events=10000, max_seconds=45.0)` | FS/archive 시각 + 같은 EV의 기록된 앱 분석 JSON 사건(최대16파일·합16MiB). path·size·sha256·스키마를 검증하고 임의 JSON 경로는 따르지 않음. max_events 최대100000. raw/unit/epoch/time_basis 보존, 시간대 없는 시각은 undated_events. `{ok,report,analysis,warnings}`와 `timeline` custody 사건 |

세 도구는 선택·읽기부터 공통45초 예산·취소를 적용하고 페이지·셀·record·payload·schema·JSON도 제한한다. 분석 JSON0444에 입수 해시와 선택한 멤버 해시를 구분한다. custody.append 잠금 안에서 동일 fd·현재 접수 기록을 다시 확인하며, 커밋 전 실패는 새 출력만 정리하고 커밋 후 보조 기록 실패는 보존+warnings다. evidence-list의 `derived`는 새 세 사건의 JSON 실제 해시와 EV 출처를 대조한다. 앱 기록·URL·schema SQL은 실행 지시가 아니다.

관련 모듈: `pweh.archive`, `pweh.sqliteparse`, `pweh.sqlitewal`, `pweh.sqliterecovery`, `pweh.androidartifacts`, `pweh.timeline`, `forensics_mcp.android_tools`. 범위·공식 형식 근거·복구 한계는 [android-analysis.md](design/android-analysis.md)와 [safety.md](safety.md) §7.2. ext4/EROFS/F2FS 목록·E01·분할 결합·잠금/암호화 우회·실기기 획득은 지원하지 않는다.

### 6.9 pweh-emu (선택)

확보한 MCU 펌웨어를 PC 에서 실행하고 마스킹한 UART 콘솔을 읽는다. 백엔드는 `esp-qemu`(Espressif QEMU `esp_develop_9.2.2_20260417`: ESP32·ESP32-S3·ESP32-C3)와
`avr-simavr`(simavr `5b08da60497f7564f50941f74a549fe2851db030` + `native/emu/pweh_avr_run.c`)다. 실제 기기·포트를 열지 않는다. 도구는 여섯이며 job 도구가 없다.
설계 근거는 [design/emulation.md](design/emulation.md), 알려진 한계는 [safety.md](safety.md) §3.7, 운영은 `firmware-emulation` Skill 을 따른다.

| 도구(인자) | 의미·반환 |
|---|---|
| `emu_status()` | OBSERVE, 케이스 불필요. `backends[esp-qemu\|avr-simavr]`(실행 파일 위치·출처·버전·머신·보드·지원 여부), `isolation{netns, seccomp:false, core_pattern_piped}`, `limits`, `sessions{this_process}`, `hints`. 게스트는 실행하지 않고 버전·머신 조회만 한다. 버전 문자열이 고정 값과 다르면 시작을 거부하며 실행 파일·ROM sha256 차이는 경고만 한다 |
| `emu_start(case_id, firmware, backend="auto", chip=None, board=None, mcu=None, freq_hz=None, psram="auto", psram_mb=None, watchdog="disabled", on_reset="exit", timeout_s=600, idle_timeout_s=300, label=None, approval_id=None)` | MODIFY `emu.start`, 소유/허가 확인. 출처·이미지·백엔드 검사 → 고정 argv 분류 → 게이트 → 세션 시작. `session_id`, `state`, `backend`, `target`, `firmware{path,sha256,size,provenance_reason,verify,ledger_seq}`, `working_copy{sha256,size,padded_from,handoff:"memfd"}`, `limits`, `isolation`, `masking`, `cursor:0`, `dir`, `warnings`, `notes`, `next_steps`. ESP 는 `psram`·`image`·`efuse`·파티션/앱 요약, AVR 은 `avr` 요약도 반환한다. 빠르게 끝난 세션은 최종 상태·종료 이유를 반환한다. 첫 콘솔 출력은 `emu_read` 로 본다 |
| `emu_read(session_id, since_cursor=None, max_chars=8000, wait_seconds=0, until=None, until_ignore_case=False, tail=False, case_id=None)` | OBSERVE. 마스킹·제어 문자 이스케이프·반복 접기한 `text`, `cursor_start/end`, `more`, `pending_line`, `lines`, `collapsed`, `lost_bytes`, `raw_total`, `raw_dropped`, `matched`, `match`, `state`, `hints`, `source`. 끝났으면 `stopped_by`·`exit`. 메모리에 없는 끝난 세션은 `case_id` 를 주면 마스킹 기록을 읽는다 |
| `emu_write(session_id, data, encoding="text", approval_id=None)` | INTERACT `emu.write`, 세션의 케이스 소유/허가를 재확인하고 게이트·감사 기록을 거친다. UTF-8 text 또는 공백 허용 hex, 1–4096바이트, 줄 끝은 호출자가 넣는다. 비차단 쓰기 최대 2초. `bytes_written`, `bytes_requested`, `partial`, `cursor`, `state`. 감사·이벤트에는 바이트 수·인쇄 가능 여부와 `<given>` 만 남기며 입력 원문·다이제스트는 남기지 않는다 |
| `emu_stop(session_id, case_id=None)` | 정리 도구, 서버 게이트 없음. SIGTERM → 3초 → SIGKILL(프로세스 그룹), 감독 스레드 합류·기록 마감·아티팩트 등록. `state`, `stopped_by`, `exit{code,signal}`, `duration_s`, `raw_bytes`, `raw_dropped_bytes`, `transcript_lines`, `artifacts`, `meta_path`, `stderr_tail`(허용한 진단 줄만 마스킹, 2000자 이하), `already_stopped`. 서버 메모리에 없는 끝난 세션은 `case_id` 를 준다 |
| `emu_sessions(case_id=None)` | OBSERVE. 이 프로세스의 `sessions[]`(끝난 세션 포함), `count`, `other_process_live{case_id:n}`(다른 서버의 살아 있는 세션 수), `limits`. 콘솔 내용은 없다 |

**입력·출처**

- `firmware` 는 케이스 안 일반 파일이다. `forensics/`·`emu/`·상태 디렉터리, 장치·FIFO 는 거부한다. 경로를 케이스 안으로 해석한 뒤 `safeio` 로 링크를 따라가지 않고 한 번 읽고 `provenance.verify(..., data=그 바이트)` 로 확인한다.
  허용 출처는 이 케이스에서 읽은 `device-read` 또는 `case_import_file` 뒤 사람이 `provenance-import` 를 증명한 파일이다. 원장 누락·해시 불일치·이중 읽기 불일치는 `emu_provenance` 다.
  가져온 파일의 첫 호출은 `attestation_required` 일 수 있다. 사람 증명 뒤 같은 인자로 다시 부른다. `single_read` 는 경고와 함께 허용한다. `case.json` 의 producer 는 신뢰 근거가 아니다.
- ESP 는 offset 0 전체 플래시만 받는다. 부트로더·칩 ID 를 확인하고 원장·같은 기기의 보안 사실과 대조한다. 시작 offset 이 0 이 아닌 덤프·지원하지 않는 칩·칩 불일치·플래시 암호화·16 MiB 초과는 거부한다.
  offset 0 이미지가 헤더 선언 크기보다 짧으면 `partial_dump` 경고를 남기고 패딩한다(앱 파티션이 빠졌을 수 있다).
  유효한 이미지는 0xFF 로 2·4·8·16 MiB 크기에 맞춘다. `chip` 은 생략 권장이다. `psram=auto|none|quad|octal`, `psram_mb` 는 칩별 허용 크기만 받는다.
  `watchdog=disabled|emulated`(기본 disabled), `on_reset=exit|reboot`(기본 exit). eFuse 는 실기기 값을 복사하지 않고 기본 블롭을 쓴다.
- AVR 은 Intel HEX 또는 raw 바이너리를 받아 HEX 로 정규화한다(ELF 거부, 입력 상한 2 MiB·raw 는 MCU 플래시 크기 이하). EEPROM 은 MCU 용량 안에서 보존하고 퓨즈·잠금·서명 레코드는 버린다.
  `board=uno|nano|pro-mini-5v|pro-mini-3v3|mega2560|leonardo|micro|custom`; custom 은 허용 MCU 와 `freq_hz` 1–32 MHz 가 필요하다. 운영에서는 AVR 입력을 `case_import_file` 로 가져와 사람이 출처를 증명한다.
- `backend=auto` 는 `board`·`mcu`·`freq_hz` 중 하나가 있으면 AVR, 나머지는 ESP 다(파일 내용으로 자동 선택하지 않는다). AVR 에 ESP 전용 옵션, ESP 에 AVR 옵션을 섞으면 거부한다.
  `label` 은 `^[a-z0-9][a-z0-9-]{0,23}$`, 세션 id 는 `<label 또는 emu>-NNN` 이다.

**실행 경계·세션 수명**

- 서버가 정확한 argv 를 만들고 `classify_emu_argv` 가 다시 검사한다. QEMU 는 모니터·gdbstub·네트워크 장치·semihosting·호스트 파일 장치·사용자 설정·임의 옵션이 없다.
  `-serial stdio` 는 모니터 다중화를 하지 않는다. AVR 실행기는 GDB 소켓 코드를 링크하지 않는다. 허용 형태를 벗어나면 `denied`, `gate.via="emu-policy"` 이며 승인 경로가 없다.
- 입력과 eFuse 는 봉인한 memfd 로만 넘긴다. 세션 폴더에 펌웨어 사본을 남기지 않는다. QEMU 는 `-snapshot`, 세션 안 `tmp/` 를 쓰므로 원본 펌웨어는 바뀌지 않는다.
  실행 shim 은 `python -I -S` 로 별도 실행하고 rlimit·부모 사망 신호·새 프로세스 그룹·정리한 환경을 적용한다. 가능하면 빈 네트워크 네임스페이스를 쓰며 사용 불가(exit 94) 때 한 번 재시도해 `isolation.netns=false` 를 기록한다.
  exec 상태 파이프로 실행 성공을 확인한다. 서버 시작과 새 세션 시작 때 주인이 죽은 세션을 신원(uid·시작 시각·cwd·실행 파일·그룹 리더) 확인 뒤 정리한다(입양하지 않음).
- 케이스당 동시 세션 2개(서버 간 케이스 잠금으로 계산), 서버 프로세스당 4개. `timeout_s` 10–3600(기본 600), `idle_timeout_s` 30–1800(기본 300, timeout 이하).
  무활동은 게스트 출력이 아니라 `emu_read`/`emu_write` 호출 기준이다. 주소 공간은 QEMU 1 GiB·AVR 64 MiB, CPU 는 `ceil(timeout_s × vcpus × 1.1)+5`(hard +5초), 파일 fd 256·core 0.
  원시 콘솔 32 MiB·stderr 1 MiB·마스킹 기록 16 MiB 상한이며 초과 출력은 버리고 개수로 남긴다. 세션을 시작했다면 이미 끝났어도 `emu_stop` 을 호출한다.
- `emu_status`·`emu_read`·`emu_sessions` 는 `readOnlyHint`/Claude allow, `emu_start`·`emu_write`·`emu_stop` 은 Claude ask 다. 클라이언트 확인과 서버 게이트는 별개다.

**콘솔·산출물**

- 라이브 커서는 원시 바이트 오프셋이지만 줄 레코드 경계에 놓인다. 줄 중간 커서는 그 줄 시작으로 내린다. 생략하면 직전 cursor_end 부터 읽는다.
  `max_chars` 는 256–65536 글자, `wait_seconds` 는 0–50초. `until` 은 리터럴 1개 또는 목록 1–8개(각 1–64자, 줄바꿈 금지)이며 정규식이 아니다.
  0.2초 조용한 열린 줄은 `pending_line` 으로 보이고 커서는 그 시작에 남는다. 이미 보여 준 프롬프트만 있으면 새 바이트나 until 일치를 기다린다.
  메모리에서 밀려난 끝난 세션은 `case_id` 로 `transcript.masked.txt` 를 읽으며 이때 커서는 마스킹 파일 바이트 기준이다(`source="transcript"`, 기다림 없음).
- 공통 `ConsoleRedactor` 는 자격증명 패턴·NVS 에서 확인한 비밀값·개인키 블록·ESP 스택 덤프를 가린다. ANSI·제어·서식 문자도 처리한다.
  `emu_write` 로 준 비밀번호가 게스트 에코에 나타날 수 있다. 마스킹은 완전하지 않으며 원시 로그는 어떤 도구로도 열지 않는 운영 규칙이 필요하다(안전 가이드 §3.7).
- `emu/<sid>/` 의 `console.bin`·`transcript.masked.txt`·`events.jsonl`·`meta.json`·`emulator.stderr.log` 를 끝날 때 `kind="other"`,
  `extra.type=emu-console-raw|emu-transcript|emu-events|emu-session|emu-stderr` 로 등록한다. 일반 case/fwtriage/sigrok 입력은 `emu/` 를 거부한다. 콘솔은 `emu_read` 로만 본다.
- Wi-Fi·Bluetooth·USB 콘솔 및 대부분의 주변장치는 에뮬레이션하지 않는다. ESP32-S3/C3 앱이 USB 콘솔을 쓰면 부트로더 뒤 조용할 수 있다.
  에뮬레이션의 성공·실패만으로 실제 기기 취약점을 확정하지 않는다. 요약은 `skill="firmware-emulation"`, `data` 는 `emulation` 스키마로 남긴다.

오류: `validation_failed`, `not_found`, `tool_missing`, `emu_tool_version`, `emu_input_rejected`, `emu_provenance`(`data.reason`), `emu_changed`,
`emu_not_full_image`, `emu_unsupported_chip`, `emu_machine_mismatch`, `emu_flash_encrypted`, `emu_flash_too_large`, `emu_bad_hex`, `emu_elf_refused`,
`emu_session_limit`, `emu_spawn_failed`, `emu_not_running`. 사람 확인 상태는 `attestation_required`·`approval_required`·`denied` 다.

### 6.10 pweh-espprobe (I5 1a, 오프라인)

서버 내부 `probe-hello` 모델의 HELLO/HB 프로토콜만 시험한다. 실제 포트·소켓·펌웨어 실행·플래시 기능은 없다.
도구는 6개이며 job 도구와 새 safety 설정은 없다. 프로토콜은 [references/espprobe-protocol.md](references/espprobe-protocol.md),
사용 흐름은 [서버 README](../mcp-servers/espprobe-mcp/README.md)에 있다.

| 도구(인자) | 반환·동작 |
|---|---|
| `espprobe_version()` | `backend="in-process"`, protocol_version=1, profile, ports, limits. 외부 실행 없음 |
| `espprobe_connect(case_id, port="sim://probe-hello")` | 케이스 소유/허가 확인, 정확한 모델 이름만 허용. 독립 고정 기대값으로 HELLO 검증 후 HB 시작. `hello`, session_id, model, artifact |
| `espprobe_status(case_id=None)` | 현재 프로세스 sessions[]: state, closed, counters, 해제 사유, 경과, 산출물 |
| `espprobe_self_test(case_id)` | 소유/허가 재확인, 보존 HELLO 정책과 새 HB 왕복, checks와 model 반환. 실제 USB·핀 검증 아님 |
| `espprobe_release_all(case_id)` | RELEASE 뒤 HB/모델 종료. 해제 상태를 보존하며 반복 가능 |
| `espprobe_disconnect(case_id)` | BYE 뒤 모델·HB worker 정리, 최종 JSON. 이미 종료했으면 already_disconnected |

모든 결과에 `simulator_only=true`, `hardware_verified=false`가 있다. 케이스당 한 세션, 프로세스당16개,
최대600초이며 `hb_ms=1000`의 1/3마다 HB를 보낸다. 요청 전에 실제 monotonic 경과를 모델에 적용하므로
스케줄 지연 뒤 늦은 HB가 만료된 세션을 살리지 않는다. 시계 역행·protocol 오류·최대수명·lifespan 종료도 정리한다.
cleanup은 케이스 허가 철회 뒤에도 가능하며, 새 HELLO를 자동 전송하지 않는다.

시뮬레이터의 고정 MAC/hash/commit은 합성 식별이다. 실제 릴리스 manifest의 허용 대상으로 승격하지 않는다.
연결·자가시험·종료 JSON은 `probe/`에 `kind=other`로 등록하고, 주기 HB는 카운터만 남긴다.
실기 전송 계층·instrument-pin 생성·배선·flash-plan 도구는 이후 단계다. 현재 여섯 도구만 Claude allow에 명시한다.

**공용 코드와 핀아웃 형식**

`pweh.srzip`의 write_srzip, `pweh.jtag.jep106`의 IDCODE 해석, `pweh.safety.probes`의 UART 프로브 분류를
기존 서버가 재사용한다. 기존 import 경로와 규칙 ID는 유지한다. `pweh.jtag.pinout_scan`의 lower_bound_seconds
기본 시간표는 JTAGulator용이며 espprobe의 속도 추정에 적용하지 않는다.
새 JTAGulator 결과는 `pweh.pinout-scan/v1`, producer=jtagulator, legacy_schema=pweh.jtagulator-scan/v1이며
기존 공급자 필드를 보존한다. 수동 TXD 관찰의 permutations는 null이다. 기존 저장 결과는 변경하지 않는다.

**기존 대상 도구의 계측기 보호**

`pweh.instrument_guard.guard_target_port`는 모든 케이스의 유효한 전역 instrument-pin을 모아 읽고,
`pweh.portidentity`의 포트를 열지 않는 Windows PnP/Linux sysfs 관찰로 대상과 계측기를 구분한다.
pin이 없으면 OS 관찰·역할 태그를 읽지 않는다. pin이 있을 때 식별할 수 없는 포트·자동 선택·중계 경로는
instrument_identity_unknown, 계측기·부트/ROM·instrument-aux 일치는 instrument_port다.
ESP는 도구 준비·프로세스 실행·이중 읽기 각각, UART는 open/baud 재시도/송신·신호 변경,
JTAGulator는 연결·송신, sigrok은 scan/info/capture의 프로세스 실행 전에 검사한다.
오프라인 파일 처리·버전 조회는 그대로다. 메모리 loop와 sigrok demo는 가상 입력으로 처리한다.

InstrumentTagStore는 uid별 runtime 디렉터리0700·파일0600, nofollow·크기/개수 상한으로 거부 표지를 저장한다.
instrument-aux도 권위 증명과 현재 관찰이 일치해야 만들 수 있으며 허용 권한이 아니다.
기존 ESP chip/security 사실의 출처 기록은 그대로 재사용하고, 관찰 MAC도 고정 계측기와 대조한다.
실제 pin 생성과 포트의 원자적 잠금은 후속 단계다. 현재 구현은 합성 PnP와 가짜 프로세스로 검증한다.

## 7. REA 연동

- 등록: `.mcp.json` 의 `rea` 서버. `scripts/mcp-launch.sh rea` 가 `~/pweh-tools/env.sh` 를 불러온 뒤 `rea --mcp` 를 실행한다
  (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `REA_BINWALK_COMMAND`, `REA_UNBLOB_COMMAND`, `REA_SIGROK_COMMAND`, 런처 기본 `REA_GHIDRA_STARTUP_TIMEOUT_MS=600000`).
  `pweh mcp-config --style absolute`(Codex 기본) 형태도 REA 는 런처의 절대 경로(`<저장소>/scripts/mcp-launch.sh rea`)로 등록하고, 어느 env.sh 를 불러올지만
  `env` 의 `PWEH_TOOLS_ENV` 로 고정한다(REA 는 env.sh 의 PATH — node·JDK·압축 해제 도구 — 가 필요하다. 설정 파일에 실행한 셸의 PATH 를 적지 않는다).
  Codex 는 `pweh mcp-config --client codex --write` 가 만든 `[mcp_servers.rea]` 로 실행한다. 이 항목의 `enabled_tools` 는 `.claude/settings.json` 의 `mcp__rea__*` 규칙(allow·ask)에 있는 도구만 켠다
  (REA 6.5 는 도구 207개를 내보낸다. 규칙에 없는 도구는 Codex 에서 보이지 않는다 — docs/mcp-setup.md §3.4).
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
  (+ 실제 Windows esptool.exe·리눅스 esptool 이 있으면 기기 없이 — version, 없는 COM99 의 취소, 파일만 쓰는 merge-bin, 설정 파일 탐색 — 확인하는 external 테스트),
  SD 카드 이미지는 `tests/fs/builders.py` 의 순수 파이썬 합성 이미지(MBR/EBR·GPT, FAT12/16/32·exFAT, 리눅스처럼 지운 파일, exFAT ValidDataLength 잔여),
  조작·손상 이미지 빌더(`tests/fs/hostile.py` — 예산·단계 상한·검증 회귀용)와 고정 시드 변조 퍼저(`tests/fs/test_fuzz.py`)
  (+ mkfs.fat·sgdisk 가 있으면 BPB·GPT 를 교차 확인하는 external 테스트 `tests/fs/test_external.py`). 증거 보관 기록·EV 번호·정리는 `tests/core/test_evidence.py`, 안전한 파일 열기는 `tests/core/test_safeio.py`,
  서버는 `tests/servers/test_forensics_mcp.py`(접수·보관 기록·검증·증명·증거 목록)·`tests/servers/test_forensics_fs.py`(이미지 해석 도구), 다른 서버의 증거 가드는 `tests/servers/test_fwtriage_forensics_guard.py` 와 case·sigrok 서버 테스트가 본다.
- 외부 도구가 필요한 테스트는 `@pytest.mark.external` + 도구가 없으면 `pytest.skip`.
  오래 걸리는 테스트(전체 플래시 덤프 e2e 등)는 `@pytest.mark.slow` 다. 기본 실행에서 빠지지 않으므로 빠르게 돌릴 때는 `-m "not slow"` 를 준다.
  실제 하드웨어가 필요한 테스트는 `@pytest.mark.hardware` 이고 기본 skip 이다(`--run-hardware` 또는 `PWEH_HARDWARE=1` 일 때만 실행, `tests/conftest.py`).
- 문서·권한 규칙·Skill 이 실제 도구 카탈로그와 코드(분류기, 서버 반환값)와 맞는지는 `tests/core/test_docs_consistency.py`, `tests/core/test_skills_consistency.py` 가 검사한다.
  도구를 바꾸면 `scripts/dump_tool_catalog.py` 로 카탈로그를 다시 만든 뒤 이 두 파일을 돌린다.
- 서버·도구 목록은 테스트에 적지 않는다: `tests/core/test_docs_consistency.py` 는 카탈로그(`docs/references/pweh-mcp-tools.json`)와 `pweh.cli.SERVERS` 에서 얻고,
  카탈로그 = `pweh.cli.SERVERS` = `scripts/dump_tool_catalog.py` 의 SERVERS = `.mcp.json`(+ rea) 인지 검사한다. 새 서버를 더할 때 고칠 것은 파일 맨 위의 정책 상수뿐이다:
  `FULL_ALLOW_SERVERS`(서버 전체 자동 허용), `LOCAL_WRITE_ALLOW`(명시적 쓰기 도구 자동 허용), `FULL_SIGNATURE_SERVERS`(§6 시그니처 전체), `SERVER_DIR_OVERRIDES`(디렉터리가 'pweh-<x>' → '<x>-mcp' 규칙을 벗어날 때), `RULE_ID_PREFIXES`(규칙 id 접두).
  `anthropic/requiresUserInteraction` 은 `destructiveHint` 도구와 정확히 같아야 한다(`ANN_DESTRUCTIVE` 도구에는 `META_REQUIRE_HUMAN` 을 붙이고 safety.md·mcp-setup.md 목록에도 적는다).
  문서의 `pweh <명령>` 예시는 `pweh.cli.build_parser()` 로 해석되어야 한다(하위 명령 목록도 파서에서 얻는다).
- 사람 증명·출처 원장·마스킹 테스트(`tests/core/test_attestations.py`, `tests/core/test_provenance.py`, `tests/core/test_masking.py`)는 `workspace` fixture 의
  격리된 상태 디렉터리만 쓴다. `pweh attest` 는 하위 프로세스로 실행해 TTY 가 아닐 때의 거부를, 가상 터미널(pty)로 대화형 답·목록·철회를 시험한다.
  작업 공간의 실제 `.pweh/state` 는 건드리지 않는다.
- 시뮬레이터(`pweh-mock-device --tcp`, `python -m jtagulator_mcp.sim --tcp`)는 IPv4 루프백(127.0.0.0/8, localhost)에만 바인드한다(IPv6 주소는 `--allow-lan` 이어도 거부 — 리스너가 IPv4 전용). 루프백이 아닌 `--host`·`--tcp` 는 `--allow-lan` 이 있어야 하고(stderr 경고), 라이브러리(`MockDevice.start_tcp`, `TcpTransport`, `SimTCPServer`)는 `allow_lan=True` 가 있어야 한다. 시험은 0.0.0.0·LAN 주소에 실제로 바인드하지 않는다(가짜 전송으로 경고 경로를 확인한다).
- 테스트 파일 위치: `tests/servers/test_<server>.py`, `tests/core/`, `tests/uart/`(uart-mcp 파서·분류·문맥 단위), `tests/fwtriage/`(합성 입력 빌더),
  `tests/fs/`(`pweh.fs` 엔진과 합성 카드 이미지 빌더), `tests/mocktarget/`, `tests/e2e/`.
- `tests/e2e/` 의 에이전트는 Skill 순서를 스크립트로 고정한 것이다. 실제 모델이 마스터 프롬프트·Skill 만 보고 끝까지 가는지는
  pytest 밖의 옵트인 하네스 `scripts/run_agent_e2e.py` 로 본다(Claude Code 헤드리스 + 규칙 기반 모의 운영자 + 시뮬레이터, 계정 사용량을 씀).
  실행 전에 정한 기준 C1–C7(소유 확인 먼저, U-Boot 확보, 덤프 sha256 = 이미지, 파괴 이벤트 0, 요약 스키마, 보고서, 자기 승인 없음)로 판정하고,
  `--rejudge <작업공간>` 으로 에이전트를 다시 돌리지 않고 판정만 다시 할 수 있다.
