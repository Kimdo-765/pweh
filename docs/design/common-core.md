# 설계안: 공통 기반 (여러 신규 기능이 함께 쓰는 코어)

> 상태: **제안 (구현 전 검토용)**. 계약이 아니다. 개요는 [README.md](README.md).
> 게임 콘솔·Flipper/RF([game-console-flipper-rf.md](game-console-flipper-rf.md)), SD 포렌식([sd-forensics.md](sd-forensics.md)), ESP32 계측기([esp32-instrument.md](esp32-instrument.md))가 이 기반 위에 선다.
> 환경 감지·물리 연결 라우팅의 전체 설계는 [port-routing.md](port-routing.md) 에 있다(§2 는 요약).
> 1차 설계 검토(구조 적합성·안전 관점)에서 "서버마다 따로 만들면 우회 구멍이 생기는 것"으로 지적된 부분을 코어로 모았다.

## 1. 무엇을 코어로 올리나

| 모듈 (제안 위치) | 역할 | 지금 상태 |
|---|---|---|
| `src/pweh/hostenv.py` | 실행 환경 감지(WSL1/WSL2/리눅스/macOS/Windows/컨테이너, interop·네트워킹 모드·usbipd), 장치 종류별 경로 추천. 표준 라이브러리 `platform` 과 이름이 겹치지 않게 `hostenv` 로 한다 | 없음(esp-mcp `ports.is_wsl` 등 서로 다른 감지 4벌) — §2 |
| `src/pweh/ports.py` (+ `src/pweh/data/usb-ids.yaml`) | 포트 참조 문법·해석(`resolve` → `PortRoute`)·열거·장치 식별, `open_serial`(TIOCEXCL 포함) | esp 만 문자열 정규식, uart 는 문법 검사만 — §2 |
| `src/pweh/wininterop.py` | interop 실행 허용 목록, `wslpath -w` 변환과 Windows 경로 검사(끝의 '.'·공백), Win32 프로세스 조회·종료·고아 처리, 자식 환경 정리, ACP 디코딩 스트리밍 실행 | esp-mcp 안에만(`ports.py`, `winproc.py`, `esptool_cli.py`) |
| `src/pweh/winserial/` + `pweh-serial-helper.exe` | WSL 에서 Windows COM 포트 사용: stdio 프레임 프로토콜 헬퍼(정수 COM1–COM4096 만, 소켓 없음, sha256 고정) + `HelperSerial(serial.SerialBase)`. `pweh.ports.open_serial` 이 직접 만든다(pyserial URL 처리기 등록 없음) | 없음 — §2 |
| `src/pweh/portlock.py` | 서버 프로세스 사이 포트 잠금: OS 객체 키(`win:COMn`·`tty:<major>:<minor>`·URL), 호스트 전체(작업 공간·클론·WSL 배포판), `os.open` 전에 잡고 승인 대기 중에도 쥔다, 커널이 해제(abstract 소켓). 역할 표지(instrument / instrument-aux / target / bridge) | 서버 안 레지스트리 + 열고 나서 flock·`/proc` 검사(최선 노력) |
| `src/pweh/procutil.py` | 프로세스 그룹 실행·종료, PID 생존 확인(Windows 에서 `os.kill(pid,0)` 금지) | 4벌(esp·sigrok·openocd·fwtriage) |
| `src/pweh/safety/attestations.py` | 사람 증명 레코드(재사용 가능, 대상·바인딩·만료) | I1 에서 구현 — §3 구현 상태 |
| `src/pweh/provenance.py` | 출처 원장(기기에서 읽은 산출물만 기록) | I1 에서 구현 — §4 구현 상태 |
| `src/pweh/safety/rf.py`, `src/pweh/rf/` | 지역 대역표·RF 수신 분류기, `.sub`/`.ook`/펄스 파서 | 없음 |
| `src/pweh/nfc/` | `.nfc`·CU 형식, ISO14443A 프레임, 태그 계열 판정 | 없음 |
| `src/pweh/jtag/jep106.py` | JEP106 제조사 코드 해석(jtagulator·espprobe 공용) | `jtagulator_mcp/jep106.py` 에만 |
| `src/pweh/jtag/pinout_scan.py` | 순열 수·`lower_bound_seconds`, 결과 형식 `pweh.pinout-scan/v1`(`pweh.jtagulator-scan/v1` 일반화) | jtagulator 서버 안(`jtagulator_mcp/server.py:862`) |
| `src/pweh/safety/probes.py` | UART 프로브 문자열 분류 `classify_uart_probe`(한 번·두 번 이어 붙인 형태) | `jtagulator_mcp/classify.py:103` 에만 |
| `src/pweh/srzip.py` | sigrok `.sr` 쓰기 `write_srzip`(espprobe 캡처·sigrok 공용) | `sigrok_mcp/writers.py:83` 에만 |

## 2. 환경 감지와 물리 연결 라우팅

> 전체 설계(감지 결정 트리, 장치 종류 × 플랫폼 라우팅 표 R1–R18, 현재 코드의 빈틈 G1–G16, 단계·시험·결정 D1–D8)는 [port-routing.md](port-routing.md). 여기에는 다른 문서가 기대는 결론만 둔다.

- **개발 환경(검증 기준)**: WSL2(3.0.3.0, bridged, interop 켜짐), usbipd 없음. 이런 환경에서 지금 하드웨어에 닿는 경로는 pweh-esp 방법 A(esptool.exe + COMn) 하나다.
- **WSL2+interop 의 기본 경로**: 장치는 Windows 에 두고 Windows 쪽 프로세스가 연다.
  직렬은 `pweh-serial-helper.exe`(stdio 프레임, 소켓 없음), 도구형은 Windows 판 도구(esptool·openocd `tcl port pipe`·sigrok-cli·ffmpeg·rtl_*)다.
  usbipd 는 사람이 고르는 대체 경로다(모든 네트워킹 모드에서 세션 동안만 bind, AutoBind 정책 금지, attach 의 `--host-ip` 는 모드별).
- **감지**(`pweh.hostenv`): 컨테이너를 WSL 보다 먼저 본다. WSL1/2 는 osrelease, 안 되면 `wslinfo --networking-mode`(`wsl1` = WSL1).
  interop 은 WSLInterop 항목 + `/init` + `wslpath` + smoke 로 판정한다(binfmt `status` 는 참고 값). 결과는 `pweh env`·doctor·`pipeline_environment()` 로 보여 준다.
- **해석**(`pweh.ports`): 에이전트는 OS 이름(`COM3`, `/dev/ttyACM0`)을 넘기고 서버가 `resolve(환경, 참조, 용도)` 로 경로를 고른다.
  `COM3` 은 WSL2+interop 에서 헬퍼, WSL1 에서 `/dev/ttyS3`(COM1–COM191 만), 그 밖에서는 거부한다. COM 문법은 COM1–COM4096(앞자리 0 금지)이다.
- **배타**(`pweh.portlock`, 새 동작): 리눅스는 모든 open 에서 DTR/RTS 를 올리므로 `os.open` 전에 OS 객체 키로 잡는다.
  범위는 호스트 전체이고 승인 대기(최대 300 s) 동안에도 쥔다. 연 뒤에는 TIOCEXCL 을 건다. Windows 의 단일 열기는 드라이버의 성질이다.
- **승인 지문**: 열기·연결 동작에 `route{backend, lock_key, device_id}` 를 넣는다. 다른 장치를 같은 이름으로 꽂으면 `approval_mismatch` 다.
- **플랫폼**: 1급 = WSL2+interop·네이티브 Linux, 최선 노력 = WSL2(usbipd 만)·WSL1·macOS(P5). 네이티브 Windows·Cygwin·MSYS 는 서버 시작을 거부한다(Windows 는 장치 호스트로만).
- **사람 단계**: 드라이버(Zadig·벤더 VCP), usbipd, udev 규칙, brltty(Ubuntu 22.04 의 CH340), SD 이미징 — 에이전트는 하지 않는다. interop 은 root·관리자와 같다(§6 호스트 위험).
- **단계**: P0 감지·안전 정리 → P1 식별·portlock·TIOCEXCL → P2 Windows COM 헬퍼(게임 문서 1b 관문) → P3 Windows 판 libusb 도구 → P4 SDR·영상 → P5 macOS.

## 3. 사람 증명 (attestation)

> **구현 상태 (I1, 2026-10-20)**: 코어 구현 — `src/pweh/safety/attestations.py`(`AttestationStore`·`Attestor`), `rt().attest(...)` → `AttestationDecision`
> (충족이 아니면 `attestation_response(...)`), 사람 명령 `pweh attest <id>`·`pweh attest --list`(`--all`)·`pweh attest --revoke <id>`(모두 TTY 전용),
> 케이스 사본 `attestations.json`(0400, 증거 아님). 계약은 architecture.md §4, safety.md §3.5·§4 규칙 12. **증명을 요구하는 도구는 아직 없다.**
> 설계와 다른 점: 사람 쪽은 `pweh approve` 의 증명 화면이 아니라 별도 명령 `pweh attest` 다. `require` 에 서버가 지금 묻는 질문을 넘겨 질문이 늘면 예전 증명을 쓰지 않는다.
> 유효 기간은 범위별 코드 기본값(case 7일·connection 12시간·job 24시간·instrument 는 철회까지, 서버가 `valid_seconds` 60초~90일), pending 은 `approval_ttl_seconds`,
> 확인 경로는 `safety.approval_methods`(새 설정 키 없음)다. 연결 해제·재연결·장치 시리얼 변화에 따른 무효화는 바인딩·subject 지문으로만 된다(연결 토큰을 쓰는 서버가 아직 없다).
> 반박 검증 뒤 보강: `pweh attest` 는 승인이 되는 답이면 화면의 확인 코드를 입력받는다(`pweh approve` 와 같은 수준), `decided_by` 는 OS 계정 이름($USER 아님),
> 시간대 없는 시각의 레코드는 불신(저장소는 멈추지 않음), 디렉터리 0700. `valid_seconds` 는 새 레코드에만 적용된다(기존 레코드는 그 만료를 따름 — 문서화).
> 남은 것: 같은 case_id 로 케이스를 다시 만들면 예전 증명·원장·솔트를 이어받는다(사람이 `cases/<id>` 를 지운 경우) — `case_create` 가 보호 상태가 남은 id 를 거부·건너뛰게 하는 일은 다음 단위.

**왜**: 기본 `modify_policy: allow` 라서, 사람만 확인할 수 있는 사실(콘솔 오프라인, 결제 수단 제거, 배선 = 채널 라벨, 1번 핀 5 V 미연결, 태그의 목적·소유, 쓰기 방지 장치 사용 등)이나
물리 부작용이 있는 MODIFY 의 전제 조건을 에이전트가 스스로 채울 수 없게 해야 한다. 기존 승인(ApprovalStore)은 **한 번 쓰면 사라지고(consume) 900초 만료**라 재사용 증명에 맞지 않는다.

- **위치**: 코어 `src/pweh/safety/attestations.py`, 레코드는 `.pweh/state/attestations/`(승인 파일처럼 에이전트 수정 금지 — AGENTS.md·safety.md 에 명시). 자기 id 접두(`att-…`).
- **레코드**: `kind`(예: `tag-purpose`, `wiring`, `console-offline`, `payment-locked`, `hdmi-source`, `bridge-serial`, `write-blocker`, `provenance-import`, `instrument-pin`, `radio-target`, `module-kc`), `subject`(UID+ATQA+SAK, 배선 계획 해시+측정 전압, 브리지 iSerial, 계측기 MAC, 캡처 소스, 파일 sha256 …),
  `binding`(케이스 전체 / 연결 토큰(JTAGulator 처럼 연결마다) / job / 계측기 전역(철회할 때까지)), `expires_at`, `answers`(사람이 항목마다 y/n 한 기록과 **사람이 입력한 값** — 측정 전압, MAC 등), `decided_via`(cli-tty 또는 elicitation).
- **요청**: 서버가 필요한 증명이 없으면 `status: "attestation_required"` 와 `attestation_id`, 확인 항목 목록을 돌려준다. 사람이 `pweh approve <id>` 하면 **증명 전용 화면**(항목마다 y/n)이 뜬다.
  이름은 기존 `pweh case attest`(소유/허가 증명)와 구별한다(예: `pweh attest <id>`).
- **확인**: 서버는 `require(kind, subject, binding)` 로 직접 찾는다(소비하지 않음). 에이전트가 넘긴 `attested_*` 필드나 케이스 파일은 증거로 받지 않는다. 계열·대상 같은 subject 값은 서버 자신의 스캔·측정 결과에서 만든다.
- **무효화**: 연결 해제·재연결·장치 시리얼 변화·만료·사람의 철회(`pweh attest --revoke`). 종류를 검사해 소비된 DESTRUCTIVE 승인을 증명으로 쓰지 못하게 한다.
- **사본**: 케이스에는 읽기 전용 사본(`attestations.json`)만 — 보고서용. 서버는 사본을 믿지 않는다.

## 4. 출처 원장 (provenance)

> **구현 상태 (I1)**: 코어 구현 — `src/pweh/provenance.py`(`ProvenanceLedger`: 정규화 JSON 줄의 해시 체인, 파일 잠금, 깨지면 모두 불신, `verify`).
> 기록하는 곳은 지금 둘이다: pweh-esp(`esp_read_flash_start` 의 끝까지 성공한 덤프 = `device-read`, `esp_chip_info`·`esp_security_info` = `device-fact`)와
> `case_import_file`(`imported-unattested`). 나머지 기록 지점(Flipper·CU·수신 job·espprobe·SD 이미지 검증)과 확인 지점(에뮬레이션·SD 올리기·패치 base·
> `espprobe_flash_plan`)은 그 서버를 만들 때 붙인다 — **지금 `verify` 를 부르는 도구는 없다.** `provenance-import` 증명의 대상은 `provenance_import_target(case_id, sha256)`·
> `PROVENANCE_IMPORT_QUESTIONS` 하나로 정했다. 기록 실패는 도구 결과를 막지 않고 응답의 `provenance.recorded=false` 로 알린다.
> 반박 검증 뒤 보강: 이중 읽기가 어긋난 덤프(`source.match=false`)는 기록하되 `verify` 가 불신한다(`device-read-mismatch` — 출처 ≠ 무결성). `case_import_file` 은 state_dir 의 파일을 거부하고,
> 대상을 `O_EXCL` 로 만들며 복사하면서 해시한다. 확인과 사용 사이의 변경(TOCTOU)은 소비자가 sha256 을 승인 지문·job 인자에 묶어 막는다(architecture §4).

**왜**: "이 케이스에서 읽은 것만 에뮬레이션/올리기", "다운로드한 덤프 금지", "남의 태그 복제 금지"는 출처를 코드로 확인해야 지킬 수 있다. 지금 `case.json` 아티팩트의 `producer` 는 자동 허용 도구의 자유 인자라 증거가 못 된다.

- **위치**: `.pweh/state/provenance/<case_id>.jsonl`(보호 대상).
- **기록하는 곳**: 기기 읽기 코드 경로만 — `flipper_nfc_read_start`, `nfc_cu_read_start`, 수신 job, `esp_read_flash_start`, espprobe 읽기, SD 이미지 해시 검증 등. 항목: sha256, 장치 식별(UID/주파수/장치 시리얼), 인벤토리·증명 id, 시각.
  산출물 외에 기기 사실도 기록한다(pweh-esp `esp_chip_info`·`esp_security_info` 결과 — ESP32 계측기를 플래시하기 전 백업·보안 상태 확인의 근거).
- **확인하는 곳**: 에뮬레이션, SD 올리기, (향후) 송신, 패치 base, `espprobe_flash_plan`(계측기 플래시 절차를 보여 주기 전). 산출물을 다시 해시해 원장과 맞춰 본다.
- `case_import_file` 과 Flipper 기존 폴더에서 가져온 파일은 `imported-unattested` 로 기록되고, `provenance-import` 증명이 있을 때만 쓸 수 있다. 출처 확인은 `producer` 를 보지 않는다.

## 5. 비밀값 마스킹

> **구현 상태 (I1)**: 코어 구현 — `src/pweh/safety/masking.py`. `rt().secret_digest(case_id, 값)` = `sha256:` + sha256(케이스 솔트 ‖ 값)의 앞 16 hex
> (솔트 `.pweh/state/salts/<case_id>.key`, 32 바이트, 0600, 처음 쓸 때 만듦), 표시용 `mask_secret`. 테스트는 게이트 action·감사 로그·승인 레코드에 원문이 없음을 확인한다
> (`approval_status` 응답·보고서는 그 레코드·감사 로그에서 나오므로 따로 시험하지 않았다). 비밀을 게이트에 넣는 새 도구가 없어 다이제스트를 쓰는 서버는 아직 없다
> (기존 `shell_login` 은 `<given>`). pweh-fwtriage 의 자체 마스킹(앞 1–2자 + `*`)은 코어 `mask_secret` 으로 통일하지 않았다.
> 반박 검증으로 확인한 한계: 솔트는 같은 계정의 에이전트가 읽을 수 있다(자동 허용된 REA `open_binary` + `read_bytes`). 다이제스트는 보고서·감사 로그를 읽는 제3자에게서만 원문을 가린다
> — 낮은 엔트로피 값은 게이트에 넣지 않는다(safety.md §3.5). 자동 허용된 REA `export_evidence_bundle`·`close_binary` 는 `.pweh/state` 를 덮어쓸 수 있다(위조는 안 되고 실패 쪽으로 닫힘)
> — allow 에서 빼고 묻기(ask)로 둘지는 사용자 결정(지금은 그대로). 비밀번호 프롬프트에 `uart_send_command` 로 입력하면 원문이 감사 로그에 남는다 → 로그인은 `shell_login`.

- 대상: 콘솔 PWD_AUTH 비밀번호, 사용자 MIFARE 키, 롤링코드·고정코드 값, 비대상 RF 기기 ID, Wi-Fi PSK·클라우드 토큰(SD·NVS 에서 찾은 것).
- 원문은 케이스 파일(필요한 것만)에만. 도구 응답·보고서는 마스킹, **게이트 `action` 과 `classification.matched` 에는 솔트 다이제스트**(`sha256(case_salt || 값)`) 또는 `<given>` 만 — 승인 지문도 다이제스트로 묶는다.
  감사 로그·승인 레코드·`approval_status` 응답·보고서에 원문이 없음을 확인하는 테스트를 둔다.
- 낮은 엔트로피 ID(24–32비트)는 케이스 솔트 HMAC 도 되돌릴 수 있으므로, 비대상 정보는 가능하면 개수만 남긴다.

## 6. 안전 관련 설정의 위치

- 새 정책 설정은 모두 `safety:` 아래에 둔다(AGENTS.md 가 에이전트 수정을 금지하는 범위): `safety.play_policy`·`safety.play.{max_duration_s, max_inputs, rate}`, `safety.rf.{region, rx_extra_bands, allow_amp}`,
  `safety.nfc.cu_slot`, `safety.forensics.*`(SD 포렌식), `safety.ports.remote_serial_hosts`(원격 시리얼 LAN 호스트, port-routing §5.5),
  `safety.espprobe.*`(컴파일된 한도를 좁히기만 하는 키와, 무선 프로필처럼 운영자만 켜는 opt-in 키를 구분 — esp32-instrument §2.5). 외부 도구 경로(`tools.*`)는 실행 파일 이름 허용 목록으로 검사한다(esptool 의 espefuse/espsecure 거부와 같은 방식, 송신 가능 도구는 거부).
- `SafetyConfig` 는 모르는 `safety.*` 키를 거부한다(오타가 조용히 무시되지 않게). (제안 — 지금은 모르는 키를 조용히 무시하고 필드도 평평하다, `src/pweh/config.py:139-151`.)
- **호스트 위험**: UAC 가 꺼진 관리자 계정 호스트에서는 interop 으로 띄운 Windows 프로세스가 관리자 권한(High IL)으로 돈다. `wsl.exe -u root` 는 어디서나 비밀번호 없는 root 이고(MS 문서), `docker`·`disk` 그룹은 root 와 같다(sd-forensics §0).
  그래서 OS 계정 분리로는 막을 수 없다. 에이전트 가드레일은 AGENTS.md 규칙과 `.claude/settings.json` deny 규칙(제안 — 지금 deny 목록은 비어 있다)에 둔다.
  코드 쪽은 port-routing §11 의 interop 실행 허용 목록(`wsl.exe`·`cmd.exe`·diskpart 등 거부)이 맡는다. UAC 설정은 사용자 결정이다.
- `authorize(..., policy_key=...)` 를 더해 위험도 대신 기능별 정책(`safety.play_policy`)을 고를 수 있게 한다(지금은 play 만, rf 송신·esp 쓰기 키는 그 기능이 생길 때).
- 서버는 시작 때 유효한 안전 설정의 해시를 감사 로그에 남기고 승인 지문에 넣는다. `pipeline_safety_policy` 가 새 키를 모두 보여 준다.

## 7. master-prompt: 목표 분기

> **구현 상태 (I1)**: master-prompt Phase 0 에 목표 표(보안 분석 = 지원, 나머지 셋 = 준비 중 → §3.1), 목표별 장비 체크리스트(Windows 관리자 권한 포함),
> 고른 목표를 `case_create` 의 `notes` 에 기록, §3.1 준비 중 목표에서 지금 할 수 있는 일, §9 목표별 완료 기준(펌웨어 확보는 보안 분석만), pweh-start 설명을 더했다.
> 설계와 다른 점: `PIPELINE_PHASES` 는 그대로 두고 선택 단계 레지스트리 `OPTIONAL_PHASES`(기록될 때만 생김)와 보고서 §4 의 '선택 단계' 블록·라벨을 더했다.
> 목표별 Skill·서버는 아직 없다.

- Phase 0 접수에서 목표를 먼저 고른다: **보안 분석**(기존 CCTV/IoT 흐름) / **게임 콘솔 분석** / **RF·하드웨어 분석** / **SD 카드 포렌식**.
- 목표마다 결정 트리, 장비 체크리스트(Flipper 펌웨어·지역·SD 플러그인, CU 모델, SDR, 캡처 카드, 브리지 보드, 카드 리더·쓰기 방지 장치, **Windows 관리자 권한 여부**), 완료 기준이 다르다
  (지금 완료 기준은 펌웨어 확보를 요구해 RF·SD 전용 케이스가 끝날 수 없다).
- pweh-start 설명, `PIPELINE_PHASES`, 보고서 섹션·라벨을 목표별로 갱신한다.

## 8. 위험도·job 규칙 보완

- 핵심 위험도 정의는 그대로 둔다. 추가 행: "계측기의 서버 소유 영역에 남는 변화"(Flipper SD 의 `/ext/pweh/<case>`, CU 의 지정 슬롯, 에뮬레이션 시작) = MODIFY.
- 계측기 연결 도구는 INTERACT, 정리 도구(`*_close`, `*_disconnect`, `nfc_emulation_stop`, `input_release_all`)는 게이트·승인 확인 없이 항상 동작.
- job 규칙(architecture §4: job 안의 명령은 INTERACT 이하)은 유지한다. MODIFY 시작은 게이트를 거친 도구 호출 안에서 하고 job 은 대기·읽기·정지만(JTAGulator 방식).
  예외는 지금처럼 명시한다: pweh-esp 덤프, 플레이 job(계획 승인, 매 동작 계획 대조 `job_command_denied`, 주기적 케이스 승인 재확인 `authorization_required`, 배타 키).
- **크레딧 규칙**(espprobe 등 스트리밍 계측기): 크레딧은 BEGIN 에 고정한 연산의 흐름 제어일 뿐 연산을 늘리지 않는다. 크레딧마다 케이스 승인을 다시 확인한다.

## 9. 테스트 기반 정리 (0단계)

> **구현 상태 (I1)**: 문서 일관성 테스트를 카탈로그 기반으로 바꿨다 — architecture §6 정규식(`6\.\d+`, `pweh-[a-z][a-z0-9-]*`), 서버 목록(카탈로그 = `pweh.cli.SERVERS` =
> `dump_tool_catalog.SERVERS` = `.mcp.json` + rea), README 디렉터리, 규칙 id 접두·정책 상수, 도구 지도 행 수(카탈로그 서버 + rea), `requiresUserInteraction` = `destructiveHint`,
> CLI 하위 명령(파서에서). job 접두 규칙과 헬퍼·펌웨어 소스 위치는 그 서버·펌웨어를 만들 때 적용한다.

- 문서 일관성 테스트의 하드코딩을 카탈로그 기반으로: architecture §6 정규식(`6\.\d+`, `pweh-[a-z-]+`), 서버 목록, README 디렉터리 표, 규칙 id 접두, Skill 표 행 수.
- 서버마다 job 접두 하나(`play_job_*` 등). esp 테스트의 monkeypatch 지점(`esp_mcp.ports`)은 코어로 옮겨도 유지(모듈 경유 호출).
- 헬퍼·펌웨어 소스 위치: `tools/winserial/`(zig 크로스 컴파일, 핀 고정 사전 빌드도 배포), `firmware/common/`(입력 브리지·계측기 공용 프로토콜·빌드·매니페스트), `firmware/input-bridge/`, `firmware/espprobe/`. 서버 테스트는 `.exe` 접미사 규칙의 파이썬 가짜 헬퍼(가짜 esptool 과 같은 방식).
