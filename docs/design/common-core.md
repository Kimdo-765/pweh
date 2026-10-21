# 설계안: 공통 기반 (여러 신규 기능이 함께 쓰는 코어)

> 상태: **공통 기반의 구현 현황과 후속 제안**. 현재 동작의 계약은 [architecture.md](../architecture.md)이며, 아래의 제안 위치·후속 단계가 모두 구현된 것은 아니다. 개요는 [README.md](README.md).
> 게임 콘솔·Flipper/RF([game-console-flipper-rf.md](game-console-flipper-rf.md)), SD 포렌식([sd-forensics.md](sd-forensics.md)), ESP32 계측기([esp32-instrument.md](esp32-instrument.md))가 이 기반 위에 선다.
> 환경 감지·물리 연결 라우팅의 전체 설계는 [port-routing.md](port-routing.md) 에 있다(§2 는 요약).
> 1차 설계 검토(구조 적합성·안전 관점)에서 "서버마다 따로 만들면 우회 구멍이 생기는 것"으로 지적된 부분을 코어로 모았다.

## 1. 무엇을 코어로 올리나

| 모듈 (제안 위치) | 역할 | 지금 상태 |
|---|---|---|
| `src/pweh/hostenv.py` | 실행 환경 감지(WSL1/WSL2/리눅스/macOS/Windows/컨테이너, interop·네트워킹 모드·usbipd), 장치 종류별 경로 추천 | I4(P0) 구현. `pweh env`·doctor·`pipeline_environment`·esp가 사용 — §2 |
| `src/pweh/ports.py` (+ 제안 `src/pweh/data/usb-ids.yaml`) | 포트 참조 문법·해석(`resolve` → `PortRoute`)·열거·장치 식별, `open_serial`(TIOCEXCL 포함) | P0 문법 검사·루프백 URL·서버 내부 끝점 키 구현. 공용 resolve·열거·portlock·open_serial은 P1 이후 제안 — §2 |
| `src/pweh/wininterop.py` | interop 실행 허용 목록, `wslpath -w` 변환과 Windows 경로 검사(끝의 '.'·공백), Win32 프로세스 조회·종료·고아 처리, 자식 환경 정리, ACP 디코딩 스트리밍 실행 | 이 이름의 공용 모듈은 없음. 관련 기능은 hostenv와 esp-mcp(`ports.py`, `winproc.py`, `esptool_cli.py`)에 있음 |
| `src/pweh/winserial/` + `pweh-serial-helper.exe` | WSL 에서 Windows COM 포트 사용: stdio 프레임 프로토콜 헬퍼(정수 COM1–COM4096 만, 소켓 없음, sha256 고정) + `HelperSerial(serial.SerialBase)`. `pweh.ports.open_serial` 이 직접 만든다(pyserial URL 처리기 등록 없음) | 없음 — §2 |
| `src/pweh/portlock.py` | 서버 프로세스 사이 포트 잠금: OS 객체 키(`win:COMn`·`tty:<major>:<minor>`·URL), 호스트 전체(작업 공간·클론·WSL 배포판), `os.open` 전에 잡고 승인 대기 중에도 쥔다, 커널이 해제(abstract 소켓). 역할 표지(instrument / instrument-aux / target / bridge) | 서버 안 레지스트리 + 열고 나서 flock·`/proc` 검사(최선 노력) |
| `src/pweh/procutil.py` | 프로세스 신원·생존 확인, pidfd·그룹 종료, 소유자 기록 | 증분 B: 공용 함수 구현, pweh-emu 의 종료·고아 정리에 사용 |
| `src/pweh/espfmt.py` | ESP 파티션·앱·NVS 해석 | 증분 B: fwtriage 에서 코어로 이동, 기존 경로는 재노출 shim. fwtriage·emu 가 함께 사용 |
| `src/pweh/console.py`, `src/pweh/safety/redact.py` | 줄 경계 커서·반복 접기·열린 프롬프트, 공용 자격증명 패턴·알려진 비밀값 마스킹 | 증분 B: emu 콘솔에 사용, fwtriage 는 공용 패턴을 가져옴 |
| `src/pweh/evidence.py` 보호 하위 트리 가드 | `forensics/`·`emu/` 를 다른 도구의 입력에서 제외 | 증분 B: case·fwtriage·sigrok 적용, 원시 콘솔은 emu_read 로만 표시 |
| `src/pweh/safety/attestations.py` | 사람 증명 레코드(재사용 가능, 대상·바인딩·만료) | I1 에서 구현 — §3 구현 상태 |
| `src/pweh/provenance.py` | 출처 원장(기기에서 읽은 산출물만 기록) | I1 에서 구현 — §4 구현 상태 |
| `src/pweh/safety/rf.py`, `src/pweh/rf/` | 지역 대역표·RF 수신 분류기, `.sub`/`.ook`/펄스 파서 | 없음 |
| `src/pweh/nfc/` | `.nfc`·CU 형식, ISO14443A 프레임, 태그 계열 판정 | 없음 |
| `src/pweh/jtag/jep106.py` | JEP106 제조사 코드 해석(jtagulator·espprobe 공용) | I5: 코어 구현, 기존 경로는 호환 재노출 |
| `src/pweh/jtag/pinout_scan.py` | 순열 수·`lower_bound_seconds`, 결과 형식 `pweh.pinout-scan/v1`(`pweh.jtagulator-scan/v1` 일반화) | I5: 공용 계산·스키마, JTAGulator 새 결과는 일반 형식으로 기록 |
| `src/pweh/safety/probes.py` | UART 프로브 문자열 분류 `classify_uart_probe`(한 번·두 번 이어 붙인 형태) | I5: 공용 분류, 기존 규칙 ID·import 경로 유지 |
| `src/pweh/srzip.py` | sigrok `.sr` 쓰기 `write_srzip`(espprobe 캡처·sigrok 공용) | I5: 공용 writer, 기존 경로는 호환 재노출 |

## 2. 환경 감지와 물리 연결 라우팅

> 전체 설계(감지 결정 트리, 장치 종류 × 플랫폼 라우팅 표 R1–R18, 현재 코드의 빈틈 G1–G16, 단계·시험·결정 D1–D8)는 [port-routing.md](port-routing.md). 여기에는 다른 문서가 기대는 결론만 둔다.
> P0 감지는 구현됐다. 아래의 통합 라우팅·Windows COM 헬퍼·호스트 전체 잠금은 P1 이후 제안이며, I5의 계측기 식별·거부 규칙이 이를 대신 구현한 것은 아니다.

- **검증 기준 환경**: WSL2(interop 켜짐), usbipd 없음. 이런 환경에서 지금 하드웨어에 닿는 경로는 pweh-esp 방법 A(esptool.exe + COMn) 하나다.
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
> 케이스 사본 `attestations.json`(0400, 증거 아님). 계약은 architecture.md §4, safety.md §3.5·§4 규칙 12. **증명을 요구하는 도구는 I2b 의 `fw_patch_build`(세이브 쓰기 명령을 보여 주기 전 `console-offline`)와 I3b 의 `forensics_acquisition_attest`(SD 카드 이미지를 쓰기 방지 장치로 만들었는지 — `write-blocker`)와 증분 B 의 `emu_start`(가져온 파일의 `provenance-import`)다**.
> 설계와 다른 점: 사람 쪽은 `pweh approve` 의 증명 화면이 아니라 별도 명령 `pweh attest` 다. `require` 에 서버가 지금 묻는 질문을 넘겨 질문이 늘면 예전 증명을 쓰지 않는다.
> 유효 기간은 범위별 코드 기본값(case 7일·connection 12시간·job 24시간·instrument 는 철회까지, 서버가 `valid_seconds` 60초~90일), pending 은 `approval_ttl_seconds`,
> 확인 경로는 `safety.approval_methods`(새 설정 키 없음)다. 연결 해제·재연결·장치 시리얼 변화에 따른 무효화는 바인딩·subject 지문으로만 된다(연결 토큰을 쓰는 서버가 아직 없다).
> 반박 검증 뒤 보강: `pweh attest` 는 승인이 되는 답이면 화면의 확인 코드를 입력받는다(`pweh approve` 와 같은 수준), `decided_by` 는 OS 계정 이름($USER 아님),
> 시간대 없는 시각의 레코드는 불신(저장소는 멈추지 않음), 디렉터리 0700. `valid_seconds` 는 새 레코드에만 적용된다(기존 레코드는 그 만료를 따름 — 문서화).
> **케이스 ID 재사용 방지**: `case_create`는 기존 케이스 경로(불완전 디렉터리·링크 포함), 보호 생성 예약, 출처·솔트·custody 흔적, 승인·증명의 케이스 참조가 남은 ID를 재사용하지 않는다. 명시 ID는 충돌을 거부하고 자동 ID는 확인된 충돌을 `-2`, `-3` 등으로 건너뛴다.
> 생성은 보호 상태의 잠금과 `case-ids/<casefold ID의 sha256>.json` 영구 예약으로 묶는다. 케이스 디렉터리를 지워도 예약은 남으며, 해당 예약 경로는 본문을 읽지 않고 어떤 객체든 충돌로 본다. 출처·솔트·custody는 이름으로 ID를 차단한다. 승인·증명 폴더의 손상·링크·미완성 기록·알 수 없는 항목이나 검사 한도 때문에 참조를 확인할 수 없으면 생성 자체를 거부한다. 감사 로그 단독 흔적은 검사 대상이 아니다. 계약과 동시 실행의 한계는 architecture §3·§6.1과 safety.md를 따른다.

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
> 기록하는 곳은 지금 셋이다: pweh-esp(`esp_read_flash_start` 의 끝까지 성공한 덤프 = `device-read`, `esp_chip_info`·`esp_security_info` = `device-fact`),
> `case_import_file`(`imported-unattested`), I3b 의 `forensics_intake_start`(SD 카드 이미지의 접수 기록 파일 = `imported-unattested`, 이미지 sha256·크기는 extra — PWEH 는 카드를 읽지 않으므로
> 기기 읽기가 아니다. 사본 검증·추출은 SD 카드 보관 기록에 남는다 — safety.md §3.5). 나머지 기록 지점(Flipper·CU·수신 job·espprobe)과 확인 지점(SD 올리기·
> `espprobe_flash_plan`)은 그 서버를 만들 때 붙인다 — `verify` 를 부르는 도구는 I2b 의 `fw_patch_build`·`fw_verify_writeback` 과 증분 B 의 `emu_start` 다. `emu_start` 는 `verify(data=…)` 로 한 번 읽은 바이트를 확인한 뒤 봉인 memfd 로 전달한다. 원장에 `patch-plan` kind(쓰기 확인의 권위 기록)가 더해졌다. `provenance-import` 증명의 대상은 `provenance_import_target(case_id, sha256)`·
> `PROVENANCE_IMPORT_QUESTIONS` 하나로 정했다. 기록 실패는 도구 결과를 막지 않고 응답의 `provenance.recorded=false` 로 알린다.
> 반박 검증 뒤 보강: 이중 읽기가 어긋난 덤프(`source.match=false`)는 기록하되 `verify` 가 불신한다(`device-read-mismatch` — 출처 ≠ 무결성). `case_import_file` 은 state_dir 의 파일을 거부하고,
> 대상을 `O_EXCL` 로 만들며 복사하면서 해시한다. 확인과 사용 사이의 변경(TOCTOU)은 소비자가 sha256 을 승인 지문·job 인자에 묶어 막는다(architecture §4).

**왜**: "이 케이스에서 읽은 것만 에뮬레이션/올리기", "다운로드한 덤프 금지", "남의 태그 복제 금지"는 출처를 코드로 확인해야 지킬 수 있다. 지금 `case.json` 아티팩트의 `producer` 는 자동 허용 도구의 자유 인자라 증거가 못 된다.

- **위치**: `.pweh/state/provenance/<case_id>.jsonl`(보호 대상).
- **기록하는 곳**: 기기 읽기 코드 경로만 — `flipper_nfc_read_start`, `nfc_cu_read_start`, 수신 job, `esp_read_flash_start`, espprobe 읽기, SD 이미지 해시 검증 등. 항목: sha256, 장치 식별(UID/주파수/장치 시리얼), 인벤토리·증명 id, 시각.
  산출물 외에 기기 사실도 기록한다(pweh-esp `esp_chip_info`·`esp_security_info` 결과 — ESP32 계측기를 플래시하기 전 백업·보안 상태 확인의 근거).
- **확인하는 곳**: 에뮬레이션, SD 올리기, (향후) 송신, 패치 base, `espprobe_flash_plan`(계측기 플래시 절차를 보여 주기 전). 산출물을 다시 해시해 원장과 맞춰 본다.
- `case_import_file` 과 Flipper 기존 폴더에서 가져온 파일은 `imported-unattested` 로 기록되고, `provenance-import` 증명이 있을 때만 쓸 수 있다. 출처 확인은 `producer` 를 보지 않는다.

> **증분 B**: 에뮬레이션 출처 확인 지점이 구현됐다. 가져온 ESP/AVR 파일은 `provenance-import` 사람 증명 뒤 실행한다(architecture §6.9). 단일 읽기는 경고와 함께 허용하고 이중 읽기 불일치는 거부한다.

## 5. 비밀값 마스킹

> **구현 상태 (I1)**: 코어 구현 — `src/pweh/safety/masking.py`. `rt().secret_digest(case_id, 값)` = `sha256:` + sha256(케이스 솔트 ‖ 값)의 앞 16 hex
> (솔트 `.pweh/state/salts/<case_id>.key`, 32 바이트, 0600, 처음 쓸 때 만듦), 표시용 `mask_secret`. 테스트는 게이트 action·감사 로그·승인 레코드에 원문이 없음을 확인한다
> (`approval_status` 응답·보고서는 그 레코드·감사 로그에서 나오므로 따로 시험하지 않았다). 기존 `shell_login`의 게이트 인자는 `<given>`이다.
> I2a: `fw_esp_nvs`·`fw_save_diff` 가 NVS 비밀값 표시에 코어 `mask_secret` + `rt().secret_digest` 를 쓴다(첫 소비자 — 게이트 action 이 아니라 응답·결과 파일).
> 반박 검증으로 확인한 한계: 솔트는 같은 계정의 에이전트가 읽을 수 있다(자동 허용된 REA `open_binary` + `read_bytes`). 다이제스트는 보고서·감사 로그를 읽는 제3자에게서만 원문을 가린다
> — 낮은 엔트로피 값은 게이트에 넣지 않는다(safety.md §3.5). 자동 허용된 REA `export_evidence_bundle`·`close_binary` 는 `.pweh/state` 를 덮어쓸 수 있다(위조는 안 되고 실패 쪽으로 닫힘)
> — allow 에서 빼고 묻기(ask)로 둘지는 사용자 결정(지금은 그대로). 비밀번호 프롬프트에 `uart_send_command` 로 입력하면 원문이 감사 로그에 남는다 → 로그인은 `shell_login`.

- 대상: 콘솔 PWD_AUTH 비밀번호, 사용자 MIFARE 키, 롤링코드·고정코드 값, 비대상 RF 기기 ID, Wi-Fi PSK·클라우드 토큰(SD·NVS 에서 찾은 것).
- 원문은 케이스 파일(필요한 것만)에만. 도구 응답·보고서는 마스킹, **게이트 `action` 과 `classification.matched` 에는 솔트 다이제스트**(`sha256(case_salt || 값)`) 또는 `<given>` 만 — 승인 지문도 다이제스트로 묶는다.
  감사 로그·승인 레코드·`approval_status` 응답·보고서에 원문이 없음을 확인하는 테스트를 둔다.
- 낮은 엔트로피 ID(24–32비트)는 케이스 솔트 HMAC 도 되돌릴 수 있으므로, 비대상 정보는 가능하면 개수만 남긴다.

## 6. 안전 관련 설정의 위치

아래의 새 `safety.*` 키·`authorize(policy_key=...)`·정책 해시 기록은 **미승인 후속 설계**이며 현재 설정에 추가하지 않았다. 현재 지원하는 설정·게이트 계약은 architecture §4를 따른다.

- 새 정책 설정은 모두 `safety:` 아래에 둔다(AGENTS.md 가 에이전트 수정을 금지하는 범위): `safety.play_policy`·`safety.play.{max_duration_s, max_inputs, rate}`, `safety.rf.{region, rx_extra_bands, allow_amp}`,
  `safety.nfc.cu_slot`, `safety.forensics.*`(SD 포렌식), `safety.ports.remote_serial_hosts`(원격 시리얼 LAN 호스트, port-routing §5.5),
  `safety.espprobe.*`(컴파일된 한도를 좁히기만 하는 키와, 무선 프로필처럼 운영자만 켜는 opt-in 키를 구분 — esp32-instrument §2.5). 외부 도구 경로(`tools.*`)는 실행 파일 이름 허용 목록으로 검사한다(esptool 의 espefuse/espsecure 거부와 같은 방식, 송신 가능 도구는 거부).
- `SafetyConfig` 는 모르는 `safety.*` 키를 거부한다(오타가 조용히 무시되지 않게). (제안 — 지금은 모르는 키를 조용히 무시하고 필드도 평평하다, `src/pweh/config.py:139-151`.)
- **호스트 위험**: UAC 가 꺼진 관리자 계정 호스트에서는 interop 으로 띄운 Windows 프로세스가 관리자 권한(High IL)으로 돈다. `wsl.exe -u root` 는 어디서나 비밀번호 없는 root 이고(MS 문서), `docker`·`disk` 그룹은 root 와 같다(sd-forensics §0).
  그래서 OS 계정 분리만으로는 이 권한을 차단하지 못한다. AGENTS.md 호스트 위험 규칙과 `.claude/settings.json` deny 규칙 추가 제안은 사용자 결정에 따라 적용하지 않았다.
  코드 쪽은 port-routing §11 의 interop 실행 허용 목록(`wsl.exe`·`cmd.exe`·diskpart 등 거부)이 맡는다. UAC 설정은 사용자 결정이다.
- `authorize(..., policy_key=...)` 를 더해 위험도 대신 기능별 정책(`safety.play_policy`)을 고를 수 있게 한다(지금은 play 만, rf 송신·esp 쓰기 키는 그 기능이 생길 때).
- 서버는 시작 때 유효한 안전 설정의 해시를 감사 로그에 남기고 승인 지문에 넣는다. `pipeline_safety_policy` 가 새 키를 모두 보여 준다.

## 7. master-prompt: 목표 분기

> **구현 상태 (I1 이후)**: master-prompt Phase 0 에 목표 표(보안 분석 = 지원, 게임·SD = 일부 지원, RF = 준비 중), 목표별 장비 체크리스트,
> 고른 목표를 `case_create` 의 `notes` 에 기록, §3.1에서 지금 할 수 있는 일, §9 목표별 완료 기준(펌웨어 확보는 보안 분석만), pweh-start 설명이 있다.
> 설계와 다른 점: `PIPELINE_PHASES` 는 그대로 두고 선택 단계 레지스트리 `OPTIONAL_PHASES`(기록될 때만 생김)와 보고서 §4 의 '선택 단계' 블록·라벨을 더했다.
> 게임은 `game-save-unlock-analysis`와 fwtriage, SD는 `sd-card-forensics`와 `pweh-forensics`로 일부 지원한다. B·C·D에서 `firmware-emulation`·`image-hints-analysis`·`android-forensics`도 추가됐다. RF 전용 Skill·서버는 아직 없다.

- Phase 0 접수에서 목표를 먼저 고른다: **보안 분석**(기존 CCTV/IoT 흐름) / **게임 콘솔 분석** / **RF·하드웨어 분석** / **SD 카드 포렌식**.
- 목표마다 장비 체크리스트·완료 기준이 다르다. master-prompt §9는 펌웨어 확보를 보안 분석에서만 요구한다.
- pweh-start 설명·보고서 섹션·라벨은 목표를 반영한다. `PIPELINE_PHASES`의 기존 보안 분석 단계와 선택 단계 레지스트리를 함께 쓴다.

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
