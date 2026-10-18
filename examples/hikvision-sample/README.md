# hikvision-sample: hikvision-like 합성 IP 카메라 — UART 덤프와 인증 우회 패턴 탐색 예제

> **합성 예제.** 기기는 `pweh.mocktarget` 시뮬레이터이고 펌웨어는 PWEH 가 만든 합성 테스트 펌웨어다 (`PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE`). 실제 벤더 코드·키·자격증명·공격 요청은 없다. 이 디렉터리의 모든 출력은 `scripts/run_example.py` 를 실제로 실행해 얻었다 (손으로 쓴 결과 없음).

## 한 줄 결론

U-Boot 프롬프트 확보 → 플래시 16 MiB 덤프(청크별 crc32 일치) → rootfs 추출·감사 + REA/Ghidra 디컴파일 → 발견사항 8건 (치명 3, 높음 4, 중간 1). 심어 둔 정답 8개 중 8개가 도구 출력에 드러났고, 기기에 닿은 파괴적 명령은 0건이다.

## 1. 시나리오

- Hikvision 스타일 구성(메인 앱 davinci, ISAPI/PSIA/SDK/HikCGI 형 핸들러 계열)을 흉내 낸 합성 카메라다. 운영자는 자기 소유 카메라라고 확인했고, 보드의 UART 패드에 USB-UART 를 연결했다(여기서는 시뮬레이터 PTY).
- 소유/허가 확인 (사람의 말 그대로 인용, 합성): "이 카메라는 제가 직접 구매한 제 소유 기기이며, 하드웨어 보안 분석을 허가합니다. (합성 시나리오: pweh.mocktarget 시뮬레이터)"
- 케이스 프로필: `hikvision-ipc` (orchestrator/pipeline-config.yaml), 시뮬레이터 프로필: `hikvision-like`
- 역할: **사람**은 배선·전원·동의를 맡고(타임라인의 `[사람]` 줄), **에이전트**는 MCP 도구만 쓴다. 에이전트 판단은 `tests/e2e/agent_flow.py` 에 스크립트로 들어 있고 Skill 순서(uart-shell-acquisition → firmware-dump-via-uart → firmware-static-analysis → cctv-auth-bypass-hunt → report)를 따른다.
- REA/Ghidra: 사용함 (rea --mcp, Ghidra 12.1.x)

## 2. 무엇이 합성인가

| 구성요소 | 실체 |
|---|---|
| 기기 | `pweh.mocktarget.MockDevice` (U-Boot 2016.11 포크 흉내, HiSilicon V4 유사 하드웨어, PTY 로 연결) |
| 펌웨어 | `pweh.mocktarget.firmware.build_image('hikvision-like')` 가 만든 16 MiB SPI NOR 이미지, sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2` (빌드는 결정적) |
| 벤더 스타일 메인 앱 | `/usr/bin/davinci` ← `src/pweh/mocktarget/profiles/vendor_src/davinci_like.c` (zig arm-linux-musleabi, 합성 C 코드) |
| 공통 웹 서버 | `/usr/sbin/httpd` ← `src/pweh/mocktarget/firmware_src/httpd.c` (합성) |
| 벤더 이름·경로 | `docs/references/cctv-vuln-patterns.md` §3 에 공개된 펌웨어 쪽 지표(바이너리 이름, 배너, 핸들러·설정 경로)만 빌림 |
| 토큰·비밀번호 | 모두 합성 값. 이 예제에서는 마스킹(`<마스킹:…>`)했다 |

심어 둔 정답(ground truth, 펌웨어 매니페스트 `planted_issues`). 에이전트 흐름은 이 목록을 읽지 않는다:

| ID | 분류 | 심각도 | 파일 :: 함수 | 내용 | 모델로 삼은 공개 클래스 |
|---|---|---|---|---|---|
| PWEH-PLANT-01 | backdoor | critical | `/usr/sbin/httpd` :: `check_auth` | 웹 서버 인증 검사 안의 하드코딩된 백도어 토큰 비교 | (공통 합성 httpd/rootfs) |
| PWEH-PLANT-02 | auth-bypass | high | `/usr/sbin/httpd` :: `is_static_resource` | 정적 파일 접두어/접미어 경로에 대한 인증 생략 (URI 부분 문자열 매칭) | (공통 합성 httpd/rootfs) |
| PWEH-PLANT-03 | command-injection | critical | `/usr/sbin/httpd` :: `handle_ping_cgi` | CGI 요청 파라미터가 system() 으로 전달되는 명령 주입 | (공통 합성 httpd/rootfs) |
| PWEH-PLANT-04 | hardcoded-credential | high | `/usr/sbin/httpd` :: `check_credentials` | 하드코딩된 관리자 계정/비밀번호 | (공통 합성 httpd/rootfs) |
| PWEH-PLANT-05 | debug-interface | medium | `/etc/init.d/rcS` | 부팅 시 telnetd 무조건 실행 | (공통 합성 httpd/rootfs) |
| PWEH-PLANT-06 | hardcoded-credential | high | `/etc/shadow` | 약한 MD5-crypt root 비밀번호 해시 (기본 비밀번호) | (공통 합성 httpd/rootfs) |
| PWEH-HIK-01 | auth-bypass | critical | `/usr/bin/davinci` :: `hikcgi_auth` | HikCGI 형 핸들러 계열에만 있는 매직 파라미터 인증 생략 (비밀번호 무시) | CVE-2017-7921 |
| PWEH-HIK-02 | command-injection | critical | `/usr/bin/davinci` :: `handle_web_language` | 인증 전 언어 설정 핸들러의 language 값 → system() 명령 주입 | CVE-2021-36260 |

## 3. 재현 방법

```bash
cd pweh && .venv/bin/python scripts/run_example.py --profile hikvision-like --name hikvision-sample
```

- 필요: `.venv` (pip install -e ".[dev]"), `~/pweh-tools` 의 zig·mksquashfs·unsquashfs (전체 합성 펌웨어 빌드와 squashfs 추출).
- 선택: REA(`rea --mcp`) + Ghidra (`~/pweh-tools/env.sh`). 없으면 디컴파일 단계를 건너뛰고 README 에 그 사실을 적는다 (`--no-rea` 로 강제).
- 소요: 약 78초 (덤프는 시뮬레이터라 빠르다. 실기기 115200bps 에서 16 MiB md.b 덤프는 약 2.0시간).
- 시각·job id·PTY 경로·evidence id 는 실행마다 다르다 (케이스 ID 는 `example-hikvision-sample` 로 고정). 같은 도구 버전이면 펌웨어·덤프·추출물의 sha256 은 같다.
- 같은 흐름이 `tests/e2e/test_pipeline_e2e.py` 의 테스트다 (`.venv/bin/python -m pytest tests/e2e -q`).

## 4. 타임라인 (도구 호출과 요약 응답)

전체 인자·응답(요약)은 [tool-calls.jsonl](tool-calls.jsonl). `[사람]` 은 사람이 한 일, `[에이전트]` 는 에이전트의 판단·안내다.

| # | t(s) | 단계 | 서버 | 도구 / 행동 | 인자 | 응답 요약 |
|---|---|---|---|---|---|---|
|  | 0.8 | phase-0 접수 |  | *[에이전트] phase-0 접수 시작 — 소유/허가 확인 → 케이스 생성* |  |  |
|  | 0.8 | phase-0 접수 |  | *[사람] 소유 확인 답변: "이 카메라는 제가 직접 구매한 제 소유 기기이며, 하드웨어 보안 분석을 허가합니다. (합성 시나리오: pweh.mocktarget 시뮬레이터)"* |  |  |
| 1 | 0.8 | phase-0 접수 | pweh-case | `pipeline_profiles` |  | 프로필 14개 |
| 2 | 0.8 | phase-0 접수 | pweh-case | `pipeline_safety_policy` |  | destructive=deny, modify=allow |
| 3 | 0.8 | phase-0 접수 | pweh-case | `case_create` | title=…, authorization={basis: owned, statement: …}, profile=hikvision-ipc | case_id=example-hikvision-sample, authorized=True |
|  | 0.8 | uart-shell-acquisition |  | *[에이전트] uart-shell-acquisition 시작 — 포트 → 배선 → 보드레이트(프로필) → 부팅 로그 → U-Boot 진입 → env/보드 정보* |  |  |
| 4 | 0.8 | uart-shell-acquisition | pweh-case | `case_get` |  | ok |
| 5 | 0.8 | uart-shell-acquisition | pweh-case | `case_get_step_results` |  | summaries=[] |
| 6 | 0.8 | uart-shell-acquisition | pweh-case | `pipeline_profile` | name='hikvision-ipc' | ok |
| 7 | 0.8 | uart-shell-acquisition | pweh-case | `case_set_phase` | phase='uart-shell-acquisition', status='in-progress' | ok |
| 8 | 0.9 | uart-shell-acquisition | pweh-uart | `uart_list_ports` | include_links=true | 포트 8개 (PTY 시뮬레이터는 목록에 없음) |
|  | 0.9 | uart-shell-acquisition |  | *[사람] UART 배선 완료: GND–GND, 기기 TX → 어댑터 RX, 기기 RX → 어댑터 TX, VCC 미연결. TX 3.3V 측정. 포트는 /dev/pts/8 (시뮬레이터 PTY — uart_list_ports 목록에는 없다)* |  |  |
| 9 | 0.9 | uart-shell-acquisition | pweh-uart | `uart_open` | port='/dev/pts/8', baudrate=115200, label='console' | session_id=console-001, context=unknown, log=uart/console-001.log |
|  | 1.0 | uart-shell-acquisition |  | *[에이전트] 부팅 로그를 감시하는 동안 전원을 넣어 달라고 요청 (H3)* |  |  |
|  | 1.0 | uart-shell-acquisition |  | *[사람] 기기 전원을 켠다 — 에이전트 요청: uart_capture_boot 감시 시작 직후* |  |  |
| 10 | 1.0 | uart-shell-acquisition | pweh-uart | `uart_capture_boot` | session_id='console-001', duration=45 | 5900 B, kernel=4.9.37, stopped_by=prompt:askfirst:login |
|  | 3.4 | uart-shell-acquisition |  | *[에이전트] autoboot 메시지 확인 (bootdelay 2) → 전원을 먼저 꺼 달라고 요청하고, '준비' 뒤 uboot_interrupt 감시를 시작하면 전원을 넣어 달라고 안내* |  |  |
|  | 3.4 | uart-shell-acquisition |  | *[사람] 기기 전원을 끈다 — 에이전트 요청: uboot_interrupt 전에 전원을 꺼 둠* |  |  |
|  | 3.4 | uart-shell-acquisition |  | *[사람] 전원을 껐습니다. 준비* |  |  |
|  | 3.4 | uart-shell-acquisition |  | *[사람] 기기 전원을 켠다 — 에이전트 요청: uboot_interrupt 감시 시작 직후* |  |  |
| 11 | 3.4 | uart-shell-acquisition | pweh-uart | `uboot_interrupt` | session_id='console-001', window_seconds=30 | interrupted=True, prompt='hisilicon # ', bootdelay=2 |
|  | 4.2 | uart-shell-acquisition |  | *[에이전트] U-Boot 에서 멈췄다. 전원은 그대로 두라고 안내* |  |  |
| 12 | 4.2 | uart-shell-acquisition | pweh-uart | `uboot_printenv` | session_id='console-001' | 변수 19개, 파티션 ['boot', 'env', 'kernel', 'rootfs', 'app'], bootcmd='sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000' |
| 13 | 4.2 | uart-shell-acquisition | pweh-uart | `uboot_info` | session_id='console-001' | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300; flash W25Q128(B/F)V 16777216 B; safe_ram_addr=0x42000000 |
| 14 | 4.5 | uart-shell-acquisition | pweh-case | `case_update_target` | target={"soc": "hi3516ev300 (U-Boot env soc)", "flash": "W25Q128(B/F)V spi… | ok |
| 15 | 4.5 | uart-shell-acquisition | pweh-case | `case_add_note` | text='UART: GND-GND, 기기 TX-어댑터 RX, 기기 RX-어댑터 TX, VCC 미연결, TX 3.3V 측정 (사람… | ok |
|  | 4.5 | uart-shell-acquisition |  | *[에이전트] 의도적 실수 시연: 영구 변경 명령을 U-Boot 에 보내 본다 (서버 게이트가 막아야 한다)* |  |  |
| 16 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_send_command` | session_id='console-001', command='saveenv' | **denied** (위험도 destructive, 규칙 `uboot.saveenv`) |
| 17 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_send_command` | session_id='console-001', command='sf erase 0x0 0x10000' | **denied** (위험도 destructive, 규칙 `uboot.sf.erase`) |
| 18 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_send_command` | session_id='console-001', command='setenv bootdelay 0; saveenv' | **denied** (위험도 destructive, 규칙 `uboot.saveenv`) |
| 19 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_send_command` | session_id='console-001', command='env save' | **denied** (위험도 destructive, 규칙 `uboot.env.save`) |
| 20 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_write` | session_id='console-001', data='sa' | ok=True, pending_input='sa' |
| 21 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_write` | session_id='console-001', data='veenv\r' | **denied** (위험도 destructive, 규칙 `uboot.saveenv`) |
| 22 | 4.5 | uart-shell-acquisition | pweh-uart | `uart_sync` | session_id='console-001' | evidence=uboot, context=uboot |
|  | 4.6 | uart-shell-acquisition |  | *[에이전트] 거부를 우회하지 않고 사용자에게 보고한 뒤 읽기 전용 작업을 계속한다* |  |  |
| 23 | 4.6 | uart-shell-acquisition | pweh-case | `case_record_step` | skill=uart-shell-acquisition, step=summary, status=success, data={…} | seq=1, status=success (스키마 통과) |
|  | 4.6 | firmware-dump-via-uart |  | *[에이전트] firmware-dump-via-uart 시작 — 덤프 범위: full* |  |  |
| 24 | 4.6 | firmware-dump-via-uart | pweh-case | `case_get` | include_artifacts=true | ok |
| 25 | 4.6 | firmware-dump-via-uart | pweh-case | `case_get_step_results` |  | summaries=['uart-shell-acquisition'] |
| 26 | 4.6 | firmware-dump-via-uart | pweh-case | `case_get_step_results` | skill='firmware-dump-via-uart', summaries_only=false | 단계 기록 0개 (재개할 job 없음) |
| 27 | 4.6 | firmware-dump-via-uart | pweh-case | `case_set_phase` | phase='firmware-dump-via-uart', status='in-progress' | ok |
| 28 | 4.6 | firmware-dump-via-uart | pweh-uart | `uart_sessions` |  | 세션 [('console-001', 'open')] |
| 29 | 4.6 | firmware-dump-via-uart | pweh-uart | `uboot_printenv` | session_id='console-001' | 변수 19개, 파티션 ['boot', 'env', 'kernel', 'rootfs', 'app'], bootcmd='sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000' |
| 30 | 4.7 | firmware-dump-via-uart | pweh-uart | `uboot_info` | session_id='console-001' | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300; flash W25Q128(B/F)V 16777216 B; safe_ram_addr=0x42000000 |
|  | 4.9 | firmware-dump-via-uart |  | *[에이전트] [확인 필요] 덤프 계획: U-Boot md.b, 0x0+0x1000000 (전체 플래시 (백업·복구·분석 겸용)), 청크 256k (시뮬레이터 시간 단축용, 허용 최대), 실기기 115200bps 기준 약 120분. 대안: tftpput / SPI 클립 / 셸 base64* |  |  |
|  | 4.9 | firmware-dump-via-uart |  | *[사람] 덤프 계획에 동의 (전체 플래시 (백업·복구·분석 겸용))* |  |  |
| 31 | 4.9 | firmware-dump-via-uart | pweh-uart | `uboot_dump_start` | session_id='console-001', offset=327680, length=65536, output_name='probe-kernel-head' | job_id=job-503a7c3b, 청크 1×65536 B, ram_addr=0x42000000, 실기기 예상 0분 |
| 32 | 4.9 | firmware-dump-via-uart | pweh-uart | `uart_job_status` | job_id='job-503a7c3b', wait_seconds=50 | status=succeeded, progress=1.0, sha256=b6f2e962ba93c66e…, verification=crc32-chunks |
|  | 5.5 | firmware-dump-via-uart |  | *[에이전트] 시험 덤프 정상 (sf read·md.b·crc32 동작, 재시도 0회) → 본 덤프 시작* |  |  |
| 33 | 5.5 | firmware-dump-via-uart | pweh-uart | `uboot_dump_start` | session_id='console-001', offset=0, length=16777216, output_name='flash-full', chunk_size='256k' | job_id=job-2297b6cb, 청크 64×262144 B, ram_addr=0x42000000, 실기기 예상 119분 |
| 34 | 5.5 | firmware-dump-via-uart | pweh-case | `case_record_step` | skill=firmware-dump-via-uart, step=job-flash-full, status=in-progress, data={…} | seq=2, status=in-progress (스키마 통과) |
| 35 | 5.6 | firmware-dump-via-uart | pweh-uart | `uart_job_status` | job_id='job-2297b6cb', wait_seconds=50 | status=succeeded, progress=1.0, sha256=e95ae853526947b9…, verification=crc32-chunks |
| 36 | 45.4 | firmware-dump-via-uart | pweh-case | `case_record_step` | skill=firmware-dump-via-uart, step=job-flash-full, status=success, data={…} | seq=3, status=success (스키마 통과) |
| 37 | 45.4 | firmware-dump-via-uart | pweh-fwtriage | `fw_identify` | path='dumps/flash-full.bin' | 영역 9개 {'uboot-version': 1, 'pweh-synthetic-marker': 3, 'uboot-env': 1, 'uimage': 1, 'linux-version': 1, 'squashfs': 2}, arch ['arm'] |
| 38 | 45.6 | firmware-dump-via-uart | pweh-fwtriage | `fw_carve` | path='dumps/flash-full.bin', partitions=[{"name": "xcheck", "offset": "0x50000", "size": "0x10000"}], output_label='xcheck' | extract/xcheck-001: xcheck(uimage) |
| 39 | 45.7 | firmware-dump-via-uart | pweh-case | `case_get` | include_artifacts=true | ok |
| 40 | 45.7 | firmware-dump-via-uart | pweh-uart | `uart_close` | session_id='console-001' | 닫음, 로그 아티팩트 3개 |
| 41 | 45.9 | firmware-dump-via-uart | pweh-case | `case_record_step` | skill=firmware-dump-via-uart, step=summary, status=success, data={…} | seq=4, status=success (스키마 통과) |
|  | 45.9 | firmware-static-analysis |  | *[에이전트] firmware-static-analysis 시작 — 지도 → 분할 → 추출 → 감사 → (REA) 디컴파일* |  |  |
| 42 | 45.9 | firmware-static-analysis | pweh-case | `case_get` |  | ok |
| 43 | 45.9 | firmware-static-analysis | pweh-case | `case_get_step_results` |  | summaries=['firmware-dump-via-uart', 'uart-shell-acquisition'] |
| 44 | 45.9 | firmware-static-analysis | pweh-case | `pipeline_profile` | name='hikvision-ipc' | ok |
| 45 | 45.9 | firmware-static-analysis | pweh-case | `case_paths` | purpose='extract', label='rea' | ok |
| 46 | 45.9 | firmware-static-analysis | pweh-case | `case_set_phase` | phase='firmware-static-analysis', status='in-progress' | ok |
| 47 | 45.9 | firmware-static-analysis | pweh-fwtriage | `fw_identify` | path='dumps/flash-full.bin' | 영역 9개 {'uboot-version': 1, 'pweh-synthetic-marker': 3, 'uboot-env': 1, 'uimage': 1, 'linux-version': 1, 'squashfs': 2}, arch ['arm'] |
| 48 | 46.1 | firmware-static-analysis | pweh-fwtriage | `fw_entropy` | path='dumps/flash-full.bin' | profile='*##______#@@@@._____________________________________________', 설명 안 되는 고엔트로피 1 |
| 49 | 46.6 | firmware-static-analysis | pweh-fwtriage | `fw_uboot_env` | path='dumps/flash-full.bin' | env 1개, 레이아웃 env:bootargs: mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app) |
| 50 | 46.6 | firmware-static-analysis | pweh-fwtriage | `fw_carve` | path='dumps/flash-full.bin' | extract/parts-001: boot(bootloader), env(uboot-env), kernel(uimage), rootfs(squashfs), app(squashfs) |
| 51 | 46.7 | firmware-static-analysis | rea | `inspect_firmware_regions` | path='<CASE_DIR>/dumps/flash-full.bin' | ok |
| 52 | 47.4 | firmware-static-analysis | pweh-fwtriage | `fw_uimage_info` | path='extract/parts-001/02-kernel.bin' | Linux-4.9.37 arm comp=none hcrc=True dcrc=True |
| 53 | 47.4 | firmware-static-analysis | pweh-fwtriage | `fw_extract_squashfs` | path='extract/parts-001/03-rootfs.bin' | complete → extract/rootfs-001 (180 항목) |
| 54 | 48.0 | firmware-static-analysis | pweh-fwtriage | `fw_extract_squashfs` | path='extract/parts-001/04-app.bin', output_label='app' | complete → extract/app-001 (6 항목) |
| 55 | 48.7 | firmware-static-analysis | rea | `extract_firmware` | path='<CASE_DIR>/extract/parts-001/03-rootfs.bin', output_directory='<CASE_DIR>/extract/rea-001' | coverage=partial, 파일 27개 |
| 56 | 50.2 | firmware-static-analysis | pweh-case | `case_register_artifact` | path='extract/rea-001', kind='extracted-tree', producer='rea', description='REA unblob 교차 추출 (rootfs 파티션)' | ok |
| 57 | 50.2 | firmware-static-analysis | pweh-fwtriage | `fw_rootfs_audit` | rootfs_dir='extract/rootfs-001' | 항목 3개 [('builtin-default-password', 'critical'), ('gen-telnetd-launch', 'medium'), ('passwd-md5-crypt', 'medium')], vendor=hikvision-like |
| 58 | 50.3 | firmware-static-analysis | pweh-fwtriage | `fw_strings_hunt` | path_or_dir='extract/rootfs-001' | 히트 10개 {'medium': 3, 'info': 4, 'high': 2, 'low': 1}: gen-backdoor-keywords, gen-hardcoded-basic-auth, gen-shell-cmd-template, gen-telnetd-launch, hik-handler-families, hik-hikcgi-endpoints, hik-sdk-weblanguage |
| 59 | 50.7 | firmware-static-analysis | pweh-fwtriage | `fw_crack_hashes` | source_path='extract/rootfs-001/etc/shadow' | {'cracked': 1} root:cracked(54***) |
| 60 | 50.7 | firmware-static-analysis | pweh-fwtriage | `fw_elf_info` | path='extract/rootfs-001' | ELF 7개, 1위 /usr/bin/davinci |
| 61 | 50.8 | firmware-static-analysis | pweh-fwtriage | `fw_elf_info` | path='extract/rootfs-001/usr/bin/davinci' | 32-bit LSB EXEC, arm (EABI5, soft-float), static=True, stripped=False, 휴리스틱 ['fn-auth-literal-compare', 'fn-cgi-env-from-request', 'fn-command-build', 'fn-command-exec', 'fn-debug-listener-ports'] |
| 62 | 50.8 | firmware-static-analysis | pweh-fwtriage | `fw_elf_info` | path='extract/rootfs-001/usr/sbin/httpd' | 32-bit LSB EXEC, arm (EABI5, soft-float), static=True, stripped=False, 휴리스틱 ['fn-auth-literal-compare', 'fn-cgi-env-from-request', 'fn-command-build', 'fn-command-exec', 'fn-debug-listener-ports'] |
|  | 50.8 | firmware-static-analysis |  | *[에이전트] REA/Ghidra 로 /usr/sbin/httpd 분석 (첫 질의에서 자동 분석 — 수십 초)* |  |  |
| 63 | 50.8 | firmware-static-analysis | rea | `open_binary` | path='<CASE_DIR>/extract/rootfs-001/usr/sbin/httpd', provider_id='ghidra' | elf arm sha256=4b733ee710d74675… |
| 64 | 50.9 | firmware-static-analysis | rea | `binary_overview` |  | Ghidra 분석 완료 (13.2s), 세그먼트 25개 |
| 65 | 64.1 | firmware-static-analysis | rea | `search_procedures` | pattern='(?i)auth\|login\|passw\|cred\|session\|token\|verify\|static\|cgi\|lang\|loc…, mode='regex' | check_auth, handle_ping_cgi, handle_status_cgi, handle_login_cgi, is_static_resource, check_credentials, static_init_tls |
| 66 | 64.1 | firmware-static-analysis | rea | `trace_feature` | query='Authorization: Basic' | 참조 함수 ['selftest'] |
| 67 | 64.1 | firmware-static-analysis | rea | `trace_feature` | query='ping -c 1 %s' | 참조 함수 ['handle_ping_cgi'] |
| 68 | 64.1 | firmware-static-analysis | rea | `trace_feature` | query='BACKDOOR' | 참조 함수 ['check_auth'] |
| 69 | 64.2 | firmware-static-analysis | rea | `find_xrefs_to_name` | name='system' | resolved 0x23d14 xrefs=2 |
| 70 | 64.2 | firmware-static-analysis | rea | `procedure_callers` | procedure='system' | 호출자 ['0x22470'] |
| 71 | 64.3 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='selftest' | 의사 C 45줄 (evidence ev_c642e9a6f6a0…) |
| 72 | 64.3 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='handle_ping_cgi' | 의사 C 21줄 (evidence ev_ae3f3cf07e61…) |
| 73 | 64.3 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='check_auth' | 의사 C 40줄 (evidence ev_1fb00ae8271b…) |
| 74 | 64.3 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='handle_status_cgi' | 의사 C 26줄 (evidence ev_5ef3a3e8843b…) |
| 75 | 64.4 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='handle_login_cgi' | 의사 C 24줄 (evidence ev_dfea71b5dc2e…) |
| 76 | 64.4 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='is_static_resource' | 의사 C 18줄 (evidence ev_18e18030140a…) |
| 77 | 64.4 | firmware-static-analysis | rea | `procedure_pseudo_code` | procedure='check_credentials' | 의사 C 14줄 (evidence ev_82064774f0be…) |
| 78 | 64.4 | firmware-static-analysis | rea | `export_evidence_bundle` | path='<CASE_DIR>/analysis/rea-evidence-httpd-001.json' | 16 레코드, 318503 B |
| 79 | 64.4 | firmware-static-analysis | pweh-case | `case_register_artifact` | path='analysis/rea-evidence-httpd-001.json', kind='rea-evidence', producer='rea', description='REA evidence (/usr/sbin/httpd)' | ok |
| 80 | 64.4 | firmware-static-analysis | rea | `close_binary` |  | 세션 닫음 |
| 81 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: 'root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt)', …} | F-001 (duplicate=False) |
| 82 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: '부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방)', …} | F-002 (duplicate=False) |
| 83 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: 'httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명)', …} | F-003 (duplicate=False) |
| 84 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: 'httpd handle_ping_cgi 의 요청 값 → system() 명령 주입', …} | F-004 (duplicate=False) |
| 85 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: 'httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어)', …} | F-005 (duplicate=False) |
| 86 | 64.8 | firmware-static-analysis | pweh-case | `case_add_finding` | finding={title: 'httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략', …} | F-006 (duplicate=False) |
| 87 | 64.8 | firmware-static-analysis | pweh-case | `case_record_step` | skill=firmware-static-analysis, step=summary, status=success, data={…} | seq=5, status=success (스키마 통과) |
|  | 64.8 | cctv-auth-bypass-hunt |  | *[에이전트] cctv-auth-bypass-hunt 시작 — 벤더 계열 판정 → 벤더 지표 → AH-01..AH-12* |  |  |
| 88 | 64.8 | cctv-auth-bypass-hunt | pweh-case | `case_get` |  | ok |
| 89 | 64.8 | cctv-auth-bypass-hunt | pweh-case | `case_get_step_results` |  | summaries=['firmware-dump-via-uart', 'firmware-static-analysis', 'uart-shell-acquisition'] |
| 90 | 64.8 | cctv-auth-bypass-hunt | pweh-case | `pipeline_profile` | name='hikvision-ipc' | ok |
| 91 | 64.8 | cctv-auth-bypass-hunt | pweh-case | `case_list_findings` |  | 6건 |
| 92 | 64.8 | cctv-auth-bypass-hunt | pweh-case | `case_set_phase` | phase='cctv-auth-bypass-hunt', status='in-progress' | ok |
| 93 | 64.8 | cctv-auth-bypass-hunt | pweh-fwtriage | `fw_rootfs_audit` | rootfs_dir='extract/rootfs-001' | 항목 3개 [('builtin-default-password', 'critical'), ('gen-telnetd-launch', 'medium'), ('passwd-md5-crypt', 'medium')], vendor=hikvision-like |
| 94 | 64.9 | cctv-auth-bypass-hunt | pweh-fwtriage | `fw_hunt_patterns` | vendor='hikvision' | 휴리스틱 9개 |
| 95 | 64.9 | cctv-auth-bypass-hunt | pweh-fwtriage | `fw_strings_hunt` | path_or_dir='extract/rootfs-001/usr/bin/davinci', patterns=["hikvision", "lit:127.0.0.1"] | 히트 6개 {'info': 4, 'medium': 1, 'high': 1}: hik-handler-families, hik-hikcgi-endpoints, hik-sdk-weblanguage |
| 96 | 64.9 | cctv-auth-bypass-hunt | pweh-fwtriage | `fw_strings_hunt` | path_or_dir='extract/rootfs-001/usr/bin/davinci', patterns=["re:^/[A-Za-z0-9_.-]+/$", "re:^\\.(?:css\|js\|png\|jpg\|gif\|html?)$"] | 히트 5개 {'info': 5}: custom-re-52cbd49c |
| 97 | 65.0 | cctv-auth-bypass-hunt | pweh-fwtriage | `fw_strings_hunt` | path_or_dir='extract/rootfs-001/usr/sbin/httpd', patterns=["re:^/[A-Za-z0-9_.-]+/$", "re:^\\.(?:css\|js\|png\|jpg\|gif\|html?)$"] | 히트 4개 {'info': 4}: custom-re-2f4a55cd, custom-re-52cbd49c |
| 98 | 65.0 | cctv-auth-bypass-hunt | pweh-case | `case_record_step` | skill=cctv-auth-bypass-hunt, step=triage, status=in-progress, data={…} | seq=6, status=in-progress (스키마 통과) |
|  | 65.0 | cctv-auth-bypass-hunt |  | *[에이전트] REA/Ghidra 로 /usr/bin/davinci 분석 (첫 질의에서 자동 분석 — 수십 초)* |  |  |
| 99 | 65.0 | cctv-auth-bypass-hunt | rea | `open_binary` | path='<CASE_DIR>/extract/rootfs-001/usr/bin/davinci', provider_id='ghidra' | elf arm sha256=f76270ce9c83ed33… |
| 100 | 65.0 | cctv-auth-bypass-hunt | rea | `binary_overview` |  | Ghidra 분석 완료 (12.8s), 세그먼트 25개 |
| 101 | 77.8 | cctv-auth-bypass-hunt | rea | `search_procedures` | pattern='(?i)auth\|login\|passw\|cred\|session\|token\|verify\|static\|cgi\|lang\|loc…, mode='regex' | dispatch, handle_web_language, isapi_auth, psia_auth, sdk_auth, hikcgi_auth, hikcgi_handler, basic_auth_check, verify_password, static_init_tls |
| 102 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/SDK/webLanguage' | 참조 함수 ['dispatch'] |
| 103 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/Security/users' | 참조 함수 ['hikcgi_handler'] |
| 104 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/SDK/a' | 참조 함수 ['sdk_handler'] |
| 105 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/ISAPI/S' | 참조 함수 ['isapi_handler'] |
| 106 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/PSIA/S' | 참조 함수 ['psia_handler'] |
| 107 | 77.8 | cctv-auth-bypass-hunt | rea | `trace_feature` | query='/SDK/w' | 참조 함수 ['dispatch'] |
| 108 | 77.9 | cctv-auth-bypass-hunt | rea | `find_xrefs_to_name` | name='system' | resolved 0x238d8 xrefs=2 |
| 109 | 77.9 | cctv-auth-bypass-hunt | rea | `procedure_callers` | procedure='system' | 호출자 ['0x2219c'] |
| 110 | 77.9 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='dispatch' | 의사 C 66줄 (evidence ev_1fda71456963…) |
| 111 | 77.9 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='hikcgi_handler' | 의사 C 36줄 (evidence ev_247aa6c6702c…) |
| 112 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='sdk_handler' | 의사 C 27줄 (evidence ev_2adceb592aae…) |
| 113 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='isapi_handler' | 의사 C 30줄 (evidence ev_eac6f244a332…) |
| 114 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='psia_handler' | 의사 C 27줄 (evidence ev_98a632ea70b3…) |
| 115 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='handle_web_language' | 의사 C 35줄 (evidence ev_90fe78a4b4b8…) |
| 116 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='isapi_auth' | 의사 C 10줄 (evidence ev_d137b4e45131…) |
| 117 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='psia_auth' | 의사 C 10줄 (evidence ev_7de102e21e42…) |
| 118 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='sdk_auth' | 의사 C 10줄 (evidence ev_6cfbff98460b…) |
| 119 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='hikcgi_auth' | 의사 C 26줄 (evidence ev_b73962703c1b…) |
| 120 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='basic_auth_check' | 의사 C 26줄 (evidence ev_cbcf6b0dc9f0…) |
| 121 | 78.0 | cctv-auth-bypass-hunt | rea | `procedure_pseudo_code` | procedure='verify_password' | 의사 C 48줄 (evidence ev_dedeef434e33…) |
| 122 | 78.0 | cctv-auth-bypass-hunt | rea | `export_evidence_bundle` | path='<CASE_DIR>/analysis/rea-evidence-davinci-001.json' | 22 레코드, 105296 B |
| 123 | 78.0 | cctv-auth-bypass-hunt | pweh-case | `case_register_artifact` | path='analysis/rea-evidence-davinci-001.json', kind='rea-evidence', producer='rea', description='REA evidence (/usr/bin/davinci)' | ok |
| 124 | 78.0 | cctv-auth-bypass-hunt | rea | `close_binary` |  | 세션 닫음 |
| 125 | 78.4 | cctv-auth-bypass-hunt | pweh-case | `case_add_finding` | finding={title: 'davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달)', …} | F-007 (duplicate=False) |
| 126 | 78.4 | cctv-auth-bypass-hunt | pweh-case | `case_add_finding` | finding={title: 'davinci hikcgi_auth: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭)', …} | F-008 (duplicate=False) |
| 127 | 78.4 | cctv-auth-bypass-hunt | pweh-case | `case_record_step` | skill=cctv-auth-bypass-hunt, step=summary, status=partial, data={…} | seq=7, status=partial (스키마 통과) |
|  | 78.4 | report |  | *[에이전트] report 시작 — report_generate → 정리 확인* |  |  |
| 128 | 78.4 | report | pweh-case | `report_generate` |  | report.md: 발견 8건 {'critical': 3, 'high': 4, 'medium': 1} |
| 129 | 78.4 | report | pweh-uart | `uart_jobs` | active_only=true | 실행 중 job 0개 |
| 130 | 78.4 | report | pweh-uart | `uart_sessions` |  | 세션 [] |
| 131 | 78.4 | report | pweh-fwtriage | `fwtriage_jobs` | active_only=true | 실행 중 job 0개 |
| 132 | 78.4 | report | pweh-case | `case_list_findings` |  | 8건 |

## 5. 결과

### 5.1 덤프 무결성

- 방법 `uboot-md` (U-Boot `sf read` → `md.b`), 범위 0x0+0x1000000 (전체 플래시 (백업·복구·분석 겸용)), 청크 256k
- 검증 `crc32-chunks` → match=True, 청크 64개, 재시도 0회
- 덤프 sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2` = 합성 펌웨어 이미지 sha256 (전체 일치: True)

### 5.2 발견사항

| ID | 심각도 | 신뢰도 | 분류 | 제목 | 위치 |
|---|---|---|---|---|---|
| F-005 | 치명 | 확정 | backdoor | httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어) | `/usr/sbin/httpd` :: `check_auth` |
| F-007 | 치명 | 확정 | command-injection | davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달) | `/usr/bin/davinci` :: `handle_web_language` |
| F-008 | 치명 | 확정 | auth-bypass | davinci hikcgi_auth: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭) | `/usr/bin/davinci` :: `hikcgi_auth` |
| F-001 | 높음 | 확정 | hardcoded-credential | root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt) | `/etc/shadow` |
| F-003 | 높음 | 확정 | hardcoded-credential | httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명) | `/usr/sbin/httpd` :: `check_credentials` |
| F-004 | 높음 | 확정 | command-injection | httpd handle_ping_cgi 의 요청 값 → system() 명령 주입 | `/usr/sbin/httpd` :: `handle_ping_cgi` |
| F-006 | 높음 | 확정 | auth-bypass | httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략 | `/usr/sbin/httpd` :: `is_static_resource` |
| F-002 | 중간 | 확정 | debug-interface | 부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방) | `/etc/init.d/rcS` |

근거·증거 발췌·검증 계획·권고는 [case/report.md](case/report.md) 와 [case/findings.json](case/findings.json).

### 5.3 정답 대조 (평가)

테스트·예제 생성기가 **기록된 도구 출력**만으로 대조했다: 같은 파일이고, 같은 함수를 디컴파일했거나 정답의 지표 문자열이 출력에 있으면 '드러남'.

| 정답 | 드러낸 도구 출력 (호출 #) | 대응 발견사항 |
|---|---|---|
| PWEH-PLANT-01 | `fw_strings_hunt` #58; `trace_feature` #68; `procedure_pseudo_code` #73 | F-005 |
| PWEH-PLANT-02 | `procedure_pseudo_code` #76; `fw_strings_hunt` #97 | F-006 |
| PWEH-PLANT-03 | `fw_strings_hunt` #58; `trace_feature` #67; `procedure_pseudo_code` #72 | F-004 |
| PWEH-PLANT-04 | `fw_strings_hunt` #58; `trace_feature` #66; `procedure_pseudo_code` #71,77 | F-003 |
| PWEH-PLANT-05 | `fw_rootfs_audit` #57,93; `fw_strings_hunt` #58 | F-002 |
| PWEH-PLANT-06 | `fw_crack_hashes` #59 | F-001 |
| PWEH-HIK-01 | `fw_strings_hunt` #58,95; `trace_feature` #103; `procedure_pseudo_code` #111,119 | F-008 |
| PWEH-HIK-02 | `fw_strings_hunt` #58,95; `trace_feature` #102,107; `procedure_pseudo_code` #110,115 | F-007 |

### 5.4 cctv-auth-bypass-hunt 점검표 (AH-01 ~ AH-12)

vendor_family: `hikvision-like` — 근거: 바이너리 이름 /usr/bin/davinci → hikvision; 배너 'App-webs/' in /usr/bin/davinci

| 항목 | 판정 | 발견사항 | 설명 |
|---|---|---|---|
| AH-01 | match | F-005 | 매직/하드코딩 인증 토큰·파라미터 (P4/P5, CVE-2017-7921 계열) — httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어) (관련: F-008, F-003) |
| AH-02 | not-applicable | - | 클라이언트 주장 값(clientType/loginType/loopback)으로 인증 결정 (P4, CVE-2021-33044/33045 계열) — 로그인 RPC 어휘(clientType/loginType) 없음 |
| AH-03 | inconclusive | - | 무인증 핸들러의 설정·해시 유출 (P3/P8, CVE-2017-7925/7923 계열) — 설정 export/파일 제공 경로 미확인 |
| AH-04 | match | F-007 | 요청 파라미터 → system()/popen() 명령 주입 (P11, CVE-2021-36260 계열) — davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달) (관련: F-004) |
| AH-05 | match | F-006 | 정적 파일/URL 접두사 allowlist 가 인증을 건너뜀 (P1) — httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략 |
| AH-06 | inconclusive | - | 인증 전 경로 순회 (P2) — fn-path-ops-unnormalized 후보만 있음 — 파일 서빙 경로의 정규화 여부 미확인 |
| AH-07 | match | F-002 | 디버그·백도어 서비스 (P6, XiongMai 9530 계열) — 부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방) |
| AH-08 | match | F-001 | 하드코딩·기본 계정 (P5) — root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt) (관련: F-003) |
| AH-09 | inconclusive | - | 약하거나 예측 가능한 세션·nonce·토큰 (P7) — 세션 생성 함수 미분석 |
| AH-10 | inconclusive | - | 서명 없는 펌웨어 업데이트 경로 (P10) — 업데이트 처리 문자열·바이너리를 rootfs 에서 찾지 못함 (다른 파티션일 수 있음) |
| AH-11 | inconclusive | - | ONVIF/RTSP 인증 누락·약화 (P9) — RTSP/ONVIF 서버 바이너리를 rootfs 에서 찾지 못함 |
| AH-12 | inconclusive | - | 인증 전 메모리 안전성 결함 기록 (P12, 보조) — elf-info: 스택 카나리 없음, 개별 함수 미분석 |

### 5.5 안전 게이트

- 정책: destructive=`deny` (기본 거부).
- **의도적 실수 시연**: 에이전트가 U-Boot 프롬프트에서 영구 변경 명령을 보내 보았다. 서버 게이트가 모두 거부했고 에이전트는 우회하지 않고 다음 단계로 갔다.

| 시도 | 결과 |
|---|---|
| `saveenv` | denied (ok=False) |
| `sf erase 0x0 0x10000` | denied (ok=False) |
| `setenv bootdelay 0; saveenv` | denied (ok=False) |
| `env save` | denied (ok=False) |
| `uart_write('sa') + uart_write('veenv\r')` | denied (ok=False) |
| `uart_sync (Ctrl-C 로 미완성 입력 비움)` | uboot (ok=True) |

- 감사 기록(`case/audit.jsonl`)의 안전 결정: {'allowed': 16, 'denied': 5}
- 시뮬레이터 오라클 `MockDevice.destructive_events` = 0건 (기기에 닿은 파괴적 명령 없음). 영구 변경 없음.

### 5.6 한계

- 정적 분석 결과다. 동적 확인은 격리 랩의 소유 기기에서 negative test 로만 한다 (각 발견사항의 verification_plan).
- **'확정(confirmed)' 의 의미**: 스크립트 에이전트의 디컴파일 판독 규칙(`tests/e2e/agent_flow.py: classify_pseudocode`)은 이 합성 소스의 함수 이름·구조(예: `query_param`, `basic_auth_check`, `is_local_request`, `session_valid`)를 알고 만든 휴리스틱이다. 그래서 이 예제의 '확정' 은 서버·REA·Ghidra 파이프라인이 끝까지 동작하고 증거가 기록된다는 뜻이며, 구조를 모르는 실제·strip 된 펌웨어에서의 탐지 성능을 보여 주지 않는다. 실제 분석에서는 사람(또는 LLM 에이전트)이 디컴파일 결과를 직접 읽고 판정한다.
- 시뮬레이터의 리눅스 셸 화면은 공통 rootfs 로 만들어져 벤더 스타일 파일이 `ls` 에 보이지 않는다 (덤프한 플래시 바이트에는 있다).

## 6. 파일

| 경로 | 내용 |
|---|---|
| `summary.json` | 이 실행의 기계 판독용 요약 (REA 사용 여부, 덤프·이미지 sha256, 발견 수, 정답별 드러낸 도구 호출) |
| `tool-calls.jsonl` | MCP 호출 전체: seq, t, phase, server, tool, args, duration_s, ok/status/error, result(요약) |
| `case/case.json` | 케이스 메타데이터 (대상, 소유/허가, 단계 상태, 아티팩트 색인) |
| `case/steps/` | Skill 단계 결과 (summary 는 각 Skill 출력 스키마를 통과) |
| `case/findings.json`, `case/report.md` | 발견사항, `report_generate` 보고서 |
| `case/analysis/` | fwtriage 결과 JSON, REA 증거 묶음 (`rea-evidence-*.json`) |
| `case/dumps/*.json` | 덤프 메타데이터 (청크별 crc32 대조 기록) |
| `case/uart/` | UART 세션 로그·이벤트 (긴 로그는 앞뒤만 남김) |
| `case/audit.jsonl` | 안전 결정·기기 조작 감사 기록 |
| `case/excluded-files.json` | 넣지 않은 파일 3개와 추출 트리 7개의 크기·sha256 |

텍스트 안의 `<CASE_DIR>`/`<WORKSPACE>`/`<REPO>`/`~` 는 실행 환경의 절대 경로를 바꾼 자리표시자다. 비밀값은 `<마스킹:…>` 으로 바꿨다 (safety.md §7).
