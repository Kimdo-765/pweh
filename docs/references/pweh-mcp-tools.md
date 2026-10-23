# PWEH MCP 도구 카탈로그 (자동 생성)

`scripts/dump_tool_catalog.py` 가 각 서버의 list_tools 결과로 생성한다. 손으로 고치지 않는다.

## pweh-case

- **`case_image_hints(case_id, path, ocr?, ocr_lang?, qr?, preview?, crop?, max_seconds?)`**  
  케이스의 정지이미지 파일 1개를 오프라인 분석한다(소유/허가 확인 필수, 최대 64 MiB). 메타데이터·구조·OCR(kor+eng 기본)·QR/바코드·스테가노그래피 단서를 JSON 으로, 정규화 PNG 를 MCP 이미지 콘텐츠로 반환한다. OCR·코드는 마스킹하지 않으며 URL 을 열지 않는다. crop=[x,y,width,height] 는 EXIF 방향을 적용한 좌표; 원본 전체 메타데이
- **`case_create(title, authorization, target?, profile?, case_id?, notes?)`**  
  새 분석 케이스 생성. authorization 은 필수: {basis: 'owned'|'written-authorization', owner, statement(사용자가 소유/허가를 확인한 말을 그대로 인용), scope?, document_ref?(서면 허가 시 필수)}. target 예: {vendor, model, serial, hardware_rev, firmware_version,
- **`case_set_authorization(case_id, authorization)`**  
  케이스의 소유/허가 증명을 기록하거나 갱신한다 (case_create 와 같은 authorization 형식).
- **`case_list()`** — [읽기전용]  
  케이스 목록.
- **`case_get(case_id, include_artifacts?, include_steps?)`** — [읽기전용]  
  케이스 요약(대상, 권한 여부, 단계 상태, 아티팩트/단계/발견사항 수). include_artifacts=true 면 아티팩트 목록 포함.
- **`case_update_target(case_id, target)`**  
  케이스의 대상 기기 정보 갱신 (예: UART 로 알아낸 SoC/플래시/펌웨어 버전).
- **`case_set_phase(case_id, phase, status, note?)`**  
  파이프라인 단계 상태 수동 갱신. phase: uart-shell-acquisition, firmware-dump-via-uart, logic-analyzer-protocol-decode, firmware-static-analysis, cctv-auth-bypass-hunt, report; status: pending, in-progress, done, partial, failed, skip
- **`case_add_note(case_id, text, author?)`**  
  케이스에 자유 형식 메모 추가 (사람이 한 물리 작업, 관찰 등).
- **`case_paths(case_id, purpose?, label?)`** — [읽기전용]  
  케이스 디렉터리의 표준 하위 경로(절대 경로)와, 외부 도구(REA extract_firmware 등)에 넘길 '아직 존재하지 않는' 새 출력 디렉터리 경로를 반환. purpose 예: 'extract', 'analysis', 'signals'.
- **`case_record_step(case_id, skill, step, status, summary, data?, artifacts?, next_actions?, blockers?, started_at?)`**  
  Skill 단계 결과 저장. 각 Skill 의 마지막에 step='summary' 로 호출해야 하며, 이때 data 는 해당 Skill 의 출력 스키마를 따라야 한다 (uart-shell-acquisition→uart-recon, firmware-dump-via-uart→firmware-dump, firmware-static-analysis→static-analysis, logic-analy
- **`case_get_step_results(case_id, skill?, summaries_only?)`** — [읽기전용]  
  이전 Skill 들의 단계 결과 조회 (다음 Skill 의 입력으로 사용). skill 을 지정하지 않으면 모든 Skill 의 최신 summary. missing 은 summary 가 없는 Skill 이다 — 보안 분석 파이프라인 Skill 과, 다른 목표의 Skill 은 이 케이스에서 시작한 것만 센다. summaries_only=false 면 해당 skill 의 모든 단계.
- **`case_register_artifact(case_id, path, kind, description?, producer?)`**  
  케이스 내부 파일/디렉터리를 아티팩트로 등록(sha256 계산). kind 예: uart-log, flash-dump, memory-dump, partition, extracted-tree, signal-capture, signal-decode, jtag-dump, triage-report, rea-evidence, decompilation, report, other.
- **`case_import_file(case_id, source_path, kind?, dest_subdir?, description?)`**  
  케이스 밖의 파일(예: 벤더 공식 펌웨어 다운로드, SPI 클립으로 읽은 덤프)을 케이스로 복사하고 등록. dest_subdir 기본 'dumps'; NFC 일반 파일은 'nfc'도 허용한다(스캔·출처 증명은 별도).
- **`case_hash_file(case_id, path, offset?, length?)`** — [읽기전용]  
  케이스 내부 파일(또는 offset/length 구간)의 해시 계산: sha256, md5, crc32. 덤프 교차 검증용 — 예: tftpput/SPI 클립으로 받은 파일과 UART 덤프의 같은 구간 비교, 기기 측 md5sum/crc32 와 대조. offset/length 는 정수 또는 '0x50000', '64k' 같은 문자열.
- **`case_add_finding(case_id, finding)`**  
  발견사항 추가 (schema_get('finding') 참고). 필수: title, category(auth-bypass|hardcoded-credential|backdoor|command-injection|debug-interface|weak-crypto|info-leak|insecure-update|memory-corruption|insecure-default|other), severit
- **`case_update_finding(case_id, finding_id, patch)`**  
  발견사항 수정 (예: status 를 static-confirmed 로, 증거 추가). patch 는 덮어쓸 필드.
- **`case_list_findings(case_id, min_severity?)`** — [읽기전용]  
  발견사항 목록 (심각도순). min_severity 로 필터 (critical|high|medium|low|info).
- **`report_generate(case_id)`**  
  케이스의 모든 결과(단계 요약, 발견사항, 아티팩트, 안전 감사)를 모아 cases/<id>/report.md 를 생성한다.
- **`pipeline_profiles()`** — [읽기전용]  
  pipeline-config.yaml 에 정의된 대상 기기 프로필 목록.
- **`pipeline_profile(name)`** — [읽기전용]  
  대상 기기 프로필 상세 (extends 해석 완료): 보드레이트 후보, U-Boot 프롬프트/autoboot 패턴, 인터럽트 키, 예상 인터페이스, 플래시/RAM 주소 힌트, 펌웨어 분석 힌트.
- **`pipeline_safety_policy()`** — [읽기전용]  
  현재 적용 중인 안전 정책 (위험도별 allow/approve/deny, 승인 방법, 영구 경로 목록).
- **`pipeline_environment(refresh?)`** — [읽기전용]  
  실행 환경 보고서와 장치 종류별 추천 경로 (기기 미접촉, OBSERVE, 읽기 전용). report(pweh.hostenv/v1): kind(WSL2_INTEROP | WSL2_NO_INTEROP | WSL1 | WSL_UNKNOWN | NATIVE_LINUX | MACOS | NATIVE_WINDOWS | CYGWIN | MSYS | CONTAINER), wsl{version, netwo
- **`approval_status(approval_id)`** — [읽기전용]  
  승인 요청 상태 조회 (pending|approved|denied|consumed|expired). 사람이 `pweh approve <id>` 를 했는지 확인할 때 사용.
- **`approvals_pending()`** — [읽기전용]  
  대기 중인 승인 요청 목록 (확인 코드는 제외).
- **`schema_get(name)`** — [읽기전용]  
  PWEH JSON 스키마 조회. name: allocation-window, android-forensics, auth-hunt, bmff-scan, case, cluster-report, dhav-candidates, dhav-record-extract, dhav-scan, emulation, finding, firmware-dump, image-hints, imported-save-pla

## pweh-uart

- **`uart_list_ports(include_links?)`** — [읽기전용]  
  시리얼 포트 목록 (OBSERVE, 포트를 열지 않음). 기존 ports 항목에 route/device_id/held_by 를 더하고 env_kind 를 반환한다. include_links=true 면 /dev/serial/by-id/… 링크도 포함. TCP 시리얼(이 호스트의 ser2net, 시뮬레이터)은 목록에 없고 uart_open 에 socket://127.0.0.1:<포트> 로 준다
- **`uart_open(case_id, port, baudrate?, bytesize?, parity?, stopbits?, line_ending?, dtr?, rts?, profile?, label?, approval_id?)`**  
  UART 세션 열기 (INTERACT, dtr/rts=true 또는 확인된 reset-wired 경로면 MODIFY — 보드 리셋/부트모드 핀일 수 있음). port 는 장치 경로, WSL interop COMn(helper), 또는 pyserial URL (루프백 호스트만: socket://127.0.0.1:<포트>, rfc2217://[::1]:<포트> / 테스트용 loop:// — LA
- **`uart_close(session_id)`**  
  UART 세션 닫기: 실행 중인 job 취소, 수신 스레드 정지, 포트 닫기, 로그(uart-log/uart-raw/uart-events) 아티팩트 등록. 끊어진(disconnected) 세션도 닫을 수 있다. 물리 close 확인 뒤 공통 잠금을 해제하며, 정리 미확인 시 잠금을 보존한다.
- **`uart_sessions(case_id?)`** — [읽기전용]  
  열린 UART 세션 목록: 상태(open/disconnected), 문맥/phase/프롬프트, rx/tx 바이트, 로그 경로, 미완성 입력, 실행 중 job.
- **`uart_read(session_id, since_cursor?, max_bytes?, wait_seconds?, tail?)`** — [읽기전용]  
  수신 버퍼 읽기 (OBSERVE). 커서는 누적 수신 바이트 오프셋. since_cursor 생략 시 에이전트 읽기 위치(직전 uart_read/명령의 cursor_end)부터. tail=true 면 마지막 max_bytes. wait_seconds>0 이면 새 데이터를 최대 그만큼 기다린다(최대 50). 반환: text(CRLF→LF), cursor_start, cursor_end, mor
- **`uart_write(session_id, data, encoding?, approval_id?)`**  
  원시 쓰기. data 는 text(JSON 이스케이프로 \r, \u0003 등) 또는 encoding="hex". 세션이 지금까지 보낸 입력과 이어서 기기 줄 버퍼처럼 조립(LineAssembler)해 완성되는 줄마다 문맥 분류기로 검사한다 — 나눠 보내기('sa'+'veenv\r')도 한 줄로 분류. 제어 문자는 CONTROL_CHAR_RISK, 탭/ESC(자동완성·히스토리)가 섞인 줄은 
- **`uart_send_command(session_id, command, timeout?, expect?, approval_id?, max_output?)`**  
  명령 한 줄 + 줄끝 전송 후 에코와 다음 프롬프트(또는 expect 정규식, 줄마다 ^$ 적용, CRLF 무관)까지 대기. 현재 문맥(uboot/linux-shell/unknown…)의 분류기로 검사하며 unknown·login 문맥은 두 분류기 중 엄격한 쪽. 반환: output(에코·프롬프트 제거), matched, match, timed_out(시간 초과는 오류가 아님), contex
- **`uart_wait_for(session_id, pattern, timeout?, since_cursor?)`** — [읽기전용]  
  정규식이 수신 데이터에 나타날 때까지 대기 (OBSERVE, 기기에 아무것도 보내지 않음). since_cursor 생략 시 에이전트 읽기 위치부터 검색 → 호출 사이에 온 출력도 놓치지 않는다. 줄마다 ^$ 적용(CR 은 LF 로 취급). 반환: matched, match, groups, text(검색 구간, 최대 8000자), cursor_end(매치 끝), timed_out. timeo
- **`uart_set_context(session_id, context, prompt?)`**  
  문맥 수동 지정: uboot / linux-shell / login / password / booting / unknown, auto 는 수동 지정 해제. prompt 를 주면 그 문자열을 그 문맥의 프롬프트로 학습한다(특이한 프롬프트). 안전: 분류는 수동 문맥과 자동 감지 문맥 둘 다로 해서 더 엄격한 쪽을 쓴다(수동 지정으로 완화 불가). 재부팅·phase 변화 증거가 나오면 수동 지정
- **`uart_sync(session_id, timeout?, approval_id?)`**  
  Ctrl-C(0x03) 한 번으로 새 프롬프트를 받고 문맥을 확정한다 (INTERACT, 추가 도구). U-Boot 는 '<INTERRUPT>' 를 출력하고(입력 줄 비움), 리눅스 셸은 새 프롬프트만 출력한다. 미완성 입력도 지운다. 빈 Enter 대신 이것을 쓴다.
- **`uart_send_break(session_id, duration?, approval_id?)`**  
  BREAK 신호 전송 (MODIFY). 리눅스 시리얼 콘솔에서는 BREAK 다음 5초 안의 문자가 Magic SysRq 명령(b=즉시 재부팅 등)이 되므로, 그 창 동안의 다음 송신은 최소 MODIFY 로 분류된다.
- **`uart_set_signals(session_id, dtr?, rts?, approval_id?)`**  
  DTR/RTS 신호 설정 (MODIFY — 보드의 리셋/부트모드 핀에 연결돼 있으면 기기가 리셋된다). PTY·socket:// 등 신호가 없는 포트는 status=unsupported.
- **`uart_detect_baud(case_id, port, candidates?, listen_seconds?, probe?, approval_id?)`**  
  보드레이트 탐지: 포트를 한 번 열고 같은 연결의 속도를 바꾸며(DTR/RTS 끔) probe="ctrl-c" 면 0x03 을 한 번 보낸 뒤 listen_seconds 동안 읽어 점수화(출력 가능 문자 비율, 부팅 키워드, 0x00/0xFF 연속 감점) → candidates(점수순), best, confidence, hint(데이터 없음: TX/RX 뒤바뀜·GND·무출력·전압). 기기가 
- **`uart_capture_boot(session_id, duration?, until?, stop_on_prompt?)`** — [읽기전용]  
  부팅 로그 수집 (OBSERVE, 기기에 아무것도 보내지 않음): 사람에게 전원을 꺼 두게 한 뒤 호출하고, 호출이 시작되면 전원을 넣게 한다. duration 초(최대 300, MCP 클라이언트 제한 고려) 또는 until 정규식까지 수집. stop_on_prompt=true 면 이 창에서 부팅이 시작된 뒤 로그인/셸/U-Boot 프롬프트가 나오고 1.5초 조용하면 멈춘다. 파싱 결과: u
- **`uboot_interrupt(session_id, keys?, window_seconds?)`**  
  autoboot 중단 (INTERACT). 사람에게 기기 전원을 먼저 꺼 두게 하고 '준비' 답을 받은 뒤 호출한다 — 사람은 호출이 시작되면 전원을 넣는다. 부팅 출력(또는 autoboot 메시지)이 보이면 인터럽트 키(keys 또는 프로필 interrupt_sequences, 기본 Ctrl-C — 빈 Enter 는 새 부팅 확인 뒤에만)를 약 50ms 마다 보내고, U-Boot 프롬프트가
- **`uboot_printenv(session_id)`**  
  U-Boot printenv 실행·파싱 (INTERACT): env{}, bootargs, bootcmd, bootdelay, mtdparts, partitions[{name, offset, size}], loadaddr, load_addresses, environment_size, flash_size/flash_size_source('-' 파티션 크기 계산에 쓴 값: uboot_info 또
- **`uboot_info(session_id, probe_flash?)`**  
  U-Boot 정보 수집 (INTERACT, 명령마다 게이트): version, bdinfo{dram_start, dram_size, relocaddr, sp_start, …}, help 의 commands[], has{}(help 기준 사용 가능 여부, U-Boot 약어 규칙 포함 — 약어로만 되면 has_via{}, help 를 못 읽으면 null), probe_flash=true 면 's
- **`uboot_dump_start(case_id, session_id, offset, length, source?, ram_addr?, chunk_size?, output_name?, verify?, resume?, retries?, final_check?, sf_probe?)`**  
  U-Boot 플래시/메모리 덤프 job 시작 → job_id (uart_job_status 로 폴링, uart_job_cancel 로 취소). 청크마다 'sf read <ram> <off> <len>' (source=nand: nand read, mmc: mmc read(512B 블록), ram: 적재 없이 offset 이 RAM 주소) → 'md.b <ram> <len>' 파싱(주소·바이트
- **`shell_login(session_id, username?, password?, timeout?)`**  
  BusyBox 로그인 처리 (INTERACT): askfirst('Please press Enter')면 Enter, 'login:' 이면 username, 'Password:' 면 password 를 프롬프트가 수신 끝에 보일 때만 보낸다. 비밀번호는 로그·이벤트·감사 기록에서 마스킹된다. 사용자가 알려 준 계정만 쓰고 추측·무차별 대입 금지 — 세션당 3회 실패하면 더 시도하지 않는다. 
- **`shell_identify(session_id)`**  
  리눅스 셸 식별 (읽기 전용 명령 묶음, 명령마다 게이트): uname -a, /proc/cpuinfo, /proc/mtd(파싱 → mtd[]), /proc/cmdline(mtdparts → partitions), /proc/mounts, ps, netstat -tuln(listening), busybox(applets), id. 반환: uname, kernel_version, arch, c
- **`shell_dump_start(case_id, session_id, path, offset?, length?, method?, chunk_size?, output_name?, resume?, retries?)`**  
  리눅스 셸 덤프 job 시작 → job_id. 청크마다 'dd if=<path> bs=… skip=… count=… 2>/dev/null | base64'(없으면 '| hexdump -C') 를 파싱하고 같은 범위의 '| md5sum' 과 비교, 실패 청크는 재시도. path 는 /dev/mtdN · /dev/mtdblockN 또는 일반 파일(절대 경로). length 생략 시 /proc/m
- **`uart_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`uart_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`uart_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-openocd

- **`openocd_start(case_id, interface_cfg, target_cfg?, transport?, adapter_speed_khz?, extra_commands?, tcl_port?, extra_cfgs?, ready_timeout?, approval_id?, backend?, windows_profile?)`**  
  OpenOCD 프로세스를 시작하고 TCL RPC 로 연결한다 (MODIFY: JTAG 초기화가 타깃 상태에 영향 가능). telnet/GDB 포트는 끄고 TCL 포트만 127.0.0.1 에 연다. interface_cfg 는 scripts 기준 상대경로(예: 'interface/ftdi/tigard.cfg', 'interface/jlink.cfg') 또는 절대경로. target_cfg 는 문
- **`openocd_attach(case_id, host?, tcl_port?, approval_id?)`**  
  이미 실행 중인 OpenOCD 의 TCL 포트에 연결한다 (예: 사람이 직접 띄운 OpenOCD, 원격 Raspberry Pi). 이 케이스에서 전에 openocd_start 로 띄운 프로세스(서버 재시작 등)면 상태 파일로 찾아 '입양'해 openocd_stop 으로 종료할 수 있게 한다. 원격 호스트면 dump_image 파일을 읽을 수 없으므로 메모리 덤프는 read_memory 방식으
- **`openocd_stop(case_id, shutdown_attached?, approval_id?)`**  
  OpenOCD 세션 종료. 이 서버가 띄운(또는 입양한) 프로세스는 TCL 'shutdown' → SIGTERM → SIGKILL 순서로 종료하고 로그를 아티팩트로 등록한다. 실행 중인 덤프 작업은 먼저 취소된다(부분 결과 보존). 외부에서 띄운 OpenOCD(attach)는 연결만 끊으며, shutdown_attached=true 일 때만 'shutdown' 을 보낸다(MODIFY 게이트)
- **`openocd_status(case_id, log_lines?)`** — [읽기전용]  
  OpenOCD 세션 상태: 연결/프로세스(종료 코드·시그널), 버전, 포트, 가동 시간, 최근 로그(log_lines 줄), 기동 요약, 진단 힌트, 실행 중인 작업, 그리고 살아 있으면 targets 조회로 현재 타깃 상태(halted/running 등). 세션이 없으면 이 케이스의 이전 실행 기록.
- **`openocd_command(case_id, command, approval_id?, timeout?, max_output_chars?)`**  
  원시 OpenOCD Tcl 명령 실행. 명령 텍스트 전체를 위험도 분류(코어 classify_openocd + 엄격한 로컬 규칙)한 뒤 게이트를 통과해야 실행된다: 조회(scan_chain, targets, mdw, read_memory, flash banks/info …)=허용, halt/reset/resume 등=MODIFY, mww/write_memory/flash write·erase
- **`openocd_scan_chain(case_id)`** — [읽기전용]  
  JTAG 스캔체인 TAP 목록 (scan_chain 파싱): tap_name, enabled, idcode, expected(목록), irlen, ircap, irmask, mismatch, decoded(제조사 코드/이름, part, version, 유효성). IDCODE 가 0x00000000/0xffffffff 면 배선·전원 문제 힌트를 준다.
- **`openocd_targets(case_id)`** — [읽기전용]  
  타깃 목록 (targets 파싱): index, current(*), name, type(arm926ejs/cortex_a/mips_m4k/mem_ap…), endian, tap_name, state(running/halted/reset/unknown/examine deferred/tap-disabled).
- **`openocd_halt(case_id, target?, approval_id?, timeout?)`**  
  타깃 CPU 정지 (halt, MODIFY). target 을 주면 그 타깃을 현재 타깃으로 바꾼 뒤 정지한다. messages 에 'target halted …, pc: …' 같은 OpenOCD 메시지, state 에 정지 후 상태.
- **`openocd_resume(case_id, address?, target?, approval_id?)`**  
  타깃 CPU 실행 재개 (resume, MODIFY). address 를 주면 그 주소에서 실행. 실제 기기의 펌웨어가 다시 돌기 시작하므로 덤프/분석 중에는 주의.
- **`openocd_reset(case_id, mode?, approval_id?, timeout?)`**  
  타깃 리셋 (MODIFY). mode: halt(리셋 직후 정지 — 부트 초기에 붙을 때), run(정상 부팅), init(reset-init 이벤트 스크립트 실행 후 정지). 리셋 라인(SRST)이 없으면 cfg 의 reset_config 에 따라 동작이 다르다.
- **`openocd_read_registers(case_id, names?, target?, refresh?, max_refresh?, save?)`** — [읽기전용]  
  레지스터 읽기 ('reg' 파싱). names 를 주면 'reg <name>' 으로 개별 조회(값을 타깃에서 읽음). names 가 없으면 전체 목록을 읽고, 타깃이 halted 이고 refresh=true 면 캐시 값이 없는 첫 레지스터 그룹(코어 레지스터)을 개별 조회로 채운다. 실행 중(running)인 타깃은 값이 없을 수 있으니 openocd_halt 먼저. 결과는 jtag/regi
- **`openocd_read_memory(case_id, address, count, width?, target?, phys?)`** — [읽기전용]  
  작은 메모리 범위 읽기 (read_memory; 0.11 은 md* 로 대체). width: 8|16|32|64, count*width/8 ≤ 4096 바이트 (큰 범위는 openocd_dump_memory_start). 값은 타깃 엔디언 정수(values), bytes_hex/hexdump 는 메모리 순서 바이트. target 을 주면 그 타깃으로 읽는다(예: Cortex-A SoC 의 m
- **`openocd_dump_memory_start(case_id, address, length, output_name?, chunk_size?, target?, method?, verify?, resume?, kind?, retries?, chunk_timeout_s?)`**  
  메모리 덤프 백그라운드 작업 시작 → job_id. 청크(chunk_size, 기본 64KiB)마다 dump_image 를 케이스 경로로만 실행해 jtag/<name>.part 에 이어 붙이고 .state.json 으로 재개 가능 (같은 output_name 으로 다시 호출하면 이어받음). OpenOCD 가 쓴 파일이 보이지 않으면(원격 OpenOCD) read_memory 방식으로 자동 전
- **`openocd_flash_banks(case_id, probe?, info?)`** — [읽기전용]  
  플래시 뱅크 목록 (flash banks 파싱 + flash list 의 타깃 정보): bank, name, driver, base, size, bus/chip width. probe=true 면 각 뱅크를 flash probe 후 다시 조회(크기가 0 인 SPI 뱅크), info=true 면 flash info 로 섹터/보호 상태까지. 카메라 SoC(HiSilicon/Ingenic/Sigm
- **`openocd_flash_read_start(case_id, bank, offset?, length?, output_name?, chunk_size?, verify?, resume?, retries?, chunk_timeout_s?)`**  
  플래시 뱅크 읽기 백그라운드 작업 → job_id. 청크마다 'flash read_bank <bank> {dumps/.이름.chunk} offset len' 을 실행해 dumps/<name>.part 에 이어 붙이고(.state.json 으로 재개), 완료 시 dumps/<name>.bin + .json + sha256 + flash-dump 아티팩트. bank 는 번호 또는 이름, offs
- **`openocd_write_memory(case_id, address, values, width?, target?, phys?, verify?, approval_id?)`** — [파괴적, 매번 사람 확인]  
  메모리 쓰기 (write_memory, DESTRUCTIVE — 기본 정책 거부). 임의 메모리/MMIO 쓰기는 플래시·eFuse·OTP 컨트롤러를 건드려 기기를 영구 손상시킬 수 있다. 정책이 approve 일 때만 사람 승인(pweh approve <id>) 후 같은 인자 + approval_id 로 1회 실행. values: 정수 또는 16진 문자열 목록(최대 1024개). verify
- **`openocd_flash_write(case_id, path, address, erase?, unlock?, verify?, approval_id?, timeout?)`** — [파괴적, 매번 사람 확인]  
  플래시에 이미지 쓰기 (flash write_image [erase] [unlock] {파일} 주소 bin, DESTRUCTIVE — 기본 정책 거부). 기기를 벽돌로 만들 수 있다. path 는 케이스 디렉터리 안의 파일만 허용. 승인 지문에 파일 sha256 이 포함되어, 승인 후 파일이 바뀌면 실행되지 않는다. 정책이 approve 일 때만 사람 승인 후 approval_id 로 1회 
- **`openocd_list_configs(kind?, pattern?, limit?)`** — [읽기전용]  
  OpenOCD scripts 디렉터리의 cfg 파일 목록 (interface|target|board|all). pattern 으로 부분 문자열 필터. 예: kind='interface', pattern='ftdi' → interface/ftdi/tigard.cfg 등. openocd_start 의 interface_cfg/target_cfg 에 그대로 쓴다.
- **`openocd_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`openocd_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`openocd_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-sigrok

- **`sigrok_version(backend?)`** — [읽기전용]  
  sigrok-cli / libsigrok / libsigrokdecode 버전, 실행 파일 경로, 지원 드라이버·디코더 수. backend 기본 linux; windows는 등록 번들·WSL interop의 무장치 정보 조회만 사용하며 Linux로 대체하지 않는다. Windows 버전 확인 뒤 목록에 decoder 로드 오류만 있으면 status=partial, counts=null이며 원시
- **`sigrok_list(kind?, query?, backend?)`** — [읽기전용]  
  sigrok 지원 목록. kind: drivers | decoders | input-formats | output-formats | transforms | all. query 로 id/설명 부분 문자열 필터. drivers 에는 이 서버의 캡처 정책(capture_allowed, output_capable, reason)이 붙는다. backend 기본 linux; windows는 등록 번들·
- **`sigrok_decoder_help(decoder)`** — [읽기전용]  
  프로토콜 디코더 상세(sigrok-cli -P <id> --show 파싱): 필수/선택 채널, 옵션(값 목록·기본값), annotation 클래스/행, 바이너리 클래스, 문서. sigrok_decode 의 -P/-A 문자열을 만들 때 사용 (libsigrokdecode 버전마다 이름이 다르므로 하드코딩 금지).
- **`sigrok_scan(driver?, conn?, case_id?, timeout_s?, backend?, approval_id?)`**  
  연결된 sigrok 장치 스캔. 인자 없으면 모든 드라이버로 USB 등 자동 탐지(읽기 전용 식별). driver 로 한정 가능. conn(시리얼 /dev/ttyACM0, USB 'bus.addr'/'VID.PID', 'tcp-raw/host/port') 을 주면 그 포트로 식별 질의를 보내므로 시리얼/네트워크 conn 은 case_id(소유/허가 증명)가 필요하다. 명시 직렬 conn 은 
- **`sigrok_device_info(case_id, driver, conn?, timeout_s?, backend?, approval_id?)`**  
  로직 애널라이저 상세(sigrok-cli -d <driver> --show 파싱): 드라이버 기능, 채널/채널 그룹, 지원 samplerate 목록 또는 범위, 지원 트리거 문자, 최대 샘플 수를 조회한다(허용 목록 드라이버만). 캡처 전에 samplerate 를 고를 때 사용. 명시 직렬 conn 은 공통 포트 잠금·route 재검증·target/bridge 거부를 적용한다. backend
- **`sigrok_capture(case_id, driver, samplerate?, duration_ms?, samples?, channels?, triggers?, output_name?, conn?, capture_ratio?, background?, timeout_s?, backend?, approval_id?)`**  
  로직 애널라이저 캡처 → cases/<id>/signals/<name>.sr (srzip) 저장 + 아티팩트 등록. 입력 신호 캡처이며 케이스 소유/허가 증명이 필요. driver 필수(sigrok_scan 결과), samplerate 예 '1m'/'8MHz'/'24m'(소문자 m=MHz, 정수 Hz 로 변환). Linux는 duration_ms 와 samples 중 정확히 하나. Linux
- **`sigrok_decode(case_id, input_path, decoders, annotations?, input_format?, samplenum?, max_lines?, background?, timeout_s?, output_name?)`**  
  sigrok-cli 로 신호 파일 디코드: -i <input_path> [-I input_format] -P <스택들> [-A annotations] [--protocol-decoder-samplenum]. 결과 전체는 signals/<입력>.<디코더>.txt 로 저장(아티팩트 signal-decode)하고 앞 max_lines 줄 미리보기와 줄 수/인스턴스별 개수를 반환. decoders 
- **`sigrok_export(case_id, input_path, output_format?, output_name?, input_format?, timeout_s?)`**  
  신호 파일 형식 변환 (예: srzip(.sr) → vcd, vcd → srzip, csv). output_format 은 sigrok_list(kind='output-formats') 의 id (옵션 가능: 'csv:label=channel'). 결과는 signals/ 에 저장하고 아티팩트(signal-capture) 등록. .sr 에 아날로그 채널이 섞여 있고 로직 전용 형식(vcd 등)
- **`sigrok_file_info(case_id, input_path, input_format?)`** — [읽기전용]  
  신호 파일 요약 (순수 Python, sigrok-cli 불필요 — srzip/VCD): 형식, samplerate, 채널, 샘플 수, 길이, 채널별 활동(에지 수, high 비율, 처음/끝 레벨). 어느 채널에 신호가 있는지(UART 후보) 고를 때 사용. 그 밖의 형식은 sigrok-cli 로 요약.
- **`sigrok_estimate_baud(case_id, input_path, channel?, data_bits?, parity?)`** — [읽기전용]  
  순수 Python 오프라인 UART 보드레이트 추정 (.sr/.vcd, sigrok-cli 불필요). 펄스 폭 분포 → 비트 시간(근사 GCD) → 표준 보드레이트 (300~3000000, 1500000 포함)에 스냅, 8N1 프레임 검사로 T/2 모호성·idle 극성(반전 라인) 판정. 반환: baudrate, baudrate_raw, confidence(0~1), idle_level(1=
- **`sigrok_uart_autodecode(case_id, input_path, channel?, baudrate?, data_bits?, parity?, max_preview_bytes?, engine?, background?, timeout_s?)`**  
  UART 자동 디코드: sigrok_estimate_baud 로 보드레이트/idle 극성을 추정한 뒤(또는 baudrate 지정) sigrok-cli uart 디코더(format=hex, 반전 시 invert_rx=yes)로 디코드해 ASCII 미리보기(text_preview), 16진 미리보기, 프레임 오류 수, 부트 로그 힌트(U-Boot 배너, autoboot 프롬프트, 커널 버전/cm
- **`sigrok_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`sigrok_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`sigrok_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-jtagulator

- **`jtagulator_connect(case_id, port, baudrate?, timeout_seconds?, allow_untested_firmware?, approval_id?)`**  
  JTAGulator 에 연결(USB-시리얼, 기본 115200 8N1). port 는 장치 경로(/dev/ttyUSB0), WSL interop COMn(helper), 또는 루프백 pyserial URL(socket://127.0.0.1:<포트> — LAN 호스트는 validation_failed). 포트를 열면 FT232 DTR 로 JTAGulator 가 리셋될 수 있으므로 Ctrl-X 
- **`jtagulator_disconnect(case_id)`**  
  JTAGulator 연결 종료. 실행 중인 스캔이 있으면 먼저 중단(LF)하고 끝날 때까지 기다린 뒤 포트를 닫고 세션 기록을 등록한다. 권장 순서: 타깃 전원을 먼저 끈 다음 호출 (포트를 닫으면 DTR 리셋으로 VADJ 가 꺼질 수 있음). 물리 close 를 확인해야 공통 잠금을 해제하며 정리 미확인 시 보존한다.
- **`jtagulator_version(case_id)`**  
  JTAGulator 펌웨어 버전/배너 정보 (메인 메뉴 'I'). 지원 범위(1.10–1.12) 여부도 반환.
- **`jtagulator_status(case_id?)`** — [읽기전용]  
  JTAGulator 연결 상태(장치 I/O 없음): 포트, 펌웨어, 현재 메뉴, 이 연결에서 확인된 전압, 실행 중 작업. case_id 생략 시 전체.
- **`jtagulator_set_voltage(case_id, volts, approval_id?)`** — [파괴적, 매번 사람 확인]  
  JTAGulator 타깃 I/O 전압(VADJ) 설정 — DESTRUCTIVE(기본 거부). 잘못된 전압은 타깃 I/O 를 손상시킬 수 있다. 사람이 멀티미터로 타깃 I/O 전압을 측정한 값만 사용한다(1.4–3.3 V, 0.1 V 단위; 0 = 끄기). status=approval_required 이면 사용자에게 측정값 확인과 `pweh approve <id>` 를 요청하고 같은 인자 + 
- **`jtagulator_idcode_scan(case_id, start_channel, end_channel, pins_low?, pins_low_ms?, pins_high_ms?, idle_timeout_seconds?, max_duration_seconds?, approval_id?)`**  
  JTAG IDCODE 스캔(JTAG 메뉴 'I'): TDO/TCK/TMS(+TRST# 후보)와 Device ID 를 찾는다(TDI 는 찾지 못함 → bypass/jtag 스캔). IDCODE 는 JEP106 제조사로 해석. 순열 = n!/(n-3)!. 채널 번호는 JTAGulator 의 CH0–CH23. 스캔은 범위 안의 모든 채널을 출력 HIGH 로 구동한다(MODIFY) — 채널이 전원 
- **`jtagulator_bypass_scan(case_id, start_channel, end_channel, known_pins?, pins_low?, pins_low_ms?, pins_high_ms?, idle_timeout_seconds?, max_duration_seconds?, approval_id?)`**  
  JTAG BYPASS 스캔(JTAG 메뉴 'B'): TDI/TDO/TCK/TMS(+TRST# 후보)와 체인 장치 수를 찾는다. IDCODE 미지원 타깃도 찾을 수 있다. known_pins 로 이미 아는 핀을 고정하면 훨씬 빠르다(예: IDCODE 스캔 결과 {"tdo":2,"tck":0,"tms":1} → TDI 만 탐색). 순열 = (n-k)!/(n-4)!, 24채널 전체는 255,024
- **`jtagulator_jtag_scan(case_id, start_channel, end_channel, pins_low?, pins_low_ms?, pins_high_ms?, idle_timeout_seconds?, max_duration_seconds?, approval_id?)`**  
  JTAG Combined 스캔(JTAG 메뉴 'J', FW 1.8+): IDCODE 순열을 돌다 유효한 IDCODE 가 나오면 남은 채널로 TDI 를 BYPASS 시험한다. TDI/TDO/TCK/TMS 와 Device ID 를 한 번에 찾으며 BYPASS 스캔보다 훨씬 빠르다(IDCODE 를 지원하는 타깃). 채널 번호는 JTAGulator 의 CH0–CH23. 스캔은 범위 안의 모든 채널을
- **`jtagulator_uart_scan(case_id, start_channel, end_channel, text?, known_pins?, delay_ms?, printable_only?, pins_low?, pins_low_ms?, pins_high_ms?, idle_timeout_seconds?, max_duration_seconds?, approval_id?)`**  
  UART 핀아웃 스캔(UART 메뉴 'U'): (TXD,RXD) 순열마다 보드레이트 21개(300–307200)로 text 를 후보 RXD 로 보내고 응답(최대 16바이트)을 받는다. TXD = 타깃 송신 핀, RXD = 타깃 수신 핀. text 기본 '\r'(CR), 최대 16바이트, 정확히 그 바이트만 송신(hex 입력, 백슬래시 이스케이프 \r \n \xHH 해석 — 응답의 text_h
- **`jtagulator_uart_txd_scan(case_id, start_channel, end_channel, duration_seconds?, ignore_nonstandard?, idle_timeout_seconds?, approval_id?)`**  
  UART TXD 전용 수동 스캔(UART 메뉴 'T', FW 1.10+): 채널을 입력으로만 두고 duration_seconds 동안 UART 활동을 감시해 TXD 채널과 보드레이트(측정값/표준값)를 찾는다. 타깃에 아무것도 보내지 않아 가장 안전한 첫 단계 — 스캔 중에 사람이 타깃 전원을 다시 넣어 부팅 로그가 나오게 하면 좋다. ignore_nonstandard=true 면 표준 보드레
- **`jtagulator_get_device_ids(case_id, tdo, tck, tms, approval_id?)`**  
  핀아웃을 알 때 Device ID 읽기(JTAG 메뉴 'D'): TDO/TCK/TMS 를 지정해 체인의 IDCODE 를 상세(제조사/파트/버전)와 함께 읽는다. 주의: 펌웨어가 24채널 전부를 출력 HIGH 로 만든 뒤 실행한다(MODIFY). 전압 설정 필요. 결과는 jtag/jtagulator-<n>-device-ids-<k>.json.
- **`jtagulator_bypass_test(case_id, tdi, tdo, tck, tms, approval_id?)`**  
  핀아웃을 알 때 BYPASS 시험(JTAG 메뉴 'T'): TDI/TDO/TCK/TMS 로 체인 장치 수를 세고 32비트 무작위 패턴이 BYPASS 를 통해 그대로 돌아오는지(Match!) 확인한다 — 찾은 핀아웃 검증용. 주의: 24채널 전부를 출력 HIGH 로 만든 뒤 실행(MODIFY). 전압 설정 필요.
- **`jtagulator_gpio_read(case_id, samples?, interval_ms?)`**  
  모든 채널의 논리 레벨 읽기(GPIO 메뉴 'R', 수동): 채널을 입력으로 두고 samples 번(간격 interval_ms) 읽어 채널별 레벨, LOW 로 고정된 채널, 표본 사이에 값이 바뀐(활동 있는) 채널을 보고한다. 타깃을 구동하지 않는 관찰 단계(레벨 변환기의 약한 풀업만). 전압 설정 필요. UART TXD 후보(유휴 HIGH, 송신 중 변화)나 GND/고정 신호를 빠르게 가늠
- **`jtagulator_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`jtagulator_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`jtagulator_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-fwtriage

- **`fwtriage_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`fwtriage_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`fwtriage_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.
- **`fw_identify(case_id, path, offset?, length?, max_results?, include_nested?, max_seconds?, background?)`**  
  펌웨어/플래시 덤프 시그니처 스캔(헤더 검증으로 오탐 억제): uImage(헤더·데이터 CRC), FIT/DTB, squashfs(v1~4, 벤더 매직), jffs2(노드 CRC), UBI/UBIFS(CRC, 볼륨 이름), cramfs/romfs/erofs/ext2·3·4, gzip/xz/lzma/bzip2(시험 해제로 정확한 크기), zstd/lz4(프레임 검증), ELF, cpio, AR
- **`fw_entropy(case_id, path, block_size?, offset?, length?, high_threshold?, annotate?, max_results?, max_seconds?, background?)`**  
  블록 Shannon 엔트로피(0~8) 계산. 높은 엔트로피 연속 구간을 압축/암호화 '후보'로 표시하고 카이제곱으로 균일(암호화·강한 압축) / 비균일(일반 압축)을 구분, annotate=true 면 알려진 시그니처와의 겹침도 표시(설명되지 않는 고엔트로피 = 암호화·난독화 의심). 낮은 엔트로피 구간(패딩), 한 줄 프로파일 문자열 포함. 전체 블록 값은 analysis/entropy-N
- **`fw_uboot_env(case_id, path, sizes?, align?, include_default_env?, max_results?)`**  
  덤프/파티션에서 U-Boot 환경변수 블록 탐색 (pweh.formats.find_uboot_env: 후보 크기별 CRC 검증, redundant 플래그; 빅엔디안 CRC 보완). env 전체, 주요 변수(bootcmd/bootargs/mtdparts/ethaddr ...), mtdparts 해석(pweh.formats.parse_mtdparts, '-' 크기는 파일 끝까지), redunda
- **`fw_carve(case_id, path, mtdparts?, partitions?, output_label?, mtd_device?, probe?, layout_source?, lp_slot?, max_output_bytes?)`**  
  덤프를 파티션으로 분할: mtdparts 문자열(예: 'mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),-(rootfs)') 또는 partitions 목록([{name, offset, size}], 16진 문자열/크기 문자열 허용, size 생략 시 끝까지)을 사용. 둘 다 없으면 이미지 안의 raw GPT/LP → U-Boot env(mtdparts
- **`fw_android_surface(case_id, rootfs_dir?, image_path?, max_results?, max_evidence?, max_file_size?, max_seconds?, background?)`**  
  Android 펌웨어 정적 점검 AN-01~09: ADB 통신/인증, debug/root 빌드, test-keys, SELinux permissive, AVB disabled flags, init 서비스 권한, OTA 검증 구성, 특권 APK/permission XML, 하드코딩 자격증명. rootfs_dir(이미 추출한 트리) 또는 image_path(boot/vendor_boot/vbme
- **`fw_uimage_info(case_id, path, offset?)`**  
  offset 의 legacy uImage 헤더 파싱(이름, load/entry 주소, OS/arch/type/압축, 헤더·데이터 CRC 검증, multi 이미지 크기표, 실제 페이로드 형식과 헤더 압축 표시 일치 여부) 또는 FIT/DTB 해석(images: type/arch/compression/load/entry/data 크기/해시, configurations; DTB 면 model/co
- **`fw_extract_squashfs(case_id, path, offset?, output_label?, timeout_seconds?, max_output_bytes?, engine?, allow_listing_anomalies?, background?)`**  
  squashfs 추출 (unsquashfs: 설정 tools.unsquashfs / PWEH_UNSQUASHFS / ~/pweh-tools/bin; 비표준 매직·v4 빅엔디안은 sasquatch 우선). superblock 을 먼저 검증하고, 'unsquashfs -lln' 목록으로 디렉터리 탈출(.., 링크 아래 항목)·비정상 줄·압축 폭탄(max_output_bytes)을 검사한 뒤 ex
- **`fw_elf_info(case_id, path, max_results?, max_files?, max_seconds?, background?)`**  
  순수 Python ELF 분석: class/엔디언/타입/e_machine, e_flags 해석(MIPS ISA·ABI(o32/n32/n64)·ASE, .MIPS.abiflags FP ABI, ARM EABI·float ABI), 인터프리터, DT_NEEDED/SONAME/RPATH, 임포트 심볼(섹션 헤더 없는 sstrip 바이너리도 PT_DYNAMIC 로), 보호기법(NX/RELRO/PIE
- **`fw_rootfs_audit(case_id, rootfs_dir, max_results?, crack_defaults?, crack_seconds?, max_file_size?, max_seconds?, background?, sd_surface?)`**  
  추출된 rootfs 감사: passwd/shadow(빈/약한 해시와 알고리즘, uid 0 추가 계정, 공개 하드코딩 해시, 내장 기본 비밀번호 오프라인 대조), inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트(telnetd·-l /bin/sh, dropbear -B, nc -e 셸, getty 자동 로그인/콘솔 셸, remserial, 쓰기 가능한 영구 저장소 스
- **`fw_sd_surface(case_id, rootfs_dir?, image_path?, max_results?, max_evidence?, max_file_size?, max_seconds?, background?)`**  
  펌웨어 쪽 SD 카드 공격 표면 정적 점검 SD-01~09 (오프라인·관찰만: 기기와 카드를 건드리지 않고 펌웨어 안의 어떤 것도 실행하지 않는다, docs/design/sd-forensics.md 5.1). rootfs_dir(추출된 rootfs)과 image_path(플래시 덤프 또는 U-Boot·env 파티션) 중 하나 이상이 필요하다. rootfs: 시작·핫플러그 스크립트(rcS/in
- **`fw_strings_hunt(case_id, path_or_dir, patterns?, max_hits?, max_results?, min_severity?, include?, min_length?, utf16?, per_pattern_cap?, max_file_size?, max_seconds?, background?)`**  
  인증 우회/백도어/명령 주입/하드코딩 자격증명 문자열 휴리스틱 검색 (기본 CCTV 팩: src/pweh/data/cctv-hunt-patterns.yaml 의 string_heuristics, scope: strings=바이너리의 ASCII·UTF-16LE 문자열, text=텍스트 파일 줄, raw=바이트). patterns='cctv'(전체) 또는 목록: 휴리스틱 id/category/v
- **`fw_hunt_patterns(vendor?, category?, pack?)`** — [읽기전용]  
  휴리스틱 목록과 패턴 파일 출처·해시·오류. pack='cctv'(기본): fw_strings_hunt / fw_rootfs_audit / fw_elf_info 가 쓰는 cctv-hunt-patterns.yaml(string_heuristics 의 id/category/severity/scope/vendor, function_heuristics, web_server_binaries). pac
- **`fw_crack_hashes(case_id, hashes?, source_path?, wordlist?, extra_words?, hash_type?, max_seconds?, reveal?, max_results?, background?)`**  
  펌웨어에서 나온 비밀번호 해시를 공개 기본 비밀번호 사전(builtin-defaults: src/pweh/data/default-passwords.txt + YAML candidate_passwords)과 오프라인 대조 — 소유 기기 감사용, 네트워크 로그인 시도 없음. hashes: 'user:hash:...' 줄 / 순수 해시 / {user, hash, type} 목록, 또는 source
- **`fw_esp_partitions(case_id, path, offset?, max_results?)`**  
  ESP32 계열 플래시 덤프의 파티션 표 해석(기본 0x8000, 없으면 4 KiB 경계 탐색): label, type/subtype 이름, offset, size, flags(암호화·읽기 전용), MD5 항목 검증, 겹침·범위 밖 경고, 세이브 쓰기 분류 write_class(nvs / raw-user-data / filesystem-analysis-only / not-a-save)와 wr
- **`fw_esp_image_info(case_id, path, offset?, partition?)`**  
  ESP32 계열 앱(또는 2단계 부트로더) 이미지 해석: 칩(chip_id → 이름·아키텍처), entry, SPI 설정, 세그먼트(load 주소·크기·메모리 영역), 체크섬·덧붙은 SHA256 검증, 앱 설명(esp_app_desc: 프로젝트 이름, 버전, IDF 버전, 빌드 시각, ELF sha256). partition=label(전체 플래시 덤프의 앱 파티션) 또는 offset 으로 
- **`fw_esp_to_elf(case_id, path, offset?, partition?, output_label?, rea_compat?)`**  
  ESP32 계열 앱 이미지를 ELF32 로 바꾼다(세그먼트마다 PT_LOAD + 영역 이름의 섹션, e_machine 94 Xtensa / 243 RISC-V, entry 유지, 심볼 없음). REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못하고, RISC-V(C3·C6·H2·P4 …)는 rea_compat=true 로 만든 ELF(e_flags 를 double-float A
- **`fw_esp_nvs(case_id, path, offset?, length?, partition?, namespace?, key?, include_erased?, export_blobs?, max_results?)`**  
  ESP NVS 파티션 해석(4 KiB 페이지): 페이지 상태·seq·버전, 헤더·항목·데이터 CRC 유효 개수, 네임스페이스, 항목(namespace/key/type/값 — 정수, 문자열, blob v1·v2 를 이어 붙인 값), 최신(live) 여부와 지워진 이전 값(include_erased=true), 같은 키의 live 중복. 비밀로 보이는 값(nvs.net80211 의 모든 값, 비
- **`fw_save_diff(case_id, paths, labels?, offset?, length?, partition?, mode?, observations?, merge_gap?, max_results?)`**  
  세이브 스냅샷 비교(시간 순서 2~16개 — 점수·진행이 바뀔 때마다 덤프): mode='bytes' 는 바뀐 바이트 범위와 인코딩 해석(u8/u16/u32 LE·BE, BCD)·추세, mode='nvs' 는 NVS 키 단위 변화(changed·added·removed — 비밀 값은 마스킹), auto 는 NVS 파티션·NVS 형식이면 nvs. 바이트 비교는 비밀값을 가리지 못하므로 NVS 
- **`fw_checksum_find(case_id, paths, offset?, length?, partition?, algorithms?, max_results?, max_seconds?, background?)`**  
  세이브 체크섬 찾기: 시간 순서 스냅샷(2~16개, 3개 이상 권장)에서 '저장값 = 알고리즘(데이터 범위)' 이 모든 스냅샷에 맞는 (알고리즘, 엔디언, 위치, 범위) 후보. 알고리즘: sum8/16/32, xor8, negsum8, crc8(-maxim), crc16(ccitt-false/xmodem/modbus/arc), crc32, adler32, fletcher16. 위치 후보는 스
- **`fw_find_seq_tables(case_id, path, offset?, length?, partition?, base_addr?, min_len?, max_results?, max_seconds?, background?)`**  
  치트 입력(버튼 시퀀스) 표 후보 찾기: 작은 알파벳(버튼 id 0–15 또는 비트마스크)의 u8/u16/u32 배열, 코나미형(AABBCDCDEF) 모양, 반복 구조 점수. ESP 앱 이미지(partition=label 또는 offset 이 앱 이미지)면 플래시 rodata·데이터 세그먼트를 각자의 load 주소로 훑고(address = 디컴파일러 주소), 그 밖에는 범위를 base_add
- **`fw_patch_build(case_id, base_path, target, edits, purpose, unlock_source, online_capable, backup_path?, description?)`**  
  세이브 값 패치 이미지 만들기(소유 기기, 사용자가 명시적으로 원할 때만). base_path = 이 케이스에서 esp_read_flash_start 로 두 번 읽어 일치한 전체 플래시 덤프(offset 0). target = {type: 'nvs', partition} (기존 정수 NVS 항목, edits=[{namespace, key, value}]) 또는 {type: 'raw-regio
- **`fw_verify_writeback(case_id, patch_path, readback_path)`**  
  세이브 패치를 쓴 결과 확인: patch_path = fw_patch_build(stage=ready) 가 출처 원장(patch-plan)에 남긴 패치, readback_path = 쓰기 명령 뒤 esp_read_flash_start 로 대상 범위를 두 번 읽은 덤프(같은 MAC, 원장에서 patch-plan 보다 뒤). 기대값은 원장의 sha256 만 쓴다(패치 파일·결과 파일은 증거가 아
- **`fw_plan_imported_save(case_id, artifact_id, offset, length, edits, purpose, unlock_source, online_capable, checksum?, max_seconds?)`**  
  케이스에 가져온 일반 세이브 파일의 로컬 변경 계획을 만든다. artifact_id로 등록 파일 하나를 고르고 기존 imported-unattested 출처·같은 FD의 SHA와 크기를 확인한다. 입력은 1바이트~8MiB, 선택 offset/length와 편집·체크섬 좌표는 파일 기준 정수다. edits는 offset/encoding/value의1~16개 객체이며 정수·BCD 인코딩을 사용한

## pweh-esp

- **`esp_version()`** — [읽기전용]  
  esptool 백엔드 확인 (기기 미접촉, OBSERVE). backends.windows(방법 A: WSL interop 으로 Windows 용 esptool.exe 실행, port='COMn') 와 backends.linux(usbipd 로 attach 한 /dev/ttyACM0·/dev/ttyUSB0 를 리눅스 esptool 로)에 대해 {available, path, source, v
- **`esp_list_ports()`** — [읽기전용]  
  시리얼 포트 목록 (포트를 열지 않음, OBSERVE). windows{available, ports, note}: Windows 의 COM 포트(powershell.exe 로 Win32_PnPEntity 조회 — port, name, vid, pid, serial_number, usb_id, kind, description_ko), linux{ports, hidden_legacy_ports
- **`esp_chip_info(case_id, port, chip?, baud?, before?, after?, no_stub?, timeout_s?, approval_id?)`**  
  칩·플래시 정보 (esptool flash-id, MODIFY: DTR/RTS 또는 USB-Serial/JTAG 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁, 플래시/eFuse 쓰기 없음, 케이스 소유/허가 증명 필요). port: 'COM3'(방법 A, Windows esptool.exe) 또는 '/dev/ttyACM0'(리눅스 esptool). 반환: chip, chip_descr
- **`esp_security_info(case_id, port, chip?, baud?, before?, after?, no_stub?, timeout_s?, approval_id?)`**  
  보안 설정 조회 (esptool get-security-info, MODIFY: 리셋으로 ROM 다운로드 모드 진입, 쓰기 없음, 케이스 소유/허가 증명 필요). 반환: status('ok' | 'unsupported'), secure_boot, flash_encryption(SPI_BOOT_CRYPT_CNT 홀수 비트=켜짐), crypt_cnt, secure_download_mode(플래그
- **`esp_read_flash_start(case_id, port, chip?, offset?, size?, output_name?, baud?, verify?, before?, after?, no_stub?, timeout_s?, approval_id?)`**  
  플래시 덤프 작업 시작 (esptool read-flash, job, MODIFY: 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁, 플래시/eFuse 쓰기 없음, 케이스 소유/허가 증명 필요). 방법 A: port='COM3' 이면 Windows esptool.exe 가 wslpath 로 바꾼 경로에 바로 쓴다. offset(정수/'0x..'), size('all'=감지 크기(offse
- **`esp_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`esp_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`esp_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-forensics

- **`forensics_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`forensics_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`forensics_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.
- **`forensics_image_hints(case_id, evidence_id, partition?, ref?, path?, method?, ocr?, ocr_lang?, qr?, preview?, crop?, max_seconds?)`**  
  증거의 정지이미지 1개를 오프라인 분석한다(소유/허가·보관 기록·open_checked 무결성 검사 필수). ref 또는 path 로 FAT/exFAT·TAR/ZIP 파일 1개를 선택한다(동시 지정 금지); 둘 다 없으면 EV 자체를 정지이미지로 읽는다. 삭제 파일은 ref 와 복구 method(auto 기본)로 선택하며 방법·신뢰도·완전성을 출처에 기록한다. 불완전한 파일은 거부한다. 최대
- **`forensics_intake_start(case_id, image_path, purpose, legal_basis, site_type, business_purpose, role, imaging_log_path?, label?, verify_copy?, storage?)`**  
  증거 이미지·TAR/ZIP 논리 추출 파일 접수 (job). storage=copy(기본)는 사본을 만들고 reference 는 제자리 참조다. reference 는 비안전 설정 forensics.reference_roots(기본 []) 아래 실제 읽기 전용 마운트(ST_RDONLY)의 일반 파일만 받으며 매번 열 때 현재 정책·마운트를 확인한다. 원본을 chmod·마운트·삭제하지 않는다. 
- **`forensics_verify_start(case_id, evidence_id)`**  
  증거 사본 전체 재해시 (job). 접수 때의 sha256·md5·sha1(보관 기록 intake 사건의 값)과 비교해 match/mismatch 를 보관 기록 verify 사건으로 남긴다. 다르면 integrity-failed 로 표시되고 그 증거의 내용 도구는 모두 거부된다(되돌리지 않는다 — 원본에서 다시 접수). 빠른 지문(크기·mtime·앞뒤 1 MiB 해시·쓰기 권한 없음)이 이미
- **`forensics_acquisition_attest(case_id, evidence_id)`**  
  획득 방법의 사람 증명 (write-blocker). 사람이 별도 터미널에서 `pweh attest <id>` 로 '하드웨어 쓰기 방지 장치를 거쳐 이미징했다'와 장치 모델·희생용 카드 시험 여부·이미징 도구를 답한다(증거 id·sha256 에 묶임, 90일). 에이전트는 답하거나 증명을 대신 만들지 않는다. 결과(승인·거부, 앞 증명의 철회·만료)는 보관 기록 attest 사건으로 남고 증
- **`forensics_evidence_list(case_id, write_files?)`**  
  증거 목록과 해시값 확인서. reference 증거가 있으면 자동 job으로 전체 재해시하고 forensics_job_status로 폴링한다. 참조 정책·읽기 전용 상태·전체 해시 확인이 끝나지 않으면 성공 확인서를 만들지 않는다. 사본만 있으면 즉시 반환한다. 항목마다 크기·해시·status(ok/unverified/integrity-failed/missing/record-invalid/c
- **`forensics_partitions(case_id, evidence_id)`** — [읽기전용]  
  증거 이미지의 파티션 구조 (읽기 전용, 호출 예산 60초): MBR/EBR·GPT(헤더·항목 CRC 검사, 512/4096 바이트 섹터)·파티션 표 없음(superfloppy) → partitions[{index, scheme, start_offset, size_bytes, type_name, name·guid(GPT), fs_hint(fat12/fat16/fat32/exfat/ntfs/e
- **`forensics_image_check(case_id, evidence_id, partition?, acquisition_date?)`** — [읽기전용]  
  호스트 오염 흔적 검사 (읽기 전용): 보관 기간에 분석 PC 가 카드에 남겼을 흔적 — strong: $RECYCLE.BIN, System Volume Information 의 IndexerVolumeGuid·WPSettings.dat, .DS_Store·._*(AppleDouble)·.Spotlight-V100·.fseventsd·.Trashes, Thumbs.db·desktop.ini,
- **`forensics_fs_list(case_id, evidence_id, partition?, include_deleted?, max_entries?, max_seconds?)`**  
  파일 시스템·논리 TAR/ZIP 목록(FAT12/16/32·exFAT 삭제 항목 포함). TAR/ZIP 은 arc:<순번> ref, 멤버 sha256를 바이트 상한 1 GiB와 max_seconds 안에서 계산한다. 예산 밖 멤버는 sha256=null,status=unverified 이며 사유를 남긴다. 비압축 TAR, ZIP stored/deflate만 지원하며 암호화·링크·sparse·
- **`forensics_extract(case_id, evidence_id, refs?, paths?, partition?, method?, region?, label?, max_files?, max_bytes?)`**  
  파일·삭제 파일·TAR/ZIP 멤버 추출 (job). 아카이브는 arc:<순번> ref 또는 정확한 path를 쓰며 중복 이름은 ref로 선택한다. 경로 탈출·링크·특수파일·암호화는 거부하고 ZIP CRC 검증을 끝낸 파일만 보존한다. refs(forensics_fs_list 결과 JSON 의 ref) 또는 paths(살아 있는 파일 경로)로 고른 파일만 forensics/recovered/
- **`forensics_sqlite_inventory(case_id, evidence_id, partition?, ref?, path?, wal_ref?, wal_path?, journal_ref?, journal_path?, method?, max_seconds?)`**  
  증거에서 선택한 SQLite DB 1개의 헤더·schema·table 행 수·freelist와 제공된 WAL/journal 정보를 읽는다. ref/path는 FAT/exFAT 또는 TAR/ZIP 멤버 선택자이며 둘 다 없으면 EV 자체가 DB여야 한다. WAL/journal은 자동 탐색하지 않고 같은 EV·파티션·디렉터리의 DB 이름+-wal/-journal을 명시한다. 각 입력64MiB, 
- **`forensics_android_artifacts(case_id, evidence_id, partition?, ref?, path?, wal_ref?, wal_path?, journal_ref?, journal_path?, method?, families?, include_deleted?, max_records?, max_seconds?)`**  
  선택한 증거 SQLite에서 SMS·통화·연락처·브라우저 기록을 스키마 프로필로 분석해 내용도 반환한다. 입력 선택·무결성·64MiB/45초 제한은 forensics_sqlite_inventory와 같다. families는 sms/calls/contacts/browser, include_deleted는 WAL 과거기록·freelist 복구 후보 포함이며 삭제 확정을 뜻하지 않는다. 최대 ma
- **`forensics_timeline(case_id, evidence_id, partition?, analysis_paths?, max_events?, max_seconds?)`**  
  증거 FAT/exFAT·TAR/ZIP의 파일 시각과 명시한 앱 분석 JSON의 사건을 타임라인으로 묶는다. analysis_paths는 같은 EV의 android-artifacts 보관 기록·SHA256에 맞는 JSON만 받는다(최대16개, 합16MiB). 시각의 raw/단위/epoch/time_basis를 보존하며 FAT·ZIP DOS의 시간대는 추정하지 않는다. UTC로 바꿀 수 없는 사
- **`forensics_scan_secrets(case_id, evidence_id, partition?, ref?, path?, method?, xor_key?, max_hits?, max_seconds?, offset?, length?)`**  
  증거의 선택 텍스트 파일 1개에서 자격증명·토큰 후보를 오프라인 검사한다. 소유/허가·보관 기록·무결성 검사 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택하며, 둘 다 없으면 EV 자체를 읽는다. 완전한 파일만, 해제 크기 최대 4 MiB·UTF-8/BOM만 받는다. offset/length를 함께 지정하면 EV 안의 1바이트~4MiB 명시 구간만 선택한다. 구간은 e
- **`forensics_scan_secrets_from_list(case_id, evidence_id, fs_list_path, partition?, xor_key?, max_seconds?)`**  
  같은 EV의 보관 기록에 결속된 FAT/exFAT fs-list 전체 JSON에서 파일을 자동 선정해 비밀값 후보를 검사한다. fs_list_path는 forensics/analysis/fs-list-EV-NNNN-NNN.json 생성 경로이며, partition 생략 시 저장 목록의 모든 지원 볼륨을 대상으로 한다. 목록의 순서대로 디렉터리·미디어 이름·빈 data·4MiB 초과 파일을 제
- **`forensics_sd_ioc_scan(case_id, evidence_id, firmware_result_path, fs_list_path, partition?, max_matches?, max_seconds?)`**  
  같은 케이스의 fw_sd_surface 전체 결과와 같은 EV의 FAT/exFAT fs-list 전체 JSON을 대조해 펌웨어 참조 경로와 카드 파일 이름이 겹치는 후보를 찾는다. firmware_result_path는 analysis/sd-surface-NNN.json, fs_list_path는 forensics/analysis/fs-list-EV-NNNN-NNN.json의 생성 상대 경로
- **`forensics_media_inventory(case_id, evidence_id, partition?, ref?, path?, method?, max_seconds?)`**  
  증거에서 선택한 파일 1개의 MP4/QuickTime 계열 ISO BMFF 상자 구조를 오프라인 목록화한다. 소유/허가·보관 기록·무결성 확인 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택한다. 둘 다 없으면 EV 자체를 읽으며 자동 검색·카빙은 하지 않는다. 완전한 파일만 최대 64 MiB, max_seconds는 0 초 초과·최대 45초(선택·읽기·구조 검사 공통)
- **`forensics_media_candidates(case_id, evidence_id, partition?, ref?, path?, method?, max_seconds?, offset?, length?, region?)`**  
  증거에서 선택한 파일 1개의 완전한 바이트 또는 EV의 명시 구간에서 ftyp 기반 ISO BMFF 연속 최상위 상자 prefix 후보를 찾는다. 소유/허가·보관 기록·무결성 확인 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택한다. ref/path와 offset/length가 모두 없으면 EV 전체를 선택한다. offset/length는 exact int를 함께 지정하
- **`forensics_dhav_candidates(case_id, evidence_id, partition?, ref?, path?, method?, max_seconds?, offset?, length?, region?)`**  
  선택한 완전 파일 또는 EV의 명시 바이트 구간에서 DHAV 고정 record 구조 후보를 관찰한다. ref/path는 FAT/exFAT·TAR/ZIP 파일 하나이며 둘 다 없으면 EV 전체를 읽는다. offset/length는 exact int로 함께 지정하고 선택자·partition과 혼용하지 않으며 method=auto만 받는다. 선택·구간은 최대 64 MiB, offset+length
- **`forensics_extract_dhav_candidate(case_id, evidence_id, analysis_path, candidate_index)`**  
  보관 기록에 결속된 dhav-candidates 보고서의 candidate_index 하나를 파생 추출한다(job). analysis_path는 같은 케이스·EV의 생성 보고서 경로이며 index는 0~127의 저장 후보를 고른다. 증거와 보고서의 무결성을 확인하고 원래 ref/partition/복구 방법, 명시 exFAT 잔여 영역 또는 EV 명시 구간으로 같은 완전 바이트를 다시 읽는다.
- **`forensics_dhav_scan(case_id, evidence_id, start_offset?, max_scan_bytes?, max_seconds?)`**  
  접수한 EV 이미지에서 DHAV record 구조 후보를 나눠 읽어 검색한다. start_offset은 EV 절대 위치(기본0), max_scan_bytes는 연속 검색 읽기 합계4 bytes..1 GiB(기본1 GiB)다. 64 KiB 이하 창과 메모리 carry로 창 경계 표지를 확인한다. 구조 필드 읽기는 별도1 MiB까지이며 검색 창 밖이라도 EV 안의 헤더/끝 표지는 대조한다. 전체
- **`forensics_bmff_scan(case_id, evidence_id, start_offset?, max_scan_bytes?, max_seconds?)`**  
  접수한 EV 이미지에서 ftyp 기반 BMFF 연속 최상위 상자 prefix 후보를 나눠 읽어 검색한다. start_offset은 EV 절대 위치(기본0), max_scan_bytes는 연속 검색 읽기 합계8 bytes..1 GiB(기본1 GiB)다. 64 KiB 이하 창과 메모리 carry로 창 경계 표지를 확인한다. 구조 필드는 별도1 MiB까지 읽으며 검색 창 밖이라도 EV 안의 헤더/
- **`forensics_media_unit_candidates(case_id, evidence_id, format, partition?, ref?, path?, method?, max_seconds?, offset?, length?, region?)`**  
  선택한 완전 파일 또는 EV 명시 구간에서 format 하나의 고정 미디어 단위 구조 후보를 관찰한다. format은 jpeg, avc-annexb, mpeg2-ps, xm만 받으며 자동 형식 판정은 하지 않는다. ref/path는 FAT/exFAT·TAR/ZIP 파일 하나, 둘 다 없으면 EV 전체다. offset/length는 exact int로 함께 지정하고 selector·partit
- **`forensics_media_unit_scan(case_id, evidence_id, format, start_offset?, max_scan_bytes?, max_seconds?)`**  
  접수한 EV 이미지에서 명시 format(jpeg, avc-annexb, mpeg2-ps, xm)의 고정 미디어 단위 후보를 나눠 읽어 검색한다. start_offset은 EV 절대 위치(기본0), max_scan_bytes는 연속 검색 읽기 합계4 bytes..1GiB(기본1GiB)다. leaf는64KiB 이하이며 검색 창 밖의 구조 읽기와 논리 검사량은 각각128MiB로 따로 제한한다. 
- **`forensics_extract_media_unit(case_id, evidence_id, analysis_path, candidate_index)`**  
  보관 기록에 결속된 media-unit-candidates 보고서의 candidate_index 하나를 파생 추출한다(job). analysis_path는 같은 케이스·EV의 생성 보고서이며 index는 저장 후보0~127이다. format과 bytes 범위는 저장된 보고서만 사용하며 새 selector/offset/길이를 받지 않는다. 원래 ref/partition/복구 방법, 명시 exF
- **`forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)`**  
  보관 기록에 결속된 media-candidates 보고서의 candidate_index 하나를 파생 추출한다(job). analysis_path는 같은 케이스·EV의 생성 보고서 경로이며 index는 0~127의 저장 후보를 고른다. 증거와 보고서의 무결성을 확인하고 원래 ref/partition/복구 방법, 명시 exFAT 잔여 영역 또는 EV 명시 구간으로 같은 완전 바이트를 다시 읽는다
- **`forensics_allocation_window(case_id, evidence_id, partition, offset, length, max_seconds?)`**  
  접수한 EV 이미지의 명시 FAT/exFAT 파티션에서 현재 할당 상태 메타데이터를 검사한다. partition은 필수 index, offset은 EV 절대 위치, length는 1 byte..64 MiB이며 exact int만 받는다. 창은 해당 파티션의 데이터 클러스터 영역 안이어야 한다. unallocated/allocated/bad/unknown 연속 범위와 미검사 suffix·nex
- **`forensics_cluster_report(case_id, evidence_id, partition, max_seconds?)`**  
  접수한 EV 이미지의 명시 FAT12/16/32·exFAT 파티션에서 현재 할당과 live 항목 참조를 비교한다. partition은 필수 exact int1..4096, max_seconds는0초 초과..45초다. 케이스 조회 전부터 같은 처리 예산으로 탐지·metadata·live 순회·분류를 수행한다. metadata 읽기 합계32MiB·클러스터2**20개·항목16384개·행128개·J

## pweh-emu

- **`emu_status()`** — [읽기전용]  
  에뮬레이션 백엔드 확인 (OBSERVE, 케이스 없음, 게스트를 실행하지 않는다). backends['esp-qemu'] = {available, xtensa{path, source(config|env|pweh-tools), version, expected_version, version_ok, machines[], sha256_ok, roms{}}, riscv32{…}, chips, chip
- **`emu_start(case_id, firmware, backend?, chip?, board?, mcu?, freq_hz?, psram?, psram_mb?, watchdog?, on_reset?, timeout_s?, idle_timeout_s?, label?, approval_id?)`**  
  펌웨어 에뮬레이션 세션 시작 (MODIFY emu.start — 호스트에서 확보한 펌웨어를 실행, 기기 미접촉, 케이스 소유/허가 필요). firmware: 케이스 상대 경로(forensics/·emu/ 거부). 이 케이스 기기에서 읽은 덤프(device-read, 오프셋 0 전체 플래시)나 사람이 출처를 증명한 가져온 파일만 — 가져온 파일의 첫 호출은 attestation_required
- **`emu_read(session_id, since_cursor?, max_chars?, wait_seconds?, until?, until_ignore_case?, tail?, case_id?)`** — [읽기전용]  
  에뮬레이터 콘솔 읽기 (OBSERVE). 서버가 줄 단위로 마스킹한 글만(자격증명·NVS 비밀값 가림, 제어 문자 이스케이프, 반복 줄 접기 '⟪위 줄 ×N⟫'). 커서는 원시 바이트 오프셋이지만 줄 경계에만 놓인다 — since_cursor 가 줄 중간이면 그 줄 시작으로 내린다. 생략하면 직전 cursor_end 부터. max_chars 256–65536(글자 수 — uart_read 의
- **`emu_write(session_id, data, encoding?, approval_id?)`**  
  에뮬레이터 콘솔에 입력 (INTERACT emu.write — 에뮬레이션된 장치에만 영향, 늘 허용되고 감사에 남는다: 바이트 수·printable 만, 원문·다이제스트 없음). data: encoding='text'(UTF-8 그대로 — 줄 끝 \r/\n 은 직접 넣는다) | 'hex'(공백 허용), 1–4096 바이트. 비차단 쓰기로 최대 2초 — 게스트가 입력을 읽지 않으면 일부만 쓰고
- **`emu_stop(session_id, case_id?)`**  
  에뮬레이터 세션 정지 (정리 도구 — 게이트 없음, 늘 동작). 이유를 먼저 기록하고 SIGTERM → 3초 → SIGKILL(프로세스 그룹), 감독 스레드 합류, 기록 마감, 아티팩트 등록(kind other + extra.type: emu-console-raw·emu-transcript·emu-events·emu-session·emu-stderr). 이미 끝난 세션도 부른다(already
- **`emu_sessions(case_id?)`** — [읽기전용]  
  에뮬레이터 세션 목록 (OBSERVE). 이 서버 프로세스의 세션(끝난 것 포함): sessions[{session_id, case_id, backend, target, state, stopped_by, started_at, uptime_s, timeout_in_s, idle_timeout_in_s, raw_bytes, cursor_end, firmware{path, sha256}, dir}

## pweh-espprobe

- **`espprobe_version()`** — [읽기전용]  
  시뮬레이터 백엔드·프로토콜 버전과 한도 조회. 장치 열거·외부 프로세스 실행 없음.
- **`espprobe_connect(case_id, port?)`**  
  케이스의 합성 HELLO/HB 시뮬레이터 연결. port는 정확히 sim://probe-hello만 허용하며 실제 포트는 열지 않는다. nonce·세션·USB 식별·빈 핀/버스/무선 정책을 고정 합성 기대값과 대조하고 HB를 시작한다. 케이스당 한 세션, 전체 16개, 최대 600초. 반환 hello의 hash/MAC은 실제 기기 증거가 아니다.
- **`espprobe_status(case_id?)`** — [읽기전용]  
  현재 프로세스의 시뮬레이터 세션 상태·해제 사유·카운터 조회. case_id 생략 시 전체(최대16개).
- **`espprobe_self_test(case_id)`**  
  연결된 모델의 HELLO 정책과 새 HB 왕복을 확인하고 결과를 케이스에 기록한다. 실제 USB·핀·전압·펌웨어 부팅을 시험한 결과가 아니다. 해제된 세션을 자동으로 다시 연결하지 않는다.
- **`espprobe_release_all(case_id)`**  
  시뮬레이터에 RELEASE를 보내고 HB를 끝낸다. 반복 호출해도 해제 상태를 유지한다. 실제 핀 제어 없음.
- **`espprobe_disconnect(case_id)`**  
  모델에 BYE를 보내고 시뮬레이터·HB worker를 종료한다. 최종 JSON을 아티팩트로 기록하며 반복 호출 가능.

## pweh-sdr

- **`sdr_analyze(case_id, artifact_id, profile, max_seconds?)`**  
  케이스에 등록된 일반 파일 하나를 오프라인 RAW 프로필로 검사한다. artifact_id는 같은 케이스 A-id이며 profile='flipper-subghz-raw-v1-strict'를 반드시 지정한다. 소유/허가 확인이 필요하며 forensics/·emu/ 입력은 받지 않는다. 최대1 MiB, max_seconds는0초 초과5초 이하(기본5)이며 입력 선택·읽기·SHA·검사가 같은 예산
- **`sdr_peaks(case_id, artifact_id, max_seconds?)`**  
  케이스에 등록된 일반 파일 하나를 고정 rtl-power-blog-v1.4.0-csv 프로필로 오프라인 검사한다. artifact_id는 같은 케이스 A-id이며 소유/허가 확인이 필요하다. forensics/·emu/ 입력은 받지 않는다. 파일은 최대1MiB, max_seconds는0초 초과5초 이하(기본5)이며 입력 선택·읽기·SHA·검사가 같은 예산을 사용한다. 결과 생성 뒤 최종 무결
- **`sdr_import_flipper_sub(case_id, artifact_id, max_seconds?)`**  
  케이스에 등록된 Flipper Sub-GHz RAW 파일 하나를 오프라인 OOK 텍스트로 변환한다. artifact_id는 같은 케이스 A-id이며 소유/허가 확인이 필요하다. forensics/·emu/ 입력은 받지 않는다. 최대1MiB 입력을 기존 strict RAW 프로필로 먼저 검사하고 complete인 OOK270/OOK650만 허용한다. 짝수 duration을 순서대로 최대1200

## pweh-play

- **`vision_validate(case_id, input_kind, observations, now, policy?)`**  
  호출자가 공급한 숫자 표본의 시간 창 합의를 계산한다. input_kind='numeric-observations'가 필수다. observations는 timestamp/value/confidence를 가진 객체0~256개이며 now와 timestamp는 같은 공급 monotonic seconds 축의0~2**53이다. 시각은 엄격 증가하고 now 이하, value는 null 또는 int64
- **`vision_template_match(case_id, reference_artifact_id, reference_preview_index, reference_roi, candidate_artifact_id, candidate_preview_index, candidate_roi, max_mean_error)`**  
  같은 소유/허가 케이스에 등록된 image-hints JSON 보고서의 정규화 PNG 두 영역을 비교한다. 두 artifact_id는 PNG가 아닌 보고서 JSON의 등록 ID이며 preview_index는 0 또는 1이다. 각 roi는 저장 PNG 픽셀의 [x,y,width,height] 정수 배열이고 두 영역의 크기는 같아야 한다. RGB 절대차 합계·표본 수·평균과 max_mean_er

## pweh-flipper

- **`flipper_connect(case_id, port, approval_id?)`**  
  명시 Flipper USB CLI 포트에 연결한다. 소유/허가 확인 및 전체 USB sibling 잠금 뒤 MODIFY gate를 거친다. 115200 8N1, DTR=true/RTS=false 고정이며 포트 열기가 장치 상태에 영향을 줄 수 있다. VID/PID0483:5740·첫 CLI interface00과 공식1.5.1 고정 문법만 받는다. 새 배너·버전·기본 프롬프트 전 명령 TX0
- **`flipper_close(case_id)`**  
  Flipper 세션을 닫는다. 새 요청을 막고 worker 취소·직렬 read 깨우기 뒤 실제 핸들 닫힘과 사용권0을 확인한다. 정리가 미확인이면 cleanup_pending으로 세션·잠금을 보존하며 같은 도구로 다시 정리한다. 케이스 허가가 철회되어도 정리할 수 있다. 장치 명령 종료나 RF field off는 증명하지 않는다.
- **`flipper_device_info(case_id)`** — [읽기전용]  
  연결된 Flipper의 loader idle을 확인하고 고정 info device 응답을 읽는다(OBSERVE). model·target·format·고정 firmware 호환 정보만 반환하며 장치 UID·이름·BLE MAC·원문을 반환하지 않는다. 소유/허가와 현재 포트·역할·잠금을 다시 확인하며 앱 유휴 관찰은 앱 실행 잠금이 아니다.
- **`flipper_storage_list(case_id, path)`** — [읽기전용]  
  연결된 Flipper의 /ext/pweh/<case_id>/ 아래 한 디렉터리를 고정 storage list로 읽는다(OBSERVE). loader idle·현재 신원 확인 후 이름/type/size 최대256개와 종결 여부를 반환한다. path는 제한 ASCII 경로이며 링크 이동·임의 루트·명령은 받지 않는다. 응답 한도256KiB를 넘으면 실패한다. listing_complete는 CL
- **`flipper_nfc_probe(case_id, approval_id?)`**  
  연결된 고정1.5.1 Flipper에서 ISO14443-3A 선택과 고정 GET_VERSION만 수행한다. 같은 case의 /ext/pweh/<case_id>/ 기존 폴더에 서버 생성 scratch 한 개를 쓰므로 MODIFY gate를 적용한다. 45초·probe4KiB 한도에서 UID7/SAK0·NTAG213/215/216 version과 CRC, 재선택 identity를 대조하고 정상 
- **`flipper_storage_pull_start(case_id, flipper_path, dest_name?)`**  
  연결된 Flipper의 /ext/pweh/<case_id>/ 아래 파일 하나를 받는 job을 시작한다(고정 읽기 OBSERVE). flipper_path는 제한 ASCII 파일 경로, dest_name은 선택적 host basename이며 출력은 flipper/ 아래 새 파일이다. 최대1MiB·300초이며 binary 본문은 해석하지 않는다. 종결 뒤 장치 MD5와 host MD5·SHA를 
- **`flipper_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`flipper_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`flipper_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

## pweh-nfc

- **`nfc_tag_inventory_add(case_id, scan_ref)`**  
  같은 케이스 flipper_nfc_probe 또는 nfc_cu_scan의 보호된 scan_ref를 NTAG213/215/216 inventory로 등록한다. 사용자 UID/family나 cache로 scan을 대신하지 않는다. 공개 tag_ref·scan_ref·케이스 솔트 지문과 scan/inventory 원장 seq/hash만 반환한다. 물리적으로 같은 태그인지는 검증하지 않는다.
- **`nfc_parse_file(case_id, artifact_id, tag_ref, max_seconds?)`**  
  등록 artifact_id의 Flipper v4 NFC 파일 또는 서버 생성 CU snapshot 하나를 같은 케이스 tag_ref와 결속해 오프라인 검사한다. v4는1MiB, CU snapshot은64KiB 이하 단일 링크 일반 파일이며 forensics/emu/보호 경로는 받지 않는다. UID/ATQA/SAK/GET_VERSION 신원은 내부에서만 비교한다. 가져온 파일은 기존 prove
- **`nfc_diff_dumps(case_id, before_artifact_id, after_artifact_id, tag_ref, max_seconds?)`**  
  같은 tag_ref에 결속한 before/after 등록 NFC 덤프 두 개의 저장 페이지를 오프라인 비교한다. 두 파일은 모두 imported v4이거나 모두 CU snapshot이어야 하며 혼합은 거부한다. v4는 각각1MiB 이하·현재 provenance-import 증명이 필요하고 CU는64KiB 이하·현재 전용 device-read 결속을 확인한다. read<total·ISO 헤더·
- **`nfc_cu_connect(case_id, port, approval_id?)`**  
  명시 USB CDC CU 포트를 전체 장치 범위로 잠근 뒤 MODIFY gate를 거쳐 연결한다. 115200 8N1/DTR=true/RTS=false이며 모델 Ultra·정확2.2/v2.2.0·현재 reader 모드를 고정 조회한다. 모드 변경은 하지 않으며 호환 확인 전 RF 명령을 보내지 않는다. 모델·버전은 자기 보고이며 서명 증명이 아니다. 조회 worker5초, 정리 최대10초이며
- **`nfc_cu_scan(case_id, session_id, approval_id?)`**  
  정확한 case/session의 CU reader에서 MODIFY gate 뒤 고정14A 선택·GET_VERSION·READ0/1을 수행한다. 45초 안에 NTAG213/215/216·UID7/ATQA/SAK와 두 시작 페이지의 UID/BCC를 내부 대조하고 scan 사실을 남긴다. READ16B마다 첫4B만 해당 시작 페이지로 사용하며 원시 UID·페이지·version은 반환하지 않는다. 
- **`nfc_cu_disconnect(case_id, session_id)`**  
  정확한 case/session의 CU worker를 취소하고 물리 transport 종료 및 사용권0 뒤 lease를 해제한다. 허가 철회 뒤에도 정리 가능하며 최대10초의 정리 미확인은 세션·잠금을 보존한다. 추가 RF-off·mode 변경 명령은 보내지 않고 RF off나 장치 명령 종료를 검증했다고 하지 않는다.
- **`nfc_cu_read_start(case_id, session_id, tag_ref, approval_id?)`**  
  같은 케이스의 ready CU session_id와 현재 tag_ref에 결속해 NTAG213/215/216 저장 페이지 읽기 job을 시작한다. 고정 Ultra2.2 reader만 사용하며 페이지 범위·임의 명령·인증·쓰기는 받지 않는다. wire45초와 별도 host 게시5초 안에 검증한 prefix를 nfc/cu-read-NNN.json에 저장한다. time_limit/nfc_scan_
- **`nfc_job_status(job_id, wait_seconds?, case_id?)`**  
  백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. wait_seconds>0 이면 이 프로세스의 작업만 최대 50초 기다린다. case_id를 주면 해당 케이스의 저장 기록도 조회하고, 소유
- **`nfc_job_cancel(job_id)`**  
  실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.
- **`nfc_jobs(active_only?, case_id?)`**  
  이 서버 프로세스의 백그라운드 작업 목록. case_id를 주면 해당 케이스에 저장된 이 서버의 기록을 최대 256개·8MiB·2초로 확인하며 잘림은 recovery에 표시한다. 소유 서버 종료가 확인된 활성 기록만 failed로 정리한다. owner 없는 과거 기록은 확인 불가로 표시하며 재개하지 않는다.

