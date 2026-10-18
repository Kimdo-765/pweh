---
name: firmware-dump-via-uart
description: Dump IP camera/DVR/IoT flash firmware over the UART console, for authorized/owned devices only. From a U-Boot prompt it runs the uboot_dump_start job (sf/nand/mmc read, md.b, device crc32 per chunk); from a root shell it runs shell_dump_start (dd piped to base64 or hexdump, md5 per chunk). It estimates the time first (16 MiB at 115200 baud is about 2 h), offers a priority range (boot+env+kernel+rootfs) or faster human/network routes (U-Boot tftpput, SPI clip, then case_import_file), picks a safe RAM address and chunk size, polls uart_job_status, resumes failed dumps, cross-checks and records the firmware-dump summary. Read-only, never sf write/erase, saveenv or writes to /dev/mtd. Trigger words — firmware dump, flash dump, firmware backup, read SPI flash, md.b, sf read, mtdblock, resume dump. 펌웨어 덤프, 플래시 덤프, 펌웨어 백업, 플래시 읽기, UART 덤프, 덤프 이어받기.
---

# UART 펌웨어 덤프 (firmware-dump-via-uart)

`orchestrator/master-prompt.md` Phase B 의 UART 경로다. 소유/서면 허가가 기록된 케이스에서만 쓴다. 플래시를 **읽기만** 한다. 결과는 연구·방어용이다(공격 페이로드나 제3자 시스템 공격 없음).
시간표, 청크·RAM 주소 선택, 응답 필드, 오류 표, 대안 경로(tftpput·SPI 클립 등), 추가 예시는 [reference.md](reference.md) 에 있다.

## 목적

- U-Boot 프롬프트나 root 셸에서 플래시(전체 또는 합의한 범위)를 청크 단위로 받아 `dumps/<name>.bin` 으로 만든다.
- 청크마다 기기 측 검사값(crc32/md5)으로 검증한다. 전체 crc32, 내용 확인, 교차 확인 결과와 sha256 을 케이스에 남긴다.
- 다음 Skill(firmware-static-analysis)이 바로 쓰도록 `firmware-dump` 요약(method, source, output, verification, chunks, partitions, duration, baudrate)을 기록한다.

## 언제 쓰나

- **쓴다**: uart-shell-acquisition 요약의 access_level 이 `uboot` 또는 `root-shell` 일 때. "펌웨어 덤프/백업", "플래시 읽기", "덤프 이어받기" 요청.
- **쓰지 않는다**
  - 케이스나 소유/허가 증명이 없다 → master-prompt Phase 0.
  - 콘솔로 덤프할 수 없다 (access_level 이 none/boot-log, login-required 인데 계정을 모름, user-shell 뿐) → reference.md §6 대안(SPI 클립, 공식 이미지) 또는 JTAG(pweh-openocd). 부트 인자를 바꿔 로그인을 건너뛰는 일은 이 Skill 에서 하지 않는다.
  - 플래시 쓰기·복구·업데이트 → 범위 밖 (docs/safety.md §3.2·§5 의 사람 승인 흐름).
  - 공식 펌웨어 파일만 분석한다 → `case_import_file` 후 firmware-static-analysis (실제 기기 펌웨어와 다를 수 있다고 기록).

## 전제 조건

- **case_id**: `case_get` 의 case.authorized 가 true 여야 한다. 아니면 멈춘다 (master-prompt §1-1).
- **이전 요약** (`case_get_step_results(case_id)`)
  - uart-shell-acquisition(uart-recon): port, baudrate, access_level, console_type, uboot.partitions·mtdparts·flash·ram_load_addr·commands, linux.mtd·user, session(열어 둔 세션의 session_id·context_at_end). 없으면 uart-shell-acquisition 부터 한다.
  - firmware-dump-via-uart 의 이전 summary 와 job-* 단계: 이미 받은 범위는 건너뛰고, 끝나지 않은 job 은 같은 인자로 재개한다 (7단계).
- **하드웨어**: uart-shell-acquisition 때의 UART 배선(GND·TX·RX, VCC 미연결)이 그대로 있고 어댑터가 PC 에 붙어 있다 (WSL 이면 usbipd attach). 기기는 안정된 DC 전원으로 켜져 있다 (PoE 대신). 덤프하는 동안 PC 절전을 끈다.
- **디스크**: 덤프 크기의 약 12배. 16 MiB 를 받으면 `uart/*.log`·`*.raw` 가 약 200 MB 쌓인다 (시뮬레이터 실측).
- **MCP 서버**: pweh-case, pweh-uart, pweh-fwtriage(검증용).

## 안전 규칙

1. **읽기 전용이다.** 덤프는 `uboot_dump_start`/`shell_dump_start` job 으로만 한다. 서버는 시작 전에 계획한 모든 명령이 INTERACT 이하인지 검사한다.
   다음은 보내지도 제안하지도 않는다: `sf write/erase/update`, `saveenv`/`env save`, `mw`·`cp`·`mm`·`nm`, `nand erase/write`, `mmc write/erase`, `fatwrite`, `flash_erase`·`flashcp`·`nandwrite`·fw_setenv, `dd of=/dev/mtd*`, `> /dev/mtd*`, 영구 경로(`/mnt/mtd`, `/mnt/sd` …) 쓰기.
   md.b 를 손으로 반복하거나 `md.l` 로 바꾸지 않는다. job 이 파싱·검증·재개를 맡는다.
   셸 경로에서는 /bin·/sbin·/usr/bin·/usr/sbin 의 표준 명령만 이름으로 쓴다. 다른 경로의 파일 실행(`./…`, `/mnt/…`), 도우미 스크립트 작성·실행,
   `PATH`·`LD_PRELOAD` 변경은 하지 않는다(게이트가 `linux.exec-nonsystem`, `linux.script`, `linux.env-hijack` 으로 거부, DESTRUCTIVE).
2. **U-Boot 에서 빈 Enter 를 보내지 않는다.** 새 프롬프트는 `uart_sync`(Ctrl-C)로 얻는다. 새로 연 세션(이어 받은 명령도 없음)의 빈 Enter 는 세션 전 명령을 몰라 `uart.repeat-unknown` 으로 거부된다.
3. **RAM 은 `uboot_info` 의 safe_ram_addr/ram_window 안에서만 쓴다.** `mw.b` 로 RAM 을 미리 채우는 요령은 쓰지 않는다 (DESTRUCTIVE).
4. **setenv 는 두 경우만** 쓴다. tftpput 경로의 `ipaddr`/`serverip`, 그리고 보드레이트 낮추기(reference.md §2)다. 둘 다 MODIFY 이고 RAM 에만 남으며 사용자 동의 후에 한다. 저장하지 않으므로 전원을 다시 넣으면 원래대로다.
5. **게이트**: `status: approval_required` 면 무엇을·왜·위험·되돌리는 법을 설명한다(템플릿 E). 사용자가 별도 터미널에서 `pweh approve <approval_id>` 하면 같은 인자 + approval_id 로 한 번만 재시도한다.
   `status: denied` 면 우회하지 않는다. 다른 문법, 셸에서 포트 직접 열기(screen·minicom·pyserial), 설정·승인 파일 수정은 모두 금지다. 사용자에게 보고하고 대안을 제시한다. 에이전트는 `pweh approve` 를 실행하지 않는다.
6. **job 이 도는 동안 같은 포트에 다른 명령을 보내지 않는다** (`busy`). `uart_close` 는 실행 중 job 을 취소하므로 job 이 끝난 뒤에만 부른다. 사용자가 멈추라고 하면 즉시 `uart_job_cancel` 한다.
   보조 명령도 앞 명령의 프롬프트가 돌아온 뒤 `uart_send_command` 로 한 줄씩 보낸다. 앞 명령이 실행 중(`timed_out` 뒤 포함)이거나 부팅 중일 때 보낸 줄(`uart.device-busy`)과
   `uart_write` 로 한 번에 보낸 여러 줄의 둘째 줄부터는 DESTRUCTIVE 로 거부된다.
7. **로그인은 사용자가 준 계정만** 쓴다 (`shell_login`, 세션당 3회 실패하면 중단).
8. **덤프는 자격증명 저장소다.** 비밀번호 해시·키·Wi-Fi 정보가 들어 있다. 케이스 밖으로 복사하거나 공유하지 않는다 (docs/safety.md §7).

## 사용하는 MCP 도구

| 도구 | 용도 |
|---|---|
| `case_get`, `case_get_step_results`, `case_set_phase` | 권한·이전 요약·기존 덤프 아티팩트 확인, 단계 상태 |
| `uart_sessions`, `uart_open`, `uart_sync`, `uart_close` | 세션 재사용/열기, 문맥 확정(Ctrl-C), 종료(로그 아티팩트 갱신) |
| `uboot_interrupt`, `uboot_printenv`, `uboot_info` | U-Boot 진입, 파티션·적재 주소, 플래시 크기·safe_ram_addr·ram_window·명령 목록 |
| `shell_login`, `shell_identify` | root 셸 로그인(사용자 계정), /proc/mtd·md5sum·base64 유무 |
| `uboot_dump_start`, `shell_dump_start` | 덤프 job (청크 검증·재시도·재개·아티팩트 등록 자동) |
| `uart_job_status`, `uart_job_cancel`, `uart_jobs` | 진행 폴링(wait_seconds ≤ 50), 취소, 실행 중 job 찾기 |
| `uart_send_command`, `uart_write`, `uart_read`, `uart_wait_for` | 보조 명령(`dmesg -n 1`, `crc32`, `nand bad` …), 보드레이트 변경 확인 대기의 `\r`, 끊김·재부팅 확인, 긴 출력(tftpput) 대기 |
| `fw_identify` | 내용 검증(env CRC, uImage CRC, squashfs 슈퍼블록) |
| `case_hash_file` | 덤프 파일·구간의 sha256/md5/crc32 (교차 확인, tftpput·SPI 클립·셸 네트워크 결과를 기기 값과 대조) |
| `case_import_file`, `case_paths`, `case_register_artifact`, `case_add_note` | 대안 경로 파일 반입, 케이스 절대 경로, 호스트에서 만든 파일 등록, 사람 작업 기록 |
| `case_record_step`, `approval_status` | job 인자 기록(재개용)과 최종 summary, 승인 상태 확인 |

## 절차

### 1. 시작: 권한·이전 결과 확인

목표: 권한을 확인하고, 이미 받은 범위와 이어 받을 job 을 찾는다.

```
case_get(case_id="<id>", include_artifacts=true)   → case.authorized, case.profile, artifacts[] (kind flash-dump/partition)
case_get_step_results(case_id="<id>")              → summaries["uart-shell-acquisition"].data, summaries["firmware-dump-via-uart"]
case_get_step_results(case_id="<id>", skill="firmware-dump-via-uart", summaries_only=false)   → 이전 job-* 단계(재개 인자)
case_set_phase(case_id="<id>", phase="firmware-dump-via-uart", status="in-progress")
```
- 볼 것: uart-recon 의 access_level, port, baudrate, uboot.partitions(size 가 null 이면 `-` 파티션), uboot.flash.size_bytes, linux.mtd.
- 같은 범위의 검증된 덤프(flash-dump 아티팩트 + 이전 summary 의 verification.match=true)가 있으면 다시 받지 않는다.
- job-* 단계는 이름마다 최신 기록만 본다. 최신 기록이 success 가 아니고 그 args 의 `dumps/<output_name>.bin` 이 아티팩트에 없으면 재개 대상이다 → 그 args 로 7단계 재개부터 한다.

### 2. 방법 고르기

목표: 콘솔 상태와 시간 예산에 맞는 덤프 경로 하나를 정한다.

| 상태 (uart-recon, shell_identify) | 방법 | 처리량 @115200 | 비고 |
|---|---|---|---|
| access_level=uboot | `uboot_dump_start` (sf read → md.b → crc32) | 약 2.3 KB/s (16 MiB ≈ 2시간) | 시스템이 멈춰 있어 일관된다. 기본 경로 |
| root-shell, md5sum·base64 있음 | `shell_dump_start` (dd \| base64, md5) | 약 8.4 KB/s (16 MiB ≈ 33분) | 파티션마다 파일 1개. 쓰기 중인 파티션은 바뀔 수 있다 |
| root-shell, base64 없음 (Ingenic 계열에 흔함) | `shell_dump_start` (hexdump -C) | 약 2.3 KB/s | U-Boot 와 속도가 같으므로 U-Boot 를 우선한다 |
| 둘 다 가능 | 시간이 급하면 셸(base64), 원본 그대로가 중요하면 U-Boot | | 사용자가 고르게 한다 |
| md5sum 없음, user-shell 뿐, 로그인 막힘, 출력 없음 | UART 덤프 불가 | | reference.md §6 또는 JTAG(pweh-openocd) |
| 사람이 랜선+TFTP 서버나 SPI 클립을 준비할 수 있고 시간이 급함 | U-Boot `tftpput`, SPI 클립 → `case_import_file` | 수 분 | reference.md §6.1·§6.4 |

### 3. 세션 준비

목표: U-Boot 프롬프트나 root 셸에 있는 세션과, 덤프에 필요한 세션 상태(env, 플래시 크기, RAM 창)를 갖춘다.

```
uart_sessions(case_id="<id>")   → sessions[].session_id, state(open/disconnected), context, job_id
```
- uart-recon 의 session.session_id(예: console-001)가 열려 있고 context 가 맞으면 재사용한다. 없으면 `uart_open(case_id="<id>", port="/dev/ttyUSB0", baudrate=115200)` 을 부른다 (port·baudrate 는 uart-recon 값, 아래 예의 uart-001 은 이렇게 새로 연 세션이다).
- **U-Boot 경로**
  - context 가 uboot 가 아니면 템플릿 C 로 알린 뒤 `uboot_interrupt(session_id="uart-001", window_seconds=30)` → interrupted=true, prompt. 실패하면 explanation 을 보고 uart-shell-acquisition 의 실패 처리를 따른다.
  - 이미 프롬프트에 있는데 context 가 unknown 이면 `uart_sync(session_id="uart-001")` → evidence="uboot".
  - 세션을 재사용해도 이 둘은 항상 다시 부른다 (몇 초, 세션 상태 갱신):
    `uboot_printenv(session_id="uart-001")` → partitions[], flash_size·flash_size_source, load_addresses. 그다음
    `uboot_info(session_id="uart-001")` → flash{type, model, size_bytes, size_bytes_lower_bound}, partitions[], safe_ram_addr, ram_window, safe_ram.confidence·avoid, has, has_via, commands.
  - `has` 는 help 목록 기준이라 힌트로만 본다 (약어로만 되는 명령은 has_via, help 를 못 읽으면 null = 모름). crc32 가 정말 없으면 job 이 verify 를 double 로 바꾼다.
- **셸 경로**
  - context 가 linux-shell 이 아니면 `shell_login(session_id="uart-001", username="<사용자가 준 계정>", password="<사용자가 준 값>")` → logged_in=true. 계정을 모르면 묻고, 추측하지 않는다. status 별 조치는 uart-shell-acquisition 8단계 표를 따른다.
  - `shell_identify(session_id="uart-001")` → user.uid=0 인지, has_md5sum, has_base64, mtd[] (dev, size, name).
- 실패: uart_open 이 busy 면 다른 프로그램(minicom 등)이 포트를 잡고 있다 → 사람에게 닫아 달라고 한다. 포트가 없으면 `pweh doctor` 와 usbipd attach 를 요청한다.

### 4. 범위·청크·RAM 주소·예상 시간 → 사용자 동의

목표: 무엇을 얼마나 오래 받을지 정하고 사용자 동의를 받는다.

- **플래시 크기**: uboot_info 의 flash.size_bytes. 없으면 size_bytes_lower_bound(mtdparts 합), 부팅 로그(`SPI Nor total size`), 칩 마킹(W25Q128 = 16 MiB, 사람에게 확인) 순서로 정한다. 크기를 모르면 job 이 범위 초과를 막지 못한다.
  16 MiB 초과 칩에 `Only lower 16MiB accessible` 경고가 있으면 U-Boot 로는 아래 16 MiB 만 읽힌다. notes 에 남기고 위쪽은 셸이나 SPI 경로로 받는다.
- **파티션 표**: uboot_printenv 의 partitions[] (또는 shell_identify 의 mtd[]). `-` 파티션 size 는 서버가 플래시 크기를 알면 채워져 온다(flash_size_source). null 이면 uboot_info 의 partitions[] 를 쓰고, 그래도 null 이면 위에서 정한 flash_size − offset 으로 채워 notes 에 출처를 적는다.
- **범위 선택지** (사용자에게 제시)
  1. 전체: offset 0, length = 플래시 크기. 백업·복구용으로 완전한 것은 이것뿐이다.
  2. 우선 범위: 0 ~ rootfs 끝(rootfs.offset + rootfs.size)을 한 번에 받는다. boot·env·kernel·rootfs 가 한 파일에 들어가고 env 의 mtdparts 로 fw_carve 자동 분할이 된다 (시뮬레이터 확인). 나머지(app 등)는 나중에 따로 받는다.
     웹 서버 바이너리가 app/user 파티션에 있는 기기(Dahua·XiongMai 계열)는 그 파티션을 우선 범위에 넣을지 함께 정한다.
  3. 파티션이 흩어져 있거나 셸 경로면 파티션별로 받는다: env → kernel → rootfs → app.
- **청크**: 기본 64 KiB 다 (115200 에서 청크당 약 28초, 실패하면 그 청크만 다시 받는다). 잡음이 의심되면(시험 덤프에서 retries > 0) 16 KiB 로 시작한다.
  허용 범위는 256 B~256 KiB 다. NAND 는 erase block 배수, mmc 는 512 B 배수로 한다. **덤프 도중에 chunk_size 를 바꾸지 않는다** (재개 조건).
- **RAM 주소** (U-Boot): ram_addr 를 생략하면 safe_ram_addr 를 쓴다. safe_ram.confidence 가 low 이거나 safe_ram_addr 가 null 이면 reference.md §3 대로 고르고 사용자에게 알린다. 서버는 DRAM 밖이나 U-Boot 영역을 침범하는 주소를 거부한다.
- **예상 시간**: md.b 는 `초 ≈ 길이 × (79/16 + 60/청크) × 10 / baud` 이고 서버의 estimated_seconds 와 같은 식이다. 셸은 `길이 × 1.37 × 10 / baud`(base64) 또는 `길이 × 5.0 × 10 / baud`(hexdump) 이다.
  @115200 예: env 64 KiB ≈ 30초, kernel 2 MiB ≈ 15분, rootfs 5 MiB ≈ 37분, 16 MiB ≈ 2시간. 57600 이면 두 배다. 전체 표는 reference.md §1.
- 템플릿 A 로 계획과 시간을 알리고 **사용자가 고를 때까지 시작하지 않는다.**

### 5. 덤프 시작

목표: 짧은 시험으로 경로를 확인한 뒤 본 덤프 job 을 시작하고, 재개용 인자를 케이스에 남긴다.

- **시험 덤프 (권장, @115200 약 30초)**: 몇 시간짜리 job 전에 kernel 파티션 앞 64 KiB 를 기본값으로 먼저 받는다 (offset 은 파티션 표의 kernel.offset, 아래 예는 hisilicon-like 의 0x50000, 셸은 kernel 의 /dev/mtdN). 평소 읽기 전용인 영역이라 교차 확인에도 알맞다 (env 는 기기가 부팅 중 스스로 다시 쓸 수 있다).
  `uboot_dump_start(case_id="<id>", session_id="uart-001", offset="0x50000", length="0x10000", output_name="probe-kernel-head")` (셸은 `shell_dump_start(case_id="<id>", session_id="uart-001", path="/dev/mtd2", offset=0, length="64k", output_name="probe-mtd2-head")`).
  RAM 주소·sf read·crc32 가 동작하는지, retries 가 0 인지, 실제 duration_seconds 가 예상과 맞는지 본다. retries > 0 이면 청크를 16 KiB 로 줄인다. 이 결과는 8단계 교차 확인에 다시 쓴다.

```
uboot_dump_start(case_id="<id>", session_id="uart-001", offset=0, length="0x750000", chunk_size="64k", output_name="flash-0-750000")
shell_dump_start(case_id="<id>", session_id="uart-001", path="/dev/mtd3", output_name="mtd3-rootfs")
```
- 응답: ok, status="started", job_id, output(dumps/<name>.bin), chunks, ram_addr, resume_from_chunk(null 이면 새로 시작, 숫자면 이어받기), estimated_seconds, notes. 셸 응답에는 chunks·estimated_seconds 가 없다 (길이·방법은 job 안에서 정해진다).
- 셸 경로는 시작 전에 `uart_send_command(session_id="uart-001", command="dmesg -n 1")` 로 커널 메시지가 끼어드는 것을 줄인다 (INTERACT, 재부팅하면 원래대로).
- 나머지 인자는 기본값으로 둔다: verify="crc32", retries=3, final_check=true, sf_probe="0", resume=true. NAND/eMMC 는 reference.md §7 을 본다.
- 시작 직후 재개용 인자를 케이스에 남긴다 (세션이 끊겨도 이어 받을 수 있게):
  ```
  case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="job-flash-0-750000", status="in-progress",
    summary="U-Boot md.b 덤프 0x0+0x750000 시작 (예상 55분)",
    data={"tool": "uboot_dump_start", "job_id": "<job_id>", "args": {"source": "sf", "offset": 0, "length": "0x750000", "chunk_size": "64k", "output_name": "flash-0-750000"}})
  ```
- 실패: approval_required/denied 면 안전 규칙 5. 오류 메시지는 7단계 표.

### 6. 폴링과 진행 보고

목표: job 이 끝날 때까지 상태를 확인하고 사용자에게 진행을 알린다.

```
uart_job_status(job_id="<job_id>", wait_seconds=50)
```
- status 가 queued/running/cancelling 이면 같은 호출을 반복한다. wait_seconds 는 MCP 클라이언트 도구 타임아웃(흔히 60초)보다 작게 둔다.
- 진행률은 **meta.overall_progress**, meta.overall_done_bytes/overall_total_bytes, **meta.eta_seconds_estimate**, message 를 쓴다. 최상위 progress·eta_seconds 는 이번 실행(재개 뒤)만 센다.
- overall_progress 가 10% 바뀔 때마다 한 줄로 알린다: `[진행] flash-0-750000 40% (47/117 청크), 남은 시간 약 33분, 재시도 1회`. 재시도는 log_tail 의 "재시도" 줄로 센다.
- 기다리는 동안 포트를 쓰지 않는다. 이미 끝난 다른 덤프의 오프라인 확인(8단계 fw_identify)은 해도 된다.
- 사용자가 중지를 원하면 `uart_job_cancel(job_id="<job_id>")` → status=cancelled. result 는 부분 결과(completed_chunks/total_chunks)다. 판단은 최상위 status 로 한다.
- succeeded 면 result 에 path, sha256, size, metadata_path, method, verification{method, match, chunks_verified, full_range}, chunks{size, count, retries, resumed_from}, duration_seconds, notes 가 있다. `dumps/<name>.bin` 과 `.json` 은 이미 아티팩트로 등록돼 있다.
- job 이 끝나면(succeeded/failed/cancelled) 5단계와 같은 step 이름으로 결과를 한 번 더 기록한다. 그래야 1단계가 끝난 job 을 재개 대상으로 착각하지 않는다:
  `case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="job-flash-0-750000", status="success", summary="완료 dumps/flash-0-750000.bin", data={"job_id": "<job_id>", "result_path": "dumps/flash-0-750000.bin", "sha256": "<sha256>"})`. 실패면 status="failed" 와 error.code, 취소면 status="partial" 과 completed_chunks 를 넣는다.

### 7. 실패 처리와 재개

목표: 원인을 고친 뒤 받은 청크를 버리지 않고 이어 받는다.

job 의 status=failed 면 error.code·message·hint·data 와 log_tail 을 본다. 시작 호출 자체의 오류는 `[validation_failed] …` 같은 텍스트로 온다. 재개 인자 불일치는 job 을 띄우기 전에 시작 호출에서 거부된다.

| 증상 | 원인 | 조치 |
|---|---|---|
| dump_chunk_failed (log: crc32 불일치, md.b 파싱 문제, 시간 초과) | 배선 잡음, 접촉 불량, 보드레이트 | 템플릿 D 로 배선을 점검한 뒤 **같은 인자 + retries=6~10** 으로 다시 시작한다(이어받기). 반복되면 reference.md §2 |
| context_changed | 재부팅(전원 흔들림, 워치독), U-Boot·셸 이탈 | `uart_read(session_id="uart-001", tail=true)` 로 확인. U-Boot: 템플릿 C → `uboot_interrupt` → `uboot_printenv` → `uboot_info` → 같은 인자. 셸: `shell_login` → 같은 인자 |
| disconnected | USB 분리, usbipd 해제 | 템플릿 D → `uart_close` → `uart_open` → `uart_sync`(또는 `uboot_interrupt`) → `uboot_printenv` → `uboot_info` → 같은 인자 |
| sf_probe_failed, dump_failed(적재 명령이 Unknown command/usage) | SPI NOR 가 아니거나 명령이 없음 | uboot_info 의 flash·commands 확인 → source="nand"/"mmc"(reference.md §7), 셸 경로, 대안 경로 |
| dump_full_crc_mismatch | 덤프 중 플래시 내용이 바뀜 | uart_sessions 의 flash_write_warnings 를 확인하고 보고 → resume=false 로 다시 |
| md5sum_unavailable, hexdump_unavailable | 셸 애플릿 없음 | U-Boot 경로 |
| `이미 완료된 덤프가 있습니다` | 같은 output_name 의 .bin 이 있음 | 새 output_name. 기존 파일은 지우지 않는다 |
| 시작 호출의 validation_failed `같은 이름의 진행 중 덤프(.state.json)가 다른 인자로` | 재개 인자 불일치 | 메시지의 "다른 값: 키=기존→요청" 에서 기존 값(offset·length·chunk_size 등)으로 다시 부른다. 아니면 새 이름 또는 resume=false(처음부터) |
| `DRAM … 밖`, `U-Boot 영역 … 침범`, `ram_addr 이 필요합니다` | 주소 문제, uboot_info 를 안 부름 | `uboot_info` 후 safe_ram_addr 사용 (reference.md §3) |
| `U-Boot 프롬프트를 확인하지 못했습니다`, `linux-shell 이 아닙니다` | 문맥 미확정 | `uart_sync` → 필요하면 `uboot_interrupt` 또는 `shell_login` |
| busy | 같은 포트에서 job 실행 중 | `uart_jobs(active_only=true)` 로 확인 → 끝날 때까지 기다리거나 사용자 동의 후 취소 |
| job_plan_denied, job_command_denied, 게이트 denied | 계획 명령이나 job 이 보내려던 명령이 INTERACT 를 넘음 (job 은 명령마다 다시 분류한다) | 우회하지 않고 보고 |
| authorization_required (job 도중) | 덤프 중 케이스 소유/허가 기록이 없어짐 (job 은 명령마다 확인한다) | 멈추고 사용자에게 확인. 기록이 돌아오면 같은 인자로 재개 |
| 시작 호출의 validation_failed `이 장치는 덤프하지 않습니다` | /dev 의 저장장치가 아닌 경로(`/dev/watchdog`, `/dev/mem` …) | /proc/mtd 의 `/dev/mtdN` 을 쓴다 (reference.md §8) |

- **재개 규칙**: U-Boot 는 source·offset·length·chunk_size, 셸은 path·offset·length·method·chunk_size 가 같고 output_name 도 같으면 resume_from_chunk=N 부터 이어 받는다. ram_addr·retries·verify·보드레이트는 달라도 된다.
  새 세션(끊김 복구, 서버 재시작)에서는 `uboot_printenv` → `uboot_info` 를 먼저 다시 불러야 한다. 안 하면 ram_addr 생략이 거부된다. 같은 세션의 재부팅 뒤에도 env 추적이 초기화되므로 다시 부른다.
- 서버가 재시작돼 job_id 를 못 찾아도 `.part`/`.state.json` 은 남아 있다. 5단계에서 기록한 args 로 다시 시작하면 이어 받는다.

### 8. 검증

목표: 덤프가 플래시 내용과 같다는 증거를 여러 겹으로 남긴다.

1. **job 결과**: verification.match=true, chunks_verified == chunks.count, size == 요청 길이 (전체면 플래시 크기).
2. **전체 범위 crc32**: U-Boot sf 경로에서 범위가 ram_window 안이면 자동으로 한다. verification.full_range.match=true 를 확인한다.
   `skipped` 는 RAM 창이 작아서이며 실패가 아니다 (예: hisilicon-legacy 는 창이 3 MiB). 그때는 4번 교차 확인을 꼭 한다.
3. **내용 확인** (오프라인): `fw_identify(case_id="<id>", path="dumps/flash-0-750000.bin")` 의 결과를 본다.
   uboot-env 영역의 CRC, uimage 의 header_crc_ok·data_crc_ok=true(커널 전체 무결성), squashfs 슈퍼블록을 확인한다. padding_bytes 가 크기와 거의 같으면(전부 0xFF/0x00) 잘못 읽은 덤프를 의심한다.
4. **교차 확인**: 같은 영역을 따로 받은 덤프와 메인 덤프의 해당 구간을 sha256 으로 비교한다. 5단계의 시험 덤프(probe-kernel-head)가 있으면 그것을 쓴다 (아래 첫 줄 생략).
   시험 덤프가 없거나, 그 뒤 배선을 고쳤거나 재부팅이 있었으면, 메인 job 이 끝난 뒤 같은 영역을 다른 청크 크기 + verify="double" + 새 이름으로 다시 받는다.
   ```
   uboot_dump_start(case_id="<id>", session_id="uart-001", offset="0x50000", length="0x10000", chunk_size="16k", verify="double", output_name="xcheck-kernel-head")
   case_hash_file(case_id="<id>", path="dumps/flash-0-750000.bin", offset="0x50000", length="0x10000")   → sha256 == 교차 덤프(또는 시험 덤프) 결과의 sha256
   ```
   - case_hash_file 의 offset 은 메인 덤프 **파일 안의** 위치다(= 플래시 오프셋 − 메인 덤프의 시작 오프셋). 파일을 새로 만들지 않으므로 fw_carve 로 잘라 낼 필요가 없다.
   - 파티션별 덤프면 같은 파티션을 다시 받아 두 sha256 을 바로 비교한다. 셸이면 `shell_dump_start(case_id="<id>", session_id="uart-001", path="/dev/mtd1", method="hexdump", chunk_size="16k", output_name="xcheck-mtd1")` 의 결과를 base64 결과와 비교한다.
   - 불일치하면 그 범위를 다시 받고 배선과 플래시 쓰기 징후를 점검한다. 확인되기 전에는 match 를 true 로 적지 않는다.
5. 결과를 data.verification 에 적는다: expected/actual = full_range 의 device/host crc32, cross_check, content_checks.

### 9. 나머지 범위와 마무리

목표: 받을 범위를 마저 받고, 세션과 기기 상태를 정리한다.

- 우선 범위가 끝나면 그 결과로 summary(status="partial")를 먼저 저장하고(출력 절) 나머지를 받을지 묻는다.
  받는다면 `uboot_dump_start(case_id="<id>", session_id="uart-001", offset="0x750000", length="0x8b0000", output_name="flash-750000-1000000")` 를 돌리고, 끝나면 summary 를 다시 저장한다 (나중 것이 최신이 된다).
  최종 summary 의 output 은 우선 범위 파일 그대로 두고(합쳤다면 합친 파일, reference.md §8), partitions[] 의 app 항목에 나머지 파일의 path·sha256 을 붙인다. 두 파일 모두 verification.match=true 일 때만 status="success" 다.
- 덤프를 더 하지 않으면 `uart_close(session_id="uart-001")` 를 부른다 (로그 아티팩트 갱신). 기기 상태를 알린다: "U-Boot 프롬프트에 멈춰 있음, 영구 변경 없음, 전원을 다시 넣으면 정상 부팅".
- 사람이 한 물리 작업(배선 수정, 전원 재투입, SPI 클립)은 `case_add_note` 로 남긴다.

## 사람에게 요청할 일

**A. 덤프 계획 동의 (시작 전 필수)**
```
[확인 필요] 펌웨어 덤프 계획
- 방법: U-Boot md.b (uboot_dump_start), 115200 bps, 청크 64 KiB, 청크마다 기기 crc32 검증
- 플래시: W25Q128 16 MiB (boot 256K / env 64K / kernel 2M / rootfs 5M / app 8.7M)
- 선택지와 예상 시간:
  1) 우선 범위 0x0~0x750000 (boot+env+kernel+rootfs, 7.3 MiB) ≈ 55분 → 분석을 먼저 시작할 수 있음
  2) 전체 16 MiB ≈ 2시간 (백업·복구용으로 완전)
  3) 더 빠른 대안: 랜선+TFTP 서버로 tftpput (수 분), SPI 클립으로 직접 읽기 (기기 전원 끄고), root 셸 base64 (≈ 33분)
- 어느 것으로 할까요? 진행 중에는 10%마다 알려 드리고, 끊겨도 받은 곳부터 이어 받습니다.
```

**B. 장시간 덤프 중 부탁**
```
[안내] 덤프 진행 중 (예상 종료 14:40)
- 기기 전원, UART 케이블, USB 어댑터를 건드리지 말아 주세요.
- PC 절전을 꺼 주세요. WSL 이면 usbipd 연결이 유지돼야 합니다.
- 멈추고 싶으면 "중지" 라고 말씀해 주세요. 받은 부분은 보존되고 나중에 이어 받습니다.
```

**C. U-Boot 다시 잡기 (재부팅·새 세션 뒤)** — uart-shell-acquisition H3 과 같은 순서다.
```
[사람 작업 필요] 전원 재투입 타이밍
1. 기기 전원을 먼저 꺼 주세요 (DC 잭 분리). 꺼진 채로 "준비" 라고 알려 주세요.
2. 제가 감시(uboot_interrupt)를 시작했다고 말하면 바로 전원을 넣어 주세요. 키 입력은 제가 합니다.
```

**D. 배선·연결 점검 (재시도 반복·끊김)**
```
[사람 작업 필요] UART 연결 점검
- 청크 검증 실패가 반복됩니다 (최근: crc32 불일치 3회 @0x3a0000).
1. 기기 전원은 그대로 두고, GND 선이 단단히 연결됐는지, 점퍼선이 짧고 흔들리지 않는지 확인해 주세요.
2. USB 어댑터가 빠졌다면 다시 꽂고, WSL 이면 usbipd attach 를 다시 해 주세요.
3. 끝나면 "완료" 라고 알려 주세요. 받은 곳부터 이어 받습니다.
```

**E. 승인 필요** (게이트가 approval_required 를 줄 때, master-prompt §6 형식)
```
[승인 필요] approval_id=ap-xxxx
- 작업: <도구/명령> (위험도 <risk>, 규칙 <rule_id>)
- 이유: …   위험: …   되돌리는 방법: …
- 승인하려면 별도 터미널에서: pweh approve ap-xxxx
```

**F. 대안 경로** (tftpput 준비, SPI 클립 읽기): reference.md §6 의 템플릿을 쓴다.

## 성공·실패 기준

- **성공(success)**: 합의한 범위 전체를 받았고 verification.match=true, sha256·size 가 기록됐다. full_range 일치 또는 교차 확인 일치가 있다. summary 가 스키마를 통과했고 실행 중 job 이 없다.
- **부분(partial)**: 우선 범위만 받았거나, 일부 파티션만 있거나, 검증 일부가 빠졌다 (full_range skipped 인데 교차 확인 없음 → match=null). 빠진 것을 notes·next_actions 에 적는다.
- **실패(failed)·차단(blocked)**: 완료된 덤프 파일이 하나도 없다. 그러면 summary 스키마(output 필수)를 채울 수 없으므로 다음 두 호출로 남기고 대안 경로로 넘어간다.
  `case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="attempt", status="failed", summary="…", data={"method": "uboot-md", "error": "<code: message>"}, blockers=["…"])`
  `case_set_phase(case_id="<id>", phase="firmware-dump-via-uart", status="failed")` (사람 조치가 필요하면 "blocked").

## 출력

job result 와 `dumps/<name>.json`(이 스키마에 맞춘 메타데이터)을 옮겨 data 를 만든다.
- chunks 에서 checks 배열은 뺀다 (.json 에 남아 있다). size·count·retries·resumed_from 만 둔다.
- 재개했으면 duration_seconds 에는 모든 실행의 합을 적는다: result 의 duration_seconds_total (없으면 각 job 의 started_at~finished_at 을 더한다). result.duration_seconds 는 마지막 실행만 센 값이다. notes 에 "재개 n회" 를 남긴다.
- verify=double 로 받았으면(기기에 crc32 가 없어 job 이 자동으로 바꾼 경우 포함) data.verification.method 는 `double-read` 다. result 가 예전 형식인 `size-only` 를 주면 `double-read` 로 고쳐 적는다.
- partitions[] 에는 파티션 표 전체를 넣는다 (offset 은 플래시 기준). 별도 파일로 받은 파티션에는 path·sha256 을 붙인다. 셸 경로는 output 을 rootfs 파일로 하고 나머지 파일은 partitions[] 에 둔다 (예시: reference.md §9).
- 대안 경로는 method 를 uboot-tftpput / spi-clip-flashrom / linux-nc / linux-tftp 로, verification 을 crc32-uboot / md5-device(SPI 클립을 두 번 읽어 비교만 했으면 double-read)로 적는다 (reference.md §6).

아래는 시뮬레이터(pweh-mock-device hisilicon-like)에서 실제로 실행한 전체 덤프 값이다. 시뮬레이터는 전송이 즉시라 77초였고, 실제 115200 bps 기기는 약 2시간 걸린다. 이 data 는 firmware-dump 스키마 검증을 통과했다.

```json
{
  "method": "uboot-md",
  "source": {"type": "sf", "flash_type": "spi-nor", "flash_model": "W25Q128(B/F)V", "flash_size": 16777216, "offset": 0, "length": 16777216, "partition": null, "ram_addr": "0x42000000", "device_path": null},
  "output": {"path": "dumps/flash-full.bin", "sha256": "75860c69364e5c99474efa495ecb5c81eaf6a7632c5b1953f6ae040540943737", "size": 16777216},
  "verification": {
    "method": "crc32-chunks", "expected": "2fd434f5", "actual": "2fd434f5", "match": true, "chunks_verified": 256,
    "full_range": {"device_crc32": "2fd434f5", "host_crc32": "2fd434f5", "match": true},
    "cross_check": {"region": "kernel 앞 0x50000+0x10000", "dump": "dumps/xcheck-kernel-head.bin", "method": "chunk 16k + verify=double, 메인 덤프 뒤", "sha256": "47e7f249cdfdbb0533289042ef4821edf73838dfcfd27736db8705e31ec9cf9e", "reference": "case_hash_file dumps/flash-full.bin offset 0x50000 length 0x10000", "match": true},
    "content_checks": ["fw_identify: uImage 'Linux-4.9.37' @0x50000 header_crc_ok=true data_crc_ok=true", "fw_identify: U-Boot env @0x40000 CRC 정상 (변수 16개)"]
  },
  "chunks": {"size": 65536, "count": 256, "retries": 0, "resumed_from": 0},
  "partitions": [
    {"name": "boot", "offset": 0, "size": 262144},
    {"name": "env", "offset": 262144, "size": 65536},
    {"name": "kernel", "offset": 327680, "size": 2097152},
    {"name": "rootfs", "offset": 2424832, "size": 5242880},
    {"name": "app", "offset": 7667712, "size": 9109504, "size_source": "mtdparts '-' → flash_size − offset"}
  ],
  "mtdparts": "mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)",
  "duration_seconds": 77.02,
  "baudrate": 115200,
  "metadata_path": "dumps/flash-full.json",
  "bootloader": "U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300",
  "notes": [
    "시뮬레이터 실행 값: 전송이 즉시라 77초. 실제 115200 bps 기기는 약 2시간",
    "ram_addr 생략 → uboot_info safe_ram_addr 0x42000000 (confidence high, 출처 bootcmd sf read)",
    "교차 확인: kernel 앞 64 KiB 를 청크 16k + verify=double 로 다시 받아 메인 덤프의 같은 구간(case_hash_file)과 sha256 일치"
  ]
}
```

```
case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="summary", status="success",
  summary="U-Boot md.b 로 16 MiB 전체 덤프. 청크 256개 crc32 일치, 전체 crc32 2fd434f5 일치, kernel 앞부분 교차 확인 일치",
  data=<위 JSON>,
  artifacts=["dumps/flash-full.bin", "dumps/flash-full.json", "dumps/xcheck-kernel-head.bin"],
  next_actions=["firmware-static-analysis: dumps/flash-full.bin 분석 (fw_carve 자동 레이아웃 가능)"],
  blockers=[])
```
서버가 스키마 검증에 실패하면 메시지대로 data 를 고쳐 다시 저장한다. summary 저장이 단계(phase) 상태도 갱신한다.

## 다음 단계

- **firmware-static-analysis**: data.output.path 를 펌웨어로 쓴다. 우선 범위 덤프도 env 가 들어 있어 fw_carve 자동 분할이 된다.
  파티션별 덤프(셸 경로)면 partitions[].path 의 파일마다 fw_identify·fw_extract_squashfs 를 하도록 next_actions 에 적는다.
- verification.match 가 true 가 아니면 다음 Skill 이 "무결성 미확인" 을 적도록 next_actions 에 남긴다.
- 사용자가 목표를 펌웨어 확보까지로 줄였으면 `report_generate(case_id="<id>")` 후 master-prompt §10 형식으로 보고한다.

## 참고

- [reference.md](reference.md): 시간표, 청크·보드레이트·RAM 주소 선택, 응답 필드, 대안 경로(tftpput·셸 네트워크·SD 카드·SPI 클립), NAND/eMMC, 셸 경로 주의, 추가 예시(우선 범위·셸).
- `orchestrator/master-prompt.md` §1 절대 규칙, §4 Phase B, §5 데이터 전달, §7 장시간 작업, §8 실패 처리.
- `mcp-servers/uart-mcp/README.md` §4 덤프 job, §5 처리량. `docs/references/uboot-and-boot-console.md` §0 드라이버 안전 규칙, §4 crc32, §5 sf/nand/mmc/tftp, §11.7, §13 처리량·대안.
- `docs/safety.md` §3·§5·§7, `docs/hardware-setup.md` §6 (SPI 클립).
