# firmware-dump-via-uart 참고 자료

[SKILL.md](SKILL.md) 의 보조 자료다. 수치와 응답 예는 `pweh-mock-device` 시뮬레이터(hisilicon-like, ingenic-like, hisilicon-legacy)에서 실제로 실행해 확인했다.

## 1. 처리량과 시간 계산

8N1 은 문자당 10비트다. 115200 baud ≈ 초당 11,520 문자.

| 방식 | 문자/바이트 | @115200 | 근거 |
|---|---|---|---|
| U-Boot `md.b` (2021.07 이전 형식, 카메라 포크 전부) | 79/16 = 4.94 | 약 2.33 KB/s | uboot-and-boot-console.md §13.1 |
| 셸 `base64` (57바이트 → 76문자 + CRLF) | 1.37 | 약 8.4 KB/s | 같은 문서 §13.1 |
| 셸 `hexdump -C` | 5.0 (0xFF 반복 줄은 `*` 로 접혀 더 빠름) | 약 2.3 KB/s | 같은 문서 §11.6 |

- md.b 식은 `uboot_dump_start` 의 estimated_seconds 와 같다: `초 = 길이 × (79/16 + 60/chunk_size) × 10 / baud`. 60 은 청크마다 붙는 명령 줄(sf read, crc32)의 대략적인 문자 수다.
- 셸: `초 ≈ 길이 × 1.37 × 10 / baud` (base64), `× 5.0` (hexdump). 청크마다 md5 확인이 붙지만 출력이 짧아 무시할 만하다.

| 범위 | 크기 | md.b @115200 | md.b @57600 | base64 @115200 |
|---|---|---|---|---|
| env | 64 KiB | 28초 | 56초 | 8초 |
| boot | 256 KiB | 1.9분 | 3.7분 | 31초 |
| kernel | 2 MiB | 15분 | 30분 | 4.2분 |
| rootfs | 5 MiB | 37분 | 75분 | 10분 |
| 0 ~ rootfs 끝 (hisilicon-like 0x750000) | 7.3 MiB | 55분 | 1.8시간 | 15분 |
| 전체 | 8 MiB | 1.0시간 | 2.0시간 | 17분 |
| 전체 | 16 MiB | 2.0시간 | 4.0시간 | 33분 |
| NAND 전체 | 128 MiB | 16시간 | 32시간 | 4.4시간 |

- 115200 을 넘는 U-Boot 콘솔 속도는 대부분의 카메라 빌드에서 불가능하다 (baudrate 표 상한 115200).
- 실제로는 청크마다 프롬프트 판정(60 ms 정적)과 명령 왕복이 더해져 몇 % 더 걸린다. 시작 응답의 estimated_seconds 와 실행 중 meta.eta_seconds_estimate 를 함께 본다.

## 2. 청크 크기, 재시도, 보드레이트 낮추기

- chunk_size 범위는 256 B~256 KiB 다 (md.b 출력이 데이터의 약 5배이고 수신 링 버퍼가 4 MiB).
- 청크를 키워도 얻는 것이 없다. 청크당 명령 오버헤드(약 100문자)는 64 KiB 에서 이미 0.03% 다. 실패하면 다시 받는 양만 커진다.
- 잡음이 있을 때 청크 실패 확률은 약 `1 − (1 − p)^(5 × chunk)` 이다 (p = 문자 오류율). p = 1e-6 이면 64 KiB 청크는 약 28%, 16 KiB 는 약 8% 실패한다.
- 재시도가 반복될 때 순서:
  1. 사람에게 배선 점검을 요청한다 (SKILL 템플릿 D). GND, 짧은 점퍼선, 흔들리는 접촉, USB 허브를 본다.
  2. **같은 인자 + retries=6~10** 으로 다시 시작한다. retries 는 재개 조건이 아니라서 받은 곳부터 이어진다 (최대 10).
  3. 보드레이트를 낮춘다 (아래). 재개 조건에 보드레이트는 없다.
  4. 그래도 안 되면 새 output_name 과 작은 chunk_size(16 KiB)로 처음부터 받는다. chunk_size 를 바꾸면 기존 진행분은 이어지지 않는다.
- **보드레이트 낮추기 (U-Boot, 시뮬레이터에서 확인)**: `setenv baudrate` 는 MODIFY 이고 RAM 에만 남는다. 시간이 두 배가 되므로 사용자 동의 후에 한다.
  1. 실행 중 job 이 있으면 `uart_job_cancel(job_id="<job_id>")` 로 멈춘다 (받은 청크는 보존).
  2. `uart_send_command(session_id="uart-001", command="setenv baudrate 57600", timeout=5)` → 콘솔 속도가 바로 바뀌어 output 이 깨지고 timed_out=true 가 정상이다.
  3. `uart_close(session_id="uart-001")` → `uart_open(case_id="<id>", port="/dev/ttyUSB0", baudrate=57600)`. 같은 케이스·같은 포트로, 서버를 재시작하지 않고 다시 연다.
  4. U-Boot 는 `## Switch baudrate to 57600 bps and press ENTER ...` 뒤 새 속도의 `\r` 을 기다린다 (프롬프트가 아니라 확인 대기다).
     먼저 `uart_read(session_id="uart-002", wait_seconds=1)` 로 프롬프트가 보이는지 본다. 안 보이면 `uart_write(session_id="uart-002", data="\r")` 를 한 번만 보낸다.
     프롬프트가 이미 보이면 보내지 않는다 (프롬프트에서 빈 Enter 는 직전 명령 반복이다). 빈 Enter 금지 규칙의 유일한 예외가 이 확인 대기다.
     - 보내는 조건: 3의 `uart_open` 응답에 `inherited_last_command`(= 2의 `setenv baudrate 57600`)가 있어야 한다. 서버가 닫힌 세션의 마지막 U-Boot 명령을 같은 케이스·포트의 새 세션에 넘겨 준 것이고, 그래서 이 `\r` 은 그 setenv 의 반복(MODIFY)으로 분류된다.
     - 이 필드가 없으면(서버 재시작, 다른 물리 포트(USB 재연결로 /dev/ttyUSB1 이 됨 등)) `\r` 은 직전 명령을 모르는 빈 Enter 라 `uart.repeat-unknown`(DESTRUCTIVE)으로 거부된다. 보내지 말고 바로 아래 전원 재투입으로 간다.
       U-Boot 는 이 대기에서 `\r` 만 받으므로 `uart_sync`(Ctrl-C)로는 끝나지 않는다.
     이 `\r` 이 게이트에서 approval_required 나 denied 로 오면 우회하지 않는다. 사람에게 전원 재투입(SKILL 템플릿 C)을 요청해 115200 으로 돌아간 뒤 그 속도로 재개한다.
  5. `uart_sync(session_id="uart-002")` → evidence="uboot" → `uboot_printenv` → `uboot_info` → 같은 인자로 `uboot_dump_start` → resume_from_chunk 확인.
  6. 전원을 다시 넣으면 115200 으로 돌아온다. summary 의 baudrate 는 마지막 실행 값이고, 실행별 값은 `dumps/<name>.json` 의 runs[] 에 있다.

## 3. RAM 주소 고르기 (U-Boot)

`uboot_info` 의 safe_ram 필드:

| 필드 | 뜻 |
|---|---|
| safe_ram_addr | 제안 시작 주소. ram_addr 를 생략하면 job 이 이 값을 쓴다 |
| source | 근거: bootcmd sf read(벤더 적재 주소), DRAM+6MiB(OpenIPC 관례), DRAM+2MiB, DRAM+1MiB, 벤더 적재 영역 |
| ram_window{start, end, size} | 쓸 수 있는 창. 청크(ram_addr+chunk)는 반드시, 전체 crc32 확인(final_check)은 범위 전체가 이 안에 들어가야 한다 |
| dram{start, size, end} | bdinfo 의 DRAM |
| avoid[] | U-Boot 가 쓰는 주소(relocaddr, sp, gd, malloc, tlb). 이보다 1 MiB 아래가 창의 끝이다 |
| confidence | high/medium: relocaddr·sp 를 앎. low: 모름 → DRAM 위쪽 절반을 U-Boot 영역으로 가정 |

시뮬레이터 값:

| 프로필 | safe_ram_addr | ram_window | confidence | 결과 |
|---|---|---|---|---|
| hisilicon-like (U-Boot 2016.11) | 0x42000000 | 0x42000000–0x43e5ded0 (약 30 MiB) | high | 16 MiB 전체 crc32 확인 가능 |
| ingenic-like (2013.07) | 0x80600000 | 0x80600000–0x81e6bf48 (약 24 MiB) | high | 전체 확인 가능. flash.size_bytes 는 null → size_bytes_lower_bound |
| hisilicon-legacy (2010.06) | 0x82000000 | 0x82000000–0x82300000 (3 MiB) | low | 3 MiB 넘는 범위는 full_range skipped → 교차 확인 필수 |

- safe_ram_addr 가 null 이면 (bdinfo 에 DRAM 정보 없음) 다음 순서로 고르고 ram_addr 를 직접 준다. 사용자에게도 알린다.
  1. `uboot_printenv` 의 load_addresses 에 있는 bootcmd 의 `sf read` 주소. 벤더가 U-Boot 실행 중에 커널을 올리는 자리라 비어 있다.
  2. DRAM 시작 + 6 MiB. 예: DRAM 0x80000000 이면 0x80600000, 0x40000000 이면 0x40600000.
- 틀린 주소는 data abort 로 기기를 리셋시킨다. 그러면 job 이 context_changed 로 끝난다. U-Boot 를 다시 잡고(SKILL 템플릿 C) 다른 주소로 시작한다. 덤프 파일은 아직 없으니 잃는 것은 없다.
- RAM 을 `mw.b` 로 미리 채우는 요령(외부 문서의 0xFF 채우기)은 쓰지 않는다. `mw` 는 DESTRUCTIVE 로 거부된다.

## 4. 응답 필드와 summary 매핑

**시작 응답** (`uboot_dump_start`): ok, status="started", job_id, output, part_path, state_path, metadata_path, chunks, chunk_size, ram_addr, resume_from_chunk, estimated_seconds, notes, next.
`shell_dump_start` 는 job_id, output, part_path, state_path, metadata_path, chunk_size, resume_from_chunk, next 만 준다 (길이·방법은 job 안에서 정해진다).

**`uart_job_status`**: status(queued/running/cancelling/succeeded/failed/cancelled), progress, done, total, eta_seconds(이번 실행), message, started_at, finished_at, elapsed_seconds, meta{overall_progress, overall_done_bytes, overall_total_bytes, eta_seconds_estimate, partial_result}, result, error{code, message, hint}, log_tail.
- 취소·실패 때 result 는 partial_result 다 (status, part_path, state_path, completed_chunks, total_chunks, resume_hint). 판단은 최상위 status 로 한다.

**완료 result**: path, path_abs, sha256, size, metadata_path, method, verification{method, detail, match, chunks_verified, full_range{device_crc32, host_crc32, match} 또는 {skipped}}, chunks{size, count, retries, resumed_from}, duration_seconds(이번 실행), duration_seconds_total(재개 포함 합계), artifact_id, notes.
`dumps/<name>.json` 에는 여기에 source{type, flash_type, flash_size, offset, length, partition, ram_addr, device_path}, chunks.checks[], baudrate, port, runs[], 그리고 U-Boot 경로면 U-Boot 버전 문자열이 더 있다.

| summary data | 가져올 곳 |
|---|---|
| method | result.method (uboot-md, linux-base64, linux-hexdump) |
| source | dumps json 의 source. 셸 경로는 flash_type·flash_size 가 null 이니 uart-recon 이나 부팅 로그 값으로 채워도 된다. flash_model 은 uboot_info |
| output | result.path, sha256, size |
| verification.method, match, chunks_verified | result.verification 그대로. verify=double 은 `double-read` 다 (예전 형식의 size-only 가 오면 double-read 로 고쳐 적는다) |
| verification.expected / actual | full_range.device_crc32 / host_crc32. 없으면 null |
| verification.cross_check, content_checks | SKILL 8단계 결과 |
| chunks | result.chunks (checks 는 넣지 않는다) |
| partitions | uboot_printenv partitions[] 또는 shell_identify mtd[]. `-` 파티션 크기는 flash_size − offset |
| duration_seconds | 모든 실행의 합: result.duration_seconds_total (없으면 job 마다 finished_at − started_at 을 더한다) |
| baudrate | dumps json 의 baudrate (마지막 실행). runs[] 에 실행별 값 |
| notes | result.notes + 시뮬레이터 여부, 재개 횟수, 빠진 범위, verify 전환 같은 판단 |

## 5. 시뮬레이터로 연습하기

```bash
.venv/bin/pweh-mock-device --profile hisilicon-like --pty --no-autostart   # 첫 줄 JSON 의 pty 경로 → uart_open(port=...)
# 꺼진 상태(--no-autostart 또는 power-off)에서 uboot_interrupt 를 부른 직후 이 터미널에 power-on 입력 = 사람이 전원을 넣은 것
```
- 케이스 프로필은 mock-hisilicon / mock-ingenic. 로그인 계정은 CLI 첫 줄 JSON 에 나온다.
- 시뮬레이터는 출력이 즉시라 16 MiB 덤프가 약 77초에 끝난다 (실기기 약 2시간). 그 밖의 동작은 실기기 형식을 따른다.
- 확인한 동작: 16 MiB 전체 덤프(청크 256개, full_range 일치), 취소 → 같은 인자 재개(resume_from_chunk), 셸 덤프 중 재부팅 → context_changed → 재로그인 후 재개, 보드레이트 57600 으로 낮춘 뒤 재개, 같은 이름 재시작 거부, DRAM 밖 ram_addr 거부.
- 게이트 확인: `sf erase`, `sf write`, `saveenv`, `mw.b`, `flash_erase`, `dd of=/dev/mtd1`, `echo x > /dev/mtdblock1`, `cp /dev/mtdblock3 /mnt/sd/…` 는 모두 denied 였고 기기에 닿지 않았다 (destructive_events = []).
- 시뮬레이터의 tftp·ping 은 링크 다운으로만 동작하고 셸의 tftp·nc 애플릿은 없다. 그래서 §6.1·§6.2 는 실기기 문서(uboot-and-boot-console.md §5.5·§13.3)를 근거로 한다.

## 6. 대안 경로

### 6.1 U-Boot tftpput (랜선 + TFTP 서버, 16 MiB 수십 초)

전제: 이더넷 PHY 드라이버가 있는 U-Boot, 분석 PC 의 TFTP 서버가 업로드(쓰기)를 허용함, 기기와 PC 가 직결 또는 격리된 랩 스위치로 연결됨.
명령 유무는 `uart_send_command(session_id="uart-001", command="help tftpput")` 로 본다 (`Unknown command` 면 없음). HiSilicon 2010.06 포크는 `tftpput` 대신 통합 `tftp` 의 **인자 3개 형태가 업로드**다.

1. 템플릿 F1 로 사람에게 준비를 요청한다.
2. `uart_send_command(session_id="uart-001", command="setenv ipaddr 192.168.1.10")`, `uart_send_command(session_id="uart-001", command="setenv serverip 192.168.1.2")`. MODIFY 이고 RAM 에만 남는다. saveenv 하지 않는다. ethaddr 가 없다는 오류가 나면 사용자와 상의한다.
3. `uart_send_command(session_id="uart-001", command="ping 192.168.1.2", timeout=15)` → `host 192.168.1.2 is alive`. 실패하거나 멈추면 `uart_sync` 로 끊고 배선·IP 를 점검한다.
4. `uart_send_command(session_id="uart-001", command="sf probe 0")` → `uart_send_command(session_id="uart-001", command="sf read 0x42000000 0x0 0x1000000", timeout=50)`. 범위가 ram_window.size 보다 크면 나눠서(예: 8 MiB 두 번) 4~6단계를 반복하고 파일 이름을 나눈다.
5. `uart_send_command(session_id="uart-001", command="crc32 0x42000000 0x1000000", timeout=30)` → `CRC32 for 42000000 ... 42ffffff ==> <device_crc>`. 대소문자는 빌드마다 다르다.
6. `uart_send_command(session_id="uart-001", command="tftpput 0x42000000 0x1000000 flash-full-tftp.bin", timeout=50)` (HiSilicon 2010.06: `tftp 0x42000000 flash-full-tftp.bin 0x1000000`).
   timed_out=true 는 오류가 아니다. `uart_wait_for(session_id="uart-001", pattern="Bytes transferred|TFTP error|Abort", timeout=50)` 를 반복한다. 기다리는 동안 다른 입력을 보내지 않는다.
   성공하면 `Bytes transferred = 16777216 (1000000 hex)` 가 나온다. `T T T …` 가 이어지면 서버에 닿지 않는 것이니 `uart_sync` 로 중단한다.
7. 사람이 알려 준 파일을 가져온다: `case_import_file(case_id="<id>", source_path="/srv/tftp/flash-full-tftp.bin", kind="flash-dump", description="U-Boot tftpput, 기기 crc32 <device_crc>")` → artifact.path, artifact.sha256, absolute_path.
8. 케이스 안 파일의 crc32 를 계산해 5단계 값과 비교한다 (읽기 전용):
   `case_hash_file(case_id="<id>", path="<artifact.path>")` → crc32, file_size. crc32 는 대소문자를 무시하고 비교하고, file_size 는 요청 길이와 같아야 한다.
9. tftp 를 보낸 뒤에는 uart-mcp 가 env 추적을 버린다. U-Boot 작업을 더 하려면 `uboot_printenv` 부터 다시 부른다.
10. summary: method="uboot-tftpput", verification={"method": "crc32-uboot", "expected": "<device_crc>", "actual": "<host_crc>", "match": true}.

### 6.2 리눅스 셸 + 네트워크

root 셸이 있고 기기 네트워크가 랩 PC 와 연결돼 있을 때 쓴다. 분류(코어 분류기로 확인): `tftp -p -l /dev/mtd3 -r mtd3.bin 192.168.1.2` 와 `nc 192.168.1.2 9000 < /dev/mtdblock3` 는 INTERACT, `cat /dev/mtdblock3 > /tmp/r.bin` 은 MODIFY(tmpfs, RAM 여유 확인), `ifconfig eth0 …` 설정은 MODIFY 다.
1. 사람이 PC 에서 수신기(TFTP 서버, 또는 `nc -l -p 9000 > mtd3.bin`)를 띄운다.
2. 파티션마다 `uart_send_command(session_id="uart-001", command="tftp -p -l /dev/mtd3 -r mtd3.bin 192.168.1.2", timeout=50)` 를 보낸다. 순서는 /proc/mtd 순서를 따른다 (글롭 `/dev/mtdblock*` 은 mtdblock10 을 2 앞에 둔다).
3. `case_import_file(case_id="<id>", source_path="<PC 경로>", kind="partition")` → artifact.path.
4. 검증: `uart_send_command(session_id="uart-001", command="md5sum /dev/mtd3", timeout=50)` 의 값과 `case_hash_file(case_id="<id>", path="<artifact.path>")` 의 md5 를 비교한다. summary 는 method="linux-tftp" 또는 "linux-nc", verification.method="md5-device".

### 6.3 SD 카드 (기본 정책에서 불가)

U-Boot `mmc write`·`fatwrite` 와 리눅스에서 `/mnt/sd` 로 복사하는 것은 DESTRUCTIVE(저장장치 쓰기, 영구 경로)라 기본 정책에서 거부된다. 에이전트는 이 경로를 실행하지도 우회하지도 않는다.
eMMC 를 쓰는 기기에서 `mmc write` 가 장치 번호를 잘못 가리키면 기기 자체 저장장치를 덮어쓴다. 사용자가 꼭 원하면 사람이 정책을 바꾸고 명령마다 승인해야 한다 (docs/safety.md §3.2). 대신 §6.1 이나 §6.4 를 권한다.

### 6.4 SPI 클립 (사람이 수행, docs/hardware-setup.md §6)

1. 템플릿 F2 로 요청한다. 기기 전원을 끄고, 칩 전압(3.3 V / 1.8 V)을 확인하고, 두 번 읽어 sha256 을 비교한다.
2. `case_import_file(case_id="<id>", source_path="/home/me/dumps/spi-read1.bin", kind="flash-dump", description="SPI 클립 flashrom 2회 읽기 sha256 일치")`.
3. 검증
   - U-Boot 를 쓸 수 있으면 §6.1 의 4~5단계(`sf read` 전체 + `crc32`)로 기기 crc32 를 받아 `case_hash_file(case_id="<id>", path="<artifact.path>")` 의 crc32 와 비교한다 → verification.method="crc32-uboot".
   - 아니면 두 번 읽은 결과가 같은지만 확인한다 → verification.method="double-read", expected/actual = 두 읽기의 sha256 (두 파일을 모두 반입했다면 `case_hash_file` 로 계산), notes 에 설명.
4. summary 의 method 는 "spi-clip-flashrom". 사람이 한 작업은 `case_add_note` 로 남긴다.

### 6.5 공식 펌웨어 이미지

덤프가 아니다. firmware-static-analysis 0단계의 `case_import_file(…, kind="firmware-image")` 로 가져가며, 실제 기기 펌웨어와 다를 수 있다고 기록한다. 이 Skill 에서 기록한다면 method="vendor-download", verification={"method": "none", "match": null} 이다.

### 6.6 대안 경로 템플릿

**F1. tftpput 준비**
```
[사람 작업 필요] 네트워크 덤프 준비 (16 MiB 약 30초~수 분)
1. 기기 이더넷 포트와 분석 PC 를 랜선으로 직접 연결해 주세요 (인터넷·사내망과 분리).
2. PC 유선 랜 IP 를 192.168.1.2/24 로 설정하고, 쓰기를 허용한 TFTP 서버를 띄워 주세요 (예: tftpd-hpa 에 --create, 쓰기 가능한 디렉터리).
3. 기기 IP 는 192.168.1.10 을 RAM 에만 임시로 설정합니다 (저장하지 않음, 전원을 다시 넣으면 사라짐).
4. 준비되면 TFTP 디렉터리 경로와 함께 "완료" 라고 알려 주세요.
```

**F2. SPI 클립 읽기**
```
[사람 작업 필요] SPI 플래시 직접 읽기
1. 기기 전원을 완전히 끄고(어댑터 분리) 플래시 칩 마킹을 알려 주세요 (예: W25Q128JV).
2. 칩 전압을 확인하고(3.3 V 또는 1.8 V) 맞는 프로그래머를 쓰세요. 1번 핀(빨간 선)을 칩의 점(●)에 맞춥니다.
3. 두 번 읽고 sha256 이 같은지 확인해 주세요. 예: flashrom -p ch341a_spi -r read1.bin, 다시 read2.bin.
4. 두 파일의 경로와 sha256 을 알려 주세요. 보드 역전원 문제는 docs/safety.md §2.5 를 봐 주세요.
```

## 7. NAND, eMMC, 16 MiB 초과, RAM 덤프

- **NAND** (부팅 로그 `NAND: 128 MiB`, `Chipsize`): `sf` 로는 읽을 수 없다. 먼저 `uart_send_command(session_id="uart-001", command="nand info")` 와 `nand bad` 를 본다 (둘 다 INTERACT).
  - source="nand", chunk_size 는 erase block 배수(예: 128 KiB = "0x20000")로 한다.
  - `nand read` 는 배드 블록을 건너뛰므로 결과는 OOB 없는 논리 데이터다. 범위 안에 배드 블록이 있으면 청크 경계가 밀릴 수 있으니 notes 에 배드 블록 목록을 남긴다.
  - 128 MiB 는 md.b 로 약 16시간이다. 파티션 우선, 셸 base64, tftpput 을 먼저 제안한다.
- **eMMC**: `mmc list`, `mmc dev 0`, `mmc part` (INTERACT)로 장치와 파티션(512 B 블록 단위)을 확인한다.
  - source="mmc" 는 2013.07 이후 문법만 지원하므로 `mmc dev <n>` 을 먼저 보낸다. offset·length·chunk_size 는 512 의 배수여야 한다.
  - 2010.06 계열은 mmc 문법이 달라 지원하지 않는다 → 셸이나 tftpput 경로를 쓴다.
  - eMMC 는 수 GB 라 UART 로 전체를 받을 수 없다. 관심 파티션만 받는다.
- **16 MiB 초과 SPI NOR**: `SF: Warning - Only lower 16MiB accessible` 이 보이면 U-Boot 로는 아래 16 MiB 만 정확하다. 위쪽은 셸(/dev/mtdN) 또는 SPI 클립으로 받는다.
- **source="ram"**: 적재 없이 offset 을 RAM 주소로 보고 md.b 로 받는다 (kind memory-dump). 펌웨어 확보에는 보통 필요 없다.

## 8. 셸 경로 주의와 파일 합치기

- 덤프 전에 `dmesg -n 1` 로 콘솔 로그 레벨을 낮춘다. 커널 메시지가 base64 사이에 끼면 청크가 재시도된다.
- 경로는 shell_identify 의 mtd[].dev 로 만든 `/dev/mtdN` 을 쓴다. 길이는 생략하면 /proc/mtd 크기다. 일반 파일도 절대 경로로 받을 수 있다.
  /dev 아래는 저장장치(mtdN, mtdblockN, mmcblkN[pM], ubiX_Y, sdX)만 받는다. `/dev/watchdog`(여는 순간 타이머가 켜져 재부팅)·`/dev/mem` 같은 장치는 시작 호출이 validation_failed 로 거부한다.
- 쓰기 가능한 상태로 마운트된 파티션(jffs2·ubifs 설정 영역, shell_identify 의 mounts 확인)은 덤프 중에 바뀔 수 있다. 청크 md5 는 맞아도 이미지 전체가 한 시점이 아닐 수 있으니 notes 에 적거나 U-Boot 로 받는다.
- 셸 경로의 결과는 파티션마다 파일 1개다. output 은 rootfs 파일로 하고 나머지는 partitions[].path 에 둔다 (§9 예시 2).
- **한 파일로 합치기** (선택, 백업용): 모든 파티션을 받았고 /proc/mtd 순서대로 빈틈없이 플래시를 덮을 때만 한다. U-Boot 의 우선 범위 + 나머지 두 파일도 같다.
  1. `case_paths(case_id="<id>")` 의 case_dir 를 얻는다.
  2. 호스트 셸에서 /proc/mtd 순서로 이어 붙인다 (글롭 금지): `cat <case_dir>/dumps/mtd0-boot.bin <case_dir>/dumps/mtd1-env.bin … > <case_dir>/dumps/flash-full-joined.bin`.
  3. `case_register_artifact(case_id="<id>", path="dumps/flash-full-joined.bin", kind="flash-dump", description="mtd0~mtd4 연결")` → size 가 플래시 크기와 같은지 확인한다.
  4. 가능하면 U-Boot 에서 §6.1 4~5단계로 전체 crc32 를 받아 `case_hash_file(case_id="<id>", path="dumps/flash-full-joined.bin")` 의 crc32 와 비교한다 (crc32-uboot). 아니면 각 파일의 검증 결과를 notes 에 남긴다.

## 9. 추가 예시

**예시 1 — 우선 범위 0x0~0x750000 (U-Boot, status="partial")**. 시뮬레이터 hisilicon-like 실행 값이다 (실기기 약 55분). firmware-dump 스키마 검증을 통과했다.

```json
{
  "method": "uboot-md",
  "source": {"type": "sf", "flash_type": "spi-nor", "flash_model": "W25Q128(B/F)V", "flash_size": 16777216, "offset": 0, "length": 7667712, "partition": null, "ram_addr": "0x42000000", "device_path": null},
  "output": {"path": "dumps/flash-0-750000.bin", "sha256": "c5861277e59a7ddabcfd448074425c85ff54df06900c4b8676d3ae9f9906c65f", "size": 7667712},
  "verification": {
    "method": "crc32-chunks", "expected": "19fd4438", "actual": "19fd4438", "match": true, "chunks_verified": 117,
    "full_range": {"device_crc32": "19fd4438", "host_crc32": "19fd4438", "match": true},
    "cross_check": {"region": "kernel 앞 0x50000+0x10000", "dump": "dumps/probe-kernel-head.bin", "method": "5단계 시험 덤프 (기본 64k 청크, 메인 덤프 전)", "sha256": "47e7f249cdfdbb0533289042ef4821edf73838dfcfd27736db8705e31ec9cf9e", "reference": "case_hash_file dumps/flash-0-750000.bin offset 0x50000 length 0x10000", "match": true},
    "content_checks": ["fw_identify: uImage 'Linux-4.9.37' @0x50000 header_crc_ok=true data_crc_ok=true", "fw_identify: U-Boot env @0x40000 CRC 정상"]
  },
  "chunks": {"size": 65536, "count": 117, "retries": 0, "resumed_from": 0},
  "partitions": [
    {"name": "boot", "offset": 0, "size": 262144, "dumped": true},
    {"name": "env", "offset": 262144, "size": 65536, "dumped": true},
    {"name": "kernel", "offset": 327680, "size": 2097152, "dumped": true},
    {"name": "rootfs", "offset": 2424832, "size": 5242880, "dumped": true},
    {"name": "app", "offset": 7667712, "size": 9109504, "dumped": false}
  ],
  "duration_seconds": 35.73,
  "baudrate": 115200,
  "metadata_path": "dumps/flash-0-750000.json",
  "notes": ["우선 범위만 받음: app(0x750000+0x8b0000) 미덤프 → 사용자 동의 시 flash-750000-1000000 으로 받을 예정", "시뮬레이터 실행 값 (실기기 115200 bps 약 55분)"]
}
```

**예시 2 — 셸 경로 파티션별 (status="partial", boot·app 미덤프)**. 시뮬레이터 hisilicon-like 에서 base64 로 받은 값이다 (세 job 합계 19초, 실기기 약 15분). 스키마 검증을 통과했다.

```json
{
  "method": "linux-base64",
  "source": {"type": "linux-shell", "flash_type": "spi-nor", "flash_size": 16777216, "offset": 0, "length": 5242880, "partition": "rootfs", "ram_addr": null, "device_path": "/dev/mtd3"},
  "output": {"path": "dumps/mtd3-rootfs.bin", "sha256": "e048334fa28cfeb31cca21304505f8de030804e97c6e98794571576a0a1cd11d", "size": 5242880},
  "verification": {
    "method": "md5-device", "expected": null, "actual": null, "match": true, "chunks_verified": 80,
    "cross_check": {"region": "/dev/mtd1 (env)", "dump": "dumps/xcheck-mtd1.bin", "method": "hexdump -C, chunk 16k", "sha256": "adc68ad2f3d78fc85369ca25765b6b3cb2eb2906439d7f9ce7f4ba60ab5297d3", "reference": "dumps/mtd1-env.bin", "match": true}
  },
  "chunks": {"size": 65536, "count": 80, "retries": 0, "resumed_from": 0},
  "partitions": [
    {"name": "boot", "offset": 0, "size": 262144, "dev": "mtd0", "dumped": false},
    {"name": "env", "offset": 262144, "size": 65536, "dev": "mtd1", "dumped": true, "path": "dumps/mtd1-env.bin", "sha256": "adc68ad2f3d78fc85369ca25765b6b3cb2eb2906439d7f9ce7f4ba60ab5297d3", "verification": "md5-device"},
    {"name": "kernel", "offset": 327680, "size": 2097152, "dev": "mtd2", "dumped": true, "path": "dumps/mtd2-kernel.bin", "sha256": "b4a0e56c89ee1ce89d8d8aac5ed08627d1d3da25bff34e629276699c36dce9c3", "verification": "md5-device"},
    {"name": "rootfs", "offset": 2424832, "size": 5242880, "dev": "mtd3", "dumped": true, "path": "dumps/mtd3-rootfs.bin", "sha256": "e048334fa28cfeb31cca21304505f8de030804e97c6e98794571576a0a1cd11d", "verification": "md5-device"},
    {"name": "app", "offset": 7667712, "size": 9109504, "dev": "mtd4", "dumped": false}
  ],
  "duration_seconds": 19.04,
  "baudrate": 115200,
  "notes": ["셸 경로: 파티션마다 파일 1개. output 은 rootfs, 나머지는 partitions[].path", "dmesg -n 1 적용 후 덤프", "boot·app 미덤프", "시뮬레이터 실행 값 (실기기 base64 약 15분)"]
}
```

예시 2 의 next_actions 예: `["firmware-static-analysis: dumps/mtd3-rootfs.bin 을 fw_identify → fw_extract_squashfs (단일 파티션이라 fw_carve 불필요)", "kernel 은 dumps/mtd2-kernel.bin"]`.
