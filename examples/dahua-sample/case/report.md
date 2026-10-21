# 하드웨어 보안 분석 보고서 — dahua-like 합성 IP 카메라 — UART 덤프와 인증 우회 패턴 탐색 예제

- 케이스 ID: `example-dahua-sample`
- 프로필: `dahua-ipc`
- 생성: 2026-10-18T17:40:24.166Z / 보고서 생성: 2026-10-18T17:41:39.596Z
- 도구: pweh 0.1.0

> 이 보고서는 소유자이거나 서면 허가를 받은 기기에 대한 연구·방어 목적의 분석 결과다. 결과를 제3자 시스템 공격에 사용해서는 안 된다.

## 1. 요약

발견사항 총 8건 (치명 2건, 높음 5건, 중간 1건).

- **[치명] F-005 httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어)** — check_auth 가 요청 토큰을 고정 문자열과 strcmp 해 일치하면 자격증명 검사 없이 1(인증 성공)을 반환한다.
- **[치명] F-008 sonia is_local_request: 로그인의 '로컬 요청' 신뢰를 클라이언트가 보낸 loginType/ipAddr 로 판정 (비밀번호 검증 생략)** — is_local_request 가 요청 본문의 login_type/ip_addr 값만으로 로컬 요청 여부를 정한다. rpc_global_login 는 그 결과가 참이면 verify_password 를 부르지 않고 성공으로 응답한다.
- **[높음] F-001 root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt)** — /etc/shadow 의 root 해시가 공개 기본 비밀번호 사전 항목과 오프라인 대조로 일치한다 (평문은 케이스 analysis/ 에만 있음).
- **[높음] F-003 httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명)** — check_credentials 가 사용자 이름·비밀번호를 고정 리터럴과 비교해 일치하면 로그인 성공으로 처리한다. 같은 자격증명이 Basic 헤더 리터럴로도 박혀 있다.
- **[높음] F-004 httpd handle_ping_cgi 의 요청 값 → system() 명령 주입** — handle_ping_cgi 가 요청 값을 포맷 문자열 "ping -c 1 %s > /tmp/ping.log 2>&1" 에 넣어 system() 으로 실행한다. 메타문자 필터나 화이트리스트가 없다.

- 콘솔 접근: 포트 `/dev/pts/8` @ 115200 bps, 콘솔 유형 `uboot`, 접근 수준 `uboot`
- 펌웨어 확보: `dumps/flash-full.bin` (16777216 bytes, sha256 `560ae32b73b130eb8b3b6fef8d712b23d6477951f16546834fb1a353af6e878f`), 방법 `uboot-md`, 검증 `crc32-chunks` → True

## 2. 범위와 권한

- 근거: 본인 소유
- 소유자/허가 주체: PWEH 테스트 랩 (합성 시나리오)
- 진술: "이 카메라는 제가 직접 구매한 제 소유 기기이며, 하드웨어 보안 분석을 허가합니다. (합성 시나리오: pweh.mocktarget 시뮬레이터)"
- 범위: UART 콘솔 접속, 플래시 읽기 전용 덤프, 펌웨어 정적 분석. 영구 변경 금지.
- 기록: 2026-10-18T17:40:24.166Z (agent-relayed, user (relayed by agent))

## 3. 대상 기기

| 항목 | 값 |
|---|---|
| vendor | pweh-synthetic (dahua-like, 실제 벤더 아님) |
| model | SYNTH-DH-IPC |
| hardware_rev | sim-1 |
| firmware_version | synthetic-2020-03-23 |
| serial | SIM-DH-0001 |
| soc | hi3516ev300 (U-Boot env soc) |
| flash | W25Q128(B/F)V spi-nor 16 MiB |
| uboot_version | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300 |
| kernel_version | 4.9.37 |

## 4. 파이프라인 단계

| 단계 | 상태 | 갱신 |
|---|---|---|
| UART 셸/U-Boot 획득 | done | 2026-10-18T17:40:27.889Z |
| 펌웨어 덤프 | done | 2026-10-18T17:41:08.586Z |
| 로직 애널라이저 디코딩 | pending |  |
| 펌웨어 정적 분석 | done | 2026-10-18T17:41:27.274Z |
| CCTV 인증 우회 탐색 | partial | 2026-10-18T17:41:39.578Z |
| 보고서 | done | 2026-10-18T17:41:39.592Z |

### UART 셸/U-Boot 획득 — success

UART 115200 8N1(/dev/pts/8): U-Boot 진입('hisilicon # ', Ctrl-C), env·플래시·safe RAM 0x42000000 확보

- 다음 조치: firmware-dump-via-uart: 세션 재사용, U-Boot md.b 덤프 (crc32 검증)
- 산출물: `uart/console-001.log`, `uart/console-001-boot-01.log`

### 펌웨어 덤프 — success

U-Boot md.b 덤프 16777216 bytes (전체 플래시 (백업·복구·분석 겸용)). 청크 64개 crc32 일치, 전체 crc32 bcecd46e 일치, kernel 앞부분 교차 확인 일치

- 다음 조치: firmware-static-analysis: dumps/flash-full.bin 분석 (env 의 mtdparts 로 fw_carve 자동 분할)
- 산출물: `dumps/flash-full.bin`, `dumps/flash-full.json`, `dumps/probe-kernel-head.bin`

### 펌웨어 정적 분석 — success

rootfs(squashfs) 추출·감사, REA/Ghidra 디컴파일. 발견 6건

- 다음 조치: cctv-auth-bypass-hunt: 벤더 메인 앱·웹 구성요소 AH-01..AH-12 판정
- 산출물: `extract/rootfs-001`, `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`

### CCTV 인증 우회 탐색 — partial

dahua-like. AH-01~AH-12: match 7, inconclusive 5. 발견 8건

- 다음 조치: 빌드 날짜를 벤더 공지 수정 빌드와 비교; 격리 랩에서 negative test (사용자 동의 후)
- 산출물: `analysis/rootfs-audit-002.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-sonia-001.json`

## 5. 콘솔/부트로더 정보

- U-Boot 버전: U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300
- 프롬프트: `hisilicon # `
- bootargs: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- mtdparts: `mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- 플래시: {'type': 'spi-nor', 'model': 'W25Q128(B/F)V', 'size_bytes': 16777216}
- 커널: 4.9.37
- cmdline: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`

## 6. 펌웨어 정적 분석 개요

- 대상 펌웨어: `dumps/flash-full.bin` (sha256 `560ae32b73b130eb8b3b6fef8d712b23d6477951f16546834fb1a353af6e878f`)
- 추출: 도구 `fwtriage`, 상태 `complete`, 출력 `extract/rootfs-001`
- rootfs: `extract/rootfs-001` (squashfs 4.0 xz, arm)
- 웹 서버/서비스: /usr/bin/sonia, /usr/sbin/httpd

| 관심 바이너리 | 이유 |
|---|---|
| `/usr/bin/sonia` | 웹/메인 앱 바이너리 (dahua); canary=False, pie=False |
| `/usr/sbin/httpd` | 웹/메인 앱 바이너리 (generic); canary=False, pie=False |
| `/var/www/cgi-bin/status.cgi` | CGI 프로그램 |
| `/usr/sbin/telnetd` | 부팅 시 실행되는 서비스 (telnetd) |

## 7. 발견사항

| ID | 심각도 | 신뢰도 | 상태 | 분류 | 제목 | 위치 |
|---|---|---|---|---|---|---|
| F-005 | 치명 | 확정 | 정적 확인 | backdoor | httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어) | /usr/sbin/httpd :: check_auth |
| F-008 | 치명 | 확정 | 정적 확인 | auth-bypass | sonia is_local_request: 로그인의 '로컬 요청' 신뢰를 클라이언트가 보낸 loginType/ipAddr 로 판정 (비밀번호 검증 생략) | /usr/bin/sonia :: is_local_request |
| F-001 | 높음 | 확정 | 정적 확인 | hardcoded-credential | root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt) | /etc/shadow |
| F-003 | 높음 | 확정 | 정적 확인 | hardcoded-credential | httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명) | /usr/sbin/httpd :: check_credentials |
| F-004 | 높음 | 확정 | 정적 확인 | command-injection | httpd handle_ping_cgi 의 요청 값 → system() 명령 주입 | /usr/sbin/httpd :: handle_ping_cgi |
| F-006 | 높음 | 확정 | 정적 확인 | auth-bypass | httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략 | /usr/sbin/httpd :: is_static_resource |
| F-007 | 높음 | 확정 | 정적 확인 | info-leak | sonia: 세션 확인 전에 설정 디렉터리 파일을 내려줌 (계정 DB 노출) | /usr/bin/sonia :: serve_config_file |
| F-002 | 중간 | 확정 | 정적 확인 | debug-interface | 부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방) | /etc/init.d/rcS |

### F-005. httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어)

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: backdoor
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_auth`, address=`0x2235c`, offset=`0xe8c`, interface=`http`

check_auth 가 요청 토큰을 고정 문자열과 strcmp 해 일치하면 자격증명 검사 없이 1(인증 성공)을 반환한다.

**근거와 추론**

요청 토큰을 .rodata 의 고정 문자열과 strcmp 해 일치하면 자격증명 검사 전에 1(성공)을 반환한다. 문자열 히트(백도어 키워드가 든 토큰)가 이 비교의 상수다. 같은 펌웨어를 쓰는 모든 기기에 같은 값이 있다 (P4/P6).

**증거**

- (string) `/usr/sbin/httpd@0xe8c`

```
PW…<마스킹:고정 토큰,36자>
```
- (triage) `analysis/strings-hunt-001.json`

```
gen-backdoor-keywords /usr/sbin/httpd@0xe8c
```
- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_1fb00ae8271ba615549c52382b19f9b3236ce7e126ce20b0de51c05cd0b97e5d`

```
       (cVar3 = strcmp((c_char *)req->token,(c_char *)"PW…<마스킹:고정 토큰,36자>"),
      return 1;
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

토큰 분기를 제거하고 모든 경로가 정상 자격증명 검증을 거치게 한다.

### F-008. sonia is_local_request: 로그인의 '로컬 요청' 신뢰를 클라이언트가 보낸 loginType/ipAddr 로 판정 (비밀번호 검증 생략)

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/sonia`, function=`is_local_request`, address=`0x2250c`, interface=`http`

is_local_request 가 요청 본문의 login_type/ip_addr 값만으로 로컬 요청 여부를 정한다. rpc_global_login 는 그 결과가 참이면 verify_password 를 부르지 않고 성공으로 응답한다.

**근거와 추론**

요청 구조체의 login_type == "Loopback" 과 ip_addr == "127.0.0.1"(클라이언트가 써 넣은 값)만으로 로컬 요청이라고 판정한다. is_local_request 가 참이면 verify_password 를 부르지 않고 성공(ok=1)으로 응답한다. 소켓 peer 주소가 아니라 클라이언트가 주장한 값이다 (P4, CVE-2021-33045 계열).

**증거**

- (string) `/usr/bin/sonia@0xb3e`

```
dh-login-loopback-local: Loopback
```
- (string) `/usr/bin/sonia@0x128777`

```
gen-loopback-trust-anchors: is_local_request
```
- (string) `/usr/bin/sonia@0x1a45b1`

```
gen-loopback-trust-anchors: is_local_request
```
- (string) `/usr/bin/sonia@0xb4b`

```
dh-login-fields: clientType
```
- (triage) `analysis/strings-hunt-001.json`

```
dh-login-fields, dh-login-loopback-local, gen-loopback-trust-anchors
```
- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_6bad37c6c1e24afce75925f2bea042a01d1aaaa7f1044d8e811c69861adef2dc`

```
  cVar1 = strcmp((c_char *)l->login_type,(c_char *)"Loopback");
    return 0;
  cVar1 = strcmp((c_char *)l->ip_addr,(c_char *)"127.0.0.1");
  return (uint)(cVar1 == 0);
```
- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_7673ea9a0576de943a8f7060e62e2c1f0d98ff1a1db2b241cd106b6f1906f298`

```
  iVar1 = is_local_request(&lStack_130);
  ok = 1;
    ok = verify_password(lStack_130.user,lStack_130.pass);
  send_login_result(fd,ok,lStack_130.user);
```

**참고**: docs/references/cctv-vuln-patterns.md#4.2

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

로컬 판정은 getpeername 결과로 하고 모든 로그인 분기에서 비밀번호/다이제스트 검증을 강제한다.

### F-001. root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt)

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: hardcoded-credential
- 위치: firmware=`dumps/flash-full.bin`, file=`/etc/shadow`, line=`1`, interface=`uart/telnet`

/etc/shadow 의 root 해시가 공개 기본 비밀번호 사전 항목과 오프라인 대조로 일치한다 (평문은 케이스 analysis/ 에만 있음).

**근거와 추론**

fw_rootfs_audit 와 fw_crack_hashes 가 같은 결과를 냈다. 같은 펌웨어의 모든 기기가 같은 비밀번호를 가질 가능성이 높다 (P5).

**증거**

- (triage) `analysis/rootfs-audit-001.json`

```
builtin-default-password /etc/shadow:1 계정 'root' 의 비밀번호가 공개 기본 비밀번호 사전과 일치 (1***)
```
- (hash) `analysis/crack-hashes-001.json`

```
root: md5crypt $1$1Qd275ca$… → cracked (1***)
```
- (triage) `analysis/rootfs-audit-001.json`

```
passwd-md5-crypt /etc/shadow:1 root:$1$1Qd…:18000:0:99999:7:::
```

**검증 계획 (소유 기기·격리 랩)**

소유 기기의 UART 콘솔에서 운영자가 이미 아는 계정으로만 확인한다. 무차별 대입은 하지 않는다.

**권고**

기기별 초기 비밀번호 또는 첫 부팅 시 변경 강제, sha512crypt 이상 사용.

### F-003. httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명)

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: hardcoded-credential
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_credentials`, address=`0x22b08`, offset=`0xcce`, interface=`http`

check_credentials 가 사용자 이름·비밀번호를 고정 리터럴과 비교해 일치하면 로그인 성공으로 처리한다. 같은 자격증명이 Basic 헤더 리터럴로도 박혀 있다.

**근거와 추론**

사용자 이름과 비밀번호를 각각 .rodata 리터럴과 strcmp 해 일치하면 1(성공)을 반환한다 (고정 계정). 문자열 단계의 Basic 헤더(디코드한 사용자:비밀번호)와 같은 값이다 (P5).

**증거**

- (string) `/usr/sbin/httpd@0xcce`

```
Authorization: Basic YW…<마스킹:Basic 자격증명,36자> (base64 디코드: admin:<마스킹>)
```
- (triage) `analysis/strings-hunt-001.json`

```
gen-hardcoded-basic-auth /usr/sbin/httpd@0xcce
```
- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_82064774f0bebee249d328907deb5592e1d91fc46791d80197c97fb289d2a7b7`

```
  cVar1 = strcmp((c_char *)user,(c_char *)"admin");
  if ((cVar1 == 0) && (cVar1 = strcmp((c_char *)pass,(c_char *)"pw…<마스킹:내장 비밀번호,21자>"), cVar1 == 0)
    return 1;
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

고정 계정과 자가 점검용 자격증명을 제거하고 기기별 비밀값을 쓴다.

### F-004. httpd handle_ping_cgi 의 요청 값 → system() 명령 주입

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: command-injection
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`handle_ping_cgi`, address=`0x22470`, offset=`0xeda`, interface=`http`

handle_ping_cgi 가 요청 값을 포맷 문자열 "ping -c 1 %s > /tmp/ping.log 2>&1" 에 넣어 system() 으로 실행한다. 메타문자 필터나 화이트리스트가 없다.

**근거와 추론**

포맷 문자열 "ping -c 1 %s > /tmp/ping.log 2>&1" 의 %s 결과 버퍼가 필터 없이 system() 으로 간다. 요청 처리 경로에서 도달한다 (인증 뒤) (P11)

**증거**

- (string) `/usr/sbin/httpd@0xeda`

```
gen-shell-cmd-template: ping -c 1 %s > /tmp/ping.log 2>&1
```
- (triage) `analysis/strings-hunt-001.json`

```
gen-shell-cmd-template /usr/sbin/httpd@0xeda
```
- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_ae3f3cf07e61780e7d9de552b8a59be432a8cd7f9c9aaf007af9b2bb1c57f138`

```
  iVar1 = get_param(req->query,"host",acStack_98,0x80);
    snprintf(acStack_198,0x100,"ping -c 1 %s > /tmp/ping.log 2>&1",acStack_98);
    system(acStack_198);
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

셸을 거치지 말고 execve 인자 배열과 입력 화이트리스트(고정 목록)를 쓴다.

### F-006. httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`is_static_resource`, address=`0x229e0`, interface=`http`

is_static_resource 가 정규화 전 URI 에 정적 접두사나 확장자 부분 문자열이 있으면 1 을 돌려 호출자가 인증 검사를 건너뛴다. 임의 경로에 확장자 문자열만 섞어도 인증 없이 처리될 수 있다.

**근거와 추론**

정규화 전 URI 원문을 접두사(strncmp)와 확장자 부분 문자열(strstr)로 비교해 1 을 반환한다 → 호출자가 인증을 생략 (P1)

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_18e18030140af3dce762fe5400157b1346b15d5b932b122013a4f5163070d802`

```
  cVar1 = strncmp((c_char *)path,(c_char *)"/static/",8);
       (pcVar2 = strstr((c_char *)path,(c_char *)".css"), pcVar2 == (____0_c_char)0x0)) &&
      (pcVar2 = strstr((c_char *)path,(c_char *)".js"), pcVar2 == (____0_c_char)0x0)) &&
     (pcVar2 = strstr((c_char *)path,(c_char *)".png"), pcVar2 == (____0_c_char)0x0)) {
    pcVar2 = strstr((c_char *)path,(c_char *)".jpg");
    return (uint)(pcVar2 != (____0_c_char)0x0);
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

경로를 정규화한 뒤 정적 디렉터리 접두사만 정확히 비교하고, CGI/API 경로는 항상 인증한다.

### F-007. sonia: 세션 확인 전에 설정 디렉터리 파일을 내려줌 (계정 DB 노출)

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: info-leak
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/sonia`, function=`serve_config_file`, address=`0x21f70`, interface=`http`

설정 파일 경로 접두사 요청이 세션 확인보다 먼저 처리되어, 같은 디렉터리의 계정 DB 를 포함한 설정 파일이 인증 없이 제공된다.

**근거와 추론**

"/current_config/" 접두사 요청을 session_valid 보다 먼저 serve_config_file 로 넘긴다 (인증 전 설정 파일 제공) / 요청 이름을 /mnt/mtd/Config/ 아래 파일 경로로 만들어 그대로 내려준다 (P1/P8, CVE-2017-7925 계열)

**증거**

- (string) `/usr/bin/sonia@0xc09`

```
dh-current-config: /current_config/
```
- (string) `/usr/bin/sonia@0xbd2`

```
gen-mtd-config-accounts: /mnt/mtd/Config/Account1
```
- (triage) `analysis/strings-hunt-001.json`

```
dh-current-config, gen-mtd-config-accounts
```
- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_674adfa25e52b31b17500fed3a6da3f241bbc00a9b1d4506ef6f375b9858c009`

```
  cVar3 = strncmp((c_char *)pcVar5,(c_char *)"/current_config/",0x10);
    serve_config_file(fd,r->path + 0x10);
    iVar4 = session_valid(r);
```
- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_0843885144b14c96288c1bd96f9bd44f6dbba6e2254f63d672f9ce07cda14ee5`

```
  if (((*name != '\0') && (pcVar1 = strchr((c_char *)name,0x2f), pcVar1 == (____0_c_char)0x0)) &&
     (pcVar1 = strstr((c_char *)name,(c_char *)".."), pcVar1 == (____0_c_char)0x0)) {
    snprintf(acStack_118,0x100,"/mnt/mtd/Config/%s",name);
    send_file(fd,acStack_118);
```

**참고**: docs/references/cctv-vuln-patterns.md#4.2

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

설정 파일 제공 경로를 제거하거나 세션 확인 뒤로 옮기고, 공개 파일은 명시적 allowlist 로 한정한다.

### F-002. 부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방)

- 심각도/신뢰도/상태: 중간 / 확정 / 정적 확인
- 분류: debug-interface
- 위치: firmware=`dumps/flash-full.bin`, file=`/etc/init.d/rcS`, line=`20`, interface=`telnet`

/etc/init.d/rcS 20행이 조건 없이 telnetd 를 백그라운드로 실행한다. 네트워크에서 로그인 프롬프트가 항상 열린다.

**근거와 추론**

시작 스크립트 원문 줄이 직접 증거다 (패턴 P6). 기본 비밀번호(별도 발견사항)와 결합하면 원격 셸 노출로 이어진다.

**증거**

- (triage) `analysis/rootfs-audit-001.json`

```
gen-telnetd-launch /etc/init.d/rcS:20 /usr/sbin/telnetd &
```
- (file) `/etc/init.d/rcS`

```
/usr/sbin/telnetd &
```
- (string) `/etc/init.d/rcS@0x22d`

```
gen-telnetd-launch: /usr/sbin/telnetd &
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서 부팅 뒤 23/tcp 리슨 여부만 확인한다 (로그인 시도 없음).

**권고**

telnetd 기동 줄을 제거하거나 개발 빌드 전용 플래그로 감싼다.

## 8. 아티팩트

| ID | 경로 | 종류 | 크기 | sha256 |
|---|---|---|---|---|
| A-0001 | `uart/console-001.log` | uart-log | 113762807 | `e15f6183166adaf2` |
| A-0002 | `uart/console-001.raw` | uart-raw | 83187263 | `bbcbe8639827d14d` |
| A-0003 | `uart/console-001.events.jsonl` | uart-events | 85159 | `f90424f9a4841ed7` |
| A-0004 | `uart/console-001-boot-01.log` | uart-log | 5772 | `84c602c57512019b` |
| A-0005 | `dumps/probe-kernel-head.bin` | flash-dump | 65536 | `6e127a00ed8f926a` |
| A-0006 | `dumps/probe-kernel-head.json` | other | 1747 | `02b4c2d702c9d88c` |
| A-0007 | `dumps/flash-full.bin` | flash-dump | 16777216 | `560ae32b73b130eb` |
| A-0008 | `dumps/flash-full.json` | other | 12224 | `5c91aab86c69443b` |
| A-0009 | `analysis/identify-001.json` | triage-report | 8731 | `3fb39c94150eb8c9` |
| A-0010 | `extract/xcheck-001/00-xcheck.bin` | partition | 65536 | `6e127a00ed8f926a` |
| A-0011 | `extract/xcheck-001/index.json` | triage-report | 916 | `5a87b6951bbd0448` |
| A-0012 | `analysis/carve-001.json` | triage-report | 1481 | `0fcd49bc46fab900` |
| A-0013 | `analysis/identify-002.json` | triage-report | 8731 | `809c57f9c1fd9282` |
| A-0014 | `analysis/entropy-001.json` | triage-report | 5286 | `1d173f74bfdce17d` |
| A-0015 | `analysis/uboot-env-001.json` | triage-report | 4288 | `ccdc1f9a518fa5ac` |
| A-0016 | `extract/parts-001/00-boot.bin` | partition | 262144 | `81f8e28f7d1df782` |
| A-0017 | `extract/parts-001/01-env.bin` | partition | 65536 | `adc68ad2f3d78fc8` |
| A-0018 | `extract/parts-001/02-kernel.bin` | partition | 2097152 | `aa75eb42a9e5edf4` |
| A-0019 | `extract/parts-001/03-rootfs.bin` | partition | 5242880 | `aab01785c9480560` |
| A-0020 | `extract/parts-001/04-app.bin` | partition | 9109504 | `e738227fea793a46` |
| A-0021 | `extract/parts-001/index.json` | triage-report | 3789 | `468e3b1c43a23257` |
| A-0022 | `analysis/carve-002.json` | triage-report | 4251 | `585c28ed5e43db03` |
| A-0023 | `analysis/uimage-001.json` | triage-report | 1079 | `8e37137d482e0a96` |
| A-0024 | `extract/rootfs-001.manifest.json` | triage-report | 35143 | `dafae86285153cc7` |
| A-0025 | `extract/rootfs-001` | extracted-tree |  | `` |
| A-0026 | `analysis/extract-squashfs-001.json` | triage-report | 2407 | `3b1a7a4f13662243` |
| A-0027 | `extract/app-001.manifest.json` | triage-report | 2102 | `bdb6d2300ec39f1c` |
| A-0028 | `extract/app-001` | extracted-tree |  | `` |
| A-0029 | `analysis/extract-squashfs-002.json` | triage-report | 1664 | `5e288a9fd35e31ad` |
| A-0030 | `extract/rea-001` | extracted-tree |  | `` |
| A-0031 | `analysis/rootfs-audit-001.json` | triage-report | 9093 | `8b734182241e17e9` |
| A-0032 | `analysis/strings-hunt-001.json` | triage-report | 31558 | `4484107da60db07a` |
| A-0033 | `analysis/crack-hashes-001.json` | triage-report | 963 | `619d3dc71bc027ad` |
| A-0034 | `analysis/elf-info-001.json` | triage-report | 7412 | `41236901ffd78140` |
| A-0035 | `analysis/elf-info-002.json` | triage-report | 4596 | `a9a015ac70f0c973` |
| A-0036 | `analysis/elf-info-003.json` | triage-report | 5271 | `32b34f5f919efb01` |
| A-0037 | `analysis/rea-evidence-httpd-001.json` | rea-evidence | 313836 | `01b11f9bada9f0c8` |
| A-0038 | `analysis/rootfs-audit-002.json` | triage-report | 9094 | `f6b8f8855b5d4263` |
| A-0039 | `analysis/strings-hunt-002.json` | triage-report | 8682 | `bc63dfe6723df803` |
| A-0040 | `analysis/strings-hunt-003.json` | triage-report | 2562 | `9b0bb290828c6513` |
| A-0041 | `analysis/strings-hunt-004.json` | triage-report | 3964 | `90885cb761b89c22` |
| A-0042 | `analysis/rea-evidence-sonia-001.json` | rea-evidence | 113150 | `3b5458efcf677bac` |

## 9. 안전 게이트 및 감사 요약

안전 결정: allowed 16건, denied 5건

| 시각 | 서버 | 도구 | 위험도 | 결정 | 규칙 | 명령 |
|---|---|---|---|---|---|---|
| 2026-10-18T17:40:27.818Z | uart-mcp | uart_send_command | destructive | denied | uboot.saveenv | `saveenv` |
| 2026-10-18T17:40:27.819Z | uart-mcp | uart_send_command | destructive | denied | uboot.sf.erase | `sf erase 0x0 0x10000` |
| 2026-10-18T17:40:27.820Z | uart-mcp | uart_send_command | destructive | denied | uboot.saveenv | `saveenv` |
| 2026-10-18T17:40:27.822Z | uart-mcp | uart_send_command | destructive | denied | uboot.env.save | `env save` |
| 2026-10-18T17:40:27.826Z | uart-mcp | uart_write | destructive | denied | uboot.saveenv | `saveenv` |

## 10. 한계 및 미확인 사항

- `boot/env/uImage` — non-filesystem: 부트로더·env·커널은 파일시스템이 아님 (예상된 gap)
- `extract/rea-001` — unpublished-entry ×125: REA 교차 추출의 심볼릭 링크 (메타데이터로만 보존)
- AH-06: fn-path-ops-unnormalized 후보만 있음 — 파일 서빙 경로의 정규화 여부 미확인
- AH-09: 세션 생성 함수 미분석
- AH-10: 업데이트 처리 문자열·바이너리를 rootfs 에서 찾지 못함 (다른 파티션일 수 있음)
- AH-11: RTSP/ONVIF 서버 바이너리를 rootfs 에서 찾지 못함
- AH-12: elf-info: 스택 카나리 없음, 개별 함수 미분석
