# 하드웨어 보안 분석 보고서 — hikvision-like 합성 IP 카메라 — UART 덤프와 인증 우회 패턴 탐색 예제

- 케이스 ID: `example-hikvision-sample`
- 프로필: `hikvision-ipc`
- 생성: 2026-10-18T17:39:06.725Z / 보고서 생성: 2026-10-18T17:40:22.987Z
- 도구: pweh 0.1.0

> 이 보고서는 소유자이거나 서면 허가를 받은 기기에 대한 연구·방어 목적의 분석 결과다. 결과를 제3자 시스템 공격에 사용해서는 안 된다.

## 1. 요약

발견사항 총 8건 (치명 3건, 높음 4건, 중간 1건).

- **[치명] F-005 httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어)** — check_auth 가 요청 토큰을 고정 문자열과 strcmp 해 일치하면 자격증명 검사 없이 1(인증 성공)을 반환한다.
- **[치명] F-007 davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달)** — handle_web_language 가 요청 값을 포맷 문자열 "cp -rf /usr/share/webroot/i18n/%s/* /tmp/i18n/ 2>/dev/null" 에 넣어 system() 으로 실행한다. 메타문자 필터나 화이트리스트가 없다. 디스패처가 "/SDK/webLanguage" 를 인증 검사보다 먼저 이 함수로 넘긴다.
- **[치명] F-008 davinci hikcgi_auth: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭)** — hikcgi_auth 는 쿼리 파라미터가 있으면 base64 디코드한 사용자 이름만으로 신원을 정하고 비밀번호를 확인하지 않는다. 다른 API 계열의 인증 함수는 같은 자리에서 표준 검사만 부른다.
- **[높음] F-001 root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt)** — /etc/shadow 의 root 해시가 공개 기본 비밀번호 사전 항목과 오프라인 대조로 일치한다 (평문은 케이스 analysis/ 에만 있음).
- **[높음] F-003 httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명)** — check_credentials 가 사용자 이름·비밀번호를 고정 리터럴과 비교해 일치하면 로그인 성공으로 처리한다. 같은 자격증명이 Basic 헤더 리터럴로도 박혀 있다.

- 콘솔 접근: 포트 `/dev/pts/8` @ 115200 bps, 콘솔 유형 `uboot`, 접근 수준 `uboot`
- 펌웨어 확보: `dumps/flash-full.bin` (16777216 bytes, sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2`), 방법 `uboot-md`, 검증 `crc32-chunks` → True

## 2. 범위와 권한

- 근거: 본인 소유
- 소유자/허가 주체: PWEH 테스트 랩 (합성 시나리오)
- 진술: "이 카메라는 제가 직접 구매한 제 소유 기기이며, 하드웨어 보안 분석을 허가합니다. (합성 시나리오: pweh.mocktarget 시뮬레이터)"
- 범위: UART 콘솔 접속, 플래시 읽기 전용 덤프, 펌웨어 정적 분석. 영구 변경 금지.
- 기록: 2026-10-18T17:39:06.725Z (agent-relayed, user (relayed by agent))

## 3. 대상 기기

| 항목 | 값 |
|---|---|
| vendor | pweh-synthetic (hikvision-like, 실제 벤더 아님) |
| model | SYNTH-HIK-IPC |
| hardware_rev | sim-1 |
| firmware_version | synthetic-2020-03-23 |
| serial | SIM-HIK-0001 |
| soc | hi3516ev300 (U-Boot env soc) |
| flash | W25Q128(B/F)V spi-nor 16 MiB |
| uboot_version | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300 |
| kernel_version | 4.9.37 |

## 4. 파이프라인 단계

| 단계 | 상태 | 갱신 |
|---|---|---|
| UART 셸/U-Boot 획득 | done | 2026-10-18T17:39:10.464Z |
| 펌웨어 덤프 | done | 2026-10-18T17:39:51.082Z |
| 로직 애널라이저 디코딩 | pending |  |
| 펌웨어 정적 분석 | done | 2026-10-18T17:40:09.379Z |
| CCTV 인증 우회 탐색 | partial | 2026-10-18T17:40:22.968Z |
| 보고서 | done | 2026-10-18T17:40:22.982Z |

### UART 셸/U-Boot 획득 — success

UART 115200 8N1(/dev/pts/8): U-Boot 진입('hisilicon # ', Ctrl-C), env·플래시·safe RAM 0x42000000 확보

- 다음 조치: firmware-dump-via-uart: 세션 재사용, U-Boot md.b 덤프 (crc32 검증)
- 산출물: `uart/console-001.log`, `uart/console-001-boot-01.log`

### 펌웨어 덤프 — success

U-Boot md.b 덤프 16777216 bytes (전체 플래시 (백업·복구·분석 겸용)). 청크 64개 crc32 일치, 전체 crc32 5a756bc0 일치, kernel 앞부분 교차 확인 일치

- 다음 조치: firmware-static-analysis: dumps/flash-full.bin 분석 (env 의 mtdparts 로 fw_carve 자동 분할)
- 산출물: `dumps/flash-full.bin`, `dumps/flash-full.json`, `dumps/probe-kernel-head.bin`

### 펌웨어 정적 분석 — success

rootfs(squashfs) 추출·감사, REA/Ghidra 디컴파일. 발견 6건

- 다음 조치: cctv-auth-bypass-hunt: 벤더 메인 앱·웹 구성요소 AH-01..AH-12 판정
- 산출물: `extract/rootfs-001`, `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`

### CCTV 인증 우회 탐색 — partial

hikvision-like. AH-01~AH-12: match 5, inconclusive 6. 발견 8건

- 다음 조치: 빌드 날짜를 벤더 공지 수정 빌드와 비교; 격리 랩에서 negative test (사용자 동의 후)
- 산출물: `analysis/rootfs-audit-002.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-davinci-001.json`

## 5. 콘솔/부트로더 정보

- U-Boot 버전: U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300
- 프롬프트: `hisilicon # `
- bootargs: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- mtdparts: `mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- 플래시: {'type': 'spi-nor', 'model': 'W25Q128(B/F)V', 'size_bytes': 16777216}
- 커널: 4.9.37
- cmdline: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`

## 6. 펌웨어 정적 분석 개요

- 대상 펌웨어: `dumps/flash-full.bin` (sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2`)
- 추출: 도구 `fwtriage`, 상태 `complete`, 출력 `extract/rootfs-001`
- rootfs: `extract/rootfs-001` (squashfs 4.0 xz, arm)
- 웹 서버/서비스: /usr/bin/davinci, /usr/sbin/httpd

| 관심 바이너리 | 이유 |
|---|---|
| `/usr/bin/davinci` | 웹/메인 앱 바이너리 (hikvision); canary=False, pie=False |
| `/usr/sbin/httpd` | 웹/메인 앱 바이너리 (generic); canary=False, pie=False |
| `/var/www/cgi-bin/status.cgi` | CGI 프로그램 |
| `/usr/sbin/telnetd` | 부팅 시 실행되는 서비스 (telnetd) |

## 7. 발견사항

| ID | 심각도 | 신뢰도 | 상태 | 분류 | 제목 | 위치 |
|---|---|---|---|---|---|---|
| F-005 | 치명 | 확정 | 정적 확인 | backdoor | httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 (백도어) | /usr/sbin/httpd :: check_auth |
| F-007 | 치명 | 확정 | 정적 확인 | command-injection | davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달) | /usr/bin/davinci :: handle_web_language |
| F-008 | 치명 | 확정 | 정적 확인 | auth-bypass | davinci hikcgi_auth: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭) | /usr/bin/davinci :: hikcgi_auth |
| F-001 | 높음 | 확정 | 정적 확인 | hardcoded-credential | root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt) | /etc/shadow |
| F-003 | 높음 | 확정 | 정적 확인 | hardcoded-credential | httpd check_credentials 의 고정 관리자 계정 비교 (하드코딩 자격증명) | /usr/sbin/httpd :: check_credentials |
| F-004 | 높음 | 확정 | 정적 확인 | command-injection | httpd handle_ping_cgi 의 요청 값 → system() 명령 주입 | /usr/sbin/httpd :: handle_ping_cgi |
| F-006 | 높음 | 확정 | 정적 확인 | auth-bypass | httpd is_static_resource: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략 | /usr/sbin/httpd :: is_static_resource |
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

### F-007. davinci handle_web_language 의 요청 값 → system() 명령 주입 (인증 전 도달)

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: command-injection
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/davinci`, function=`handle_web_language`, address=`0x2219c`, interface=`http`

handle_web_language 가 요청 값을 포맷 문자열 "cp -rf /usr/share/webroot/i18n/%s/* /tmp/i18n/ 2>/dev/null" 에 넣어 system() 으로 실행한다. 메타문자 필터나 화이트리스트가 없다. 디스패처가 "/SDK/webLanguage" 를 인증 검사보다 먼저 이 함수로 넘긴다.

**근거와 추론**

포맷 문자열 "cp -rf /usr/share/webroot/i18n/%s/* /tmp/i18n/ 2>/dev/null" 의 %s 결과 버퍼가 필터 없이 system() 으로 간다. 디스패처가 "/SDK/webLanguage" 를 인증 호출보다 먼저 handle_web_language() 로 넘긴다 (인증 전 도달) (P11)

**증거**

- (string) `/usr/bin/davinci@0xcd1`

```
hik-sdk-weblanguage: /SDK/webLanguage
```
- (triage) `analysis/strings-hunt-001.json`

```
hik-sdk-weblanguage
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_90fe78a4b4b826a62ff7860813029da2a79edf81018f8f108a0247451aaea3ba`

```
  iVar3 = xml_value(req->body,acStack_58,in_r2,in_r3);
    snprintf(acStack_158,0x100,"cp -rf /usr/share/webroot/i18n/%s/* /tmp/i18n/ 2>/dev/null",
    system(acStack_158);
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_1fda71456963b97de9b76c8ddead2c330e010334b936e15d28a768fa52540373`

```
  cVar2 = strcmp((c_char *)pcVar5,(c_char *)"/SDK/webLanguage");
    handle_web_language(fd,req);
  iVar3 = (*paVar4->auth)(req,(char *)auStack_58,0x40);
```

**참고**: docs/references/cctv-vuln-patterns.md#4.1

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다. 빌드 날짜를 벤더 공지 기준과 비교한다.

**권고**

셸을 거치지 말고 execve 인자 배열과 입력 화이트리스트(고정 목록)를 쓴다.

### F-008. davinci hikcgi_auth: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭)

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/davinci`, function=`hikcgi_auth`, address=`0x22568`, interface=`http`

hikcgi_auth 는 쿼리 파라미터가 있으면 base64 디코드한 사용자 이름만으로 신원을 정하고 비밀번호를 확인하지 않는다. 다른 API 계열의 인증 함수는 같은 자리에서 표준 검사만 부른다.

**근거와 추론**

쿼리 파라미터가 있으면 base64 디코드한 값의 ':' 앞 사용자 이름을 신원으로 쓰고 1 을 반환한다. 비밀번호 비교 호출이 없고 표준 basic_auth_check 는 그 분기 뒤에만 있다. 한 핸들러 계열에만 있는 '존재하면 생략' 분기는 CVE-2017-7921 계열의 가장 강한 신호다 (P4).

**증거**

- (string) `/usr/bin/davinci@0xc02`

```
hik-hikcgi-endpoints: /Security/users
```
- (string) `/usr/bin/davinci@0xbee`

```
hik-handler-families: /SDK/activateStatus
```
- (string) `/usr/bin/davinci@0xc21`

```
hik-handler-families: /ISAPI/System/deviceInfo
```
- (string) `/usr/bin/davinci@0xc3a`

```
hik-handler-families: /PSIA/System/deviceInfo
```
- (triage) `analysis/strings-hunt-001.json`

```
hik-handler-families, hik-hikcgi-endpoints
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_b73962703c1bf196d6d72d26e133225b0e7bbc165baea7fd2d1ad2c25ca35ab4`

```
  iVar1 = query_param(req->query,acStack_b8,(char *)userlen,in_r3);
  if ((iVar1 != 0) && (iVar1 = b64_decode(acStack_b8,(char *)acStack_158,0xa0), 0 < iVar1)) {
    snprintf(user,userlen,"%s",acStack_158);
    return 1;
  iVar1 = basic_auth_check(req,user,userlen);
```

**참고**: docs/references/cctv-vuln-patterns.md#4.1

**검증 계획 (소유 기기·격리 랩)**

격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.

**권고**

디버그 분기를 제거하고 모든 계열이 같은 인증 함수를 거치게 한다.

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
builtin-default-password /etc/shadow:1 계정 'root' 의 비밀번호가 공개 기본 비밀번호 사전과 일치 (54***)
```
- (hash) `analysis/crack-hashes-001.json`

```
root: md5crypt $1$7Q21e26b$… → cracked (54***)
```
- (triage) `analysis/rootfs-audit-001.json`

```
passwd-md5-crypt /etc/shadow:1 root:$1$7Q2…:18000:0:99999:7:::
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
| A-0001 | `uart/console-001.log` | uart-log | 113762944 | `36035c654bd63c6c` |
| A-0002 | `uart/console-001.raw` | uart-raw | 83187263 | `e022835050725481` |
| A-0003 | `uart/console-001.events.jsonl` | uart-events | 85163 | `015b518d473cbaaf` |
| A-0004 | `uart/console-001-boot-01.log` | uart-log | 5772 | `9cd810aee5c90660` |
| A-0005 | `dumps/probe-kernel-head.bin` | flash-dump | 65536 | `b6f2e962ba93c66e` |
| A-0006 | `dumps/probe-kernel-head.json` | other | 1747 | `176ca34fa06fafbe` |
| A-0007 | `dumps/flash-full.bin` | flash-dump | 16777216 | `e95ae853526947b9` |
| A-0008 | `dumps/flash-full.json` | other | 12224 | `1689105f5fa59c9e` |
| A-0009 | `analysis/identify-001.json` | triage-report | 10682 | `6e199bb549681983` |
| A-0010 | `extract/xcheck-001/00-xcheck.bin` | partition | 65536 | `b6f2e962ba93c66e` |
| A-0011 | `extract/xcheck-001/index.json` | triage-report | 916 | `c1519e822d02e721` |
| A-0012 | `analysis/carve-001.json` | triage-report | 1485 | `57da9855894445f6` |
| A-0013 | `analysis/identify-002.json` | triage-report | 10682 | `b783605702620bb0` |
| A-0014 | `analysis/entropy-001.json` | triage-report | 5286 | `038a25fccb3bfebf` |
| A-0015 | `analysis/uboot-env-001.json` | triage-report | 4292 | `14daa5d6d57fee04` |
| A-0016 | `extract/parts-001/00-boot.bin` | partition | 262144 | `af3bdcd6765632e3` |
| A-0017 | `extract/parts-001/01-env.bin` | partition | 65536 | `adc68ad2f3d78fc8` |
| A-0018 | `extract/parts-001/02-kernel.bin` | partition | 2097152 | `cd3325c4e11951b6` |
| A-0019 | `extract/parts-001/03-rootfs.bin` | partition | 5242880 | `24d9d2f238d18bb8` |
| A-0020 | `extract/parts-001/04-app.bin` | partition | 9109504 | `7008981ed12f14e4` |
| A-0021 | `extract/parts-001/index.json` | triage-report | 3789 | `ba39edaa6b757fdc` |
| A-0022 | `analysis/carve-002.json` | triage-report | 4255 | `9e0446812fcfb205` |
| A-0023 | `analysis/uimage-001.json` | triage-report | 1083 | `24103dc8ca98b878` |
| A-0024 | `extract/rootfs-001.manifest.json` | triage-report | 35869 | `b5bb72c7c2ea826e` |
| A-0025 | `extract/rootfs-001` | extracted-tree |  | `` |
| A-0026 | `analysis/extract-squashfs-001.json` | triage-report | 2419 | `fa0743369d1d96f8` |
| A-0027 | `extract/app-001.manifest.json` | triage-report | 2102 | `ad8879ba512aba5a` |
| A-0028 | `extract/app-001` | extracted-tree |  | `` |
| A-0029 | `analysis/extract-squashfs-002.json` | triage-report | 1668 | `839b6dee50bdfc9c` |
| A-0030 | `extract/rea-001` | extracted-tree |  | `` |
| A-0031 | `analysis/rootfs-audit-001.json` | triage-report | 9091 | `a731e2d795689889` |
| A-0032 | `analysis/strings-hunt-001.json` | triage-report | 29328 | `9709d7a283e94493` |
| A-0033 | `analysis/crack-hashes-001.json` | triage-report | 968 | `e8d818b47a451519` |
| A-0034 | `analysis/elf-info-001.json` | triage-report | 7651 | `41bcc60518365100` |
| A-0035 | `analysis/elf-info-002.json` | triage-report | 5277 | `d2ff3988644d452f` |
| A-0036 | `analysis/elf-info-003.json` | triage-report | 5275 | `dd47c6699e8cf055` |
| A-0037 | `analysis/rea-evidence-httpd-001.json` | rea-evidence | 318503 | `ddc6412b3b148122` |
| A-0038 | `analysis/rootfs-audit-002.json` | triage-report | 9091 | `e13d84442eeff6e1` |
| A-0039 | `analysis/strings-hunt-002.json` | triage-report | 8294 | `60d2ae613d9f31ae` |
| A-0040 | `analysis/strings-hunt-003.json` | triage-report | 4215 | `0cb642ba5dd02230` |
| A-0041 | `analysis/strings-hunt-004.json` | triage-report | 3968 | `7320406fc7851640` |
| A-0042 | `analysis/rea-evidence-davinci-001.json` | rea-evidence | 105296 | `a0f915e78e5cf44b` |

## 9. 안전 게이트 및 감사 요약

안전 결정: allowed 16건, denied 5건

| 시각 | 서버 | 도구 | 위험도 | 결정 | 규칙 | 명령 |
|---|---|---|---|---|---|---|
| 2026-10-18T17:39:10.393Z | uart-mcp | uart_send_command | destructive | denied | uboot.saveenv | `saveenv` |
| 2026-10-18T17:39:10.395Z | uart-mcp | uart_send_command | destructive | denied | uboot.sf.erase | `sf erase 0x0 0x10000` |
| 2026-10-18T17:39:10.396Z | uart-mcp | uart_send_command | destructive | denied | uboot.saveenv | `saveenv` |
| 2026-10-18T17:39:10.397Z | uart-mcp | uart_send_command | destructive | denied | uboot.env.save | `env save` |
| 2026-10-18T17:39:10.400Z | uart-mcp | uart_write | destructive | denied | uboot.saveenv | `saveenv` |

## 10. 한계 및 미확인 사항

- {'region': 'boot/env/uImage', 'kind': 'non-filesystem', 'note': '부트로더·env·커널은 파일시스템이 아님 (예상된 gap)'}
- {'region': 'extract/rea-001', 'kind': 'unpublished-entry', 'count': 125, 'note': 'REA 교차 추출의 심볼릭 링크 (메타데이터로만 보존)'}
- AH-03: 설정 export/파일 제공 경로 미확인
- AH-06: fn-path-ops-unnormalized 후보만 있음 — 파일 서빙 경로의 정규화 여부 미확인
- AH-09: 세션 생성 함수 미분석
- AH-10: 업데이트 처리 문자열·바이너리를 rootfs 에서 찾지 못함 (다른 파티션일 수 있음)
- AH-11: RTSP/ONVIF 서버 바이너리를 rootfs 에서 찾지 못함
- AH-12: elf-info: 스택 카나리 없음, 개별 함수 미분석
