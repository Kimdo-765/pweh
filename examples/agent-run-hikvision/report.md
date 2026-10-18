# 하드웨어 보안 분석 보고서 — 실내형 IP 카메라 (IPC 보드, Hikvision 계열 추정) 하드웨어 보안 분석

- 케이스 ID: `20261018-unknown-hikvision-ip-ipc`
- 프로필: `generic-ipcam`
- 생성: 2026-10-18T16:30:03.030Z / 보고서 생성: 2026-10-18T16:44:35.926Z
- 도구: pweh 0.1.0

> 이 보고서는 소유자이거나 서면 허가를 받은 기기에 대한 연구·방어 목적의 분석 결과다. 결과를 제3자 시스템 공격에 사용해서는 안 된다.

## 1. 요약

발견사항 총 8건 (치명 3건, 높음 3건, 중간 2건).

- **[치명] F-001 httpd check_auth 의 하드코딩 서비스 토큰 비교로 인증 생략** — check_auth 가 요청 token(X-Service-Token 헤더 또는 query 의 token 파라미터)을 고정 문자열과 strcmp 해 일치하면 Basic 인증 검사 없이 1(성공)을 반환한다.
- **[치명] F-005 davinci /SDK/webLanguage 인증 전 명령 주입** — dispatch 가 '/SDK/webLanguage' 를 인증 함수 호출 전에 handle_web_language 로 보낸다. handle_web_language 는 요청 본문 XML 의 <language> 값(최대 63자)을 'cp -rf /usr/share/webroot/i18n/%s/* ...' 에 넣어 system() 으로 실행한다.
- **[치명] F-006 davinci hikcgi_auth 의 매직 query 파라미터로 비밀번호 검증 생략** — /Security/ 계열 인증 함수 hikcgi_auth 는 query 에 특정 파라미터가 있고 값이 base64 로 디코드되면, 그 안의 사용자 이름을 그대로 신뢰하고 verify_password 없이 1 을 반환한다.
- **[높음] F-002 httpd check_credentials 의 하드코딩 admin 계정** — check_credentials 가 사용자 'admin' 과 .rodata 의 고정 비밀번호를 strcmp 로 비교한다. 설정 저장소를 읽지 않으므로 비밀번호를 바꿀 수 없다. selftest 함수의 Basic 헤더 문자열도 같은 계정이다.
- **[높음] F-003 httpd handle_ping_cgi 의 host 파라미터 명령 주입** — handle_ping_cgi 가 query 의 host 값을 URL 디코드한 뒤 필터 없이 'ping -c 1 %s ...' 에 snprintf 하고 system() 으로 실행한다(httpd 는 root 로 기동, rcS).

- 콘솔 접근: 포트 `<WORKSPACE>/ttyCAM0` @ 115200 bps, 콘솔 유형 `uboot`, 접근 수준 `uboot`
- 펌웨어 확보: `dumps/flash-full.bin` (16777216 bytes, sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2`), 방법 `uboot-md`, 검증 `crc32-chunks` → True

## 2. 범위와 권한

- 근거: 본인 소유
- 소유자/허가 주체: PWEH 테스트 랩
- 진술: "제가 직접 구매한 제 소유 기기입니다. 소유자 이름은 "PWEH 테스트 랩" 로 기록해 주세요. 서면 허가 문서는 없습니다(소유 기기)."
- 범위: UART 콘솔 확보, 펌웨어 덤프(읽기 전용), 오프라인 정적 분석, 인증 관련 의심 지점 보고
- 기록: 2026-10-18T16:30:03.030Z (agent-relayed, user (relayed by agent))

## 3. 대상 기기

| 항목 | 값 |
|---|---|
| vendor | unknown (Hikvision 계열 추정, 미확인) |
| model | 실내형 IP 카메라 (보드 실크 'IPC') |
| soc | hi3516ev300 (U-Boot env soc/board + 버전 태그; 커널 확인 전) |
| flash | W25Q128(B/F)V SPI NOR 16 MiB (sf probe) |
| uboot_version | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300 |
| arch | armv7 (U-Boot env cpu) |
| dram | 64 MiB |

## 4. 파이프라인 단계

| 단계 | 상태 | 갱신 |
|---|---|---|
| UART 셸/U-Boot 획득 | done | 2026-10-18T16:32:04.084Z |
| 펌웨어 덤프 | done | 2026-10-18T16:34:33.576Z |
| 로직 애널라이저 디코딩 | pending |  |
| 펌웨어 정적 분석 | done | 2026-10-18T16:40:08.510Z |
| CCTV 인증 우회 탐색 | partial | 2026-10-18T16:44:28.244Z |
| 보고서 | done | 2026-10-18T16:44:35.920Z |

### UART 셸/U-Boot 획득 — success

UART 115200 8N1: U-Boot 2016.11 (hi3516ev300) 진입(Ctrl-C), env 전체·W25Q128 16MiB·safe RAM 0x42000000 확보. 리눅스 셸은 시도하지 않음(계정 없음, 덤프 후 정적 분석 경로).

- 다음 조치: firmware-dump-via-uart: 세션 console-001(uboot) 재사용, sf 0x0 16MiB, RAM 0x42000000, crc32 검증
- 산출물: `uart/console-001.log`, `uart/console-001.events.jsonl`

### 펌웨어 덤프 — success

U-Boot md.b 로 16 MiB 전체 덤프. 청크 256개 crc32 일치(재시도 0), 전체 crc32 5a756bc0 일치, kernel 앞 64KiB 시험 덤프와 sha256 일치, uImage CRC·env CRC 정상

- 다음 조치: firmware-static-analysis: dumps/flash-full.bin (fw_carve 자동 레이아웃)
- 산출물: `dumps/flash-full.bin`, `dumps/flash-full.json`, `dumps/probe-kernel-head.bin`

### 펌웨어 정적 분석 — success

16MiB 덤프 지도화·분할, rootfs/app squashfs 추출·감사, httpd·davinci Ghidra 디컴파일. 발견 8건 (critical 4, high 2, medium 2). 펌웨어에 PWEH 합성 마커 있음

- 다음 조치: cctv-auth-bypass-hunt: davinci/httpd 인증 전 디스패치 표, P1~P12 점검; 격리 랩 negative test (사용자 동의 후)
- 산출물: `extract/rootfs-001`, `extract/app-001`, `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-davinci-001.json`

### CCTV 인증 우회 탐색 — partial

hikvision-like(합성 펌웨어). AH-01~AH-12: match 6, no-match 1, not-applicable 1, inconclusive 4. 발견 8건(critical 3, high 3, medium 2). 빌드 비교 미실시.

- 다음 조치: 기기 빌드/버전 정보를 받아 벤더 공지와 비교; httpd g_root 확인 후 AH-03/AH-06 재판정; 격리 랩 negative test (사용자 동의 후)
- 산출물: `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-davinci-001.json`

## 5. 콘솔/부트로더 정보

- U-Boot 버전: U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300
- 프롬프트: `hisilicon # `
- bootargs: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- mtdparts: `mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- 플래시: {'type': 'spi-nor', 'model': 'W25Q128(B/F)V', 'size_bytes': 16777216}

## 6. 펌웨어 정적 분석 개요

- 대상 펌웨어: `dumps/flash-full.bin` (sha256 `e95ae853526947b9d29011f61c4cb3b92ce6fdff8a368cd23eef14cd40c5c2a2`)
- 추출: 도구 `fwtriage`, 상태 `complete`, 출력 `extract/rootfs-001`
- rootfs: `extract/rootfs-001` (squashfs 4.0 xz, arm)
- 웹 서버/서비스: /usr/bin/davinci, /usr/sbin/httpd

| 관심 바이너리 | 이유 |
|---|---|
| `/usr/bin/davinci` | Hikvision 계열 메인 웹 앱(ISAPI/PSIA/SDK/Security 디스패치), 정적 링크 system/execve, 카나리 없음 (score 28.5) |
| `/usr/sbin/httpd` | 네트워크 대면 웹 서버, system/execve, 카나리 없음 (score 28.5) |
| `/var/www/cgi-bin/status.cgi` | CGI 프로그램 (문자열 휴리스틱 히트 없음) |
| `/usr/sbin/telnetd` | rcS 가 무조건 기동하는 서비스 (BusyBox) |

## 7. 발견사항

| ID | 심각도 | 신뢰도 | 상태 | 분류 | 제목 | 위치 |
|---|---|---|---|---|---|---|
| F-001 | 치명 | 확정 | 정적 확인 | backdoor | httpd check_auth 의 하드코딩 서비스 토큰 비교로 인증 생략 | /usr/sbin/httpd :: check_auth |
| F-005 | 치명 | 확정 | 정적 확인 | command-injection | davinci /SDK/webLanguage 인증 전 명령 주입 | /usr/bin/davinci :: handle_web_language |
| F-006 | 치명 | 확정 | 정적 확인 | auth-bypass | davinci hikcgi_auth 의 매직 query 파라미터로 비밀번호 검증 생략 | /usr/bin/davinci :: hikcgi_auth |
| F-002 | 높음 | 확정 | 정적 확인 | hardcoded-credential | httpd check_credentials 의 하드코딩 admin 계정 | /usr/sbin/httpd :: check_credentials |
| F-003 | 높음 | 확정 | 정적 확인 | command-injection | httpd handle_ping_cgi 의 host 파라미터 명령 주입 | /usr/sbin/httpd :: handle_ping_cgi |
| F-008 | 높음 | 확정 | 정적 확인 | debug-interface | 부팅 시 telnetd 무조건 기동 + root 계정이 공개 기본 비밀번호 | /etc/init.d/rcS |
| F-004 | 중간 | 유력 | 미검증 | auth-bypass | httpd is_static_resource 의 부분 문자열 허용 목록으로 인증 생략 + 경로 정규화 없음 | /usr/sbin/httpd :: is_static_resource |
| F-007 | 중간 | 확정 | 정적 확인 | weak-crypto | davinci verify_password 의 솔트 없는 64비트 비암호 해시(FNV-1a 계열) | /usr/bin/davinci :: pw_digest |

### F-001. httpd check_auth 의 하드코딩 서비스 토큰 비교로 인증 생략

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: backdoor
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_auth`, address=`0x2235c`, interface=`http`

check_auth 가 요청 token(X-Service-Token 헤더 또는 query 의 token 파라미터)을 고정 문자열과 strcmp 해 일치하면 Basic 인증 검사 없이 1(성공)을 반환한다.

**근거와 추론**

handle_client(0x22084) 는 모든 요청에서 디스패치 전에 check_auth 를 호출하고, check_auth 는 토큰 일치 시 자격증명 검사 전에 성공을 반환한다. 같은 펌웨어를 쓰는 모든 기기에 같은 값이 있다. 토큰은 query 로도 받으므로 URL 하나로 인증을 우회할 수 있다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_c2a5faf2e6e13979c8f843d2611405d391c0e7ed4be14939a3ed2310ea19ed5b`

```
if ((req->token[0] != '\0') && (strcmp(req->token, "<고정 토큰, 마스킹>") == 0)) { return 1; }
```
- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_90f01b0bfb30e54f55686261a8ca4ff5bab945a998d4c872959f40a1f7bd31c9`

```
parse_request: 'X-Service-Token: ' 헤더 → req->token; 없으면 get_param(query, "token", ...)
```
- (string) `/usr/sbin/httpd@0xe8c`

```
36자 고정 토큰 (마스킹), VA 0x10e7d, 참조 0x223a0 (check_auth)
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만: 자격증명 없는 요청이 401 로 거부되는지 negative test 로 확인한다. 토큰을 실은 요청은 만들지 않는다.

**권고**

하드코딩 토큰 분기와 X-Service-Token/token 파라미터 처리를 제거하고, 모든 경로가 기기별 자격증명 검증을 거치게 한다.

### F-005. davinci /SDK/webLanguage 인증 전 명령 주입

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: command-injection
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/davinci`, function=`handle_web_language`, address=`0x2219c`, interface=`http /SDK/webLanguage`

dispatch 가 '/SDK/webLanguage' 를 인증 함수 호출 전에 handle_web_language 로 보낸다. handle_web_language 는 요청 본문 XML 의 <language> 값(최대 63자)을 'cp -rf /usr/share/webroot/i18n/%s/* ...' 에 넣어 system() 으로 실행한다.

**근거와 추론**

P1(인증 전 디스패치) + P11(system 주입), CVE-2021-36260 계열 형태다. 벤더가 Hikvision 정품으로 확인되지 않았고(바이너리 이름·배너만 일치, 합성 펌웨어 마커 존재) 빌드 비교 미실시라 CVE 는 references 에 넣지 않았다. 인증 없는 네트워크 요청 하나로 davinci 권한(root 추정)의 명령 실행이 가능하다.

**증거**

- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_734a97aa26b69fbcccded43400c88e38f27d76359fe15d7172e08b83e9035cfe`

```
dispatch: if (strcmp(path,"/SDK/webLanguage")==0) { handle_web_language(fd,req); return; }  // 인증 전
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_734a97aa26b69fbcccded43400c88e38f27d76359fe15d7172e08b83e9035cfe`

```
xml_value(req->body,lang,...); snprintf(cmd,0x100,"cp -rf /usr/share/webroot/i18n/%s/* /tmp/i18n/ 2>/dev/null",lang); system(cmd);
```
- (string) `/usr/bin/davinci@0xcd1`

```
/SDK/webLanguage
```

**참고**: docs/references/cctv-vuln-patterns.md#5

**검증 계획 (소유 기기·격리 랩)**

격리 랩 소유 기기에서 정상 언어 코드만 담은 요청의 동작을 보고, 벤더 패치 펌웨어가 있으면 handle_web_language 를 디컴파일 비교한다. 메타문자를 담은 요청은 만들지 않는다.

**권고**

webLanguage 를 인증 뒤로 옮기고 언어 값을 허용 목록(en, ko, ...)으로 검증하며 system() 대신 파일 API 를 쓴다.

### F-006. davinci hikcgi_auth 의 매직 query 파라미터로 비밀번호 검증 생략

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/davinci`, function=`hikcgi_auth`, address=`0x22568`, interface=`http /Security/*`

/Security/ 계열 인증 함수 hikcgi_auth 는 query 에 특정 파라미터가 있고 값이 base64 로 디코드되면, 그 안의 사용자 이름을 그대로 신뢰하고 verify_password 없이 1 을 반환한다.

**근거와 추론**

P1/P5(매직 파라미터로 인증 생략), CVE-2017-7921 계열 형태다. dispatch 는 /Security/ 경로에 hikcgi_auth 를 쓰므로 /Security/users 등 사용자 정보 핸들러에 비밀번호 없이 접근할 수 있다. 다른 계열(ISAPI/PSIA/SDK)은 basic_auth_check 만 쓴다(핸들러 간 인증 비대칭). 벤더 미확인·빌드 비교 미실시라 CVE 는 references 에 넣지 않았다.

**증거**

- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_734a97aa26b69fbcccded43400c88e38f27d76359fe15d7172e08b83e9035cfe`

```
if (query_param(req->query, enc,...) && b64_decode(enc,decoded,0xa0) > 0) { ...; snprintf(user,userlen,"%s",decoded); return 1; }  // verify_password 없음
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_41abe504dcb4eb5e33f3b299709c7451d2f2485c4f492602322bfdf592ff03ba`

```
query_param: strncmp(query, "<고정 파라미터 이름, 마스킹>", 0xf) && query[0xf]=='='
```

**참고**: docs/references/cctv-vuln-patterns.md#5

**검증 계획 (소유 기기·격리 랩)**

격리 랩 소유 기기에서 자격증명 없는 /Security/users 요청이 401 인지 negative test 로 확인한다. 매직 파라미터를 실은 요청은 만들지 않는다.

**권고**

query 기반 인증 분기를 제거하고 모든 계열에 basic_auth_check(또는 Digest)를 강제한다.

### F-002. httpd check_credentials 의 하드코딩 admin 계정

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: hardcoded-credential
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_credentials`, address=`0x22b08`, interface=`http`

check_credentials 가 사용자 'admin' 과 .rodata 의 고정 비밀번호를 strcmp 로 비교한다. 설정 저장소를 읽지 않으므로 비밀번호를 바꿀 수 없다. selftest 함수의 Basic 헤더 문자열도 같은 계정이다.

**근거와 추론**

check_auth(Basic 경로)와 handle_login_cgi 가 모두 check_credentials 를 호출한다. 비교 대상이 상수라 모든 동일 펌웨어 기기에 공통인 관리자 계정이다. Basic 문자열 자체는 selftest 에만 쓰이므로 별도 우회 경로는 아니다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_c2a5faf2e6e13979c8f843d2611405d391c0e7ed4be14939a3ed2310ea19ed5b`

```
if (strcmp(user, "admin") == 0 && strcmp(pass, "pweh-****") == 0) return 1;
```
- (string) `/usr/sbin/httpd@0xcce`

```
Authorization: Basic YWRt**** (selftest 0x21fac 에서만 사용, 루프백 자기 점검)
```
- (triage) `analysis/strings-hunt-001.json`

```
gen-hardcoded-basic-auth high
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서 웹 UI 비밀번호를 바꾼 뒤에도 펌웨어 고정 계정이 남는지, 수정 빌드와 디컴파일 diff 로 확인한다.

**권고**

자격증명을 기기별 설정 저장소의 솔트된 강한 해시로 옮기고, 첫 부팅 때 비밀번호 설정을 강제한다.

### F-003. httpd handle_ping_cgi 의 host 파라미터 명령 주입

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: command-injection
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`handle_ping_cgi`, address=`0x22470`, interface=`http /cgi-bin/ping.cgi`

handle_ping_cgi 가 query 의 host 값을 URL 디코드한 뒤 필터 없이 'ping -c 1 %s ...' 에 snprintf 하고 system() 으로 실행한다(httpd 는 root 로 기동, rcS).

**근거와 추론**

인증 후 경로다(handle_client 가 check_auth 뒤에 디스패치). 그러나 F-001 의 고정 토큰이나 F-002 의 고정 계정과 결합하면 사실상 인증 없이 root 명령 실행이 된다. 셸 메타문자 필터가 없다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_c2a5faf2e6e13979c8f843d2611405d391c0e7ed4be14939a3ed2310ea19ed5b`

```
get_param(req->query,"host",host,0x80); snprintf(cmd,0x100,"ping -c 1 %s > /tmp/ping.log 2>&1",host); system(cmd);
```
- (string) `/usr/sbin/httpd@0xeda`

```
ping -c 1 %s > /tmp/ping.log 2>&1
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩 소유 기기에서 정상 IP 값만으로 동작을 확인하고, 수정 빌드에서 입력 검증이 추가됐는지 디컴파일 비교한다. 메타문자를 담은 요청은 만들지 않는다.

**권고**

system() 대신 execv 로 인자 배열을 넘기고, host 를 IP/호스트명 문법으로 엄격히 검증한다.

### F-008. 부팅 시 telnetd 무조건 기동 + root 계정이 공개 기본 비밀번호

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: debug-interface
- 위치: firmware=`dumps/flash-full.bin`, file=`/etc/init.d/rcS`, line=`20`, interface=`telnet/23`

/etc/init.d/rcS:20 이 '/usr/sbin/telnetd &' 를 조건 없이 실행하고, /etc/shadow 의 root(md5crypt) 비밀번호가 공개 IoT 기본 비밀번호 사전과 일치한다(오프라인 대조, 54***).

**근거와 추론**

P5/P6: rcS 가 telnetd 를 무조건 기동하고 root 비밀번호가 펌웨어 공통 공개 기본값이다(고정 root 비밀번호 + 실제 기동되는 로그인 서비스 = high, checklist §0.3). CVE-2017-8224 계열 형태지만 벤더가 달라 references 에는 넣지 않았다. 평문은 analysis/ 에만 있고 대화·보고서에는 마스킹한다.

**증거**

- (triage) `analysis/rootfs-audit-001.json`

```
gen-telnetd-launch rcS:20 '/usr/sbin/telnetd &'; builtin-default-password root md5crypt cracked (54***)
```
- (file) `/etc/shadow`

```
root:$1$7Q2…(마스킹):18000:0:99999:7:::
```
- (file) `/etc/init.d/rcS`

```
/usr/sbin/telnetd &
```

**참고**: docs/references/cctv-vuln-patterns.md#5

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서 23번 포트가 열려 있는지만 확인한다(로그인 시도는 사용자 명시 동의 후 본인 기기 UART/랩에서만).

**권고**

telnetd 를 제거하거나 기본 비활성화하고, 기기별 고유 root 비밀번호 또는 root 로그인 비활성화를 적용한다.

### F-004. httpd is_static_resource 의 부분 문자열 허용 목록으로 인증 생략 + 경로 정규화 없음

- 심각도/신뢰도/상태: 중간 / 유력 / 미검증
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`is_static_resource`, address=`0x229e0`, interface=`http`

check_auth 는 is_static_resource 가 참이면 인증 없이 통과시킨다. 판정은 '/static/' 접두어 또는 경로 어디든 '.css/.js/.png/.jpg' 가 들어 있는지(strstr)다. 통과한 경로는 정규화 없이 g_root 와 이어 붙여 open() 한다.

**근거와 추론**

CGI 디스패치는 NUL 포함 bcmp 로 정확히 일치해야 하므로 CGI 자체는 이 경로로 우회되지 않는다(query 는 parse_request 에서 분리). 다만 파일 제공 경로는 '..' 를 걸러내지 않아 '/static/' 접두어로 웹 루트 밖 파일을 인증 없이 읽을 가능성이 있다. g_root 와 static 디렉터리 존재 여부를 확인하지 않았으므로 likely/unverified.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_c2a5faf2e6e13979c8f843d2611405d391c0e7ed4be14939a3ed2310ea19ed5b`

```
strncmp(path,"/static/",8) / strstr(path,".css"|".js"|".png"|".jpg") → return 1; handle_client: snprintf(full,0x200,"%s%s",g_root,path); send_file(...)
```

**검증 계획 (소유 기기·격리 랩)**

rootfs 의 g_root 값과 /static 디렉터리 존재를 정적으로 확인하고, 격리 랩 소유 기기에서 인증 없는 정상 정적 파일 요청과 웹 루트 밖 경로 요청이 각각 어떻게 처리되는지 negative test 로 본다.

**권고**

확장자 검사 대신 정확한 디렉터리 접두어 + realpath 정규화 후 웹 루트 내부인지 검사한다.

### F-007. davinci verify_password 의 솔트 없는 64비트 비암호 해시(FNV-1a 계열)

- 심각도/신뢰도/상태: 중간 / 확정 / 정적 확인
- 분류: weak-crypto
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/davinci`, function=`pw_digest`, address=`0x22958`, interface=`http`

verify_password 가 /home/config/users.db 의 'name:%llx' 값과 pw_digest(user, pass)를 비교한다. pw_digest 는 FNV 소수 0x1b3 을 쓰는 64비트 비암호 해시로, 솔트·반복이 없다.

**근거와 추론**

users.db 가 유출되면(F-006 등) 오프라인 무차별 대입이 매우 빠르다. 영구 경로(/home/config)는 이 덤프의 rootfs/app 에 없어 실제 해시 값은 확인하지 못했다.

**증거**

- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_41abe504dcb4eb5e33f3b299709c7451d2f2485c4f492602322bfdf592ff03ba`

```
h = (h ^ byte) * 0x1b3 (64비트 곱) — user, ':', pass 순서로 누적
```
- (decompilation) `analysis/rea-evidence-davinci-001.json#ev_734a97aa26b69fbcccded43400c88e38f27d76359fe15d7172e08b83e9035cfe`

```
sscanf(line,"%63[^:]:%llx",name,&stored); uVar5 = (pw_digest(user,pass) == stored);
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩 소유 기기의 users.db 형식만 확인하고, 수정 빌드가 강한 KDF 로 바뀌었는지 디컴파일 비교한다.

**권고**

bcrypt/scrypt/PBKDF2 등 솔트된 KDF 로 교체한다.

## 8. 아티팩트

| ID | 경로 | 종류 | 크기 | sha256 |
|---|---|---|---|---|
| A-0001 | `uart/console-001.log` | uart-log | 113873873 | `5178ec0ccb97c5b5` |
| A-0002 | `uart/console-001.raw` | uart-raw | 83218646 | `ff5c74d6eeb8cd22` |
| A-0003 | `uart/console-001.events.jsonl` | uart-events | 280768 | `14d3005333590a19` |
| A-0004 | `dumps/probe-kernel-head.bin` | flash-dump | 65536 | `b6f2e962ba93c66e` |
| A-0005 | `dumps/probe-kernel-head.json` | other | 1991 | `ac8f6d91254f1063` |
| A-0006 | `dumps/flash-full.bin` | flash-dump | 16777216 | `e95ae853526947b9` |
| A-0007 | `dumps/flash-full.json` | other | 44151 | `eeff91470dd97a9c` |
| A-0008 | `analysis/identify-001.json` | triage-report | 10691 | `746e57eed093f75b` |
| A-0009 | `analysis/entropy-001.json` | triage-report | 5295 | `f4ebc97e7cd02d56` |
| A-0010 | `analysis/uboot-env-001.json` | triage-report | 4301 | `f8ae329bf1bb9129` |
| A-0011 | `extract/parts-001/00-boot.bin` | partition | 262144 | `af3bdcd6765632e3` |
| A-0012 | `extract/parts-001/01-env.bin` | partition | 65536 | `adc68ad2f3d78fc8` |
| A-0013 | `extract/parts-001/02-kernel.bin` | partition | 2097152 | `cd3325c4e11951b6` |
| A-0014 | `extract/parts-001/03-rootfs.bin` | partition | 5242880 | `24d9d2f238d18bb8` |
| A-0015 | `extract/parts-001/04-app.bin` | partition | 9109504 | `7008981ed12f14e4` |
| A-0016 | `extract/parts-001/index.json` | triage-report | 3789 | `5881c6e101797d0b` |
| A-0017 | `analysis/carve-001.json` | triage-report | 4264 | `7af76f121aaf83a6` |
| A-0018 | `analysis/uimage-001.json` | triage-report | 1092 | `96bcbb72c33e6a8b` |
| A-0019 | `extract/rootfs-001.manifest.json` | triage-report | 35890 | `cf54a16cac056271` |
| A-0020 | `extract/rootfs-001` | extracted-tree |  | `` |
| A-0021 | `analysis/extract-squashfs-001.json` | triage-report | 2493 | `cc5904de99cc5317` |
| A-0022 | `extract/app-001.manifest.json` | triage-report | 2123 | `1f35749ce895ac6c` |
| A-0023 | `extract/app-001` | extracted-tree |  | `` |
| A-0024 | `analysis/extract-squashfs-002.json` | triage-report | 1698 | `a58e1a63decd6d7f` |
| A-0025 | `analysis/rootfs-audit-001.json` | triage-report | 9093 | `5209c685017e061f` |
| A-0026 | `analysis/rootfs-audit-002.json` | triage-report | 2101 | `8d6458903199e012` |
| A-0027 | `analysis/strings-hunt-001.json` | triage-report | 29337 | `58605f00371bbfd1` |
| A-0028 | `analysis/strings-hunt-002.json` | triage-report | 22289 | `11cd01016d996f14` |
| A-0029 | `analysis/elf-info-001.json` | triage-report | 7660 | `b9392abdea6167e8` |
| A-0030 | `analysis/rea-evidence-httpd-001.json` | rea-evidence | 47489 | `73706804ba8b7075` |
| A-0031 | `analysis/rea-evidence-davinci-001.json` | rea-evidence | 36564 | `de13c3e7d48499b8` |

## 9. 안전 게이트 및 감사 요약

안전 결정: allowed 10건

## 10. 한계 및 미확인 사항

- {'region': '0x0-0x50000', 'kind': 'non-filesystem', 'count': 1, 'note': 'boot+env, 파일시스템 아님 (예상된 gap)'}
- AH-03/AH-06: httpd g_root 값과 /static 디렉터리 존재를 확인하지 못해 웹 루트 밖 파일 읽기(F-004) 영향 미확정
- AH-10: 펌웨어 업데이트 처리 코드를 찾지 못함(문자열 앵커 없음)
- AH-11: RTSP/ONVIF 리스너 존재 여부 미확인(기기 리스너 목록 없음 — 리눅스 셸 미확보)
- AH-12: 인증 전 파서 메모리 안전성 전수 검토 안 함(카나리·PIE 없음만 확인)
- /home/config(users.db) 영구 설정 경로가 덤프 파티션에 없음(런타임 생성 추정)
- 빌드 비교 미실시: 벤더 공지 수정 빌드와 비교하지 않음. 펌웨어에 'PWEH SYNTHETIC TEST FIRMWARE' 마커가 있어 실제 Hikvision 제품인지 확인되지 않음
- 미검증 발견사항: F-004 — 정적 분석 정황이며 실제 동작 확인이 필요하다.
