# 하드웨어 보안 분석 보고서 — 실내형 IP 카메라 (IPC, Dahua 계열 추정) 하드웨어 보안 분석

- 케이스 ID: `20261018-unknown-dahua-ip-ipc`
- 프로필: `generic-ipcam`
- 생성: 2026-10-18T16:25:15.565Z / 보고서 생성: 2026-10-18T16:37:33.081Z
- 도구: pweh 0.1.0

> 이 보고서는 소유자이거나 서면 허가를 받은 기기에 대한 연구·방어 목적의 분석 결과다. 결과를 제3자 시스템 공격에 사용해서는 안 된다.

## 1. 요약

발견사항 총 9건 (치명 4건, 높음 2건, 중간 3건).

- **[치명] F-001 httpd check_auth 의 하드코딩 토큰 비교로 인증 생략** — check_auth 가 요청의 토큰 값을 펌웨어에 고정된 문자열과 비교해 일치하면 자격증명 검사 없이 인증 성공을 반환한다.
- **[치명] F-005 sonia global.login 이 클라이언트가 제공한 루프백 표시를 신뢰해 비밀번호 검사 생략** — rpc_global_login 은 요청 본문의 필드만으로 '로컬 요청' 여부를 판단하고(is_local_request), 로컬이면 verify_password 를 부르지 않고 세션을 발급한다. 실제 소켓 피어 주소(peer_loopback)는 계산되지만 판단에 쓰이지 않는다. Dahua 계열의 알려진 로그인 우회 클래스와 같은 구조다.
- **[치명] F-006 sonia /current_config/ 경로가 인증 없이 설정 파일(계정 해시 포함) 제공** — http_dispatch 가 /current_config/ 접두사 경로를 세션 검사보다 먼저 처리해 /mnt/mtd/Config/ 아래 파일을 그대로 돌려준다. 이 디렉터리에는 verify_password 가 읽는 계정 파일(Account1)이 있다. 경로 탈출('/', '..')은 막지만 디렉터리 안의 파일은 모두 인증 없이 읽힌다.
- **[치명] F-008 root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (/etc/shadow, md5crypt)** — rootfs 의 /etc/shadow 에 있는 root 의 md5crypt 해시가 공개 IoT 기본 비밀번호 사전의 값과 오프라인 대조에서 일치했다. rootfs 는 읽기 전용 squashfs 라 모든 동일 펌웨어 기기에 같은 값이 있다.
- **[높음] F-002 httpd check_credentials 의 하드코딩 관리자 자격증명** — check_credentials 가 사용자 이름과 비밀번호를 바이너리에 고정된 리터럴과 비교한다. 사용자가 바꿀 수 없는 공통 관리자 계정이다. 같은 값이 selftest 의 Basic 헤더에도 들어 있다.

- 콘솔 접근: 포트 `<WORKSPACE>/ttyCAM0` @ 115200 bps, 콘솔 유형 `uboot`, 접근 수준 `uboot`
- 펌웨어 확보: `dumps/flash-full.bin` (16777216 bytes, sha256 `560ae32b73b130eb8b3b6fef8d712b23d6477951f16546834fb1a353af6e878f`), 방법 `uboot-md`, 검증 `crc32-chunks` → True

## 2. 범위와 권한

- 근거: 본인 소유
- 소유자/허가 주체: PWEH 테스트 랩
- 진술: "제가 직접 구매한 제 소유 기기입니다. 소유자 이름은 "PWEH 테스트 랩" 로 기록해 주세요. 서면 허가 문서는 없습니다(소유 기기)."
- 범위: UART 콘솔 확보, 펌웨어 덤프, 정적 분석, 인증 관련 의심 지점 보고
- 기록: 2026-10-18T16:25:15.565Z (agent-relayed, user (relayed by agent))

## 3. 대상 기기

| 항목 | 값 |
|---|---|
| vendor | unknown (Dahua 계열 추정, 미확인) |
| model | 실내형 IP 카메라 (보드 실크 'IPC') |
| soc | hi3516ev300 (U-Boot env soc/board + 버전 태그) |
| flash | W25Q128(B/F)V SPI NOR 16 MiB (sf probe) |
| uboot_version | U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300 |
| arch | armv7 (U-Boot env cpu) |
| dram | 64 MiB |

## 4. 파이프라인 단계

| 단계 | 상태 | 갱신 |
|---|---|---|
| UART 셸/U-Boot 획득 | done | 2026-10-18T16:26:38.622Z |
| 펌웨어 덤프 | done | 2026-10-18T16:28:47.916Z |
| 로직 애널라이저 디코딩 | pending |  |
| 펌웨어 정적 분석 | done | 2026-10-18T16:34:46.916Z |
| CCTV 인증 우회 탐색 | partial | 2026-10-18T16:37:27.706Z |
| 보고서 | done | 2026-10-18T16:37:33.077Z |

### UART 셸/U-Boot 획득 — success

UART 115200 8N1(ttyCAM0): auto-scan score 0.99, U-Boot 2016.11 hi3516ev300 진입(Ctrl-C), printenv 완전, W25Q128 16MiB, safe RAM 0x42000000 확보. 리눅스 로그인은 계정 없음으로 시도 안 함.

- 다음 조치: firmware-dump-via-uart: 세션 console-001(uboot) 재사용, 16 MiB 전체 uboot_dump_start (crc32)
- 산출물: `uart/console-001.log`, `uart/console-001.events.jsonl`

### 펌웨어 덤프 — success

U-Boot md.b 로 16 MiB 전체 덤프. 청크 256개 crc32 일치, 전체 crc32 bcecd46e 일치, kernel 앞 64 KiB 시험 덤프와 교차 확인 일치

- 다음 조치: firmware-static-analysis: dumps/flash-full.bin 분석 (env mtdparts 로 fw_carve 자동 분할)
- 산출물: `dumps/flash-full.bin`, `dumps/flash-full.json`, `dumps/probe-kernel-head.bin`

### 펌웨어 정적 분석 — success

rootfs/app squashfs 추출·감사, httpd·sonia Ghidra 분석. 발견 9건 (critical 4, high 2, medium 3). 합성(PWEH SYNTHETIC) 펌웨어 마커 확인

- 다음 조치: cctv-auth-bypass-hunt: httpd/sonia 인증 전 디스패치 표와 P1~P12 점검
- 산출물: `extract/rootfs-001`, `extract/app-001`, `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-sonia-001.json`

### CCTV 인증 우회 탐색 — partial

dahua-like (sonia+httpd). AH-01~AH-12 판정: match 7, no-match 1, not-applicable 1, inconclusive 3. 발견 9건 (critical 4). 합성 펌웨어, 빌드 비교 미실시.

- 다음 조치: 격리 랩에서 negative test (사용자 동의 후): 무자격 요청 401/403, 포트 23 리슨 여부; AH-06: 웹 루트 구성 확인 후 재판정
- 산출물: `analysis/rootfs-audit-001.json`, `analysis/strings-hunt-001.json`, `analysis/elf-info-001.json`, `analysis/rea-evidence-httpd-001.json`, `analysis/rea-evidence-sonia-001.json`

## 5. 콘솔/부트로더 정보

- U-Boot 버전: U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300
- 프롬프트: `hisilicon # `
- bootargs: `mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- mtdparts: `mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)`
- 플래시: {'type': 'spi-nor', 'model': 'W25Q128(B/F)V', 'size_bytes': 16777216}

## 6. 펌웨어 정적 분석 개요

- 대상 펌웨어: `dumps/flash-full.bin` (sha256 `560ae32b73b130eb8b3b6fef8d712b23d6477951f16546834fb1a353af6e878f`)
- 추출: 도구 `fwtriage`, 상태 `complete`, 출력 `extract/rootfs-001`
- rootfs: `extract/rootfs-001` (squashfs 4.0 xz, arm)
- 웹 서버/서비스: /usr/bin/sonia, /usr/sbin/httpd

| 관심 바이너리 | 이유 |
|---|---|
| `/usr/sbin/httpd` | 네트워크 대면 웹 서버, system/execve 임포트, 카나리 없음 (elf-info score 28.5) |
| `/usr/bin/sonia` | Dahua 계열 메인 서비스(RPC2 로그인, /current_config/), score 15 |
| `/var/www/cgi-bin/status.cgi` | CGI 프로그램 |
| `/usr/sbin/telnetd` | rcS 가 무조건 기동하는 서비스 |

## 7. 발견사항

| ID | 심각도 | 신뢰도 | 상태 | 분류 | 제목 | 위치 |
|---|---|---|---|---|---|---|
| F-001 | 치명 | 확정 | 정적 확인 | backdoor | httpd check_auth 의 하드코딩 토큰 비교로 인증 생략 | /usr/sbin/httpd :: check_auth |
| F-005 | 치명 | 확정 | 정적 확인 | auth-bypass | sonia global.login 이 클라이언트가 제공한 루프백 표시를 신뢰해 비밀번호 검사 생략 | /usr/bin/sonia :: rpc_global_login / is_local_request |
| F-006 | 치명 | 확정 | 정적 확인 | info-leak | sonia /current_config/ 경로가 인증 없이 설정 파일(계정 해시 포함) 제공 | /usr/bin/sonia :: http_dispatch / serve_config_file |
| F-008 | 치명 | 확정 | 정적 확인 | hardcoded-credential | root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (/etc/shadow, md5crypt) | /etc/shadow |
| F-002 | 높음 | 확정 | 정적 확인 | hardcoded-credential | httpd check_credentials 의 하드코딩 관리자 자격증명 | /usr/sbin/httpd :: check_credentials |
| F-003 | 높음 | 확정 | 정적 확인 | command-injection | httpd ping.cgi 의 host 파라미터가 필터 없이 system() 으로 전달 | /usr/sbin/httpd :: handle_ping_cgi |
| F-004 | 중간 | 유력 | 정적 확인 | auth-bypass | httpd is_static_resource 의 부분 문자열 판정으로 인증 생략 범위 과대 | /usr/sbin/httpd :: is_static_resource |
| F-007 | 중간 | 확정 | 정적 확인 | weak-crypto | sonia verify_password 가 솔트 없는 64비트 FNV-1a 해시로 비밀번호 검증 | /usr/bin/sonia :: pw_digest / verify_password |
| F-009 | 중간 | 확정 | 정적 확인 | debug-interface | rcS 가 부팅 때 telnetd 를 무조건 기동 | /etc/init.d/rcS |

### F-001. httpd check_auth 의 하드코딩 토큰 비교로 인증 생략

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: backdoor
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_auth`, address=`0x2235c`, interface=`http`

check_auth 가 요청의 토큰 값을 펌웨어에 고정된 문자열과 비교해 일치하면 자격증명 검사 없이 인증 성공을 반환한다.

**근거와 추론**

handle_client 는 모든 요청에서 check_auth 를 먼저 호출하고, check_auth 는 토큰이 일치하면 Basic 인증 검사 전에 성공을 반환한다. 같은 펌웨어를 쓰는 모든 기기에 같은 값이 있다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_d81e375ef2b6f79e3d1f82d19357ea2968cf1cc7912e1d0faa56425de160a61a`

```
if (req->token[0] != 0 && strcmp(req->token, "<고정 문자열, 마스킹>") == 0) return 1;
```
- (string) `/usr/sbin/httpd@0xe8c`

```
고정 토큰 문자열 (마스킹), VA 0x10e7d
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 자격증명 없는 요청이 401 로 거부되는지 확인하는 negative test. 수정 빌드가 나오면 check_auth 디컴파일 diff.

**권고**

하드코딩 토큰 분기를 제거하고 모든 경로가 check_credentials 를 거치게 한다.

### F-005. sonia global.login 이 클라이언트가 제공한 루프백 표시를 신뢰해 비밀번호 검사 생략

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/sonia`, function=`rpc_global_login / is_local_request`, address=`0x22400`, interface=`http`

rpc_global_login 은 요청 본문의 필드만으로 '로컬 요청' 여부를 판단하고(is_local_request), 로컬이면 verify_password 를 부르지 않고 세션을 발급한다. 실제 소켓 피어 주소(peer_loopback)는 계산되지만 판단에 쓰이지 않는다. Dahua 계열의 알려진 로그인 우회 클래스와 같은 구조다.

**근거와 추론**

/RPC2_Login 은 session_valid 검사 전에 처리되고, 로컬 판정에 쓰는 값은 모두 원격 클라이언트가 정하는 본문 필드다. send_login_result 는 ok 일 때 유효한 SessionID 를 돌려주고, 이 세션은 /RPC2 인증에 그대로 통과한다.

**증거**

- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_5269ae69e69ad990857c22a06ecc813244a9445ae0c628e1f7c5a6edbbce2ff9`

```
iVar1 = is_local_request(&l); ok = 1; if (iVar1 == 0) ok = verify_password(user, pass); send_login_result(fd, ok, user);
```
- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_5269ae69e69ad990857c22a06ecc813244a9445ae0c628e1f7c5a6edbbce2ff9`

```
is_local_request: 본문의 loginType/ipAddr 문자열만 비교. peer_is_loopback 인자는 로그 출력에만 사용
```

**참고**: CVE-2021-33044 (유사 클래스, Dahua)

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 잘못된 비밀번호의 일반 로그인이 거부되는지 negative test. 벤더 패치 버전이 있으면 is_local_request 가 소켓 피어 주소를 쓰도록 바뀌었는지 디컴파일 diff.

**권고**

로컬 신뢰 판단은 getpeername 결과(peer_loopback)로만 하고, 원격 요청에는 항상 비밀번호를 검증한다. 루프백 로그인 모드 자체를 없애는 것이 좋다.

### F-006. sonia /current_config/ 경로가 인증 없이 설정 파일(계정 해시 포함) 제공

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: info-leak
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/sonia`, function=`http_dispatch / serve_config_file`, address=`0x21e0c`, interface=`http`

http_dispatch 가 /current_config/ 접두사 경로를 세션 검사보다 먼저 처리해 /mnt/mtd/Config/ 아래 파일을 그대로 돌려준다. 이 디렉터리에는 verify_password 가 읽는 계정 파일(Account1)이 있다. 경로 탈출('/', '..')은 막지만 디렉터리 안의 파일은 모두 인증 없이 읽힌다.

**근거와 추론**

세션 검사는 /RPC2_Login 이 아닌 경로에만 적용되는데, /current_config/ 분기가 그보다 앞에 있다. 계정 파일의 해시는 솔트 없는 빠른 해시(F-007)라 노출 시 오프라인 추측에 취약하다. Dahua 계열의 알려진 설정 노출 클래스와 같다. 런타임 계정 파일은 쓰기 가능한 파티션에 생기므로 덤프에는 없다.

**증거**

- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_5269ae69e69ad990857c22a06ecc813244a9445ae0c628e1f7c5a6edbbce2ff9`

```
if (strncmp(path,"/current_config/",0x10)==0) { serve_config_file(fd, path+0x10); return; }  // session_valid 보다 앞
```
- (string) `/usr/bin/sonia@0xc09`

```
/current_config/ (strings-hunt dh-current-config)
```
- (triage) `analysis/strings-hunt-001.json`

```
/mnt/mtd/Config/Account1 @0xbd2
```

**참고**: CVE-2017-7921 / Dahua 설정 노출 유사 클래스

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 수정 빌드에서 이 경로가 세션 검사 뒤로 옮겨졌는지 디컴파일 diff. 기기 자체에서는 자격증명 없는 요청이 401 을 받는지만 보고, 응답 내용은 케이스 밖으로 복사하지 않는다.

**권고**

/current_config/ 엔드포인트를 제거하거나 session_valid 뒤로 옮기고, 계정 파일은 웹으로 제공하지 않는다.

### F-008. root 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (/etc/shadow, md5crypt)

- 심각도/신뢰도/상태: 치명 / 확정 / 정적 확인
- 분류: hardcoded-credential
- 위치: firmware=`dumps/flash-full.bin`, file=`/etc/shadow`, line=`1`, interface=`uart/telnet`

rootfs 의 /etc/shadow 에 있는 root 의 md5crypt 해시가 공개 IoT 기본 비밀번호 사전의 값과 오프라인 대조에서 일치했다. rootfs 는 읽기 전용 squashfs 라 모든 동일 펌웨어 기기에 같은 값이 있다.

**근거와 추론**

해시가 읽기 전용 rootfs 에 고정돼 있고, F-009 의 telnetd 와 UART 콘솔 로그인에 쓰이는 계정이다. 평문은 analysis/ 에만 남기고 마스킹했다.

**증거**

- (triage) `analysis/rootfs-audit-001.json`

```
builtin-default-password: root md5crypt cracked (1***)
```
- (file) `extract/rootfs-001/etc/shadow`

```
root:$1$1Qd…:18000:0:99999:7::: (해시 일부)
```

**검증 계획 (소유 기기·격리 랩)**

사용자가 명시적으로 동의하면 자기 기기의 UART 콘솔에서만 확인한다. 네트워크 로그인이나 다른 기기에는 쓰지 않는다.

**권고**

기기별 고유 비밀번호를 쓰고, root 로그인을 끈다.

### F-002. httpd check_credentials 의 하드코딩 관리자 자격증명

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: hardcoded-credential
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`check_credentials`, address=`0x22b08`, interface=`http`

check_credentials 가 사용자 이름과 비밀번호를 바이너리에 고정된 리터럴과 비교한다. 사용자가 바꿀 수 없는 공통 관리자 계정이다. 같은 값이 selftest 의 Basic 헤더에도 들어 있다.

**근거와 추론**

자격증명 저장소를 쓰지 않고 리터럴만 비교하므로 비밀번호를 바꿀 방법이 없다. Basic 헤더 문자열은 selftest(루프백 자가 점검)에서만 참조되지만 같은 자격증명을 담고 있다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_d81e375ef2b6f79e3d1f82d19357ea2968cf1cc7912e1d0faa56425de160a61a`

```
strcmp(user, "admin") == 0 && strcmp(pass, "<마스킹>") == 0 -> return 1
```
- (string) `/usr/sbin/httpd@0xcce`

```
Authorization: Basic <마스킹> (selftest 전용, ev_244a300a...)
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 웹 UI 에서 비밀번호를 바꾼 뒤에도 펌웨어 고정값이 유효한지 확인한다. 고정값으로 로그인을 시도하지는 않는다. 수정 빌드와 디컴파일 diff 를 비교한다.

**권고**

자격증명을 기기별로 설정 가능한 저장소(솔트 해시)로 옮기고, 첫 부팅 때 비밀번호 변경을 강제한다.

### F-003. httpd ping.cgi 의 host 파라미터가 필터 없이 system() 으로 전달

- 심각도/신뢰도/상태: 높음 / 확정 / 정적 확인
- 분류: command-injection
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`handle_ping_cgi`, address=`0x22470`, interface=`http`

handle_ping_cgi 가 쿼리의 host 값을 셸 명령 템플릿에 snprintf 로 끼워 넣고 문자 검증 없이 system() 을 호출한다. 이 핸들러는 인증 뒤에 있지만, F-001 처럼 인증을 건너뛰는 경로와 결합되면 위험이 커진다.

**근거와 추론**

get_param 은 URL 디코딩만 하고 셸 메타문자를 거르지 않는다. 그 값이 그대로 셸 명령 문자열이 된다. 디스패치 순서상 check_auth 를 통과해야 이 핸들러에 도달한다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_d81e375ef2b6f79e3d1f82d19357ea2968cf1cc7912e1d0faa56425de160a61a`

```
get_param(query,"host",host,0x80); snprintf(cmd,0x100,"ping -c 1 %s > /tmp/ping.log 2>&1",host); system(cmd);
```
- (rea-evidence) `analysis/rea-evidence-httpd-001.json#ev_d87b64bd1282dea92c2c47dc15725eb18a19f7b29f4c233bd34dfd5517ffa687`

```
trace_call_path handle_client -> handle_ping_cgi -> system: reached
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 정상적인 IP 값이 동작하는지 확인하고, 수정 빌드에서 입력 검증이 들어갔는지 디컴파일로 비교한다. 주입 페이로드는 보내지 않는다.

**권고**

host 를 IP/호스트명 허용 목록으로 검증하고, system() 대신 인자 배열로 execv 계열을 쓴다.

### F-004. httpd is_static_resource 의 부분 문자열 판정으로 인증 생략 범위 과대

- 심각도/신뢰도/상태: 중간 / 유력 / 정적 확인
- 분류: auth-bypass
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/sbin/httpd`, function=`is_static_resource`, address=`0x229e0`, interface=`http`

check_auth 는 경로에 정적 파일 확장자 부분 문자열(.css/.js/.png/.jpg)이 어디든 들어 있거나 /static/ 으로 시작하면 인증 없이 통과시킨다. 파일 제공 경로는 웹 루트와 요청 경로를 정규화 없이 이어 붙인다.

**근거와 추론**

CGI 핸들러는 정확한 경로 비교(bcmp, NUL 포함)로 고르고 parse_request 가 쿼리를 떼어 내므로, 이 우회는 CGI 에는 닿지 않는 것으로 보인다. 다만 일반 파일 제공은 인증 없이 이루어지고 '..' 를 거르지 않는다. 웹 루트 밖 파일이 노출되는지는 디렉터리 구성에 달려 있어 likely 로 둔다.

**증거**

- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_d81e375ef2b6f79e3d1f82d19357ea2968cf1cc7912e1d0faa56425de160a61a`

```
strncmp(path,"/static/",8) / strstr(path,".css"|".js"|".png"|".jpg") -> return 1
```
- (decompilation) `analysis/rea-evidence-httpd-001.json#ev_d81e375ef2b6f79e3d1f82d19357ea2968cf1cc7912e1d0faa56425de160a61a`

```
handle_client: snprintf(full,0x200,"%s%s",g_root,...) -> send_file (경로 정규화 없음)
```

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서만 진행: 정적 확장자가 아닌 보호 페이지가 자격증명 없이 401 로 거부되는지 negative test. 웹 루트 디렉터리 구성은 rootfs 에서 확인한다.

**권고**

확장자는 접미사로만 비교하고, 경로를 정규화(realpath)한 뒤 웹 루트 안인지 검사한다. 인증 면제는 명시적인 목록으로만 둔다.

### F-007. sonia verify_password 가 솔트 없는 64비트 FNV-1a 해시로 비밀번호 검증

- 심각도/신뢰도/상태: 중간 / 확정 / 정적 확인
- 분류: weak-crypto
- 위치: firmware=`dumps/flash-full.bin`, file=`/usr/bin/sonia`, function=`pw_digest / verify_password`, address=`0x22b18`, interface=`http`

pw_digest 는 user, ':' , pass 를 이어 FNV-1a 64비트(비암호 해시, 솔트·반복 없음)로 계산하고 Account1 의 저장값과 비교한다.

**근거와 추론**

FNV 는 빠른 비암호 해시이고 솔트가 사용자 이름뿐이라, 저장값이 노출되면(F-006) 오프라인 추측이 쉽다.

**증거**

- (decompilation) `analysis/rea-evidence-sonia-001.json#ev_836b69250f9fe6d5d5238183f29d3fc1771fe60f2eac530533bfe8f3d9e0733c`

```
초깃값 0x14650fb0:739d0383 → FNV-1a 오프셋(0xcbf29ce484222325 에 첫 바이트 연산 포함), 곱 0x1b3(+<<40) = FNV 소수 0x100000001b3
```

**검증 계획 (소유 기기·격리 랩)**

오프라인 검증만 한다: 사용자가 알고 있는 자기 기기 비밀번호로 만든 값이 Account1 형식과 맞는지 비교한다.

**권고**

bcrypt/scrypt/PBKDF2 처럼 느리고 솔트를 쓰는 KDF 로 바꾼다.

### F-009. rcS 가 부팅 때 telnetd 를 무조건 기동

- 심각도/신뢰도/상태: 중간 / 확정 / 정적 확인
- 분류: debug-interface
- 위치: firmware=`dumps/flash-full.bin`, file=`/etc/init.d/rcS`, line=`20`, interface=`telnet`

/etc/init.d/rcS 20행이 설정 조건 없이 /usr/sbin/telnetd 를 백그라운드로 실행한다. F-008 의 root 계정과 함께 원격 셸 접근 면을 만든다.

**근거와 추론**

읽기 전용 rootfs 의 부팅 스크립트라 사용자가 끌 방법이 없다. 실제 리스닝 여부는 아직 기기에서 보지 않았다.

**증거**

- (triage) `analysis/rootfs-audit-001.json`

```
/usr/sbin/telnetd &
```
- (file) `extract/rootfs-001/etc/init.d/rcS`

```
line 20: /usr/sbin/telnetd &
```

**참고**: CVE-2017-8224, CVE-2020-24218

**검증 계획 (소유 기기·격리 랩)**

격리 랩의 소유 기기에서 포트 23 이 열려 있는지만 확인한다(로그인 시도 없음).

**권고**

telnetd 를 제거하거나 기본 비활성화하고, 필요하면 키 기반 SSH 로 대체한다.

## 8. 아티팩트

| ID | 경로 | 종류 | 크기 | sha256 |
|---|---|---|---|---|
| A-0001 | `uart/console-001.log` | uart-log | 113873742 | `b4d08c4c4fd5c783` |
| A-0002 | `uart/console-001.raw` | uart-raw | 83218646 | `1209bb33e86af844` |
| A-0003 | `uart/console-001.events.jsonl` | uart-events | 280770 | `9221fccd87a335ad` |
| A-0004 | `dumps/probe-kernel-head.bin` | flash-dump | 65536 | `6e127a00ed8f926a` |
| A-0005 | `dumps/probe-kernel-head.json` | other | 1991 | `a5f26672e1a49cc6` |
| A-0006 | `dumps/flash-full.bin` | flash-dump | 16777216 | `560ae32b73b130eb` |
| A-0007 | `dumps/flash-full.json` | other | 44151 | `b0388dbb34c4684c` |
| A-0008 | `analysis/identify-001.json` | triage-report | 8740 | `4a942d1b14b24c13` |
| A-0009 | `analysis/entropy-001.json` | triage-report | 5295 | `8903644fca4b5ad2` |
| A-0010 | `analysis/uboot-env-001.json` | triage-report | 4297 | `528f87e3ff52edb0` |
| A-0011 | `extract/parts-001/00-boot.bin` | partition | 262144 | `81f8e28f7d1df782` |
| A-0012 | `extract/parts-001/01-env.bin` | partition | 65536 | `adc68ad2f3d78fc8` |
| A-0013 | `extract/parts-001/02-kernel.bin` | partition | 2097152 | `aa75eb42a9e5edf4` |
| A-0014 | `extract/parts-001/03-rootfs.bin` | partition | 5242880 | `aab01785c9480560` |
| A-0015 | `extract/parts-001/04-app.bin` | partition | 9109504 | `e738227fea793a46` |
| A-0016 | `extract/parts-001/index.json` | triage-report | 3789 | `9153ae1dc7b39550` |
| A-0017 | `analysis/carve-001.json` | triage-report | 4260 | `9cf3f2abb0040f6f` |
| A-0018 | `extract/rootfs-001.manifest.json` | triage-report | 35164 | `a04ae5e0d0cf9c8e` |
| A-0019 | `extract/rootfs-001` | extracted-tree |  | `` |
| A-0020 | `analysis/extract-squashfs-001.json` | triage-report | 2481 | `300af2553b24921c` |
| A-0021 | `extract/app-001.manifest.json` | triage-report | 2123 | `09c59fd66d0e50dd` |
| A-0022 | `extract/app-001` | extracted-tree |  | `` |
| A-0023 | `analysis/extract-squashfs-002.json` | triage-report | 1694 | `28974d4c878803a5` |
| A-0024 | `analysis/uimage-001.json` | triage-report | 1088 | `68f53eb644ef1a1f` |
| A-0025 | `analysis/rootfs-audit-001.json` | triage-report | 9100 | `690d6a5fc1653478` |
| A-0026 | `analysis/rootfs-audit-002.json` | triage-report | 2097 | `a7da34b03895a3b9` |
| A-0027 | `analysis/strings-hunt-001.json` | triage-report | 31567 | `9ec49cb2e1f7874d` |
| A-0028 | `analysis/strings-hunt-002.json` | triage-report | 22285 | `59250574c99d14d0` |
| A-0029 | `analysis/elf-info-001.json` | triage-report | 7421 | `3d72d2506dae9ca0` |
| A-0030 | `analysis/rea-evidence-httpd-001.json` | rea-evidence | 62707 | `eabf81ae38facdef` |
| A-0031 | `analysis/rea-evidence-sonia-001.json` | rea-evidence | 38533 | `302bfd7c2d9b1272` |

## 9. 안전 게이트 및 감사 요약

안전 결정: allowed 10건

## 10. 한계 및 미확인 사항

- {'region': '0x0-0x50040', 'kind': 'non-filesystem', 'count': 1, 'note': 'boot+env 블롭과 uImage 헤더, 파일시스템 아님 (예상된 gap)'}
- AH-06: httpd 파일 제공의 snprintf 두 번째 인자를 Ghidra 가 복원하지 못했고, 웹 루트(g_root) 값·디렉터리 구성을 확인하지 않아 경로 순회 여부 미확정
- AH-10: 업데이트 처리 코드가 rootfs/app 에 없음. 업데이트 경로가 없는지 다른 곳에 있는지 미확인
- AH-12: 카나리 없는 정적 바이너리. 파싱 함수 일부만 검토했고 전수 검토는 하지 않음
- /var/www/cgi-bin/status.cgi 와 telnetd 바이너리는 REA 로 보지 않음 (httpd 는 status.cgi 를 내장 핸들러로 처리)
- 빌드 비교 미실시: 펌웨어가 'PWEH SYNTHETIC TEST FIRMWARE' 로 표시된 합성 이미지라 벤더 공지와 비교할 수 없음
- 런타임 계정 파일(/mnt/mtd/Config/Account1)은 덤프에 없음: 쓰기 가능한 설정 파티션이 따로 있거나 런타임에 생성되는 것으로 보임
