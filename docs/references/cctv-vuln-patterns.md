# CCTV · IP 카메라 · DVR/NVR 인증 우회 / 백도어 패턴 레퍼런스 (정적 분석용)

- 문서 경로: `docs/references/cctv-vuln-patterns.md`
- 짝 파일(기계 판독용 휴리스틱): `docs/references/cctv-hunt-patterns.yaml`
- 마지막 검증일: 2026-10-18
  - CVE 설명, CWE, CVSS: CVE.org 레코드 API(`https://cveawg.mitre.org/api/cve/<ID>`)와 NVD API 2.0(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<ID>`)으로 대조했다.
  - KEV 등재 여부: CISA KEV JSON feed(`catalogVersion` `2026.10.16`)로 확인했다.
  - 교차 검증(2026-10-18): 인용 문자열, CVE 사실, 배너 형식, 해시-평문 쌍을 1차 출처(원문 재다운로드, crypt(3) 재계산)로 다시 대조했고, 정정 사항은 해당 항목에 바로 반영했다.
- NVD 상세 페이지 URL 규칙: `https://nvd.nist.gov/vuln/detail/<CVE-ID>`. 본문의 모든 CVE는 이 규칙의 URL로 열람할 수 있다.

---

## 0. 용도, 범위, 표기 규칙

### 0.1 용도

이 문서의 독자는 두 부류다.

1. `fwtriage-mcp`의 휴리스틱, 파서, mock-device 시뮬레이터를 구현하는 엔지니어
2. `cctv-auth-bypass-hunt`, `firmware-static-analysis` 같은 에이전트 Skill 작성자

이 문서는 공개된 IP 카메라·DVR/NVR 취약점을 근본 원인 패턴으로 분해한다. 그리고 운영자가 소유하거나 서면 허가를 받은 장비의 펌웨어를 정적으로 리뷰할 때 무엇을 찾아야 하는지 정리한다.

### 0.2 범위 밖 (의도적으로 넣지 않은 것)

- exploit payload, 요청 본문, 매직 파라미터가 포함된 완성 URL, 쿠키 값, PoC 실행 절차
- 제3자 시스템을 대상으로 한 단계별 공격 방법

펌웨어 쪽 지표(문자열, 핸들러 이름, 비교 상수, 키 상수, 경로, 포트)만 적는다. 하드코딩 비밀번호·키 상수는 정적 탐지 시그니처로 쓰이므로 출처와 함께 기재한다.

### 0.3 표기 규칙

| 표기 | 의미 |
|---|---|
| `(미확인)` | 1차 출처에서 정확한 문자열이나 형식을 직접 확인하지 못했다. 최선의 추정 형태이므로 구현 시 실기기나 실펌웨어로 재확인해야 한다. |
| `(커뮤니티)` | 포럼 등 비공식 출처다. 해당 페이지는 자동 수집이 차단되어 검색 요약으로만 확인했다. |
| `(추정)` | 공개 PoC나 문서의 동작에서 추론한 내용이다. 원 연구자가 근본 원인을 공개하지 않은 경우가 해당한다. |
| `CVE 미확인` | 공개 write-up은 있지만 검증된 CVE 번호가 없다. 임의로 CVE를 붙이지 않았다. |

- CVSS는 NVD Primary 점수에 버전을 붙여 표기한다(예: `9.8 (v3.1)`). 벤더나 ICS-CERT 점수가 다르면 따로 적는다.
- CWE는 CVE 레코드(CNA)가 CWE 번호를 준 경우 그 값을 적었다. NVD Primary CWE가 다른 항목은 다음과 같다: CVE-2017-7923(NVD CWE-200), CVE-2017-7925(NVD CWE-522), CVE-2017-7927(NVD CWE-798), CVE-2018-17917(NVD CWE-200), CVE-2018-17919(NVD CWE-798), CVE-2024-8956(NVD CWE-287), CVE-2024-7339(CNA CWE-200, NVD `NVD-CWE-noinfo`), CVE-2017-3223(CNA CWE-121, NVD CWE-119). CVE-2019-3948은 CNA가 `CWE 285`, NVD가 CWE-306이며 이 문서는 NVD 값을 적었다.
- 인용 원문(영문)은 코드 블록이나 인라인 코드로 남긴다.

---

## 1. 과제 질의에 대한 정정 사항 (먼저 읽을 것)

| 질의된 가정 | 1차 출처로 확인한 결과 |
|---|---|
| CVE-2020-24218/24219가 Vladislav Yarmak의 2020년 "HiSilicon" 백도어인가? | **아니다.** CVE-2020-24214~24219는 Alexei Kojenov가 보고한 hi3520d 기반 IPTV/H.264/H.265 **비디오 인코더**(URayTech 등) 취약점이다. CERT/CC VU#896979는 HiSilicon을 `Not Affected`로 분류한다. Yarmak의 TCP 9530 백도어는 CVE-2020-22253(포트 9530)과 CVE-2021-41506(`macGuarder`/`dvrHelper` 정적 root 자격증명)으로 추적된다. Yarmak 본인도 2020-02-05 업데이트에서 이를 HiSilicon이 아닌 **Xiongmai 소프트웨어** 문제로 정정했다. |
| CVE-2017-16725와 CVE-2018-10088은 XiongMai 하드코딩 telnet/root 자격증명인가? | **아니다.** 둘 다 **버퍼 오버플로**다. CVE-2017-16725는 NetSurveillance Web 인터페이스, CVE-2018-10088은 `uc-httpd 1.0.0`에 있다. 하드코딩 root 자격증명에 해당하는 검증된 CVE는 CVE-2021-41506이다. tothi가 공개한 root 해시 `absxcfbgXtb3o`와 Sofia 만능 비밀번호 `I0TO5Wv9`에는 검증된 CVE가 없다(`CVE 미확인`). |
| CVE-2013-6117(DVRIP 37777)은 확인 가능한가? | **확인됨.** Dahua DVR 2.608.0000.0 / 2.608.GV00.0, TCP 37777. |
| CVE-2018-17915 / CVE-2018-17917 | SEC Consult 권고(SA-20181009-0)는 17915를 "Predictable XMEye Cloud IDs", 17917을 "unencrypted communication"으로 표기한다. CVE 레코드, NVD, ICSA-18-282-06은 반대로 **17915 = 암호화 누락(CWE-311)**, **17917 = MAC 기반 Cloud ID 예측(CWE-341)**으로 기록한다. 이 문서는 **CVE/NVD 매핑을 따른다.** |

---

## 2. 빠른 참조 표

"정적 앵커"는 펌웨어 안에서 grep이나 xref의 출발점으로 쓸 문자열이다. 대응하는 YAML 휴리스틱 id를 괄호에 적었다.

### 2.1 Hikvision

| CVE | 클래스 (CWE) | 위치 | 정적 앵커 → YAML id | NVD | KEV |
|---|---|---|---|---|---|
| CVE-2017-7921 | 인증 우회, HikCGI `auth` 파라미터 (CWE-287) | 메인 앱/웹 바이너리의 HikCGI 핸들러 | `/Security/users`, `/System/configurationFile`, `/onvif-http/snapshot` → `hik-hikcgi-endpoints` | 9.8 (v3.1) | 2026-03-05 |
| CVE-2017-7923 | 설정 파일 내 비밀번호 (CWE-260) | 설정 백업 export | `configurationFile`, 정적 AES 키 → `hik-configurationfile`, `hik-config-aes-key-*` | 8.8 (v3.0) | – |
| CVE-2021-36260 | 웹 서버 명령 주입 (CWE-78) | 웹 서버의 `/SDK/webLanguage` 처리 | `webLanguage` → `hik-sdk-weblanguage` | 9.8 (v3.1) | 2022-01-10 |
| CVE-2013-4975 | 저권한 사용자의 admin 비밀번호 획득 (CWE-269) | `/PSIA/System/ConfigurationData` | → `hik-psia-configurationdata` | 8.8 (v3.1) | – |
| CVE-2013-4976 | 하드코딩 anonymous 자격증명 (CWE-287) | 웹 UI `login.js` | `anonymous:` + `\177`×6 → `hik-anonymous-hardcoded` | 9.8 (v3.1) | – |
| CVE-2013-4977 / CVE-2014-4880 | RTSP 헤더 오버플로(인증 전) | RTSP 핸들러(`Range`, `Authorization`) | `fn-unsafe-copy` | 10.0 (v2) / 7.5 (v2) | – |

### 2.2 Dahua (OEM: Amcrest 등)

| CVE | 클래스 (CWE) | 위치 | 정적 앵커 → YAML id | NVD | KEV |
|---|---|---|---|---|---|
| CVE-2021-33044 | 로그인 시 신원 인증 우회, `NetKeyboard` (CWE-287) | `sonia`의 `global.login` (DHIP/HTTP) | `NetKeyboard`, `clientType` → `dh-login-netkeyboard`, `dh-login-fields` | 9.8 (v3.1) | 2024-08-21 |
| CVE-2021-33045 | 로그인 시 신원 인증 우회, `Loopback` (CWE-287) | `sonia`의 `global.login` (DHIP) | `Loopback`, `Local`, `ipAddr` → `dh-login-loopback-local` | 9.8 (v3.1) | 2024-08-21 |
| CVE-2017-7925 | 설정 파일 내 비밀번호 (CWE-260) | `/current_config/` ↔ `/mnt/mtd/Config/` | → `dh-current-config`, `gen-mtd-config-accounts` | 9.8 (v3.0) | – |
| CVE-2017-7927 | 비밀번호 대신 해시로 인증 (CWE-836) | 로그인 루틴 | (코드 패턴) `fn-auth-literal-compare` | 7.3 (v3.0) | – |
| CVE-2022-30563 | ONVIF 로그인 재전송 | ONVIF WS-UsernameToken 처리 | `PasswordDigest`, `wsse:Nonce`, `wsu:Created`, `UsernameToken` → `gen-onvif-wsse-anchors` (실펌웨어 존재 여부 `(미확인)`) | 7.4 (v3.1) | – |
| CVE-2013-6117 | DVRIP 명령 무인가 (CWE-287) | TCP 37777 서비스 | (바이너리 프로토콜) | 7.5 (v2) | – |
| CVE-2013-3612~3615 | 하드코딩 root/백도어 계정, 약한 해시 등 | DVR | – | v2 7.8~10.0 | – |
| CVE-2019-3948 | `/videotalk` 인증 누락 (CWE-306) | HTTP 핸들러 | `/videotalk` → `dh-videotalk` | 7.5 (v3.0) | – |

### 2.3 XiongMai (Sofia / XMeye, 다수 OEM)

| CVE | 클래스 | 위치 | 정적 앵커 → YAML id | NVD | KEV |
|---|---|---|---|---|---|
| CVE-2020-22253 | 9530 포트로 telnet 개방(무인증) | `macGuarder`/`dvrHelper` | `OpenTelnet:OpenOnce` → `xm-opentelnet-*` | 9.8 (v3.1) | – |
| CVE-2021-41506 | `macGuarder`/`dvrHelper` 백도어, 정적 root 자격증명 (CWE-287) | 동상 | `TelnetOEMPasswd`, `2wj9fsa2` → `xm-telnetoempasswd`, `xm-default-psk` | 9.8 (v3.1) | – |
| CVE-2017-7577 | `uc-httpd` 디렉터리 순회 (CWE-22) | Sofia 내장 HTTP | 배너 `uc-httpd 1.0.0` | 9.8 (v3.0) | – |
| CVE-2017-16725 | NetSurveillance Web 스택 오버플로 | Sofia HTTP | `fn-unsafe-copy` | 9.8 (v3.0) | – |
| CVE-2018-10088 | `uc-httpd` 로그인 버퍼 오버플로 | Sofia HTTP | `fn-unsafe-copy` | 9.8 (v3.0) | – |
| CVE-2018-17915/17917/17919 | XMeye 암호화 누락 / Cloud ID 예측 / 숨은 계정 `default` | XMeye P2P | `tluafed` → `xm-default-user-tluafed` | 9.8 / 5.3 / 6.5 | – |
| CVE-2022-45045 | 34567 업그레이드 경로 명령 실행(인증 필요) | Sofia 34567 서비스 | `UpgradeCommand`, `SkipCheck` → `xm-upgrade-*` | 8.8 (v3.1) | – |
| CVE-2022-45460 | 긴 URI → `sprintf` 스택 오버플로(무인증) | Sofia HTTP | `fn-unsafe-copy` | 9.8 (v3.1) | – |
| CVE-2024-3765 | Sofia 서비스 접근 제어 오류(문서화 안 된 명령 1009) | Sofia 34567 서비스 | (메시지 ID 디스패치) | 9.8 (v3.1, CNA) | – |

### 2.4 HiSilicon hi3520d 기반 비디오 인코더 (Kojenov, VU#896979)

| CVE | 클래스 | 정적 앵커 → YAML id | NVD |
|---|---|---|---|
| CVE-2020-24215 | 웹 백도어 비밀번호 | `neworange88888888` → `hienc-backdoor-password` | 9.8 (v3.1) |
| CVE-2020-24218 | telnet root 하드코딩 비밀번호 | `/etc/passwd` 해시 → `known-hash-hienc-*` | 9.8 (v3.1) |
| CVE-2020-24219 | 정적 파일 판별 부분 문자열 + 경로 순회 | `fn-uri-substring-match` | 7.5 (v3.1) |
| CVE-2020-24217 | 무인증 파일 업로드(`multipart/form-data`) | `fn-uri-substring-match` | 9.8 (v3.1) |
| CVE-2020-24214 | RTSP `CSeq` → `sprintf` 오버플로 | `fn-unsafe-copy` | 9.8 (v3.1) |
| CVE-2020-24216 | RTSP 비밀 URL 무시 | – | 7.5 (v3.1) |

### 2.5 기타 벤더 / 공통 컴포넌트

| CVE | 벤더/제품 | 클래스 | 정적 앵커 → YAML id | NVD | KEV |
|---|---|---|---|---|---|
| CVE-2021-45039 | Uniview IPC | UDP 7788 `maintain` 오버플로 → telnetd `root/123456` | `/program/bin/maintain` → `unv-maintain-daemon` | 9.8 (v3.1) | – |
| CVE-2019-20085 | TVT NVMS-1000 | `GET /..` 디렉터리 순회 | – | 7.5 (v3.1) | 2021-11-03 |
| CVE-2024-7339 | TVT DVR | `/queryDevInfo` 정보 노출 | → `tvt-querydevinfo` | 5.3 (v3.1) | – |
| CVE-2017-8224 / 8225 / 8223 / 8222 / 8221 | WIFICAM(GoAhead 개조 OEM) | 백도어 root / `.ini` 인증 우회 / RTSP 무인증 / 개인키 / 평문 클라우드 | `loginuse`, `loginpas`, `ck.pem` → `wificam-*` | 9.8 / 9.8 / 7.5 / 7.5 / 7.5 | – |
| CVE-2018-9995 | TBK DVR 및 리브랜드 | 쿠키 `uid` 값으로 인증 결정 | `device.rsp` → `tbk-device-rsp` | 9.8 (v3.0) | – |
| CVE-2020-25078 / 25079 | D-Link DCS-2530L/2670L | `/config/getuser` 무인증 / `ddns_enc.cgi` 명령 주입 | → `dlink-*` | 7.5 / 8.8 | 2025-08-05 (둘 다) |
| CVE-2024-8956 / 8957 | PTZOptics PT30X | `Authorization` 헤더가 없으면 인증 미적용 / `ntp_addr` 명령 주입 | → `ptz-*` | 9.1 / 7.2 | 2024-11-04 (둘 다) |
| CVE-2018-6830 / 6831 / 6832, CVE-2017-2849 | Foscam | URI 부분 문자열 + 순회 파일 삭제 / NTP 명령 주입 / 스택 오버플로 | `/snapPic/`, `ntpServer` → `foscam-*` | 7.5 / 7.2 / 7.5, 8.8 | – |
| CVE-2017-17562 | Embedthis GoAhead < 3.6.5 | CGI 환경 변수 주입(`LD_PRELOAD`) | → `comp-goahead-version` | 8.1 (v3.1) | 2021-12-10 |
| CVE-2018-18778 | ACME mini_httpd < 1.30 | 임의 파일 읽기 | → `comp-mini-httpd-version` | 6.5 (v3.0) | – |

CVE 미확인 항목은 4.6절에 정리했다. 대상은 TVT 4567 백도어, Uniview `main-cgi`, Herospeed TelnetSwitch, Dahua TCP 6789 디버그, tothi의 Sofia 만능 비밀번호다.

### 2.6 KEV에 등재된 기타 카메라·NVR CVE (이 문서에서 상세 분석하지 않음)

KEV feed의 `vulnerabilityName`을 그대로 옮겼다(앞뒤 공백만 제거). 우선순위를 정할 때 참고한다. catalogVersion `2026.10.16`에서 vendor/product/이름에 camera·NVR·DVR·감시 장비 벤더명이 들어간 항목을 다시 훑어 Digiever, D-Link DNR-322L(NVR), GeoVision, NUUO 항목을 추가했다.

| CVE | KEV vulnerabilityName | KEV 추가일 |
|---|---|---|
| CVE-2023-52163 | `Digiever DS-2105 Pro Missing Authorization Vulnerability` | 2025-12-22 |
| CVE-2022-40799 | `D-Link DNR-322L Download of Code Without Integrity Check Vulnerability` | 2025-08-05 |
| CVE-2024-11120 | `GeoVision Devices OS Command Injection Vulnerability` | 2025-05-07 |
| CVE-2024-6047 | `GeoVision Devices OS Command Injection Vulnerability` | 2025-05-07 |
| CVE-2025-1316 | `Edimax IC-7100 IP Camera OS Command Injection Vulnerability` | 2025-03-19 |
| CVE-2021-40407 | `Reolink RLC-410W IP Camera OS Command Injection Vulnerability` | 2024-12-18 |
| CVE-2019-11001 | `Reolink Multiple IP Cameras OS Command Injection Vulnerability` | 2024-12-18 |
| CVE-2022-23227 | `NUUO NVRmini2 Devices Missing Authentication Vulnerability` | 2024-12-18 |
| CVE-2018-14933 | `NUUO NVRmini Devices OS Command Injection Vulnerability` | 2024-12-18 |
| CVE-2023-47565 | `QNAP VioStor NVR OS Command Injection Vulnerability` | 2023-12-21 |
| CVE-2016-11021 | `D-Link DCS-930L Devices OS Command Injection Vulnerability` | 2022-03-25 |
| CVE-2020-5735 | `Amcrest Cameras and NVR Stack-based Buffer Overflow Vulnerability` | 2021-11-03 |

---

## 3. 벤더별 펌웨어 지형도 (정적 분석의 출발점)

### 3.1 Hikvision

- **API 핸들러 계열**: Monte Crypto의 2017 Full Disclosure는 일반적인 Hikvision 카메라 펌웨어에 API 요청을 처리하는 핸들러가 네 개 있다고 썼다. 출처: <https://seclists.org/fulldisclosure/2017/Sep/23>

  ```
  There are four handlers in a typical Hikvision camera firmware that process API requests: ISAPI, PSIA, HikCGI, and Genetec.
  ```

  정적 분석에서는 네 핸들러의 인증 코드가 대칭인지 비교하는 것이 핵심 기법이다(4.1의 CVE-2017-7921 참조).
- **HTTP Server 배너**: nmap 공식 `nmap-service-probes`의 match 규칙 기준이다. 출처: <https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes>
  - `Server: App-webs/` → `Hikvision IP camera httpd`
  - `Server: Hikvision-Webs` → `Hikvision DVR httpd` / `Hikvision camera httpd`
  - `Server: DNVRS-Webs` → `Hikvision Network Video Recorder http admin`

  배너 문자열은 웹 서버를 내장한 바이너리 안에 들어 있을 가능성이 높다. 메인 바이너리를 식별하는 보조 근거로 쓴다(추정).
- **메인 애플리케이션 이름** `(커뮤니티)`: IPCamTalk 포럼에 따르면 대부분의 펌웨어에서 메인 앱은 `davinci`라는 이름이고, 웹 서버와 업데이트 루틴도 이 바이너리에 들어 있다. 일부 최신 HiWatch 펌웨어에서는 `centaurus`로 이름이 바뀌었고 암호화 키도 달라졌다는 보고가 있다. 원문 <https://ipcamtalk.com/goto/post?id=380970>은 자동 수집이 차단되어 검색 요약으로만 확인했다.
- **제한 셸**: 장비 소유자에게도 입력이 필터링된 "protected shell" `psh`만 제공된다(Watchful_IP). 출처: <https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html>
- **펌웨어 이미지 보호**: Monte Crypto는 대부분의 장비가 펌웨어 이미지를 난독화만으로 보호한다고 지적했다.

  ```
  Because most Hikvision devices only protect firmware images by obfuscation, ...
  ```

### 3.2 Dahua (OEM: Amcrest 등)

- **메인 바이너리**: `/usr/bin/sonia`. CERT/CC(CVE-2017-3223)는 다음과 같이 기술한다. 출처: <https://nvd.nist.gov/vuln/detail/CVE-2017-3223>, <https://www.kb.cert.org/vuls/id/547255>

  ```
  Dahua IP camera products include an application known as Sonia (/usr/bin/sonia) that provides the web interface and other services for controlling the IP camera remotely.
  ```

  bashis는 2017 백도어 PoC 주석에서 `'Challenge' / 'Sonia'`를 Dahua의 주요 바이너리로 지목했다. 출처: <https://github.com/mcw0/PoC/blob/master/dahua-backdoor-PoC.py>

  Amcrest(OEM) 펌웨어에서도 `sonia`가 기본 자격증명을 설정해 `/mnt/mtd/Config/Account1`에 기록한다(CVE-2017-8226). 출처: <https://nvd.nist.gov/vuln/detail/CVE-2017-8226>
- **원격 프로토콜과 포트**

  | 포트 | 용도 | 출처 |
  |---|---|---|
  | TCP 80/443 | HTTP. `/RPC2_Login`, `/RPC2` JSON-RPC 엔드포인트가 있다. | bashis PoC |
  | TCP 37777 | 바이너리 관리 프로토콜. "DVRIP"이라는 이름은 bashis 도구(PoC README, DahuaConsole `--proto dvrip`) 기준이다. | Depth Security (CVE-2013-6117), bashis |
  | TCP 37778 | DVR 기본 리슨 포트 중 하나 | Depth Security |
  | TCP 5000 | DHIP. HTTP 포트로도 동작한다. | DahuaConsole README <https://github.com/mcw0/DahuaConsole> |
  | UDP 37810 | 장비 탐색(multicast / 직접 probe) | bashis PoC README <https://github.com/mcw0/PoC> |
  | TCP 6789 | 과거 디버그 코드 리슨 포트(l/p 인증 있음) | bashis PoC 주석 |

  6789 관련 원문은 다음과 같다.

  ```
  Dahua has lots of debug code compiled into the Firmware that may/normally listening on TCP/6789, although protected by l/p authorization
  ```
- **민감 파일**: bashis PoC 주석 기준이다.
  - `/mnt/mtd/Config/{passwd|Account1}`: 사용자 DB
  - `Config1` 등: bashis가 "원격 접근되면 안 된다"고 지목한 다른 파일
  - 같은 디렉터리에 의도적으로 공개되는 `WebCapConfig`, `preLanguage`가 함께 있다.
- **로그인 필드 어휘**: `global.login` 요청의 `params`에 쓰이는 키와 값이다. bashis FD와 DahuaConsole `dahua_logon_modes.py`에서 수집했다. 펌웨어에서는 이 문자열들이 로그인 분기 비교 상수로 나타난다. 분기 하나하나를 감사해야 한다.

  | 키 | 공개 자료에서 관찰된 값 |
  |---|---|
  | `clientType` | `NetKeyboard`, `Local`, `WSSE`, `Onvif`, `Web3.0`, `Console`, `RtspClient`, `Ushield`, `Dahua3.0-Web3.0-NOTIE` |
  | `loginType` | `Direct`, `Loopback`, `Local`, `Onvif`, `LDAP`, `ActiveDirectory`, `CMS`, `GUI`, `Ushield` |
  | `authorityType` | `Default`, `Onvif`, `OTP`, `HttpDigest`, `OldDigest`, `Local`, `Ushield` |
  | `passwordType` | `Default`, `Plain`, `HttpDigest`, `WSSE`, `Onvif`, `OldDigest`, `Local`, `Direct`, `Basic`, `Ushield` |
  | `ipAddr` | 클라이언트가 직접 써 넣는 IP 문자열. CVE-2021-33045에서는 `127.0.0.1`이 쓰였다. |

  DahuaConsole `--logon` 옵션 목록도 참고한다: `wsse,loopback,netkeyboard,onvif:plain,onvif:digest,onvif:onvif,plain,ushield,ldap,ad,cms,local,rtsp,basic,old_digest,gui`

### 3.3 XiongMai (XMeye / Sofia, 다수 OEM과 화이트라벨)

- **메인 앱**: `/var/Sofia`. 정적 링크에 strip된 ARM ELF이며 HTTP와 RTSP를 포함한 대부분의 인터페이스를 구현한다. 출처: tothi <https://github.com/tothi/pwn-hisilicon-dvr> (`README.adoc`)
- **포트와 프로세스 소유**

  2016년 펌웨어(VulnCheck의 `netstat`):
  - 34567, 554, 80 → `Sofia`
  - 9527 → `dvrHelper`
  - 9530 → `macGuarder`

  2021년 펌웨어:
  - 80, 554, 23000, 30100, 34567 → 모두 `Sofia`

  출처: <https://vulncheck.com/blog/xiongmai-iot-exploitation>

  tothi는 추가로 TCP 34599, UDP 34568/34569, TCP 23(BusyBox telnetd)을 관찰했다.

  | 포트 | 의미 |
  |---|---|
  | 80 | `uc-httpd 1.0.0` 배너 (tothi의 nmap 결과) |
  | 554 | RTSP. 응답 헤더 형식은 `Server: H264DVR <ver>`다(nmap-service-probes 규칙 `Server: H264DVR ([\d.]+)`). VulnCheck가 인용한 `H264DVR rtspd 1.0`은 nmap 표시명(product `H264DVR rtspd` + version `1.0`)이므로 펌웨어 grep 문자열로 쓰지 않는다. tothi의 nmap은 같은 계열의 554를 `LuxVision or Vacron DVR rtspd`로 표시했으므로 배너는 펌웨어마다 다를 수 있다. |
  | 9527 | 애플리케이션 콘솔. 앱 계정으로 로그인한 뒤 `shell` 명령으로 root 셸에 들어간다(tothi). Web UI와 같은 계정을 받는다(Yarmak). |
  | 9530 | `OpenTelnet:OpenOnce` 백도어 (Yarmak, CVE-2020-22253 / CVE-2021-41506) |
  | 34567 | Sofia 독자 바이너리 프로토콜. 업그레이드와 명령 처리에 쓰인다(CVE-2022-45045, CVE-2024-3765). VulnCheck는 "custom protocol", netsecfish는 "Sofia service"라고만 부른다. "DVRIP/NetIP"라는 명칭은 1차 출처에서 확인하지 못했다 `(미확인)`. bashis 도구가 "DVRIP"이라고 부르는 Dahua TCP 37777 프로토콜과 혼동하지 않는다. |
- **계정 저장소와 해시**
  - 웹 계정 해시: `/mnt/mtd/Config/Account1` (tothi). Yarmak은 `/mnt/mtd/Config/Account*`로 적었다.
  - 해시 함수: MD5 다이제스트 16바이트를 두 바이트씩 더해 `% 0x3e`하고 영숫자로 매핑한 **8문자** 문자열. tothi의 `sofia_hash.py`가 원본 구현이다. <https://github.com/tothi/pwn-hisilicon-dvr/blob/master/sofia_hash.py>
  - **빈 비밀번호의 해시 = `tlJwpbo6`**. tothi가 명시했고 이 문서 작성 중 위 알고리즘으로 재계산해 일치를 확인했다. NVD의 CVE-2022-45045 설명에도 `default admin:tlJwpbo6 credentials`라는 표현이 있다.
- **업데이트 경로**: SEC Consult(SA-20181009-0)에 따르면 다음과 같다. 출처: <https://seclists.org/bugtraq/2018/Oct/27>
  - 펌웨어 업데이트 이미지는 **서명되지 않는다**.
  - 업데이트 이미지 안의 `InstallDesc`는 "업데이트 중 실행되는 명령"을 담은 텍스트 파일이다. 키 이름으로 `"UpgradeCommand"`, `"Command" : "Shell"`, `"Script"`가 확인된다.
  - 업데이트 서버는 `upgrade.secu100.net`이다.
- **기본 계정**: SEC Consult 기준으로 `admin`은 빈 비밀번호다. 문서화되지 않은 `default` 계정의 비밀번호는 `tluafed`다(CVE-2018-17919).
- **2020년 이후 펌웨어의 변화**(VulnCheck)
  - 업그레이드 `Script`에 `telnetd` 문자열이 있으면 거부하는 블랙리스트가 생겼다. VulnCheck 디컴파일 기준 `strstr(pcVar7,"telnetd")`.
  - 일부 펌웨어는 개조된 BusyBox telnetd를 쓴다. 이 telnetd는 명령줄에 특정 값이 있어야 기동한다.

### 3.4 HiSilicon hi3520d 기반 비디오 인코더 (URayTech, J-Tech Digital, Pro Video Instruments 등)

출처: Kojenov <https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/>, CERT/CC <https://www.kb.cert.org/vuls/id/896979>

- **메인 앱**: 벤더 웹 애플리케이션 `box.v400_hdmi`. 장비마다 이름이 다를 수 있다. 80, 8086, 554, 8554 포트를 직접 리슨한다.
- **기동 체인**: `rcS → load → run → box.v400_hdmi`. 펌웨어 백업(`up.rar`)에 `passwd`, `run`, `box.ini`가 포함되어 있다.
- **기타 포트**
  - 23: BusyBox `telnetd`. 기본 실행이며 UI에서 끌 수 없다.
  - 5150: `remserial -p 5150 -s 9600 raw /dev/ttyAMA1`. UART를 네트워크로 브리지한다.
  - 9588: `nginx/1.6.0`
  - 1935: RTMP
- **설정**: `/box/box.ini`의 `html_password` 키에 admin 비밀번호가 평문으로 저장된다. Kojenov의 `grep` 출력 기준 줄 형식은 `html_password:<값>`이고, 웹 API(`get_sys`) 응답 XML에서는 `<html_password>…</html_password>` 요소로 나온다.
- **RTSP 배너**: RTSP 응답 헤더는 `Server: Server Version 9.0.6`이다(Kojenov 캡처).
- **HTTP 인증 방식**: 세 가지를 지원한다. Digest 응답의 `nonce`가 고정값이라는 점에 주목한다.
  - Digest: 응답 헤더가 `WWW-Authenticate: Digest qop="auth", realm="pbox", nonce="tick"`이다.
  - Basic
  - 쿼리 파라미터 `user`/`pass`

### 3.5 TVT (NVMS-9000 계열, 80개 이상 OEM)

출처: bashis 2018 <https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt>. 벤더 권고 <http://en.tvt.net.cn/news/227.html>은 직접 열람하지 못했다.

- **구조**: `/mnt/mtd/ConfigSyncProc`가 HTTP(TCP/80)를 TCP/4567의 `NVMS9000` 프로세스로 중계하는 wrapper다. 문제는 `NVMS9000`이 loopback이 아닌 모든 인터페이스에서 리슨한다는 점이다.

  ```
  'NVMS9000' process listen on all available interfaces, and not only on loopback/127.0.0.1.
  ```
- **식별 단서**: 웹 API(`/doLogin` 등)에서 `NVMS-9000` 시스템 식별자가 쓰인다(bashis 기재).
- **영향 범위**: TVT와 OEM의 2018년 3월 이후 펌웨어는 영향이 없다고 bashis가 기재했다.

### 3.6 Uniview

- `/program/bin/maintain`이 UDP 7788에서 독자 TLV 프로토콜을 리슨한다. telnetd를 쓰면 제한 셸 `uvsh`가 뜬다. 출처: SSD <https://ssd-disclosure.com/ssd-advisory--uniview-preauth-rce/>
- 웹 CGI `/cgi-bin/main-cgi`는 `json=` 파라미터의 `cmd` 번호로 기능을 디스패치한다. 출처: bashis 2017 <https://github.com/mcw0/PoC/blob/master/Uniview%20RCE%20PoC.txt>

### 3.7 기타

| 벤더/제품 | 펌웨어 구조 요약 | 출처 |
|---|---|---|
| WIFICAM 계열(GoAhead 개조, 1250+ 모델로 보고) | GoAhead 기반 OEM 웹 서버. htdigest 또는 URI 자격증명(`loginuse`/`loginpas`) 인증. 웹 루트에 `system.ini` 등 `.ini` 심볼릭 링크. telnetd 기본 실행. RTSP 10554. | Pierre Kim <https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html> |
| Foscam | `lighttpd`(벤더 코드 추가) → FastCGI `CGIProxy.fcgi` → `webService`(인증과 핸들러) → `devMng`(`system()`/`popen()`). 모든 프로세스가 root. 웹 포트 88. | VDOO (아카이브) <http://web.archive.org/web/20181206084221/https://blog.vdoo.com/2018/06/06/vdoo-has-found-major-vulnerabilities-in-foscam-cameras/> |
| Herospeed (Fullhan/HiSilicon/Ambarella 기반 IPC) | `TelnetSwitch` 데몬이 TCP/787에서 telnetd 활성화 요청을 받는다. 동적으로 생성한 비밀번호로 검증한다. | bashis <https://github.com/mcw0/PoC/blob/master/Herospeed-TelnetSwitch.py> |
| TBK DVR4104/DVR4216 및 리브랜드(Novo, CeNova, QSee, Pulnix, Night OWL 등) | `device.rsp` 핸들러 | NVD CVE-2018-9995 |
| PTZOptics PT30X-SDI/NDI | `/cgi-bin/param.cgi` | NVD CVE-2024-8956 |

---

## 4. CVE 카탈로그 (상세)

각 항목은 다음 순서로 정리했다: 출처, 분류, 근본 원인 패턴, 정적 분석 체크포인트, 안전한 검증. "안전한 검증"은 운영자 소유 장비를 **격리된 랩 네트워크**에서 다루는 경우만 전제한다. 공개 PoC 실행은 권장하지 않는다. 기본은 버전과 빌드 비교, 그리고 패치 전후 핸들러의 디컴파일 diff다.

### 4.1 Hikvision

#### CVE-2017-7921: HikCGI `auth` 파라미터에 의한 사용자 사칭 (Improper Authentication)

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2017-7921>
  - ICS-CERT ICSA-17-124-01 <https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-01>
  - 연구자 Monte Crypto(IPCamTalk "Montecrypto") <https://seclists.org/fulldisclosure/2017/Sep/23>
  - Hikvision 보안 공지 <https://www.hikvision.com/us-en/support/cybersecurity/security-advisory/security-notification--privilege-escalating-vulnerability-in-cer>. 원 페이지는 봇 차단으로 열리지 않아 Wayback 스냅샷 <http://web.archive.org/web/20260209074212/https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification--privilege-escalating-vulnerability-in-cer/>으로 원문을 확인했다.
    - `SN No. HSRC-201703-04`, Initial Release Date `2017-03-10`, Update Release Date `2017-03-12`, CVE ID `CVE-2017-7921; CVE-2017-7923`.
    - 수정 빌드(Resolved Versions): DS-2CD2xx2F-I·DS-2CD4x2xFWD는 `V5.4.41 build 170310 and later`, DS-2CD2xx0·DS-2CD4xx5·DS-2CD2xx2FWD는 `V5.4.41 build 170309 and later`, DS-2DEx·DS-2DFx는 `V5.4.71 build 170309 and later`.
    - 벤더 표와 NVD 설명의 제품 목록은 다르다. 벤더 표에는 DS-2DEx가 있고 DS-2CD63xx가 없다. NVD/ICSA 목록은 그 반대다. 벤더 표의 DS-2CD2xx0 영향 범위(~V5.4.4 build 161107)도 NVD의 DS-2CD2xx0F-I 범위(~V5.4.0 Build 160401)와 다르다.
- **분류**
  - CWE-287, NVD 9.8 (v3.1). ICS-CERT 점수는 CVSS v3 10.0이다.
  - KEV 등재일 2026-03-05.
- **영향**: NVD 설명 기준 DS-2CD2xx2F-I 시리즈 V5.2.0 build 140721 ~ V5.4.0 build 160530 등 7개 계열이다.
- **근본 원인 패턴** (FD 원문)

  ```
  The HikCGI protocol handler checks for the presence of a parameter named "auth" in the query string and if that parameter contains a base64-encoded "username:password" string, the HikCGI API call assumes the idntity of the specified user. The password is ignored.
  ```

  ```
  Only one of the four (HikCGI) has an additional piece of code with a very simple logic of "if this exists, then skip all authentication".
  ```

  Hikvision은 이를 개발자가 남긴 디버그 코드라고 설명했다(FD 기재). 연구자는 이 백도어 코드가 2017년 1~2월 펌웨어부터 사라지기 시작했다고 적었다.
- **정적 분석 체크포인트**
  1. 메인 웹/앱 바이너리에서 HikCGI 계열 URI 문자열을 찾는다. FD 예시는 `/Security/users`, `/System/configurationFile`, `/onvif-http/snapshot`이다. 이 문자열의 xref로 HikCGI 디스패처를 찾는다.
  2. 디스패처 앞단에서 쿼리 스트링 파라미터 이름 `auth`를 조회하는 코드를 찾는다. 이어서 base64 디코드, `:` 분리, 사용자명만으로 세션이나 권한을 설정하는 흐름이 있는지 본다. 비밀번호 비교 호출이 없으면 이 패턴에 해당한다.
  3. 같은 바이너리의 ISAPI, PSIA, Genetec 핸들러의 인증 함수와 나란히 비교한다. 한 핸들러에만 "존재하면 인증 생략" 분기가 있는 비대칭이 가장 강한 신호다.
  4. 공개 자료의 예시 `auth` 값은 `admin` 계정에 임의 비밀번호를 붙인 문자열의 base64일 뿐이다. 펌웨어 상수가 아니므로 펌웨어 시그니처로 쓰지 않는다.
- **안전한 검증**
  - 장비 펌웨어 빌드를 공지의 수정 빌드와 비교한다.
  - 같은 모델의 수정 전후 펌웨어를 디컴파일해 HikCGI 인증 분기의 제거 여부를 diff한다.
  - 동적 확인은 격리 랩에서 자격증명 없는 HikCGI 요청이 401로 거부되는지 보는 negative test로 한정한다.
- **YAML**: `hik-hikcgi-endpoints`, `hik-handler-families`, `fn-auth-literal-compare`

#### CVE-2017-7923: 설정 백업 파일 내 비밀번호 (Password in Configuration File)

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2017-7923>, ICSA-17-124-01, Monte Crypto FD
- **분류**: CWE-260, NVD 8.8 (v3.0). ICSA-17-124-01 시점에 Hikvision은 이 항목을 고치지 않았다고 기재되어 있다.
- **근본 원인 패턴** (FD 원문)

  ```
  Configuration backup files, unfortunately, contain usernames and plain-text passwords for all configured users. While the files are encrypted, the encryption is easily reversible, because Hikvision chose to use a static encryption key, which is derived from the password "abcdefg".
  ```
- **정적 키**: 제3자 복호화 도구에 구현된 값이다. 벤더가 확인한 값이 아니다.
  - AES-128-ECB 키 `279977f62f6cfd2d91cd75b889ce0c9a`
  - 이어서 4바이트 XOR 키 `73 8B 55 44`를 반복 적용한다.
  - 출처: <https://github.com/WormChickenWizard/hikvision-xor-decrypter> (`README.md`, `XORDecode.java`), <https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor> (`decrypt_configurationFile.py`)
  - 포럼에서는 5.3.x 이후 펌웨어의 처리 방식이 다르다는 보고가 있다 `(커뮤니티)`.
- **정적 분석 체크포인트**
  - 메인 바이너리의 raw 바이트에서 위 16바이트 키를 검색한다(`27 99 77 f6 2f 6c fd 2d 91 cd 75 b8 89 ce 0c 9a`). 키가 있으면 xref로 설정 export/import 루틴을 찾는다.
  - AES 키 스케줄 함수의 키 인자가 상수 주소인지 확인한다.
  - `configurationFile` 핸들러의 접근 권한 요구 수준을 확인한다.
- **안전한 검증**: 소유 장비에서 내보낸 설정 파일을 오프라인에서만 다룬다. 복호화 가능 여부로 정적 키 사용을 확인하되 결과물은 케이스 보관소 밖으로 반출하지 않는다.
- **YAML**: `hik-configurationfile`, `hik-config-aes-key-raw`, `hik-config-aes-key-hex`, `fn-hardcoded-crypto-key`

#### CVE-2021-36260: 웹 서버 명령 주입 (`/SDK/webLanguage`)

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2021-36260>
  - Hikvision 공지(CNA) <https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/>. 원 페이지는 봇 차단으로 열리지 않아 Wayback 스냅샷 <http://web.archive.org/web/20260604201155/https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/security-notification-command-injection-vulnerability-in-some-hikvision-products/>으로 원문을 확인했다.
    - `SN No.: HSRC-202109-01`, Initial release date `2021-09-19`(이후 2021-12-31 V1.4까지 영향 버전 갱신), Base score `9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`, 제보자 Watchful IP.
    - 판정 기준 원문: `Your device firmware is affected by this security vulnerability (CVE-2021-36260) if its version dated earlier than 210628.` 제품군별 표에는 `Versions which Build time before 210625`, `Versions which Build time before 210702`, NVR의 `V4.30.210 Build201224 - V4.31.000 Build210511` 같은 별도 기준도 있다.
  - 발견자 Watchful_IP <https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html>
  - Metasploit 모듈 메타데이터 <https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hikvision_cve_2021_36260_blind.rb>
  - bashis PoC 주석 <https://github.com/mcw0/PoC/blob/master/CVE-2021-36260.py>
- **분류**: CWE-78, NVD 9.8 (v3.1), KEV 등재일 2022-01-10
- **CVE 설명 원문**

  ```
  A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.
  ```
- **Watchful_IP가 공개한 내용**
  - 인증이 필요 없고 HTTP(S) 포트(보통 80/443) 접근만 있으면 된다.
  - 장비 자체 로그로는 탐지되지 않는다.
  - 소유자에게 주어지는 제한 셸 `psh`와 달리 무제한 root 셸을 얻는다.
  - 2016년 펌웨어까지 영향을 받는다.
  - 수정 펌웨어 IPC_G3와 IPC_H5 `V5.5.800 build 210628`을 검증했다.
  - 기술 세부는 "Not for public release"로 비공개다.
- **공개 PoC에서 확인되는 펌웨어 측 사실**
  - 엔드포인트는 `/SDK/webLanguage`이고 HTTP `PUT`으로 받는다.
  - XML 본문의 `language` 요소 값이 셸에서 평가된다. 명령 치환이 실행되는 것으로 관찰되었다.
  - bashis 주석에 따르면 존재하는 언어(`en`)는 200, 존재하지 않는 값은 500을 반환하며 `webLib` 디렉터리와 관련된다.
- **근본 원인 패턴** `(추정)`: 언어 코드 값을 화이트리스트로 검증하지 않는다. 이 값을 파일·디렉터리 조작용 셸 명령 문자열에 `sprintf`류로 삽입한 뒤 `system`/`popen`류로 실행한다. 정확한 싱크 함수와 명령 템플릿은 공개되지 않았다.
- **정적 분석 체크포인트**
  1. 웹 바이너리에서 `webLanguage` 문자열의 xref를 찾는다.
  2. XML 파서에서 `language` 노드 값을 꺼내는 지점부터 문자열 포맷 함수와 명령 실행 싱크까지 데이터 흐름을 추적한다.
  3. 값이 고정 목록(예: 언어 코드 집합)과 비교되는지, 메타문자 필터가 있는지 본다.
  4. 이 핸들러가 인증 확인 이전에 디스패치되는지 확인한다.
- **안전한 검증**
  - 빌드 날짜를 비교한다. Watchful_IP가 확인한 수정본은 해당 계열 `build 210628`이다. 벤더 공지(HSRC-202109-01)의 일반 기준은 "version dated earlier than 210628"이면 영향이며, 제품군마다 210625·210702·NVR 빌드 범위 같은 별도 기준이 있으므로 공지 표를 따른다.
  - 수정 전후 핸들러를 diff한다.
  - Metasploit 모듈 설명에 따르면 테스트한 `HWI-B120-D/W` V5.5.101 build 200408은 취약했고, `DS-2CD2142FWD-I` V5.5.0 build 170725는 비취약이었다.
- **YAML**: `hik-sdk-weblanguage`, `fn-command-exec`, `fn-command-build`

#### CVE-2013-4975 / CVE-2013-4976 / CVE-2013-4977 (Core Security CORE-2013-0708)

- **출처**: NVD 각 항목, Core 권고의 Bugtraq 사본 <https://seclists.org/bugtraq/2013/Aug/56>. 대상 장비는 DS-2CD7153-E 펌웨어 v4.1.0 b130111이다.
- **CVE-2013-4975** (CWE-269, NVD 8.8 v3.1)
  - 유효한 저권한 계정이 `/PSIA/System/ConfigurationData`를 요청하면 설정 데이터를 받는다.
  - 이 데이터는 4바이트 반복 XOR로만 보호된다. Core에 따르면 평문 끝 4바이트가 0이어서 키가 그대로 드러난다. 결과적으로 admin 비밀번호가 노출된다.
  - 정적 체크: 설정 export 핸들러의 권한 수준 요구, 반복 XOR 루틴.
- **CVE-2013-4976** (CWE-287, NVD 9.8 v3.1)
  - 내장 `anonymous` 계정을 비활성화해도 하드코딩 자격증명으로 우회된다. 사용자 `anonymous`, 비밀번호는 `\177` 6개다.
  - 웹 UI `/doc/pages/scripts/login.js`의 `DoLogin()`이 문자열 리터럴 `"anonymous:\177\177\177\177\177\177"`를 `Base64.encode`한다. Core 원문에서 쿠키 이름은 `userInfoXX`(XX = 웹 서버 포트)로 표기된다.
  - Core가 제시한 쿠키 값을 base64 디코드하면 백슬래시가 그대로 들어간 34바이트 ASCII 텍스트 `anonymous:\177\177\177\177\177\177`가 나온다(0x7F 바이트가 아니다. 이 문서 작성 중 디코드해 확인). 따라서 펌웨어 시그니처는 우선 이 텍스트 형태로 찾고, 0x7F 바이트 형태는 `(미확인)` 보조 패턴으로만 쓴다. Core는 같은 자격증명이 CGI(바이너리)에도 여러 번 참조된다고 적었다(`There are several references to those hardcoded credentials in the cgis`).
  - 정적 체크: 웹 루트 JS와 바이너리에서 `anonymous:` 다음에 `\177` 반복이 오는 문자열.
- **CVE-2013-4977** (CWE-119, NVD 10.0 v2): RTSP 트랜잭션의 `Range` 헤더가 길면 오버플로가 나고 인증 전에 도달한다.
- **CVE-2014-4880** (CWE-119, NVD 7.5 v2): DS-7204 DVR 등에서 RTSP `PLAY`의 긴 `Authorization` 헤더로 오버플로가 난다. 출처: <https://nvd.nist.gov/vuln/detail/CVE-2014-4880>
- **벤더 권고**: Core 기재상 Hikvision의 공식 답변이 없었고 벤더 권고는 미확인이다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `hik-psia-configurationdata`, `hik-anonymous-hardcoded`, `fn-unsafe-copy`

#### 참고: CVE-2020-7057 (사용자 열거)

`ISAPI/Security/sessionLogin/capabilities`에 대한 실패 응답이 계정 존재 여부에 따라 달라진다. 대상은 DS-7204HGHI-F1이고 NVD 5.3 (v3.1)이다. 인증 우회는 아니지만 계정 존재 여부가 새는 info-leak 클래스다. 출처: <https://nvd.nist.gov/vuln/detail/CVE-2020-7057>. 벤더 권고는 미확인이다. 안전한 검증: 7절 표 참조.

### 4.2 Dahua (OEM 포함)

#### CVE-2021-33044 / CVE-2021-33045: 로그인 과정의 신원 인증 우회

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2021-33044>, <https://nvd.nist.gov/vuln/detail/CVE-2021-33045>
  - Dahua `DHCC-SA-202106-001` <https://www.dahuasecurity.com/support/cybersecurity/details/957>. 원 URL은 현재 404이고 아카이브 <http://web.archive.org/web/20230607233541/https://www.dahuasecurity.com/support/cybersecurity/details/957>로 열람했다. First Published 2021-09-01, Last Published 2021-11-15.
  - 연구자 bashis FD <https://seclists.org/fulldisclosure/2021/Oct/13>, PoC 도구 <https://github.com/mcw0/DahuaConsole>
- **분류**: CWE-287, NVD 9.8 (v3.1) 두 건 모두. 벤더 점수는 Base 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`)이다. KEV 등재일 2024-08-21(둘 다).
- **CVE 설명 원문** (두 CVE 동일)

  ```
  The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.
  ```
- **CVE-2021-33044 (NetKeyboard)**
  - bashis 원문은 `"clientType": "NetKeyboard",`다. 1차 또는 2차 `global.login` 시퀀스에서 이 값이 쓰이면 인증이 생략된다.
  - 대상 장비: IPC/VTH/VTO에서 시험했다. 영향 펌웨어는 "NetKeyboard" 기능을 지원하지 않는 장비, 즉 2021년 6월 이전 빌드다.
  - 프로토콜: `DHIP and HTTP/HTTPS`
  - 벤더 표의 영향 버전은 `Versions which Build time before June,2021`이다. 수정 빌드 예는 `DH_IPC-HX2XXX-Molec_MultiLang_PN_V2.820.0000000.33.R.210705`다.
- **CVE-2021-33045 (Loopback)**
  - bashis 원문은 `"ipAddr": "127.0.0.1",`, `"loginType": "Loopback",`, `"clientType": "Local",`다. 요청이 loopback에서 온 것처럼 가장해 정상 인증을 우회한다.
  - 대상 장비: IPC/VTH/VTO/NVR/DVR에서 시험했다. 영향 펌웨어는 2020년 초·중반 이전이다.
  - 프로토콜: `DHIP`
  - 벤더 표의 기준: IPC `Build time before May,2020`, VTO `before December,2019`. NVR/XVR 수정 빌드 목록도 별도로 있다.
- **근본 원인 패턴**
  - 33044: 클라이언트가 주장하는 `clientType`에 따라 인증 경로를 고르는데, 지원하지 않는 클라이언트 유형의 분기가 비밀번호 검증 없이 성공을 반환한다.
  - 33045: "로컬 요청이면 신뢰"라는 판단을 소켓의 실제 peer 주소가 아니라 **클라이언트가 JSON에 써 넣은 `ipAddr`/`loginType`**으로 내린다.
- **정적 분석 체크포인트**
  1. `sonia`에서 `global.login` 문자열의 xref로 로그인 RPC 핸들러를 찾는다.
  2. 3.2절 표의 `clientType`/`loginType`/`authorityType`/`passwordType` 값 문자열마다 `strcmp`/`std::string::compare` 비교 지점을 열거한다. 각 분기가 어떤 검증 함수를 부르는지 표로 만든다.
  3. 성공 응답(bashis 원문 `"result":true`)으로 가는 경로 중 비밀번호나 다이제스트 검증 호출이 없는 경로를 찾는다. 특히 `NetKeyboard`, `Loopback`, `Local` 분기를 본다.
  4. "로컬" 판정에 쓰는 값의 출처를 확인한다. `getpeername`이나 accept 시점의 주소 구조체가 아니라 JSON 파싱 결과라면 이 패턴이다.
  5. 같은 로그인 로직이 DHIP(TCP 5000, HTTP 포트 겸용)와 HTTP `/RPC2_Login` 양쪽에서 공유되는지 확인한다.
- **안전한 검증**: 장비의 Build time을 벤더 표 기준일과 비교한다. Dahua 공지 DHCC-SA-202206-001에 따르면 Build time은 Web UI의 Settings → System Information → Version Information에서 볼 수 있다. 수정 빌드와 로그인 핸들러를 diff한다.
- **YAML**: `dh-login-netkeyboard`, `dh-login-loopback-local`, `dh-login-fields`, `dh-rpc2-endpoints`, `fn-auth-literal-compare`

#### CVE-2021-33046: 비밀번호 재설정 과정의 접근 제어

- NVD 9.8 (v3.1, CWE-287). 원문은 `Some Dahua products have access control vulnerability in the password reset process.`다. 출처: <https://nvd.nist.gov/vuln/detail/CVE-2021-33046>. Dahua 공지 957과 987이 참조되어 있다.
- 정적 체크: 비밀번호 재설정 RPC의 인증 전 노출 여부와 재설정 토큰·보안 질문 검증 로직을 본다.
- 안전한 검증: 7절 표 참조.

#### CVE-2017-7925 / CVE-2017-7927 (그리고 bashis의 2017 "백도어" 공개)

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2017-7925>, <https://nvd.nist.gov/vuln/detail/CVE-2017-7927>
  - ICS-CERT ICSA-17-124-02 <https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-02>. 이 권고는 `Researcher Bashis disclosed these vulnerabilities without coordination with ICS-CERT.`라고 공개자를 명시한다.
  - bashis FD <https://seclists.org/fulldisclosure/2017/Mar/7>, PoC 주석 <https://github.com/mcw0/PoC/blob/master/dahua-backdoor-PoC.py>
- **분류**
  - CVE-2017-7925: Password in Configuration File (CWE-260), ICSA와 NVD 모두 9.8.
  - CVE-2017-7927: Use of Password Hash Instead of Password for Authentication (CWE-836), ICSA와 NVD 모두 7.3.
- **근본 원인 패턴** (bashis PoC 주석 원문)

  ```
  2.1) /mnt/mtd/Config/{passwd|Account1} downloadable with /current_config/{passwd|Account1} by HTTP/HTTPS
  2.2) User database hash in format: <username>:<realm>:<password>
  2.4) /mnt/mtd/Config contains also of intentionally public accessible files (WebCapConfig and preLanguage)
  ```

  ```
  7) The 'hotfix' remediation was done by hardcoding from full access to two intentionally public accessible files (WebCapConfig and preLanguage)
  ```

  1. URL 접두사 `/current_config/`가 쓰기 가능한 설정 디렉터리 `/mnt/mtd/Config/`에 그대로 매핑된다. 공개용 파일과 민감 파일이 같은 디렉터리에 섞여 있고 인증 없이 열람된다.
  2. 로그인 프로토콜이 저장된 해시를 아는 것만으로 성공한다(pass-the-hash).
     - Generation 2: 해시를 그대로 제출한다.
     - Generation 3: bashis 원문 `<username>:<random>:[MD5 format as in user database (2.2)]` 형태의 MD5를 제출한다.
  3. 응급 수정은 "공개 파일 두 개만 허용"하는 하드코딩 allowlist였다.
  4. 부수 관찰: `888888` admin 계정의 "로컬 전용" 제한이 브라우저의 `loginEx.js`에서만 검사되었다. 서버 측에서는 강제하지 않았다.
- **정적 분석 체크포인트**
  - `sonia`/`Challenge`에서 `current_config` 문자열과 `/mnt/mtd/Config` 경로의 xref를 찾는다.
  - URL → 파일 매핑 함수에 인증 게이트가 있는지, 파일명 allowlist가 있는지 본다.
  - 로그인 검증 함수가 "평문 비밀번호로 다이제스트를 계산"하는지, 아니면 "저장된 다이제스트를 입력과 직접 비교"하는지 확인한다. 후자가 pass-the-hash다.
  - 웹 루트 JS(`loginEx.js` 등)에만 있는 권한 검사를 서버 쪽 대응 검사와 짝지어 확인한다.
- **연관 CVE**(nullku7, 2017, DHI-HCVR7216A-S3): 출처 <https://nvd.nist.gov/vuln/detail/CVE-2017-6343>
  - CVE-2017-6341: 응답에 평문 비밀번호가 담긴다. NVD 5.9.
  - CVE-2017-6342: SmartPSS가 백그라운드에서 admin으로 자동 로그인한다. NVD 9.8.
  - CVE-2017-6343: MD5 Admin Hash만 알면 로그인된다. NVD 8.1.
- **벤더 권고**: ICSA-17-124-02에 Dahua 보안 공지 제목(2017-03-06/08, 2017-04-03, `Security Notification DHCC-201703-01`)이 열거되어 있다. ICSA 본문에는 URL이 없다. URL `http://us.dahuasecurity.com/en/us/Security-Bulletin_030617.php`는 bashis PoC 주석에 적힌 것이며 열람하지 못했다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `dh-current-config`, `dh-public-config-allowlist`, `dh-loginex-js`, `gen-mtd-config-accounts`

#### CVE-2022-30563: ONVIF 로그인 패킷 재전송 (그리고 CVE-2022-30561)

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2022-30563>
  - Dahua `DHCC-SA-202206-001` <https://www.dahuasecurity.com/support/cybersecurity/details/1017>. 아카이브 <http://web.archive.org/web/20230606230812/https://www.dahuasecurity.com/support/cybersecurity/details/1017>로 열람했다. 2022-06-28 공개, 발견자 Andrea Palanca(Nozomi Networks).
  - Nozomi Networks <https://nozominetworks.com/blog/vulnerability-in-dahua-s-onvif-implementation-threatens-ip-camera-security>
- **분류**: NVD 7.4 (v3.1). 벤더 Base 6.8 (`AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`).
- **영향**: IPC-HDBW2XXX/IPC-HFW2XXX의 2022년 4월 이전 빌드. 수정 예는 `DH_IPC-HX2XXX-Molec_MultiLang_PN_V2.820.0000000.48.R.220614`다. ASI7XXXX는 2021년 9월 이전 빌드가 영향을 받는다.
- **CVE 설명 원문**

  ```
  When an attacker uses a man-in-the-middle attack to sniff the request packets with success logging in through ONVIF, he can log in to the device by replaying the user's login packet.
  ```
- **WS-UsernameToken 구조** (Nozomi 기재)

  ```
  Digest = B64ENCODE( SHA1( B64DECODE( Nonce ) + Created + Password ) )
  ```

  Nozomi가 든 예시 값은 구현 검증용 테스트 벡터로 쓸 수 있다(이 문서 작성 중 Python `hashlib`/`base64`로 재계산해 일치 확인).

  ```
  Nonce    LKqI6G/AikKCQrN0zqZFlg==
  Created  2010-09-16T07:50:45Z
  Password userpassword
  Digest   tuOSpGlFlIXsozq4HFNeeGeFLEI=
  ```

  ONVIF가 권고하는 재전송 대응책은 세 가지다(Nozomi 기재: `According to the ONVIF standard, ... three counter measures are also recommended`).
  1. nonce나 created가 없는 토큰을 거부한다.
  2. timestamp 신선도를 검사한다(최소 5분 가이드).
  3. 사용된 nonce를 신선도 기간 동안 캐시하고 재사용을 거부한다.

  Nozomi는 관리자 계정이 보낸 `GetScopes` 요청의 인증 데이터(UsernameToken)를 그대로 재사용해 위조한 `CreateUsers` 요청을 약 30시간 뒤 다른 IP에서 보냈고, 장비가 이를 받아들여 관리자 계정을 생성하는 것을 관찰했다.
- **정적 분석 체크포인트**
  - ONVIF SOAP 핸들러에서 `PasswordDigest`, `Nonce`, `Created` 파싱 지점을 찾는다. YAML `gen-onvif-wsse-anchors`는 접두사 붙은 `wsse:Nonce`, `wsu:Created`와 `UsernameToken`, `PasswordDigest`를 찾는다. 접두사 없는 이름만 있는 펌웨어도 있을 수 있다 `(미확인)`.
  - `Created`를 현재 시각과 비교하는 코드가 있는지 본다(`time()` 호출과 차이 비교).
  - 최근 nonce를 저장하는 캐시 자료구조가 있는지 본다.
  - 다이제스트 비교가 성공하면 곧바로 권한을 부여하는지 확인한다.
- **CVE-2022-30561**(NVD 5.9 v3.1): 같은 공지에 실린 웹 로그인 패킷 재전송이다. 일반 HTTP 로그인에서도 일회성 challenge가 없는지 확인한다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `gen-onvif-wsse-anchors`, `fn-weak-token-generation`

#### CVE-2013-6117: DVRIP(TCP 37777) 명령 무인가

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2013-6117>
  - Bugtraq <https://seclists.org/bugtraq/2013/Nov/62>
  - Depth Security(Jake Reynolds) <http://blog.depthsecurity.com/2013/11/dahua-dvr-authentication-bypass-cve.html>
- **분류**: CWE-287, NVD 7.5 (v2)
- **근본 원인 패턴** (원문)

  ```
  The various commands supported by the server are not authorized in any way. Authentication simply serves as a way to let the client transition past the login screen.
  ```

  인증 없이 재전송 가능하다고 열거된 명령은 다음과 같다.
  - 펌웨어 버전, 시리얼
  - 이메일·DDNS·NAS 설정(평문 자격증명 포함)
  - 사용자 목록(해시 포함), 그룹, 채널
  - 로그 삭제
  - 사용자 비밀번호 변경

  영향 버전은 v2.608.0000.0과 2.608.GV00.0이다. 기본 포트는 TCP/80, 37777, 37778이다.
- **정적 분석 체크포인트**: 37777 서비스의 opcode 디스패치 테이블을 복원한다. 각 opcode 핸들러가 연결별 "인증됨" 상태 플래그를 검사하는지 본다. 로그인 성공 플래그가 클라이언트 UI 전환용으로만 쓰이고 서버 측 디스패치에서는 무시되는 형태가 이 패턴이다.
- **벤더 권고**: 없음. Depth Security에 따르면 Dahua는 수정 의사를 밝힌 뒤 응답하지 않았다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2013-3612 / 3613 / 3614 / 3615 (CERT/CC VU#800094)

출처: <https://www.kb.cert.org/vuls/id/800094>, NVD 각 항목

| CVE | 내용 | NVD |
|---|---|---|
| CVE-2013-3612 | 하드코딩 root 비밀번호(같은 시리즈 전체 동일, 읽기 전용 파티션에 있어 펌웨어 재기록으로만 변경 가능), ActiveX/독립 클라이언트 경로의 원격 "backdoor" 계정. 날짜 해시 기반 마스터 비밀번호도 보고되었는데, Dahua는 로컬 전용이라고 주장한다. | 10.0 (v2) |
| CVE-2013-3613 | 외부 UPnP 요청을 허용해 telnet 포트가 포워딩될 수 있다. | 7.8 (v2) |
| CVE-2013-3614 | 비밀번호 최대 6자 | 9.3 (v2) |
| CVE-2013-3615 | 약한 48비트 해시 | 7.8 (v2) |

Dahua는 3612~3614에 이의를 제기했다(VU#800094 기재). 정적 체크 대상은 다음과 같다.
- 읽기 전용 파티션의 `/etc/passwd`/`/etc/shadow` 해시
- 날짜를 입력으로 하는 비밀번호 생성 함수(`time`/`localtime` → 해시 → 비교)
- UPnP 포트 매핑 대상에 23번이 들어 있는지

벤더 권고는 없다(VU#800094: 벤더 상태 Unknown). 안전한 검증은 7절 표를 참조한다.

#### CVE-2019-3948: `/videotalk` 인증 누락

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2019-3948>, Tenable TRA-2019-36 <https://www.tenable.com/security/research/tra-2019-36>
- **분류**: CWE-306, NVD 7.5 (v3.0)
- **영향**: Amcrest IP2M-841B, Dahua IPC/SD/NVR 일부 모델
- **원문**: `do not require authentication to access the HTTP endpoint /videotalk`
- **정적 체크**: HTTP 라우트 등록 테이블에서 인증 래퍼 없이 등록된 핸들러를 찾는다. `videotalk` 문자열이 출발점이다.
- **벤더 권고**: Dahua 공지 <https://www.dahuasecurity.com/support/cybersecurity/details/627?us>는 CVE 레코드의 참조 URL이며 열람하지 못했다.
- **안전한 검증**: 7절 표 참조.

#### 참고: CVE-2017-3223, CVE-2017-8226

- **CVE-2017-3223**(NVD 9.8 v3.0): `sonia` 웹 인터페이스의 `password` 필드 길이를 검증하지 않아 인증 전 스택 오버플로가 난다(CWE-121). CERT VU#547255.
- **CVE-2017-8226**(NVD 9.8 v3.0): Amcrest IPM-721S의 `sonia`가 하드코딩 기본 자격증명을 설정해 `/mnt/mtd/Config/Account1`에 기록한다(CWE-798).
- 벤더 권고: CVE-2017-3223은 CERT VU#547255가 수정 펌웨어를 기재한다. CVE-2017-8226의 벤더 권고는 미확인이다. 안전한 검증은 7절 표를 참조한다.

### 4.3 XiongMai (Sofia / XMeye)

#### CVE-2020-22253 / CVE-2021-41506: TCP 9530 `macGuarder`/`dvrHelper` 백도어

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2020-22253>, <https://nvd.nist.gov/vuln/detail/CVE-2021-41506>
  - Xiongmai 공지 <http://www.xiongmaitech.com/en/index.php/news/info/12/68>. 직접 열람하지 못했고 CVE 레코드의 참조 URL을 그대로 적었다.
  - Vladislav Yarmak <https://habr.com/en/post/486856/>, PoC 저장소 <https://github.com/Snawoot/hisilicon-dvr-telnet>, <https://github.com/tothi/hs-dvr-telnet>
- **분류**
  - CVE-2020-22253: NVD 9.8 (v3.1). 원문 `port 9530 open which allows unauthenticated attackers to make arbitrary Telnet connections`
  - CVE-2021-41506: CWE-287, NVD 9.8 (v3.1). 원문 `affected by a backdoor in the macGuarder and dvrHelper binaries of DVR/NVR/IP camera firmware due to static root account credentials in the system.` CVE 레코드의 참조는 Yarmak 글과 PoC 저장소 두 개, Xiongmai 공지다.
  - 해석 차이: VulnCheck 블로그는 CVE-2021-41506을 "Port 9527 debug interface that allows an attacker using default credentials to execute arbitrary operating system commands"로 요약하면서 CVE 문구가 9530(CVE-2020-22253)도 포함할 수 있다고 덧붙였다. 2016년 펌웨어에서 9527은 `dvrHelper`, 9530은 `macGuarder`가 리슨하므로(VulnCheck `netstat`) 두 데몬을 함께 지목한 CVE 문구와 모순되지는 않는다. CVE 매핑 시 두 포트를 모두 고려한다.
- **근본 원인 패턴** (Yarmak 기재를 펌웨어 쪽에서 요약)
  1. 세대별 변화
     - 구버전: telnet을 정적 root 비밀번호와 함께 노출했다.
     - 다음 세대: 9527(디버그)과 telnet을 기본 비활성화하고, 9530 데몬이 특수 명령 문자열을 받으면 telnetd를 켠다.
     - 최신 세대: 같은 명령을 공통 PSK 기반 대칭 암호(3DES-EDE2 변형) challenge-response로 검증한다. 모든 장비가 같은 PSK를 쓰므로 인증이라기보다 난독화에 가깝다.
  2. 데몬(`macGuarder`/`dvrHelper`)이 비교하거나 송신하는 문자열: `OpenTelnet:OpenOnce`, `randNum:`, `verify:OK`, `verify:ERROR`, `CMD:`, `Telnet:OpenOnce`, `Open:OK`. 검증에 성공하면 9527 디버그 포트를 열고 telnetd를 기동한다.
  3. PSK 출처: `/mnt/custom/TelnetOEMPasswd`가 있으면 그 파일을 쓰고, 없으면 기본값 `2wj9fsa2`를 쓴다.
  4. 2차 결함: 9530 인증 루틴이 `CMD` 데이터를 길이 제한 없이 32바이트 스택 버퍼로 복호화한다.
  5. `dvrHelper`는 초기 펌웨어에서 BusyBox applet으로 컴파일되어 있었다.
- **Yarmak이 제시한 활성화 후 유효 root 비밀번호 후보**: `xmhdipc`, `klv123`, `xc3511`, `123456`, `jvbzd`, `hi3518`. 펌웨어 `/etc/passwd` 해시의 오프라인 대조용이다.
- **정적 분석 체크포인트**
  - rootfs 전체에서 `OpenTelnet:OpenOnce`, `Telnet:OpenOnce`, `randNum:`, `verify:OK`, `Open:OK`, `TelnetOEMPasswd`, `2wj9fsa2`를 grep한다.
  - `macGuarder`/`dvrHelper` 바이너리 존재, 그리고 BusyBox applet 목록에 `dvrHelper`가 있는지 확인한다.
  - init 스크립트에서 이 데몬들을 기동하는지 본다.
  - `bind` 상수 포트에 9530(`0x253A`)이나 9527(`0x2537`)이 있는지 본다.
- **안전한 검증**: 격리 랩에서 소유 장비의 포트 인벤토리(23/9527/9530)를 확인한다. 9530 리슨만으로도 위험 신호로 기록한다.
- **YAML**: `xm-opentelnet-cmd`, `xm-opentelnet-handshake`, `xm-telnetoempasswd`, `xm-default-psk`, `xm-backdoor-daemons`, `known-default-password-candidates`

#### CVE-2017-7577: `uc-httpd` 디렉터리 순회

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2017-7577>. CVE 원 참조인 zeroday.insecurity.zone은 접속되지 않는다. tothi README도 참고했다.
- **분류**: CWE-22, NVD 9.8 (v3.0)
- **원문**: `XiongMai uc-httpd has directory traversal allowing the reading of arbitrary files via a "GET ../" HTTP request.`
- **관찰 출력**: tothi의 응답에는 `Server: uc-httpd 1.0.0`과 `Index of /mnt/web/../../etc`가 보인다. 웹 루트가 `/mnt/web`이고 디렉터리 목록 기능이 켜져 있다는 뜻이다.
- **정적 체크**
  - 요청 경로를 웹 루트에 문자열로 연결(`sprintf("%s%s")`, `strcat`)한 뒤 `open`/`opendir`로 바로 넘기는지 본다.
  - `..` 제거나 `realpath` 검증이 없는지 본다.
  - 디렉터리 목록 템플릿(`Index of`)이 있는지 본다.
- **악용 연쇄**: VulnCheck에 따르면 이 결함은 다른 오버플로 공격의 메모리 맵(`/proc/<pid>/maps`) 유출과 Sofia 바이너리 회수에 악용되었다.
- **벤더 권고**: 없음 또는 미확인. CVE 레코드에 벤더 참조가 없다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2017-16725: NetSurveillance Web 인터페이스 스택 버퍼 오버플로

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2017-16725>, ICSA-17-341-01 <https://www.cisa.gov/news-events/ics-advisories/icsa-17-341-01>. 보고자 Clinton Mielke.
- **분류**: CWE-121(ICSA). NVD는 CWE-119, 9.8 (v3.0)이다.
- **특기 사항**: 크래시와 재부팅 후 장비가 더 취약한 상태로 돌아간다.

  ```
  After rebooting, the device restores itself to a more vulnerable state in which Telnet is accessible.
  ```

  이 CVE는 하드코딩 자격증명 CVE가 아니다.
- **정적 체크**: HTTP 요청 파서의 고정 크기 스택 버퍼와 `sprintf`/`strcpy`를 본다. 부팅 시 설정 무결성이 깨지면 telnet을 켜는 폴백 로직이 init 스크립트나 Sofia에 있는지도 확인한다.
- **벤더 권고**: 없음. ICSA-17-341-01에 따르면 Xiongmai는 조율 요청에 응답하지 않았다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2018-10088: `uc-httpd 1.0.0` 로그인 버퍼 오버플로

- **출처**
  - NVD <https://nvd.nist.gov/vuln/detail/CVE-2018-10088>. 원문 `Buffer overflow in XiongMai uc-httpd 1.0.0 has unspecified impact and attack vectors, a different vulnerability than CVE-2017-16725.`
  - VulnCheck 분석 <https://vulncheck.com/blog/xiongmai-iot-exploitation>
- **분류**: NVD 9.8 (v3.0, CWE-119)
- **근본 원인** (VulnCheck 디컴파일): `command=login` 요청의 username과 password를 전역 버퍼에 복사한다. 디컴파일 원문은 `strcpy(&global_username,iVar1 + 9)`, `strcpy(&global_password,iVar1 + 9)`이고 길이 검증이 없다. 하드코딩 자격증명 CVE가 아니다.
- **정적 체크**: 로그인 폼 파서 → 전역 버퍼로 가는 `strcpy` 패턴. 전역 버퍼 뒤에 함수 포인터가 놓였는지도 본다.
- **벤더 권고**: 없음 또는 미확인. CVE 레코드 참조는 GitHub와 Exploit-DB뿐이다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2018-17915 / 17917 / 17919 (XMeye P2P Cloud)와 서명 없는 업데이트

- **출처**
  - NVD 각 항목
  - ICSA-18-282-06 <https://www.cisa.gov/news-events/ics-advisories/icsa-18-282-06>
  - SEC Consult SA-20181009-0 <https://seclists.org/bugtraq/2018/Oct/27>, <https://sec-consult.com/en/blog/advisories/vulnerabilities-xiongmai-ip-cameras-nvrs-dvrs-cve-2018-17915-cve-2018-17917-cve-2018-17919>
  - 보고자 Stefan Viehböck
- **CVE/NVD 기준 매핑**

  | CVE | 내용 | 분류 / NVD |
  |---|---|---|
  | CVE-2018-17915 | XMeye 서비스와 펌웨어 업데이트 통신 미암호화 | CWE-311, 9.8 (v3.0). ICSA는 8.1. |
  | CVE-2018-17917 | MAC 주소로 Cloud ID 열거 가능 | CWE-341, 5.3 |
  | CVE-2018-17919 | 문서화되지 않은 `default` 계정과 기본 비밀번호 | CWE-912, 6.5 |

  SEC Consult 본문의 번호는 17915와 17917이 서로 바뀌어 있다(1절 참조).
- **SEC Consult가 함께 보고한 사실** (별도 CVE 없음)
  - `admin` 기본 비밀번호는 공란이다.
  - `default` 계정의 비밀번호는 `tluafed`다.
  - Cloud ID는 16자리 hex이고 부팅 시 MAC에서 단순 연산으로 파생된다.
  - **Firmware update integrity not checked**: 펌웨어 업데이트가 서명되지 않는다(CWE-494). 업데이트 이미지의 `InstallDesc`에 든 명령이 업데이트 중 실행된다.
  - 업데이트 서버는 `upgrade.secu100.net`이다.
- **정적 체크**
  - Sofia와 설정 기본값에서 `tluafed`, `default` 계정 정의를 찾는다.
  - 업그레이드 파서에서 `InstallDesc`, `UpgradeCommand`를 찾고, 서명 검증 함수(RSA/ECDSA verify) 호출이 있는지 본다.
  - `secu100.net` 도메인 문자열을 찾는다.
- **벤더 권고**: 없음. ICSA-18-282-06 기재상 벤더 완화책이 없었다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `xm-default-user-tluafed`, `xm-upgrade-descriptor`, `xm-upgrade-server`

#### CVE-2022-45045: TCP 34567 업그레이드 경로의 명령 실행 (인증 필요)

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2022-45045>, VulnCheck 블로그
- **분류**: CWE-78, NVD 8.8 (v3.1)
- **NVD 원문 요지**: 인증된 원격 공격자가 34567 포트로 접속해 업그레이드 요청의 조작된 JSON으로 OS 명령을 실행한다. 기본 자격증명 `admin:tlJwpbo6`이 쓰일 수 있다. 2019년부터 실제 악용되었다. 2021년 이후 Xiongmai가 telnetd 실행을 막는 패치를 적용했다.
- **근본 원인 패턴** (VulnCheck)
  - 업그레이드 기술 JSON의 `UpgradeCommand` 배열에서 `"Command"`가 `Shell`인 항목의 `"Script"` 값을 `system()`에 넘긴다.
  - 파서에 특수값 `SkipCheck`와 일치하면 하드웨어·플래시·장비 ID·CRC 같은 호환성 검사를 생략하는 분기가 있다. 무결성 검증을 우회하는 매직 값 비교다.
  - 2020년경 수정: 파일시스템 파일을 필수로 했고, VulnCheck 표현으로 "(poorly enforced) digital signature"를 추가했으며, `telnetd` 문자열 블랙리스트를 넣었다. 근본 수정이라기보다 블랙리스트 방식이다.
- **정적 체크**
  - Sofia에서 `UpgradeCommand`, `Script`, `SkipCheck`, `CompatibleVersion` 문자열의 xref를 따라 업그레이드 파서를 찾는다.
  - JSON에서 꺼낸 값이 `system`/`popen`으로 가는지 본다.
  - 서명 검증이 업그레이드 처리보다 먼저 일어나는지 본다.
  - `strstr(pcVar7,"telnetd")` 같은 문자열 블랙리스트만 있는지 본다.
- **벤더 권고**: 미확인. NVD에는 2021년 이후 패치가 적용되었다고만 적혀 있다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `xm-upgrade-descriptor`, `xm-upgrade-skipcheck`, `xm-empty-password-hash`, `fn-command-exec`

#### CVE-2022-45460: HTTP URI 파싱 스택 오버플로 (무인증)

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2022-45460>, VulnCheck 권고 <https://vulncheck.com/advisories/xiongmai-uri-overflow>, tothi `pwn_hisilicon_dvr.py`
- **분류**: CWE-787, NVD 9.8 (v3.1)
- **근본 원인**: 긴 URI가 `sprintf` 호출로 넘어가 스택 버퍼를 넘친다(NVD 원문 `via a long URI passed to a sprintf call`). NVD는 CVE-2017-16725와 겹칠 수 있다고 덧붙였다. tothi의 2017 분석에서는 당시 Sofia에 NX와 스택 카나리가 없었고 스택이 `rwx`였다.
- **정적 체크**: URI를 포맷 인자로 쓰는 `sprintf`를 찾는다. 바이너리 보호 상태도 확인한다(`checksec` 상당 항목: NX, PIE, 카나리).
- **벤더 권고**: 미확인. VulnCheck 권고만 있다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2024-3765: Sofia 서비스의 잘못된 접근 제어 (문서화되지 않은 명령 코드)

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2024-3765>(CNA VulDB, NVD 상태 Deferred), 연구자 README <https://github.com/netsecfish/xiongmai_incorrect_access_control>
- **분류**: CWE-284. CNA 점수 9.8 (v3.1). 벤더는 무응답이었다.
- **근본 원인**: Sofia(기본 34567)가 **문서화되지 않은 명령 코드 `1009`**를 담은 패킷을 인증 없이 처리한다. 이후 사용자 정보, 시스템 정보, 저장소 정보 조회 명령이 세션 검증 없이 수락된다.
- **정적 체크**
  - Sofia의 34567 메시지 디스패처(메시지 ID → 핸들러 테이블)를 복원한다.
  - 세션 ID 검증 전에 처리되는 메시지 ID 집합을 열거한다. 로그인 계열과 keepalive 외의 ID가 들어 있으면 결함이다.
  - 세션 ID 값 `0` 같은 특수값을 특별 취급하는지 본다.
- **벤더 권고**: 없음(CVE 레코드: 벤더 무응답).
- **안전한 검증**: 7절 표 참조.

#### 참고: CVE-2022-26259 및 CVE 미확인 XiongMai 이슈

- **CVE-2022-26259**(NVD 7.8 v3.1, CWE-120): RTSP 요청 파싱 버퍼 오버플로. 출처 <https://nvd.nist.gov/vuln/detail/CVE-2022-26259>. 벤더 공지 <https://www.xiongmaitech.com/en/index.php/service/notice_info/51/2>는 CVE 레코드의 참조 URL이며 열람하지 못했다. 안전한 검증은 7절 표를 참조한다.
- **tothi 2017(CVE 미확인)**, 출처 <https://github.com/tothi/pwn-hisilicon-dvr>, SSD <https://ssd-disclosure.com/ssd-advisory-hisilicon-multiple-vulnerabilities/>
  - Sofia 인증 함수는 사용자 설정 해시를 읽기 **전에** 평문 비밀번호를 하드코딩 문자열 `I0TO5Wv9`와 비교한다. 일치하면 어떤 사용자로든 인증된다(80/tcp, 554/tcp).
  - 상황에 따라 비밀번호 대신 **저장된 해시**(`Account1`)도 받아들인다. pass-the-hash 패턴이다.
  - 9527 콘솔은 어떤 앱 계정이든 `shell` 명령으로 root 셸을 준다.
  - `/etc/passwd`에 `root:absxcfbgXtb3o:0:0:root:/:/bin/sh`가 있다. DES crypt이고 tothi가 공개한 평문은 `xc3511`이다.
  - tothi의 인증 함수 탐색 기법: 이름에 `"Users"`가 있는 심볼과 `"Password"`가 있는 심볼을 **동시에** 참조하는 함수를 교집합으로 찾는다. Skill에서 재사용할 수 있다.

### 4.4 HiSilicon hi3520d 기반 비디오 인코더 (CVE-2020-24214 ~ 24219)

출처: NVD 각 항목, Kojenov <https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/>, CERT/CC VU#896979 <https://www.kb.cert.org/vuls/id/896979>. 벤더 상태: URayTech, New Orange, Oupree는 6건 모두 Affected. J-Tech Digital과 Provideo는 24214~24217만 Affected이고, J-Tech는 V3.02에서 수정했다. HiSilicon은 Not Affected다.

| CVE | 근본 원인 (Kojenov 기재) | 정적 체크포인트 |
|---|---|---|
| CVE-2020-24215 (CWE-798) | `box_Authenticate()`는 사용자명을 `"admin"`과, 비밀번호를 하드코딩 `"neworange88888888"`과 **먼저** 비교한 뒤 성공을 반환한다. 설정 값 비교는 그 다음이다. Digest 외에 Basic과 쿼리 `user`/`pass`도 같은 함수를 거치므로 어느 경로로든 백도어가 통한다. | 기본 사용자명 문자열(`admin`)의 xref로 인증 함수를 찾는다. 같은 함수 안에서 리터럴 비밀번호 비교를 찾는다. |
| CVE-2020-24218 (CWE-798) | telnetd가 기본 실행이며 끌 수 없다. root 비밀번호가 백도어 값이다. crypt가 8자로 잘리므로 `neworang`가 된다. Kojenov의 경로 순회 예시 출력에 나온 `root:qiYX370VaJ3u.:...`가 바로 이 값의 DES 해시다(crypt(3)로 `neworang`와 일치 확인). 다른 펌웨어 해시: `root:9yVwSCpfKcYJg:...`(평문 `unisheen`), J-Tech `root:$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0:...`(평문 `neworangetech`). 해시-평문 쌍은 모두 crypt(3)로 재확인했다. 단, VU#896979는 J-Tech를 24218에 대해 Not Affected로 표기한다. | 펌웨어 `passwd`와 `run` 스크립트의 `cp /tmp/passwd /etc/`, telnetd 기동 라인 |
| CVE-2020-24219 (CWE-22) | 정적 파일 판별을 `find()`로 하는데, 확장자 같은 부분 문자열이 리소스 이름 **어디든** 있으면 인증 없이 파일 읽기 경로로 보낸다. 리소스 이름은 정화 없이 웹 루트에 덧붙는다. 두 결함이 겹치면 이름에 해당 부분 문자열이 든 디렉터리를 경유해 평문 비밀번호가 든 설정 파일을 포함한 웹 루트 밖 파일을 읽을 수 있다. | URI에 대한 `strstr`/`find` 기반 "정적 파일 예외" 분기, 경로 정규화 부재 |
| CVE-2020-24217 (CWE-306) | 요청이 `multipart/form-data`면 `box_ProcessRequest()`가 인증 확인 없이 업로드 핸들러로 곧바로 넘긴다. URL은 무관하다. 업로드 파일명별 처리 중 하나는 RAR 안의 스크립트를 즉시 실행한다. 또 PNG 로고 업로드 시 사용자 파일명을 그대로 넣은 명령 문자열로 `png2bmp`를 호출해 명령 주입이 된다. | Content-Type 비교가 인증 분기보다 앞에 있는지, 업로드 파일명 분기, `png2bmp` 등 외부 유틸 명령 템플릿 |
| CVE-2020-24214 | RTSP `CSeq` 값을 `sprintf`로 고정 크기 스택 버퍼(`acStack2064`)에 기록한다. 인증 전 DoS이고 RCE 가능성이 있다. | RTSP 파서의 `sprintf`, 고정 버퍼 |
| CVE-2020-24216 | 관리자가 설정한 비밀 RTSP URL이 무시되어 `/0` 등 기본 이름이나 임의 URL로 스트림이 제공된다. | RTSP 경로 매칭 로직이 설정값을 실제로 비교하는지 |

벤더 권고는 VU#896979의 벤더 상태 표로 대신한다(J-Tech Digital V3.02 수정). 안전한 검증은 7절 표를 참조한다.

YAML: `hienc-backdoor-password`, `hienc-box-ini-password`, `known-hash-hienc-*`, `gen-static-digest-nonce`, `fn-uri-substring-match`, `fn-unsafe-copy`

### 4.5 기타 벤더

#### CVE-2021-45039: Uniview UDP 7788 `maintain` 오버플로 → 하드코딩 telnet 자격증명

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2021-45039>, SSD <https://ssd-disclosure.com/ssd-advisory--uniview-preauth-rce/>(원 페이지는 자동 수집에 403을 반환해 아카이브 <http://web.archive.org/web/20230928141452/https://ssd-disclosure.com/ssd-advisory--uniview-preauth-rce/>로 원문 대조), Uniview 공지 <https://www.uniview.com/About_Us/Security/Notice/202112/920471_140493_0.htm>
- **분류**: CWE-120, NVD 9.8 (v3.1)
- **NVD 원문 요지**: 문서화되지 않은 UDP 7788 서비스의 버퍼 오버플로로 telnetd를 기동할 수 있다. telnetd에는 하드코딩 기본 계정 `root/123456`이 있다. 제한 셸은 내장 `ECHO` 명령으로 우회된다.
- **근본 원인 코드** (SSD): `/program/bin/maintain`의 TLV 처리(`FUN_00013074`, `case 10`)가 `__isoc99_sscanf(param_3 + local_1c + 2, "%[^:]:%hu", auStack336, &local_3a)`처럼 폭 지정 없는 `%[^:]`로 스택 버퍼에 쓴다. 또 telnetd 비밀번호는 Web UI에서 비밀번호를 바꿔도 함께 바뀌지 않는다.
- **정적 체크**
  - `sscanf`/`fscanf` 포맷 문자열 중 `%s`나 `%[`에 폭 지정이 없는 것을 찾는다.
  - `/program/bin/` 아래 UDP 리스너를 찾는다.
  - 셸 계정 비밀번호와 웹 계정 비밀번호의 동기화 여부를 본다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `unv-maintain-daemon`, `unv-uvsh`, `fn-unbounded-scanf`

#### CVE-2019-20085 / CVE-2024-7339: TVT

- **CVE-2019-20085**: TVT NVMS-1000 `GET /..` 디렉터리 순회(CWE-22). NVD 7.5 (v3.1), KEV 등재일 2021-11-03. 출처 <https://nvd.nist.gov/vuln/detail/CVE-2019-20085>
- **CVE-2024-7339**: TVT DVR TD-2104TS-CL 등의 `/queryDevInfo` 정보 노출(CWE-200). NVD 5.3 (v3.1). CNA는 VulDB이고 벤더는 무응답이었다. 출처 <https://nvd.nist.gov/vuln/detail/CVE-2024-7339>
- **정적 체크**: 웹 루트 결합 경로의 정규화 여부, 장비 정보 엔드포인트의 인증 래퍼 유무
- **벤더 권고**: 없음 또는 미확인. CVE-2024-7339는 벤더 무응답으로 기재되어 있다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `tvt-querydevinfo`

#### WIFICAM(GoAhead 개조 OEM): CVE-2017-8221 ~ 8225

출처: Pierre Kim <https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html>, NVD 각 항목

| CVE | 내용 | 정적 앵커 |
|---|---|---|
| CVE-2017-8224 (CWE-798, 9.8) | telnetd 기본 실행, 백도어 root 계정 `root:$1$ybdHbPDn$ii9aEIFNiolBbM9QxW9mr0:0:0::/root:/bin/sh` | `known-hash-wificam-root` |
| CVE-2017-8225 (CWE-522, 9.8) | 웹 디렉터리에 `system.ini`, `system-b.ini`, `factory.ini` 등 설정 파일 심볼릭 링크가 있다. `.ini` 접근 인증이 잘못 검사되어 **빈** `loginuse`/`loginpas` URI 파라미터로 우회된다. `.cgi`는 같은 입력을 거부한다. 경로 유형별 인증 비대칭이다. | `wificam-loginuse-loginpas`, `wificam-ini-credential-files` |
| CVE-2017-8223 (CWE-287, 7.5) | RTSP TCP 10554에서 `tcp/av0_1`, `tcp/av0_0` 스트림을 인증 없이 볼 수 있다. | `wificam-rtsp-av0` |
| CVE-2017-8222 (CWE-522, 7.5) | `/system/www/pem/ck.pem`에 Apple Push 인증서와 RSA 개인키가 있다. | `wificam-push-key`, `gen-private-key-pem` |
| CVE-2017-8221 (CWE-311, 7.5) | "Cloud" 평문 UDP 터널 | – |
| CVE 미확인 | `set_ftp.cgi`의 FTP 설정값이 셸에서 평가된다(인증 필요). 위 자격증명 유출과 연쇄하면 인증 전 RCE가 된다. | `wificam-ftp-cgi`, `gen-shell-cmd-template` |

벤더 권고는 없다. OEM이 다수이고 원 제조사가 불명확하다. 안전한 검증은 7절 표를 참조한다.

#### CVE-2018-9995: TBK DVR 계열의 쿠키 기반 인증 결정

- **출처**: NVD <https://nvd.nist.gov/vuln/detail/CVE-2018-9995>(NVD 9.8 v3.0), 연구자 블로그 <http://misteralfa-hack.blogspot.cl/2018/04/tbk-vision-dvr-login-bypass.html>
- **근본 원인**: `Cookie` 헤더의 `uid` 값을 신원으로 사용한다. 세션 검증이 없다. `device.rsp` 핸들러의 사용자 목록 기능이 JSON으로 자격증명을 반환한다(NVD 원문 기재).
- **정적 체크**: 쿠키 파서에서 `uid` 키를 꺼내 권한 결정에 직접 쓰는지 본다. 세션 테이블 조회가 있는지도 본다. `device.rsp` 핸들러의 `opt`/`cmd` 디스패치를 확인한다.
- **벤더 권고**: 없음 또는 미확인.
- **안전한 검증**: 7절 표 참조.

#### CVE-2020-25078 / CVE-2020-25079: D-Link DCS-2530L / DCS-2670L

- **CVE-2020-25078**: `The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.` NVD 7.5 (v3.1), KEV 등재일 2025-08-05.
- **CVE-2020-25079**: `cgi-bin/ddns_enc.cgi allows authenticated command injection.` NVD 8.8 (v3.1), KEV 등재일 2025-08-05.
- **출처**: NVD, D-Link SAP10180 <https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180>
- **정적 체크**: 웹 서버 설정이나 바이너리의 무인증 경로 목록에 `/config/` 계열이 있는지, DDNS 설정값이 명령 템플릿으로 가는지 본다.
- **안전한 검증**: 7절 표 참조.

#### CVE-2024-8956 / CVE-2024-8957: PTZOptics PT30X-SDI/NDI (펌웨어 6.3.40 이전)

- **CVE-2024-8956**(CWE-306, NVD 9.1, KEV 등재일 2024-11-04): `The camera does not properly enforce authentication to /cgi-bin/param.cgi when requests are sent without an HTTP Authorization header.` 헤더가 **없을 때** 인증 검사 자체를 건너뛰는 패턴이다.
- **CVE-2024-8957**(CWE-78, NVD 7.2, KEV 등재일 2024-11-04): `ntp_addr` 설정값을 충분히 검증하지 않아 `ntp_client` 기동 시 명령이 실행된다.
- **출처**: NVD, VulnCheck 권고 <https://vulncheck.com/advisories/ptzoptics-insufficient-auth>, <https://vulncheck.com/advisories/ptzoptics-command-injection>
- **정적 체크**: `Authorization` 헤더 파싱 실패나 부재 시의 기본 분기가 "허용"인지, NTP 주소가 명령 문자열로 들어가는지 본다.
- **벤더 참조**: <https://ptzoptics.com/firmware-changelog/>는 CVE 레코드의 참조 URL이며 열람하지 못했다.
- **안전한 검증**: 7절 표 참조.

#### Foscam: CVE-2018-6830 / 6831 / 6832, CVE-2017-2849

- **출처**: NVD 각 항목, VDOO(아카이브) <http://web.archive.org/web/20181206084221/https://blog.vdoo.com/2018/06/06/vdoo-has-found-major-vulnerabilities-in-foscam-cameras/>, Talos(CVE-2017-2849) <https://talosintelligence.com/vulnerability_reports/TALOS-2017-0351>
- **CVE-2018-6830**(CWE-22, 7.5): lighttpd 벤더 코드가 URI 경로에서 `/configs/export/`나 `/snapPic/` 문자열을 **검색**한다. 발견하면 문서 루트 `/tmp/www`에 URI를 `strncat`으로 붙이고 `access()` 다음 `remove()`를 호출한다. 무인증 상태에서 `../`로 임의 파일을 삭제할 수 있다. VDOO 시나리오에서는 이것으로 인증 관련 파일을 지워 재시작 시 인증 우회로 연결했다.
- **CVE-2018-6832**(CWE-787, 7.5): `getSWFlag`의 `callbackJson` 스택 오버플로. `webService`를 크래시시켜 watchdog 재시작을 유도한다.
- **CVE-2018-6831**(CWE-78, 7.2): `setSystemTime`의 `ntpServer` 인자에 `;`를 넣으면 명령이 실행된다(인증 필요). CVE-2017-2849(NVD 8.8)의 불완전 수정이다. CVE 레코드 원문은 `NOTE: this issue exists because of an incomplete fix for CVE-2017-2849.`다.
  - VDOO 블로그 본문은 선행 취약점을 `CVE-2017-2879`로 적었다. 그러나 CVE-2017-2879는 CVE 레코드상 Foscam C1의 UPnP 버퍼 오버플로(TALOS-2017-0386)이므로 VDOO 쪽 표기 오류로 보고, 이 문서는 CVE 레코드의 CVE-2017-2849(TALOS-2017-0351, NTP 서버 설정 명령 주입)를 따른다.
  - 펌웨어 쪽 지표(VDOO 디컴파일): `devMng`의 NTP 갱신 스레드가 `sprintf(buf, "ntpclient -h %s -c 3 -s", NTP_Server_URL)`로 명령을 만들고 `popen(buf, "r")`로 실행한다. 선행 패치는 `gethostbyname(NTP_Server_URL)`이 성공할 때만 진행하게 했지만, VDOO에 따르면 uClibc의 `gethostbyname()`은 `;`나 공백이 든 이름도 거부하지 않았다. 따라서 이름 해석 성공 여부를 입력 검증으로 쓰는 코드는 이 패턴으로 본다.
- **정적 체크**
  - URI 부분 문자열 검색 뒤에 파일 조작(`remove`/`unlink`/`open`)이 오는 코드를 찾는다.
  - `devMng`류 프로세스에서 설정값이 `system`/`popen`으로 흐르는지 본다.
- **벤더 권고**: <https://www.foscam.com/company/securing-your-foscam-camera-important-notice.html>는 CVE 레코드의 참조 URL이며 열람하지 못했다.
- **안전한 검증**: 7절 표 참조.
- **YAML**: `foscam-uri-substring-delete`, `foscam-ntp-server`, `fn-path-ops-unnormalized`

#### 공통 컴포넌트

- **CVE-2017-17562 (Embedthis GoAhead < 3.6.5)**: CGI가 켜져 있고 CGI 프로그램이 동적 링크인 경우 원격 코드 실행이 가능하다. `cgiHandler`가 신뢰할 수 없는 HTTP 요청 파라미터로 CGI 환경 변수를 초기화하고, glibc 동적 링커와 결합하면 `LD_PRELOAD` 같은 특수 파라미터 이름으로 악용된다. NVD 8.1 (v3.1), KEV 등재일 2021-12-10. 출처 <https://nvd.nist.gov/vuln/detail/CVE-2017-17562>
- **CVE-2018-18778 (ACME mini_httpd < 1.30)**: 임의 파일 읽기(CWE-200). NVD 6.5 (v3.0). 출처 <https://nvd.nist.gov/vuln/detail/CVE-2018-18778>
- **정적 체크**: 번들된 웹 서버의 버전 문자열을 추출해 수정 버전과 비교한다. 배너 형식은 nmap probe 기준으로 `Server: mini_httpd/<ver>`, `Server: GoAhead-Webs`, `Server: GoAhead-Webs/<ver>`다. 현행 Embedthis GoAhead 소스(<https://raw.githubusercontent.com/embedthis/goahead/master/src/http.c>, v6 계열)는 버전 없는 `Server: GoAhead-http` 헤더를 보내고 CGI 환경 변수 `SERVER_SOFTWARE`를 `GoAhead/%s`(ME_VERSION)로 설정한다. 따라서 배너만으로는 버전을 알 수 없는 경우가 많다. GoAhead 3.x 바이너리의 버전 문자열 형식은 `(미확인)`이다(GitHub 저장소에는 v6 태그만 남아 있어 3.x 소스를 대조하지 못했다).
- **안전한 검증**: 7절 표 참조.
- **YAML**: `comp-goahead-version`, `comp-mini-httpd-version`

### 4.6 CVE 미확인 공개 이슈 (write-up 기반)

| 이슈 | 핵심 펌웨어 지표 | 출처 |
|---|---|---|
| TVT TCP/4567 하드코딩 인증 | 4567 서비스가 하드코딩 GUID `{D79E94C5-70F0-46BD-965B-E17497CCB598}`로 인증하고, `requestSystemConfig`가 평문 로그인과 비밀번호를 담은 설정을 반환한다. | bashis 2018 |
| TVT 하드코딩 웹 비밀번호 | `admin` 또는 `root`(OEM에 따라 다름) + `{12213BD1-69C7-4862-843D-260500D1DA40}` | bashis 2018 |
| TVT 하드코딩 root (telnetd) | `root:tsfhKsZ1p7nE2:15506:0:99999:7:::`(공개 평문 `china123`), `root:3kzd9/xqjB.3k:16772:0:99999:7:::`(공개 평문 `1001chin`). 두 쌍 모두 crypt(3)로 재확인했다. | bashis 2018 |
| TVT Base64 Authorization 스택 오버플로 | `/mnt/mtd/ConfigSyncProc`의 HTTP Basic 디코드 경로 | bashis 2018 |
| TVT 인증 후 명령 주입 | `editBlackAndWhiteList`의 IP 필드 | bashis 2018 |
| Uniview `main-cgi` (2017) | `cmd` 번호 디스패치에서 일부 명령(설정 export, 패킷 캡처)이 세션 검증 없이 처리된다. 캡처 NIC 이름 필드가 셸 명령에 삽입된다. | bashis 2017 |
| Herospeed `TelnetSwitch` | TCP/787 데몬이 telnetd 활성화 요청을 받는다. 동적 생성 비밀번호를 스택 오버플로로 덮어쓸 수 있다. Fullhan FH8830, HiSilicon 3518EV200/3519V100, Ambarella S2L/S2E 펌웨어에서 확인되었다. | bashis 2018 |
| Dahua TCP/6789 디버그 | 디버그 코드가 리슨한다(l/p 인증). 이후 DHIP JSON "Debug Console"로 이어진다. | bashis PoC 주석, README |
| Dahua `888888` 로컬 전용 제한 | 브라우저 `loginEx.js`에서만 검사한다. | bashis PoC 주석 |
| XiongMai Sofia 만능 비밀번호 | `I0TO5Wv9`. 해시 비교 전에 리터럴로 비교한다. | tothi 2017 |
| XiongMai 9527 콘솔 | 앱 계정으로 로그인한 뒤 `shell`로 root 셸 | tothi 2017 |

---

## 5. 일반화된 취약 패턴 클래스 (펌웨어 정적 인식 힌트)

각 클래스마다 "펌웨어에서 어떻게 보이는가", "무엇을 찾을 것인가", "공개 사례"를 정리한다. YAML의 `string_heuristics`, `function_heuristics`, `credential_patterns`가 이 분류를 따른다.

### P1. URL 접두사·접미사·부분 문자열 기반 인증 예외 (정적 파일 화이트리스트)

- **모습**
  - 인증 미들웨어 앞단에 "정적 리소스면 통과" 분기가 있다.
  - 판별을 `strstr`, `std::string::find`, `strncmp(uri, "/prefix", n)`, 확장자 비교로 한다.
  - 부분 문자열이 경로 **어디에나** 있어도 매칭되거나, 쿼리 스트링과 경로 정규화 이전의 원문에 대해 검사한다.
- **찾을 것**
  - 인증 함수 호출보다 앞서 URI 문자열 비교로 return/goto하는 분기
  - 확장자 리터럴 배열(예: 이미지와 스크립트 확장자)
  - 공개 디렉터리와 민감 파일이 같은 경로에 섞여 있는지
- **사례**
  - Kojenov CVE-2020-24219(`find()` 부분 문자열)
  - Foscam CVE-2018-6830(`/snapPic/`, `/configs/export/` 검색)
  - WIFICAM CVE-2017-8225(`.ini`만 인증 검사 오류)
  - Dahua `/current_config/` + `WebCapConfig`/`preLanguage` allowlist(CVE-2017-7925)
- **YAML**: `fn-uri-substring-match`, `dh-public-config-allowlist`, `foscam-uri-substring-delete`, `wificam-ini-credential-files`

### P2. 경로 정규화 전 파일 접근 (디렉터리 순회)

- **모습**: `웹루트 + URI`를 `sprintf("%s%s")`, `strcat`, `strncat`으로 연결한 뒤 곧바로 `open`/`fopen`/`opendir`/`access`/`remove`를 호출한다. `realpath`나 `..` 제거가 없다. 디렉터리 목록 기능(`Index of`)이 켜져 있으면 피해가 커진다.
- **사례**: XiongMai `uc-httpd` CVE-2017-7577(웹 루트 `/mnt/web`), TVT CVE-2019-20085, Kojenov CVE-2020-24219, Foscam CVE-2018-6830(삭제), mini_httpd CVE-2018-18778
- **YAML**: `fn-path-ops-unnormalized`

### P3. 인증 없는 CGI·엔드포인트·메시지 ID

- **모습**
  - 라우트 등록 테이블에서 인증 래퍼 없이 등록된 핸들러
  - 바이너리 프로토콜에서 세션 검증 전에 처리되는 opcode/메시지 ID
  - Content-Type 등 요청 속성만 보고 인증 이전에 분기하는 경로
- **사례**
  - D-Link `/config/getuser`(CVE-2020-25078)
  - PTZOptics `/cgi-bin/param.cgi`(CVE-2024-8956)
  - Dahua `/videotalk`(CVE-2019-3948)
  - TVT `/queryDevInfo`(CVE-2024-7339)
  - Kojenov `multipart/form-data` 업로드(CVE-2020-24217)
  - Dahua 37777 opcode 전체(CVE-2013-6117)
  - XiongMai 메시지 1009(CVE-2024-3765)
  - Hikvision `/SDK/webLanguage`(CVE-2021-36260)
  - Uniview `main-cgi` `cmd` 번호(CVE 미확인)
- **찾을 것**: URL/opcode → 핸들러 매핑을 전부 표로 만든다. 각 항목의 "인증 검사 위치(전/후/없음)"를 기록한다. 이 표가 Skill 산출물의 핵심이다.
- **YAML**: `dlink-config-getuser`, `ptz-param-cgi`, `dh-videotalk`, `tvt-querydevinfo`, `hik-sdk-weblanguage`, `unv-main-cgi-json`

### P4. 클라이언트가 보낸 값으로 인증을 결정 (client type, loopback, 쿠키, 쿼리 파라미터, 헤더 유무)

- **모습**
  - 요청 필드(JSON `clientType`/`loginType`/`ipAddr`, 쿠키 `uid`, 쿼리 `auth`, `user`/`pass`, 빈 `loginuse`/`loginpas`)나 `Authorization` 헤더 **부재**가 신뢰 경로로 이어진다.
  - "로컬"이나 "내부 클라이언트" 판정을 소켓 peer 주소가 아닌 요청 본문 값으로 한다.
  - 권한 제한을 클라이언트 JS에서만 검사한다.
- **사례**
  - Dahua `NetKeyboard`(CVE-2021-33044), `Loopback`/`Local`/`ipAddr`(CVE-2021-33045)
  - TBK 쿠키 `uid`(CVE-2018-9995)
  - Hikvision HikCGI `auth`(CVE-2017-7921), Hikvision anonymous 쿠키(CVE-2013-4976)
  - WIFICAM 빈 `loginuse`/`loginpas`(CVE-2017-8225)
  - PTZOptics 헤더 부재(CVE-2024-8956)
  - Dahua `loginEx.js`의 `888888` 제한(bashis)
- **찾을 것**
  - 로그인과 권한 함수에서 요청 값 문자열 비교 → 성공 return 경로
  - `127.0.0.1`/`localhost` 리터럴 비교 지점과 그 비교 대상 변수의 출처
  - 헤더 파싱 실패 시의 기본값(허용/거부)
- **YAML**: `dh-login-*`, `tbk-device-rsp`, `hik-hikcgi-endpoints`, `hik-anonymous-hardcoded`, `wificam-loginuse-loginpas`, `ptz-param-cgi`, `dh-loginex-js`, `fn-auth-literal-compare`

### P5. 하드코딩·기본 계정 (`/etc/passwd`, `/etc/shadow`, 벤더 설정 DB, 바이너리 리터럴)

- **모습**
  - `/etc/passwd`에 직접 들어간 DES crypt(13자) 해시나 `$1$` MD5-crypt 해시
  - 빈 비밀번호 필드, uid 0 계정이 여럿
  - 읽기 전용 파티션의 고정 해시
  - 인증 함수 안 리터럴 비밀번호 비교
  - 설정 DB 기본값(빈 admin, 숨은 `default` 계정)
  - GUID나 긴 무작위 문자열 형태의 "기계 계정" 비밀번호
- **사례**
  - XiongMai: `absxcfbgXtb3o`, `I0TO5Wv9`, `tluafed`, 빈 admin(`tlJwpbo6`)
  - Kojenov: `neworange88888888`, `9yVwSCpfKcYJg`, `qiYX370VaJ3u.`(= `neworang`), `$1$/5bWggz/...`
  - TVT: GUID 비밀번호와 DES 해시 2종
  - WIFICAM: `$1$ybdHbPDn$...`
  - Uniview: telnet `root/123456`(CVE-2021-45039)
  - Dahua: CVE-2013-3612, Amcrest CVE-2017-8226
  - Hikvision: anonymous `\177`×6(CVE-2013-4976)
- **찾을 것**: 부록 B의 해시와 리터럴을 grep한다. `strcmp`/`memcmp`의 한쪽 인자가 `.rodata` 문자열 상수이고 다른 쪽이 요청에서 온 값인 지점을 찾는다(YAML `fn-auth-literal-compare` 참조).
- **YAML**: `credential_patterns` 전체, `xm-universal-password`, `hienc-backdoor-password`, `tvt-hardcoded-web-password`

### P6. 디버그·백도어 서비스 (매직 패킷 telnetd, 숨은 콘솔, UART 무인증 셸)

- **모습**
  - 부팅 스크립트의 `telnetd` 무조건 기동
  - 특수 포트 데몬이 명령 문자열을 받아 telnetd를 기동하는 구조(`OpenTelnet:OpenOnce`, `TelnetSwitch`)
  - 앱 콘솔의 `shell` 명령
  - UART를 TCP로 브리지하는 `remserial`
  - BusyBox inittab의 `::askfirst:-/bin/sh` / `::respawn:/bin/sh` 같은 무로그인 콘솔
  - `getty -n -l /bin/sh`
- **BusyBox 근거**
  - inittab 형식은 `<id>:<runlevels>:<action>:<process>`이고, 예제 파일 자체에 `::askfirst:-/bin/sh`가 있다. 출처 <https://raw.githubusercontent.com/mirror/busybox/master/examples/inittab>
  - `telnetd`의 `-l LOGIN`은 "Exec LOGIN on connect"다.
  - `getty`의 `-n`은 "Don't prompt for login name", `-l LOGIN`은 "Invoke LOGIN instead of /bin/login"이다.
  - BusyBox `networking/telnetd.c`, `loginutils/getty.c` usage 문자열에서 확인했다.
- **사례**
  - XiongMai 9530/9527(CVE-2020-22253, CVE-2021-41506)
  - Herospeed 787
  - TVT 4567
  - Uniview 7788
  - Dahua 6789
  - Kojenov `remserial` 5150, telnetd 기본 실행(CVE-2020-24218)
  - WIFICAM telnetd 기본 실행(CVE-2017-8224)
- **YAML**: `gen-telnetd-launch`, `gen-telnetd-login-shell`, `gen-inittab-console-shell`, `gen-getty-autologin`, `gen-inetd-telnet`, `xm-*`, `herospeed-telnetswitch`, `fn-debug-listener-ports`

### P7. 예측 가능하거나 재사용 가능한 세션, nonce, 토큰, 식별자

- **모습**
  - 고정 Digest nonce(예: Kojenov 장비의 `nonce="tick"`)
  - nonce 캐시나 timestamp 검사가 없는 WS-Security(CVE-2022-30563)
  - challenge 없는 로그인 재전송(CVE-2022-30561)
  - 저장 해시 자체가 자격증명 역할을 하는 구조(CVE-2017-7927, CVE-2017-6343, tothi의 Sofia 해시 수락)
  - 고정 GUID 핸드셰이크(TVT)
  - MAC 파생 Cloud ID(CVE-2018-17917)
  - 세션 ID를 `time()`, `rand()`, 연번으로 생성
- **찾을 것**
  - `WWW-Authenticate` 포맷 문자열에 `%s` 없이 nonce가 박혀 있는지
  - `srand(time(NULL))` → `rand()`로 세션을 만드는지
  - 로그인 검증 입력에 서버 생성 난수가 포함되는지
- **YAML**: `gen-static-digest-nonce`, `gen-onvif-wsse-anchors`, `tvt-4567-handshake-guid`, `fn-weak-token-generation`

### P8. 자격증명·해시 유출 (설정 export, 사용자 목록, 평문 저장)

- **사례**
  - Hikvision 설정 백업(CVE-2017-7923), PSIA ConfigurationData(CVE-2013-4975)
  - Dahua `/current_config/`(CVE-2017-7925), DVRIP 사용자 목록(CVE-2013-6117), 평문 응답(CVE-2017-6341)
  - WIFICAM `system.ini`(CVE-2017-8225)
  - D-Link `getuser`(CVE-2020-25078)
  - TVT `requestSystemConfig`(CVE 미확인)
  - Kojenov `box.ini`의 `html_password`
  - 약한 해시: Dahua 48비트(CVE-2013-3615), Sofia 8자 MD5 파생 해시
- **찾을 것**
  - 설정 직렬화 루틴이 비밀번호 필드를 평문이나 가역 암호로 쓰는지
  - export 핸들러 권한 수준
  - 해시 함수의 출력 길이와 솔트 유무
- **YAML**: `hik-configurationfile`, `dh-current-config`, `wificam-ini-credential-files`, `dlink-config-getuser`, `hienc-box-ini-password`, `gen-mtd-config-accounts`

### P9. ONVIF/RTSP 인증 누락이나 약화

- **사례**
  - RTSP 무인증 스트림(CVE-2017-8223)
  - 비밀 URL 무시(CVE-2020-24216)
  - `/videotalk`(CVE-2019-3948)
  - ONVIF 재전송(CVE-2022-30563)
  - RTSP 헤더 오버플로(CVE-2013-4977, CVE-2014-4880, CVE-2020-24214, CVE-2022-26259)
- **찾을 것**: RTSP `DESCRIBE`/`SETUP`/`PLAY` 처리 전에 인증 상태를 확인하는지, ONVIF 서비스별(Device/Media 등) 인증 요구 수준이 어떻게 다른지

### P10. 업데이트 이미지 서명 부재와 업데이트 기술자의 명령 실행

- **사례**
  - XiongMai 업데이트 무서명, `InstallDesc`의 `UpgradeCommand`(SEC Consult), CVE-2022-45045
  - Kojenov 업로드된 RAR 스크립트 즉시 실행(CVE-2020-24217)
  - Hikvision 펌웨어 이미지는 난독화만 적용(Monte Crypto)
  - XMeye 업데이트 채널 평문(CVE-2018-17915)
- **찾을 것**
  - 업그레이드 경로에서 서명 검증 함수의 존재와 호출 순서
  - `SkipCheck`류 우회 값
  - 업데이트 서버 도메인이 HTTP 평문인지
- **YAML**: `xm-upgrade-descriptor`, `xm-upgrade-skipcheck`, `xm-upgrade-server`

### P11. 명령 주입 싱크 (설정값 → 셸)

- **모습**
  - 네트워크 유틸 래퍼(NTP, FTP, DDNS, ping, tcpdump, 이미지 변환)가 `sprintf` 템플릿에 설정값을 넣고 `system`/`popen`으로 실행한다.
  - 주로 인증 뒤 기능이지만 P3~P5와 연쇄되면 인증 전 RCE가 된다.
- **사례**
  - Hikvision `language`(CVE-2021-36260)
  - Foscam `ntpServer`(CVE-2018-6831, CVE-2017-2849)
  - PTZOptics `ntp_addr`(CVE-2024-8957)
  - D-Link `ddns_enc.cgi`(CVE-2020-25079)
  - WIFICAM `set_ftp.cgi`
  - Kojenov `png2bmp` 파일명
  - Uniview 캡처 NIC 이름
  - TVT `editBlackAndWhiteList`
  - XiongMai 업그레이드 `Script`(CVE-2022-45045)
- **YAML**: `gen-shell-cmd-template`, `gen-sh-c-template`, `fn-command-exec`, `fn-command-build`

### P12. 인증 전 메모리 안전성 결함 (인증 우회와 연쇄)

- **사례**
  - `strcpy`: CVE-2018-10088
  - `sprintf`: CVE-2022-45460, CVE-2020-24214
  - 폭 없는 `sscanf("%[^:]")`: CVE-2021-45039
  - 길이 검증 없는 password 필드: CVE-2017-3223
  - Base64 Authorization 디코드 결과 복사(TVT, CVE 미확인)
  - 9530 `CMD` 복호화 → 32바이트 스택(Yarmak)
- **찾을 것**: 요청 파서에서 고정 크기 스택 버퍼로 가는 복사·포맷 호출. 바이너리 보호(NX, 카나리, PIE)가 없는지도 함께 기록한다. tothi와 VulnCheck가 2016~2017년 Sofia에서 `rwx` 스택과 카나리 부재를 보고했다.
- **YAML**: `fn-unsafe-copy`, `fn-unbounded-scanf`

---

## 6. 에이전트 정적 분석 절차 (Skill 작성 지침)

전제: `case-mcp`에 대상 장비의 소유나 서면 허가 근거가 기록되어 있어야 한다. 펌웨어는 REA(binwalk/unblob)로 추출이 끝난 상태다. 아래 REA 도구 이름은 `docs/references/rea-mcp-tools.json`에 실제로 있는 이름이다(`search_strings`, `list_strings`, `xrefs`, `find_xrefs_to_name`, `procedure_pseudo_code`, `procedure_callers`, `procedure_callees`, `search_bytes`, `trace_call_path`, `get_call_graph`, `batch_decompile`).

1. **플랫폼 식별**
   - rootfs에서 YAML `web_server_binaries`의 이름(`Sofia`, `sonia`, `davinci` 등)을 찾는다.
   - YAML `notes`의 배너 문자열(`App-webs/`, `Hikvision-Webs`, `DNVRS-Webs`, `uc-httpd 1.0.0`, RTSP `Server: H264DVR <ver>`의 `H264DVR`)과 경로 지표(`/mnt/mtd/Config`, `/program/bin/maintain`, `/system/www`)로 벤더를 추정한다.
2. **rootfs 감사** (`interesting_paths`, `credential_patterns`)
   - `etc/passwd`와 `etc/shadow`: 빈 비밀번호, DES/MD5-crypt, 알려진 해시, uid 0 중복
   - `etc/inittab`: 무로그인 셸
   - `etc/init.d/*`, `rcS`, 벤더 기동 스크립트: telnetd, 디버그 데몬
   - `inetd.conf`
   - 설정 DB 기본값
3. **문자열 휴리스틱 실행** (`string_heuristics`)
   - 히트를 바이너리별·카테고리별로 집계한다.
   - `critical`/`high` 히트마다 `search_strings` → `xrefs`로 사용 함수를 특정한다.
4. **인증 함수 찾기**. 아래 기법 중 하나 이상을 쓴다.
   - 기본 사용자명 리터럴(`admin`)의 xref(Kojenov 기법)
   - "Users"와 "Password" 관련 심볼을 동시에 참조하는 함수(tothi 기법)
   - 로그인 RPC 이름(`global.login`, `/RPC2_Login`, `/doLogin`)의 xref
   - `procedure_pseudo_code`로 디컴파일한 뒤 다음을 표시한다.
     - 리터럴 문자열과의 비교
     - "존재하면 생략" 분기
     - 요청 값 기반 신뢰 분기
     - 해시 직접 비교
5. **인증 전 디스패치 표 작성**
   - URL/CGI/opcode/메시지 ID → 핸들러 → 인증 검사 위치(전/후/없음)를 표로 만든다.
   - 정적 파일 예외, Content-Type 분기, 특수 세션값 분기를 별도 행으로 기록한다.
6. **싱크 추적**
   - `procedure_callers`와 `trace_call_path`로 `system`/`popen`/`exec*`까지의 경로를 찾는다.
   - 요청 파라미터가 `sprintf`류를 거쳐 싱크에 도달하는지, 그 사이에 검증(화이트리스트, 메타문자 필터)이 있는지 본다.
7. **암호와 업데이트 경로**
   - `search_bytes`로 알려진 키 바이트를 찾는다(예: Hikvision 설정 AES 키).
   - 업그레이드 파서의 서명 검증 유무와 `UpgradeCommand`류 기술자 실행 여부를 확인한다.
8. **CVE 매핑과 신뢰도**: 기존 스키마 `src/pweh/schemas/finding.schema.json`의 값을 쓴다.
   - 이 문서의 CVE와 근본 원인이 일치하면 `references`에 CVE ID와 출처 URL을 넣는다. 펌웨어 빌드를 공지의 수정 빌드와 비교한 결과는 `reasoning`에 적는다.
   - 일치하는 CVE가 없으면 패턴 클래스(P1~P12)를 `reasoning`에 적는다.
   - `confidence`
     - `confirmed`: 디컴파일로 경로를 확인함
     - `likely`: 문자열과 구조가 일치함
     - `possible`: 문자열 히트만 있음
   - `status`: 정적 확인을 마치면 `static-confirmed`, 그 전에는 `unverified`.
9. **보고**(`case-mcp`의 `case_add_finding`, 스키마 `finding`)
   - 필수 필드: `id`(`F-001` 형식), `title`, `category`, `severity`, `confidence`, `status`, `summary`, `location`, `evidence`, `reasoning`
   - `location`: `file`(rootfs 내부 경로), `function`, `address`, `interface`(http/rtsp/onvif/telnet 등)를 채운다.
   - `evidence[].type`: `string`, `decompilation`, `triage`, `rea-evidence` 중 맞는 것. `ref`에는 케이스 상대 경로나 REA evidence id를 넣는다.
   - `verification_plan`: 7절 원칙에 따라 격리 랩 검증 방법을 적는다(공격 페이로드 금지).
   - YAML 카테고리 → `finding.category` 매핑

     | YAML 카테고리 | `finding.category` |
     |---|---|
     | `crypto` | `weak-crypto`. 업데이트 서명이나 무결성 문제면 `insecure-update`. |
     | `memory-safety`(function_heuristics) | `memory-corruption` |
     | `path-traversal` | 파일 읽기 피해면 `info-leak`. 인증 우회로 이어지면 `auth-bypass`. |
     | `session-token` | `auth-bypass` 또는 `weak-crypto` |
     | 빈 기본 비밀번호 | `insecure-default` |
     | 나머지 | 같은 이름을 그대로 쓴다 |

   - Skill 요약(`case_record_step`, 스키마 `auth-hunt`)
     - `vendor_family`: Hikvision → `hikvision-like`, Dahua/Amcrest → `dahua-like`, XiongMai → `xiongmai-like`, HiSilicon 인코더·OEM → `hisilicon-oem`, 그 외(TVT, Uniview, WIFICAM 등) → `generic`
     - `checks[].id`: YAML 휴리스틱 id(예: `xm-opentelnet-cmd`)나 패턴 클래스(P1~P12)를 쓴다. `result`는 `match`, `no-match`, `not-applicable`, `inconclusive` 중 하나다.
   - 증거에는 경로, 주소, 문자열, 디컴파일 발췌만 담는다. 재현용 요청이나 페이로드는 쓰지 않는다.

---

## 7. 안전한 검증 원칙 (운영자 소유 장비, 격리 랩)

1. **네트워크 격리**: 인터넷과 사내망에서 분리된 VLAN이나 스위치를 쓴다. 장비 기본 게이트웨이를 무효화하거나 아웃바운드를 차단한다. XMeye/P2P 클라우드 같은 외부 연결을 막는다.
2. **사전 백업**: UART로 펌웨어와 설정을 덤프해 둔다(`firmware-dump-via-uart` Skill). 해시를 기록한다. 플래시 쓰기와 업데이트 업로드는 사용자 확인 없이 하지 않는다.
3. **정적 우선**: 판단은 다음 순서로 한다.
   1. 빌드 비교
   2. 디컴파일 diff(패치 전후 핸들러)
   3. 포트 인벤토리(23, 554, 9527, 9530, 34567, 37777, 5000, 6789, 4567, 7788, 787, 10554)
   4. 무자격 요청이 401/403으로 거부되는지 보는 negative test
4. **공개 PoC**: 제3자 시스템에는 절대 쓰지 않는다. 소유 장비에서도 서면 범위와 사용자 승인 아래에서만 다룬다. 이 문서와 YAML에는 PoC 페이로드가 없다.
5. **증거 취급**: 복호화한 설정, 비밀번호, 해시는 케이스 디렉터리 안에서만 다룬다. 보고서에는 마스킹해서 싣는다.

### 7.1 CVE별 안전한 확인 방법

4절 각 항목의 "안전한 검증: 7절 표 참조"는 이 표를 가리킨다. 모든 동적 확인은 소유 장비, 격리 랩, 사용자 승인을 전제로 한다. 백도어 활성화, 퍼징, 조작된 업데이트 업로드, 경로 순회 시도는 하지 않는다.

| 대상 | 확인 방법 |
|---|---|
| CVE-2017-7921 | HSRC-201703-04의 수정 빌드(V5.4.41 build 170309/170310, DS-2DEx·DS-2DFx는 V5.4.71 build 170309)와 비교한다. HikCGI 인증 분기를 수정 전후로 diff한다. 자격증명 없는 HikCGI 요청이 401로 거부되는지 본다. |
| CVE-2017-7923, CVE-2013-4975 | 정상 권한으로 내보낸 설정 파일을 오프라인에서만 검사한다(정적 키나 반복 XOR 사용 여부). export 핸들러의 요구 권한을 정적으로 확인한다. |
| CVE-2013-4976 | 웹 루트 `login.js`와 바이너리에 하드코딩 anonymous 문자열이 있는지 정적으로 확인한다. anonymous를 비활성화한 상태에서 무자격 페이지 요청이 거부되는지 본다. |
| CVE-2021-36260 | 빌드를 비교한다(HSRC-202109-01: "version dated earlier than 210628"이면 영향, 제품군별 별도 기준은 공지 표 참조). `webLanguage` 핸들러를 diff한다. |
| CVE-2021-33044 / 33045 | Build time을 벤더 표 기준일과 비교한다. 로그인 분기 표를 만들고 수정 빌드와 diff한다. |
| CVE-2021-33046 | 비밀번호 재설정 RPC의 인증 요구를 정적으로 확인한다. 공지 957/987의 수정 빌드와 비교한다. |
| CVE-2017-7925 / 7927, CVE-2017-6341~6343 | `/current_config/` 매핑의 인증 게이트를 정적으로 확인한다. 무자격 요청으로 사용자 DB 경로가 401/403/404를 반환하는지 본다. 로그인 검증이 해시 직접 비교인지 정적으로 확인한다. |
| CVE-2022-30563 / 30561 | nonce 캐시와 `Created` 시간창 검사를 정적으로 확인하고 수정 빌드와 비교한다. 선택적으로, 자신의 계정으로 만든 만료 토큰이 거부되는지 본다. |
| CVE-2013-6117 | 37777 opcode 디스패치의 인증 상태 검사를 정적으로 확인한다. 포트 인벤토리(37777/37778)를 작성한다. 바이너리 프로토콜 재전송 시험은 하지 않는다. |
| CVE-2013-3612~3615 | 읽기 전용 파티션의 `/etc/passwd`/`/etc/shadow` 해시를 오프라인으로 검사한다(`credential_patterns`). UPnP 설정과 23번 포트 노출을 확인한다. |
| CVE-2019-3948 | 무자격 요청에 대한 `/videotalk` 응답이 401/403인지 본다. 빌드를 비교한다. |
| CVE-2020-22253 / CVE-2021-41506 | 포트 인벤토리(23/9527/9530)와 rootfs 문자열 검사만 한다. 9530 백도어 활성화는 시도하지 않는다. |
| 경로 순회: CVE-2017-7577, CVE-2019-20085, CVE-2020-24219, CVE-2018-6830, CVE-2018-18778 | 경로 결합과 정규화 코드를 정적으로만 확인한다. 동적 순회 시험은 하지 않는다. CVE-2018-6830은 파일 삭제 위험이 있다. |
| 메모리 안전성: CVE-2013-4977, CVE-2014-4880, CVE-2017-16725, CVE-2018-10088, CVE-2017-3223, CVE-2020-24214, CVE-2022-26259, CVE-2022-45460, CVE-2021-45039 | 퍼징이나 크래시 재현은 하지 않는다(장비 손상과 watchdog 재부팅 위험). 빌드를 비교하고 해당 파서의 고정 버퍼와 길이 검증을 정적으로 확인한다. CVE-2021-45039는 telnetd 계정 `root/123456` 존재를 rootfs에서 확인한다. |
| CVE-2018-17915 / 17917 / 17919 | 설정 기본값에서 `default` 계정과 빈 admin 비밀번호를 확인한다. P2P 클라우드 기능의 활성화 여부와 랩의 외부 통신 차단을 확인한다. |
| CVE-2022-45045, 무서명 업데이트(SEC Consult) | 업그레이드 파서의 서명 검증 순서와 `Shell` 명령 실행 경로를 정적으로 확인한다. 조작된 업데이트 업로드는 하지 않는다(벽돌화 위험). |
| CVE-2024-3765 | Sofia 메시지 디스패처의 세션 검증 위치를 정적으로 확인한다. 34567 포트 인벤토리를 작성한다. |
| CVE-2020-24215 / 24218 | 바이너리 리터럴과 `passwd` 해시를 정적으로 확인한다. 23번 포트 노출을 본다. VU#896979의 벤더별 수정 상태를 대조한다. |
| CVE-2020-24217 / 24216 | 업로드 핸들러의 인증 분기와 RTSP 경로 매칭 코드를 정적으로 확인한다. 업로드 시험은 하지 않는다. |
| CVE-2017-8221~8225 | `passwd` 해시, `ck.pem`, 웹 루트 `.ini` 링크를 정적으로 확인한다. 자격증명 없는 `.ini` 요청이 거부되는지 본다. |
| CVE-2018-9995 | 쿠키 파서와 세션 검증을 정적으로 확인한다. |
| CVE-2020-25078 / 25079 | 무자격 `/config/getuser` 요청이 거부되는지 본다. 빌드를 비교한다(DCS-2530L 1.06.01 Hotfix 이상, DCS-2670L은 2.02까지 영향). |
| CVE-2024-8956 / 8957 | 펌웨어가 6.3.40 이상인지 본다. `Authorization` 헤더가 없는 요청의 기본 분기를 정적으로 확인한다. |
| CVE-2018-6831 / 6832, CVE-2017-2849 | NVD 영향 버전 목록과 빌드를 비교한다. 명령 템플릿을 정적으로 확인한다. |
| CVE-2017-17562 | GoAhead가 3.6.5 이상이거나 CGI가 비활성인지 본다. `cgiHandler` 환경 변수 필터를 정적으로 확인한다. |
| CVE 미확인 항목(TVT 4567, Uniview `main-cgi`, Herospeed 787, Dahua 6789, Sofia 만능 비밀번호, 9527 콘솔) | 문자열과 상수를 정적으로 확인하고 포트 인벤토리(4567, 787, 6789, 9527)를 작성한다. 백도어 프로토콜 활성화는 시도하지 않는다. |

---

## 8. 부록

### 부록 A. 포트·서비스 지표

| 벤더 | 포트 | 서비스 / 의미 | 출처 |
|---|---|---|---|
| Hikvision | 80/443 | 웹(ISAPI/PSIA/HikCGI/SDK). CVE-2021-36260은 이 포트만 있으면 된다. | Watchful_IP |
| Hikvision | 554 | RTSP(CVE-2013-4977) | Core |
| Dahua | 37777 / 37778 | DVRIP 관리 / DVR 기본 리슨 | Depth Security |
| Dahua | 5000 | DHIP(HTTP 포트로도 동작) | DahuaConsole |
| Dahua | 37810/udp | 탐색 | bashis |
| Dahua | 6789 | 구 디버그 | bashis |
| XiongMai | 80 / 554 | `Server: uc-httpd 1.0.0` / `Server: H264DVR <ver>`(nmap 표시명 `H264DVR rtspd 1.0`) | tothi, VulnCheck, nmap-service-probes |
| XiongMai | 9527 | 앱 콘솔(`shell`) | tothi, Yarmak |
| XiongMai | 9530 | `OpenTelnet` 백도어 | Yarmak |
| XiongMai | 34567 (+34599, 34568/udp, 34569/udp) | Sofia 독자 프로토콜 | tothi, VulnCheck |
| XiongMai | 23000, 30100 | 2021 펌웨어의 Sofia 포트 | VulnCheck |
| HiSilicon 인코더 | 23, 80, 8086, 554, 8554, 1935, 5150, 9588 | telnet, 웹, RTSP, RTMP, `remserial`, nginx | Kojenov |
| TVT | 80 → 4567 | `ConfigSyncProc` → `NVMS9000` | bashis |
| Uniview | 7788/udp | `maintain` | SSD |
| WIFICAM | 23, 10554 | telnetd, RTSP | Pierre Kim |
| Foscam | 88 | lighttpd 웹 | VDOO |
| Herospeed | 787 | `TelnetSwitch` | bashis |

`bind()` 상수 탐색용 hex(호스트 바이트 순서):

| 포트 | hex |
|---|---|
| 23 | `0x0017` |
| 9527 | `0x2537` |
| 9530 | `0x253A` |
| 34567 | `0x8707` |
| 37777 | `0x9391` |
| 5000 | `0x1388` |
| 6789 | `0x1A85` |
| 4567 | `0x11D7` |
| 7788 | `0x1E6C` |
| 787 | `0x0313` |

네트워크 바이트 순서로 저장된 경우에는 바이트를 뒤집어 검색한다.

### 부록 B. 공개된 하드코딩 자격증명·해시·키 (정적 탐지용)

| 값 (펌웨어 내 형태) | 위치 | 공개 평문 / 비고 | 출처 |
|---|---|---|---|
| `root:absxcfbgXtb3o:` | XiongMai `/etc/passwd` | `xc3511` | tothi |
| `I0TO5Wv9` | Sofia 인증 함수 리터럴 | 만능 비밀번호 | tothi |
| `tlJwpbo6` | Sofia 계정 해시 | 빈 비밀번호의 Sofia 해시 | tothi, NVD CVE-2022-45045 |
| `tluafed` | XMeye `default` 계정 | – | SEC Consult, CVE-2018-17919 |
| `2wj9fsa2` | `dvrHelper`/`macGuarder` 기본 PSK | `/mnt/custom/TelnetOEMPasswd`가 없을 때 쓰인다 | Yarmak |
| `neworange88888888` | 인코더 `box_Authenticate` 리터럴 | crypt 8자 절단 `neworang` | Kojenov, CVE-2020-24215 |
| `root:9yVwSCpfKcYJg:` | 인코더 `passwd` | `unisheen` | Kojenov |
| `root:qiYX370VaJ3u.:` | 인코더 `/etc/passwd`(경로 순회 예시 출력) | `neworang`(백도어 비밀번호 앞 8자, crypt(3)로 확인) | Kojenov, CVE-2020-24218 |
| `root:$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0:` | J-Tech 인코더 `passwd` | `neworangetech` | Kojenov |
| `root:$1$ybdHbPDn$ii9aEIFNiolBbM9QxW9mr0:` | WIFICAM `/etc/passwd` | 평문 미공개 | Pierre Kim, CVE-2017-8224 |
| `root:tsfhKsZ1p7nE2:` / `root:3kzd9/xqjB.3k:` | TVT shadow | `china123` / `1001chin`(crypt(3)로 확인) | bashis |
| `{12213BD1-69C7-4862-843D-260500D1DA40}` | TVT 웹 비밀번호 | – | bashis |
| `{D79E94C5-70F0-46BD-965B-E17497CCB598}` | TVT 4567 핸드셰이크 | – | bashis |
| `anonymous` + `\177\177\177\177\177\177` | Hikvision 웹 `login.js` | – | Core, CVE-2013-4976 |
| `root` / `123456` | Uniview telnetd | 제한 셸 `uvsh` | NVD CVE-2021-45039 |
| AES-128 `279977f62f6cfd2d91cd75b889ce0c9a` + XOR `73 8B 55 44` | Hikvision 설정 백업 | 제3자 도구 기준 | WormChickenWizard, chrisjd20 |

추가로 Yarmak이 XiongMai root 비밀번호 후보로 제시한 값은 `xmhdipc`, `klv123`, `xc3511`, `123456`, `jvbzd`, `hi3518`이다.

Mirai 소스 `scanner.c`의 자격증명 목록은 대조용 사전으로 쓸 수 있다(<https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c>). 값은 주석이 아니라 인코딩된 바이트를 XOR `0x22`로 디코드해 확인해야 한다. 주석 두 곳이 실제 값과 다르다: 주석에 사용자 `Administrator`/비밀번호 `admin`으로 적힌 항목의 실제 비밀번호는 `meinsm`이고, 주석에 `admin`/`1234`로 적힌 두 항목 중 두 번째의 실제 비밀번호는 `4321`이다(이 문서 작성 중 디코드해 확인). 이 목록은 벤더별 매핑을 제공하지 않으므로 이 문서에서도 벤더와 짝짓지 않는다(`(미확인)`).

### 부록 C. 서버 배너와 서비스 핑거프린트

| 문자열 | 의미 | 출처 |
|---|---|---|
| `Server: App-webs/` | Hikvision IP camera httpd | nmap-service-probes |
| `Server: Hikvision-Webs` | Hikvision DVR / camera httpd | nmap-service-probes |
| `Server: DNVRS-Webs` | Hikvision NVR | nmap-service-probes |
| `Server: uc-httpd 1.0.0` | XiongMai Sofia 내장 HTTP(tothi 응답 원문. nmap 규칙은 `Server: uc-httpd[ /]<ver>`) | tothi, VulnCheck, NVD CVE-2018-10088 |
| `Server: H264DVR <ver>` | XiongMai RTSP. `H264DVR rtspd 1.0`은 nmap 표시명이며 응답·펌웨어 문자열이 아니다. 펌웨어에 따라 다른 배너도 있다(tothi의 nmap: `LuxVision or Vacron DVR rtspd`). | nmap-service-probes, VulnCheck |
| `Server: box` | Kojenov 인코더 앱 응답 헤더 | Kojenov |
| `Server: Server Version 9.0.6` | Kojenov 인코더 RTSP 응답 헤더 | Kojenov |
| `Welcome to HiLinux.` | HiSilicon SDK 기반 로그인 배너(Kojenov 장비의 telnet 로그인 프롬프트는 `(none) login:`) | Kojenov |
| `LocalHost login:` | XiongMai 장비 telnet 로그인 프롬프트(Yarmak 예시 세션) | Yarmak |
| `Server: GoAhead-Webs`, `Server: GoAhead-Webs/<ver>` | GoAhead 계열 | nmap-service-probes |
| `Server: GoAhead-http` | 현행 Embedthis GoAhead 소스의 Server 헤더(버전 없음) | GoAhead `src/http.c` |
| `Server: mini_httpd/<ver>` | ACME mini_httpd | nmap-service-probes |

`-Webs` 접미사를 쓰는 Hikvision 배너가 GoAhead 계열 기원인지는 확인하지 못했다 `(미확인)`.

### 부록 D. 출처 목록 (1차 출처 우선)

- 데이터베이스와 카탈로그
  - CVE.org API: `https://cveawg.mitre.org/api/cve/<ID>`
  - NVD: `https://nvd.nist.gov/vuln/detail/<ID>`
  - CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> (JSON feed `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- ICS-CERT/CISA 권고
  - <https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-01>
  - <https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-02> (연구자 크레딧 문구는 아카이브 <http://web.archive.org/web/20190603093617/https://ics-cert.us-cert.gov/advisories/ICSA-17-124-02>에서 원문 대조)
  - <https://www.cisa.gov/news-events/ics-advisories/icsa-17-341-01>
  - <https://www.cisa.gov/news-events/ics-advisories/icsa-18-282-06>
- CERT/CC
  - <https://www.kb.cert.org/vuls/id/800094>
  - <https://www.kb.cert.org/vuls/id/547255>
  - <https://www.kb.cert.org/vuls/id/896979>
- 벤더 공지
  - Hikvision (원 URL은 봇 차단, Wayback 스냅샷으로 열람)
    - <https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/> → <http://web.archive.org/web/20260604201155/https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/security-notification-command-injection-vulnerability-in-some-hikvision-products/> (HSRC-202109-01)
    - <https://www.hikvision.com/us-en/support/cybersecurity/security-advisory/security-notification--privilege-escalating-vulnerability-in-cer> → <http://web.archive.org/web/20260209074212/https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification--privilege-escalating-vulnerability-in-cer/> (HSRC-201703-04)
  - Dahua (원 URL은 404, 아카이브로 열람)
    - <https://www.dahuasecurity.com/support/cybersecurity/details/957> → <http://web.archive.org/web/20230607233541/https://www.dahuasecurity.com/support/cybersecurity/details/957>
    - <https://www.dahuasecurity.com/support/cybersecurity/details/1017> → <http://web.archive.org/web/20230606230812/https://www.dahuasecurity.com/support/cybersecurity/details/1017>
  - 기타
    - Uniview: <https://www.uniview.com/About_Us/Security/Notice/202112/920471_140493_0.htm>
    - D-Link SAP10180: <https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180>
    - Xiongmai: <http://www.xiongmaitech.com/en/index.php/news/info/12/68>
    - TVT: <http://en.tvt.net.cn/news/227.html>
- 연구자 원문
  - Hikvision
    - Monte Crypto: <https://seclists.org/fulldisclosure/2017/Sep/23>
    - Watchful_IP: <https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html>
    - Core CORE-2013-0708: <https://seclists.org/bugtraq/2013/Aug/56>
  - Dahua
    - bashis(2021): <https://seclists.org/fulldisclosure/2021/Oct/13>
    - bashis(2017): <https://seclists.org/fulldisclosure/2017/Mar/7>
    - bashis PoC 저장소: <https://github.com/mcw0/PoC>
    - DahuaConsole: <https://github.com/mcw0/DahuaConsole>
    - Depth Security: <https://seclists.org/bugtraq/2013/Nov/62>
    - Nozomi Networks: <https://nozominetworks.com/blog/vulnerability-in-dahua-s-onvif-implementation-threatens-ip-camera-security>
    - Tenable TRA-2019-36: <https://www.tenable.com/security/research/tra-2019-36>
  - XiongMai
    - tothi: <https://github.com/tothi/pwn-hisilicon-dvr>
    - Yarmak: <https://habr.com/en/post/486856/>
    - VulnCheck: <https://vulncheck.com/blog/xiongmai-iot-exploitation>
    - SEC Consult: <https://seclists.org/bugtraq/2018/Oct/27>
    - netsecfish: <https://github.com/netsecfish/xiongmai_incorrect_access_control>
  - 기타
    - Kojenov: <https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/>
    - Pierre Kim: <https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html>
    - SSD(Uniview): <https://ssd-disclosure.com/ssd-advisory--uniview-preauth-rce/> (아카이브 <http://web.archive.org/web/20230928141452/https://ssd-disclosure.com/ssd-advisory--uniview-preauth-rce/>)
    - VDOO(Foscam, 아카이브): <http://web.archive.org/web/20181206084221/https://blog.vdoo.com/2018/06/06/vdoo-has-found-major-vulnerabilities-in-foscam-cameras/>
- 도구와 코드
  - nmap-service-probes: <https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes>
  - Embedthis GoAhead `src/http.c`(현행 v6 계열): <https://raw.githubusercontent.com/embedthis/goahead/master/src/http.c>
  - Metasploit 모듈: <https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hikvision_cve_2021_36260_blind.rb>
  - BusyBox `examples/inittab`, `networking/telnetd.c`, `loginutils/getty.c`(<https://github.com/mirror/busybox>)
  - Mirai `scanner.c`: <https://github.com/jgamblin/Mirai-Source-Code>
  - Hikvision 설정 복호화 도구
    - <https://github.com/WormChickenWizard/hikvision-xor-decrypter>
    - <https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor>
- 커뮤니티 `(커뮤니티)`: IPCamTalk <https://ipcamtalk.com/goto/post?id=380970> (`davinci`/`centaurus`)
