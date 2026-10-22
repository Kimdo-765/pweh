# cctv-auth-bypass-hunt 점검표 (AH-01 ~ AH-12)

[SKILL.md](SKILL.md) 절차 5단계에서 쓰는 패턴별 상세 점검표다. 대상은 **운영자가 소유했거나 서면 허가를 받은 기기**의 펌웨어뿐이다.
근거 문서는 [cctv-vuln-patterns.md](../../docs/references/cctv-vuln-patterns.md)(사실 확인됨)와 [cctv-hunt-patterns.yaml](../../docs/references/cctv-hunt-patterns.yaml)이다.
아래 CVE 번호는 모두 그 문서에서 가져왔다. 이 표에 없는 CVE 를 새로 붙이지 않는다. 근본 원인이 같아 보여도 확인되지 않으면 패턴 클래스(P1~P12)만 적는다.

이 표에는 공격 요청, 매직 파라미터 값, 경로 순회 문자열, 매직 패킷 내용, 쿠키 값이 없다. finding 에도 그런 것을 쓰지 않는다.
하드코딩 비밀번호 같은 정적 시그니처 값은 YAML 휴리스틱 id 로만 가리킨다. 실제 값은 YAML 과 fwtriage 결과 JSON 에 있다. 예외는 REA 바이트 검색에 꼭 필요한 공개 키 시그니처(AH-03)뿐이며, YAML 과 같은 값이다.

---

## 0. 공통 규칙

### 0.1 판정 (checks[].result)

| result | 언제 |
|---|---|
| `match` | "확인 형태"를 디컴파일(REA)이나 실행되는 설정 줄(init 스크립트, inittab, passwd)로 직접 확인했다. finding 을 만들고 `finding_id` 를 채운다. |
| `inconclusive` | 앵커(문자열·바이트)는 있지만 코드를 확인하지 못했다. 예: xref 없음, 간접 호출·점프 테이블, REA 거부, 분석 시간 초과, 업데이트 처리 코드가 rootfs 밖. 이유를 `coverage_gaps` 에 한 줄로 적는다. 정황이 강하면 `confidence: possible` finding 을 만들어도 된다. |
| `no-match` | 해당 기능의 코드는 있다(로그인 함수, 요청 디스패처, 업데이트 파서 등). 그 코드를 읽었는데 패턴이 없다. 문자열 검색이 비었다는 것만으로는 `no-match` 가 아니다. REA 의 search_strings 는 Ghidra 가 정의한 문자열만 본다. |
| `not-applicable` | 해당 기능 자체가 이 펌웨어에 없다. 예: RTSP/ONVIF 코드 없음, 웹 서버 없음. `description` 에 근거를 적고, 근거가 된 검색 결과를 `evidence_ref` 로 남긴다. |

### 0.2 evidence_ref 형식 (케이스 상대 경로 + 앵커)

- REA 디컴파일·xref: `analysis/rea-evidence-<bin>-NNN.json#<evidence_id>`.
  evidence_id 는 REA 응답의 `evidence_id`(예: `ev_685f…`)다. 줄이지 말고 전체를 쓴다. export_evidence_bundle 로 내보낸 파일에 그 레코드가 들어 있다.
- fwtriage 항목: `<result_path>#<휴리스틱 id>`. 예: `analysis/rootfs-audit-001.json#gen-telnetd-login-shell`, `analysis/strings-hunt-001.json#dh-current-config`.
- fw_strings_hunt 의 checks 를 그대로 복사한 항목은 도구가 준 값(`/usr/bin/Sofia@0x5c0` = rootfs 경로 @ **파일 오프셋**)을 그대로 둔다.
- `no-match` 는 실제로 읽은 함수의 REA 증거나 검색 결과 경로를 적는다. `not-applicable` 은 부재를 보여 준 검색 결과 경로를 적거나 null 로 둔다.

fw_strings_hunt 의 오프셋은 파일 오프셋이고, REA 주소는 가상 주소다.
address_to_file_offset(address="0x105de") → `{"file_offset": 1502}`(=0x5de)로 서로 맞춘다. 합성 테스트 픽스처(zig ARM)에서 확인했다.

### 0.3 finding 필드 기준

- `evidence`: firmware-static-analysis 와 같은 규칙을 쓴다.
  - `decompilation`/`rea-evidence`: ref = `<번들 경로>#<evidence_id>`.
  - `triage`: ref = fwtriage result_path. 휴리스틱 id 와 `<rootfs 경로>@<파일 오프셋>` 은 excerpt 에 둔다.
  - `string`: ref = `<rootfs 경로>@<파일 오프셋>`. REA 가상 주소는 excerpt 나 location.address 에 둔다.
  - `file`/`config`: ref = rootfs 경로.
- `confidence`: `confirmed` = 디컴파일로 경로를 확인했다. `likely` = 문자열과 구조(호출 관계)가 일치한다. `possible` = 문자열 히트만 있다.
- `status`: 정적 확인을 마쳤으면 `static-confirmed`, 아니면 `unverified`. `dynamically-confirmed` 는 사람이 격리 랩에서 소유 기기로 확인한 뒤에만 쓴다.
- `severity`: 기준은 다음과 같다.
  - `critical`: 인증 없이 네트워크에서 관리자·root 권한에 도달한다. 우회, 백도어 셸, 인증 전 명령 실행이 확인된 경우다.
  - `high`: 다음 중 하나다.
    - 인증 전 자격증명·해시 유출
    - 인증 후 명령 주입
    - 고정 root 비밀번호 + 실제로 기동되는 로그인 서비스
    - 서명 없는 업데이트 + 기술자 명령 실행
  - `medium`: 다음 중 하나다.
    - 고정 nonce·약한 토큰
    - 기동되지 않는 서비스의 고정 계정
    - 정적 키 설정 암호화
  - `low`/`info`: 확인되지 않은 앵커, 보호기법 부재.
- `category`: finding 어휘만 쓴다(서버가 다른 값을 거부한다). YAML·fwtriage 카테고리는 다음처럼 바꾼다.

| YAML/fwtriage 카테고리 | finding.category |
|---|---|
| `crypto` | `weak-crypto`. 업데이트 서명·무결성 문제면 `insecure-update` |
| `memory-safety` | `memory-corruption` |
| `path-traversal` | 파일 읽기 피해면 `info-leak`, 인증 우회로 이어지면 `auth-bypass` |
| `session-token` | `auth-bypass` 또는 `weak-crypto` |
| 빈 기본 비밀번호 | `insecure-default` |
| 나머지(auth-bypass, backdoor, hardcoded-credential, command-injection, debug-interface, info-leak) | 같은 이름 |

- `references`: CVE 는 근본 원인이 일치하고, 이 기기의 벤더·제품군이 그 CVE 의 영향 범위에 들 때만 넣는다. 함께 `docs/references/cctv-vuln-patterns.md#<절>` 을 넣는다.
  - 다른 벤더에서 같은 패턴을 찾았으면 CVE 를 references 에 넣지 않는다. `reasoning` 에 "P4, CVE-2021-33044 계열" 처럼 계열로만 적는다. 보고서는 references 를 "이 기기가 해당 CVE 영향을 받는다"로 읽히게 싣기 때문이다.
  - CVE 미확인 이슈는 CVE 대신 그 문서에 적힌 출처 URL 을 넣는다.
- `reasoning`: 패턴 클래스(P1~P12), 근거 함수·주소, CVE 대응 여부를 적는다. 빌드 비교를 했는지와 그 결과도 적는다(안 했으면 "빌드 비교 미실시").
- `verification_plan`: [cctv-vuln-patterns.md §7.1](../../docs/references/cctv-vuln-patterns.md) 의 방법만 쓴다.
  - 빌드를 비교한다.
  - 수정 전후 펌웨어를 디컴파일해 diff 한다.
  - 기기 자신의 리슨 포트 목록을 본다.
  - 무자격 요청이 401/403 으로 거부되는지 보는 negative test 를 한다.
  - 경로 순회·퍼징·백도어 활성화·조작된 업데이트 업로드는 하지 않는다.

### 0.4 계열별 우선 순서

| vendor_family | 먼저 볼 항목 | 주 대상 바이너리 |
|---|---|---|
| `hikvision-like` | AH-01(ISAPI/PSIA/HikCGI/Genetec 핸들러 인증 비대칭), AH-04(webLanguage), AH-03(configurationFile, PSIA), AH-11 | davinci 또는 centaurus (커뮤니티 출처의 이름) |
| `dahua-like` | AH-02(global.login 분기), AH-03(/current_config/, 37777 opcode, pass-the-hash), AH-09, AH-11(/videotalk, ONVIF) | sonia, Challenge |
| `xiongmai-like` | AH-07(9530/9527), AH-01(만능 비밀번호), AH-08, AH-10(InstallDesc/UpgradeCommand), AH-06(uc-httpd), AH-03(34567 메시지 디스패치) | Sofia, dvrHelper, macGuarder |
| `hisilicon-oem` | AH-01(인증 함수 리터럴), AH-05·AH-06(부분 문자열 정적 파일 판별), AH-07(telnetd, remserial), AH-08 | box.* 웹 앱, 벤더 웹 서버 |
| `ingenic-oem` / `generic` / `unknown` | AH-08 → AH-07 → AH-05 → AH-04 → AH-02 → 나머지 | boa/goahead/lighttpd/thttpd/mini_httpd/uhttpd/httpd/nginx 와 CGI |

벤더 계열과 관계없이 AH-01 ~ AH-12 는 모두 판정한다. 해당 기능이 없으면 `not-applicable` 로 남긴다.

### 0.5 strip 된 정적 바이너리 읽기 (합성 테스트 픽스처(zig ARM)에서 확인)

- 카메라 메인 앱은 대개 정적 링크에 strip 되어 있다. fw_elf_info 의 `imports` 가 비고 `risk.heuristics` 도 빈다(`elf.static: true`, `elf.stripped: true`).
  이 경우 위험 함수 판정은 REA 로 한다.
- libc 함수도 `FUN_xxxxxxxx` 로 보인다. 모양으로 구분한다.
  - strcmp 형: 포인터 두 개를 받고 결과를 `== 0` / `!= 0` 으로 검사한다.
  - sprintf 형: (버퍼, 포맷 리터럴, 인자…) 를 받는다.
  - system/popen 형: 내부에서 `/bin/sh` 바이트를 참조한다.
- find_xrefs_to_name(name="system") 은 이런 바이너리에서 `{"status": "unresolved", "reason": "name_not_found"}` 를 돌려준다. 다음 순서로 싱크를 찾는다.
  1. search_bytes(pattern="2f 62 69 6e 2f 73 68 00") 로 `/bin/sh` 바이트를 찾는다.
  2. xrefs(address=<match.address>) 로 참조 위치를 얻는다.
  3. resolve_containing_procedure(address=<참조 위치>) 가 돌려준 함수가 system/popen 형 싱크다.
  4. trace_call_path(start=<싱크>, direction="backward") 로 호출자 사슬(`edges`)을 올라간다.
- trace_feature / search_strings 가 비어도 바이트는 있을 수 있다(Ghidra 가 문자열로 정의하지 않은 경우). 이때는 search_bytes 로 확인한다.
- 문자열이 **로드 세그먼트 밖**(파일 끝에 덧붙은 데이터 등)에 있으면 fw_strings_hunt 는 찾지만 REA 는 찾지 못한다. 이 경우 코드 참조가 없는 것이므로 그 항목은 `inconclusive` 다.

---

## AH-01 매직·하드코딩 인증 토큰과 파라미터 — P4/P5 (CVE-2017-7921 계열)

- **찾는 것**: 인증 함수 안의 다음 네 가지.
  - (a) 특정 파라미터가 **존재하기만 하면** 인증을 생략하는 분기. 예: HikCGI 의 쿼리 파라미터를 base64 디코드한 뒤 사용자명만으로 신원을 정하고 비밀번호는 무시한다.
  - (b) 저장된 자격증명보다 **먼저** 리터럴 비밀번호와 비교하는 만능 비밀번호.
  - (c) 하드코딩 anonymous·백도어 자격증명.
  - (d) 바이너리에 박힌 Authorization 헤더.
- **1차 탐색 (fwtriage)**: fw_strings_hunt id 는 다음과 같다.
  - Hikvision: `hik-handler-families`, `hik-hikcgi-endpoints`, `hik-anonymous-hardcoded`, `hik-anonymous-hardcoded-raw`
  - XiongMai·HiSilicon 인코더·TVT: `xm-universal-password`, `hienc-backdoor-password`, `tvt-hardcoded-web-password`, `tvt-4567-handshake-guid`
  - 일반: `gen-hardcoded-basic-auth`, `gen-backdoor-keywords`
- **REA 질의**:
  - trace_feature(query="<히트 문자열>") 로 참조 함수를 얻고, procedure_pseudo_code(procedure="<주소>") 로 디컴파일한다.
  - Hikvision 이면 trace_feature(query="/Security/users"), trace_feature(query="/ISAPI/"), trace_feature(query="/PSIA/") 로 핸들러별 디스패처를 찾는다.
    네 계열(ISAPI, PSIA, HikCGI, Genetec)의 인증 함수를 나란히 비교한다. **한 곳에만 있는 "존재하면 생략" 분기**가 가장 강한 신호다.
  - 인증 함수를 찾는 보조 기법:
    - 기본 사용자명 리터럴(`admin`)의 xref (Kojenov)
    - "Users" 와 "Password" 관련 이름·문자열을 **동시에** 참조하는 함수 (tothi)
    - 로그인 RPC 이름(`global.login`, `/RPC2_Login`, `/doLogin`)의 xref
- **확인 형태 (match)**:
  - `if (FUN_x(pass, "<리터럴>") == 0) return 1;` 이 저장 해시 비교 **앞에** 있다.
  - 또는 파라미터 조회 → base64 디코드 → `:` 분리 → 세션 사용자 설정으로 이어지는 경로에 비밀번호 비교 호출이 없다.
- **반증·보류**:
  - 리터럴이 로그·UI 문자열로만 쓰인다.
  - 비교 결과가 실패 분기로만 간다.
  - 리터럴 비교 뒤에도 정상 검증이 계속된다.
  - 위 경우는 `no-match` 다. 문자열에 xref 가 없으면 `inconclusive` 다.
- **CVE 계열**: CVE-2017-7921(HikCGI 파라미터 존재 시 인증 생략), CVE-2013-4976(하드코딩 anonymous), CVE-2020-24215(인코더 인증 함수의 리터럴 비밀번호).
  XiongMai Sofia 만능 비밀번호와 TVT GUID 는 CVE 미확인이다. 출처 URL(tothi, bashis)만 적는다.
- **기록**:
  - 만능 비밀번호·존재만으로 생략: `backdoor` 또는 `auth-bypass`, 인증 전 도달이면 `critical`.
  - 내장 자격증명만 있고 코드 확인이 안 됨: `hardcoded-credential`, `possible`.
  - `location.function` 에는 REA 함수 이름(`FUN_000211e0` 등)과 주소를 둔다.

## AH-02 클라이언트 주장 값으로 인증 결정 — P4 (CVE-2021-33044/33045 계열)

- **찾는 것**: 다음 값이 비밀번호 검증 없는 성공 경로로 이어지는지 본다.
  - 요청 본문의 `clientType`·`loginType`·`authorityType`·`passwordType` 값
  - 클라이언트가 직접 써 넣은 `ipAddr`(loopback 자기 신고)
  - 쿠키 `uid`
  - Authorization 헤더 **부재**
  - 빈 URI 자격증명
  - 클라이언트 JS 에서만 하는 권한 검사
- **1차 탐색 (fwtriage)**:
  - fw_strings_hunt id: `dh-login-netkeyboard`, `dh-login-loopback-local`, `dh-login-fields`, `dh-rpc2-endpoints`, `dh-loginex-js`, `gen-loopback-trust-anchors`, `tbk-device-rsp`, `wificam-loginuse-loginpas`, `ptz-param-cgi`
  - loopback 리터럴은 patterns=["lit:127.0.0.1"] 로 찾는다. 결과 check id 는 `custom-lit-<해시 8자>` 이다(같은 패턴이면 항상 같은 id).
- **REA 질의**:
  - trace_feature(query="global.login"), trace_feature(query="NetKeyboard"), trace_feature(query="Loopback"), trace_feature(query="127.0.0.1")
  - 로그인 함수에서 analyze_function(procedure="<주소>") 를 호출하고 callees·referenced_strings 를 본다.
  - cctv-vuln-patterns.md §3.2 의 값 문자열마다 **비교 지점 → 그 분기가 부르는 검증 함수** 표를 만든다.
    "로컬" 판정 값이 어디서 왔는지 본다. accept/getpeername 의 소켓 주소인지, JSON 필드인지가 핵심이다.
- **확인 형태 (match)**: 합성 테스트 픽스처(zig ARM)의 실제 Ghidra 출력이다.

  ```
  iVar1 = FUN_0002711c(param_1,"NetKeyboard");
  if (iVar1 != 0) {
    iVar1 = FUN_0002711c(param_2,"Loopback");
    if ((iVar1 != 0) || (iVar1 = FUN_0002711c(param_3,"127.0.0.1"), iVar1 != 0)) {
      return FUN_00021160(iVar1,param_5);     /* 정상 비밀번호 검증 */
    }
  }
  return 1;                                     /* 검증 없이 성공 */
  ```

  일치하면 상수 성공을 반환하고, 검증 함수는 일치하지 않을 때만 호출된다. `param_3` 은 요청에서 온 값이다.
- **반증·보류**:
  - 모든 분기가 결국 같은 다이제스트 검증을 부른다.
  - "로컬" 판정이 소켓 peer 주소로 이루어진다.
  - 위 경우는 `no-match` 다. 디스패치가 간접 호출이라 분기를 다 열거하지 못하면 `inconclusive` 다.
- **CVE 계열**: CVE-2021-33044(NetKeyboard), CVE-2021-33045(Loopback/Local/ipAddr). 같은 클래스의 다른 사례는 다음과 같다.
  - CVE-2018-9995(쿠키 uid)
  - CVE-2024-8956(Authorization 헤더 부재 시 미적용)
  - CVE-2017-8225(빈 URI 자격증명, 경로 유형별 비대칭)
  - Dahua loginEx.js 의 로컬 전용 제한은 CVE 미확인이다.
- **기록**: `auth-bypass`. 인증 전 관리자 권한이면 `critical`. DHIP 와 HTTP 가 로그인 로직을 공유하는지 `reasoning` 에 적는다.

## AH-03 무인증 핸들러의 설정·해시 유출 — P3/P8 (CVE-2017-7925/7923 계열)

- **찾는 것**: 다음 다섯 가지.
  - 쓰기 가능한 설정 디렉터리에 URL 접두사가 그대로 매핑된다(예: `/current_config/` ↔ `/mnt/mtd/Config/`).
  - 정적 키로 "암호화"한 설정 export.
  - 저권한으로 받을 수 있는 설정 데이터.
  - 인증 없는 사용자·장비 정보 엔드포인트.
  - 세션 검증 **전에** 처리되는 바이너리 프로토콜 opcode·메시지 ID (37777, 34567).
  - 함께 볼 것: 저장 해시를 비밀번호처럼 받는 로그인(pass-the-hash).
- **1차 탐색 (fwtriage)**:
  - fw_strings_hunt id: `dh-current-config`, `dh-public-config-allowlist`, `gen-mtd-config-accounts`, `hik-configurationfile`, `hik-config-aes-key-raw`, `hik-config-aes-key-hex`, `hik-psia-configurationdata`, `dlink-config-getuser`, `tvt-querydevinfo`, `tvt-nvms-anchors`, `dh-videotalk`, `hienc-box-ini-password`, `wificam-ini-credential-files`
  - fw_rootfs_audit 의 `builtin-credential-db-symlink` 항목도 본다.
- **REA 질의**:
  - trace_feature(query="/current_config/"), trace_feature(query="/mnt/mtd/Config"), trace_feature(query="configurationFile")
  - 설정 AES 키: search_bytes(pattern="27 99 77 f6 2f 6c fd 2d 91 cd 75 b8 89 ce 0c 9a") → xrefs → export 루틴 (`fn-hardcoded-crypto-key`).
  - opcode 디스패처: inspect_native_api(procedure="<디스패처>") 의 jump-table case 매핑으로 핸들러 표를 만든다. 각 핸들러가 "인증됨" 플래그를 검사하는지 본다.
  - pass-the-hash: 로그인 함수에서 저장 해시와 입력을 직접 비교하는지 본다(`fn-login-hash-compare`).
- **확인 형태 (match)**:
  - URL → 파일 매핑 함수가 인증 함수를 부르기 전에 `/mnt/mtd/Config/...` 를 연다.
  - allowlist 가 공개 파일 두 개만 정의하지만 다른 이름도 같은 경로로 서빙된다.
  - AES 키 스케줄의 키 인자가 상수 주소다.
  - 픽스처에서 확인한 pass-the-hash 모양: `FUN_x(pass, <저장 해시 전역>) == 0` 이면 성공.
- **반증·보류**:
  - 매핑 앞에 세션 검사가 있다.
  - 파일명 allowlist 가 엄격하고 정규화 뒤에 비교한다.
  - 위 경우는 `no-match` 다. 디스패치 테이블을 복원하지 못하면 `inconclusive` 다(보고서 한계에 남김).
- **CVE 계열**: CVE-2017-7925, CVE-2017-7927(pass-the-hash), CVE-2017-7923(설정 백업 정적 키), CVE-2013-4975(PSIA 설정 데이터). 같은 클래스의 다른 사례는 다음과 같다.
  - CVE-2020-25078, CVE-2024-7339, CVE-2019-3948
  - CVE-2013-6117(37777 명령 무인가), CVE-2024-3765(34567 메시지 1009)
  - CVE-2017-6341, CVE-2017-6342, CVE-2017-6343
- **기록**:
  - 유출: `info-leak`, 인증 전 해시·비밀번호면 `high`. 관리자 탈취로 바로 이어지면 `critical`.
  - pass-the-hash·무인증 핸들러: `auth-bypass`.
  - 정적 키: `weak-crypto`.
  - verification_plan 은 정상 권한으로 내보낸 설정 파일을 오프라인에서만 검사하는 것과, 무자격 요청이 401/403/404 를 받는지만 적는다.

## AH-04 요청 파라미터 → system()/popen() 명령 주입 — P11 (CVE-2021-36260 계열)

- **찾는 것**: 요청이나 설정 값이 `sprintf` 류로 셸 명령 템플릿에 들어간 뒤 `system`/`popen`/`exec*` 로 실행된다. 값의 예는 다음과 같다.
  - 언어 코드, NTP 서버, DDNS, FTP 설정
  - 업로드 파일명, NIC 이름
  - 업그레이드 기술자의 Script
  - CGI 환경 변수 주입(GoAhead)도 이 항목이다.
- **1차 탐색 (fwtriage)**:
  - fw_strings_hunt id: `hik-sdk-weblanguage`, `gen-shell-cmd-template`, `gen-sh-c-template`, `foscam-ntp-server`, `ptz-ntp-addr`, `dlink-ddns-enc`, `wificam-ftp-cgi`, `xm-upgrade-descriptor`, `comp-goahead-version`
  - 동적 링크 바이너리는 fw_elf_info 의 `risk.heuristics` 에 `fn-command-exec`/`fn-command-build`/`fn-cgi-env-from-request` 가 잡힌다.
- **REA 질의**:
  - trace_feature(query="<히트한 템플릿, 예: ntpdate %s>") → 템플릿을 쓰는 함수 → procedure_pseudo_code.
  - 싱크를 찾는다. 동적 링크면 find_xrefs_to_name(name="system") / (name="popen") 이다. strip 된 정적 링크면 §0.5 의 `/bin/sh` 경로다.
  - 요청 핸들러에서 싱크까지 경로를 본다: trace_call_path(start="<핸들러>", goal="<싱크>", direction="forward"), trace_call_path(start="<싱크>", direction="backward").
- **확인 형태 (match)**: 픽스처의 실제 출력이다.

  ```
  FUN_00022e5c(auStack_88,"ntpdate %s",param_1);   /* sprintf 형 */
  FUN_0002196c(auStack_88);                         /* /bin/sh 를 참조하는 system 형 싱크 */
  ```

  `param_1` 이 요청 값이고, 사이에 화이트리스트, 메타문자 필터, 숫자·IP 형식 검사가 없다.
  이 핸들러가 인증 검사 **전**에 디스패치되면 인증 전 명령 실행이다.
- **반증·보류**:
  - 값이 고정 목록과 비교된다(예: 언어 코드 집합).
  - `inet_aton` 같은 엄격한 형식 검사를 통과해야 한다.
  - 인자 배열로 `execv` 를 부른다(셸 없음).
  - 위 경우는 `no-match` 다. 이름 해석 성공(`gethostbyname`)을 입력 검증으로 쓰는 코드는 이 패턴으로 본다(CVE-2018-6831 사례).
- **CVE 계열**: CVE-2021-36260(webLanguage, 인증 전). 같은 클래스의 다른 사례는 다음과 같다.
  - CVE-2022-45045(34567 업그레이드 Script, 인증 필요)
  - CVE-2018-6831 / CVE-2017-2849(ntpServer)
  - CVE-2024-8957(ntp_addr), CVE-2020-25079(ddns_enc.cgi)
  - CVE-2017-17562(GoAhead CGI 환경 변수)
- **기록**: `command-injection`. 인증 전이면 `critical`, 인증 후면 `high`. 명령 템플릿 문자열과 싱크 주소를 evidence 에 남긴다. 주입 문자열은 쓰지 않는다.

## AH-05 정적 파일·URL 접두사 allowlist 가 인증을 건너뜀 — P1

- **찾는 것**:
  - 인증 미들웨어 앞의 "정적 리소스면 통과" 분기. 확장자·접두사·부분 문자열 비교(`strstr`, `std::string::find`, `strncmp(uri, "/prefix", n)`)를 정규화 전 원문 URI 에 대해 한다.
  - Content-Type(`multipart/form-data`)만 보고 인증 전에 업로드 처리로 가는 분기.
- **1차 탐색 (fwtriage)**: fw_strings_hunt id 는 `foscam-uri-substring-delete`, `wificam-ini-credential-files`, `dh-public-config-allowlist`, `dh-current-config` 다.
  - REA 판정 기준: function_heuristics `fn-uri-substring-match`. fw_strings_hunt 선택자가 아니다(넘기면 리터럴 검색이 된다).
- **REA 질의**:
  - 401 응답을 만드는 함수에서 출발한다: trace_feature(query="401"), trace_feature(query="WWW-Authenticate"), trace_feature(query="Unauthorized").
  - 그 함수의 호출자(procedure_callers)가 요청 디스패처다.
  - 디스패처를 procedure_pseudo_code 로 읽고, 인증 호출보다 **앞에** 있는 return/goto 분기를 모두 표로 만든다.
- **확인 형태 (match)**: 픽스처 모양이다.
  `if (strstr(uri, ".js")) return serve_file(uri); if (strncmp(uri, "/current_config/", 16) == 0) return serve_file(uri); if (!authed) return 401;`
  부분 문자열이 경로 **어디에 있어도** 통과하고, 같은 경로로 민감 파일이 서빙된다.
- **반증·보류**:
  - 접두사 비교가 정규화된 경로에 대해 이루어지고, 공개 디렉터리에 민감 파일이 없다.
  - 위 경우는 `no-match` 다. 공개 파일만 노출되면 `low`/`info` finding 으로 둔다.
- **CVE 계열**: CVE-2020-24219, CVE-2018-6830, CVE-2017-8225, CVE-2017-7925(응급 수정의 하드코딩 allowlist), CVE-2020-24217(multipart 가 인증보다 먼저).
- **기록**: `auth-bypass`. 설정·자격증명 파일까지 닿으면 `high` 이상. AH-06 과 같은 함수면 finding 하나에 두 check 가 같은 `finding_id` 를 가리킨다.

## AH-06 인증 전 경로 순회 — P2

- **찾는 것**: `웹루트 + URI` 를 `sprintf("%s%s")`/`strcat`/`strncat` 으로 붙인다. 그 경로가 `realpath` 검증이나 `..` 제거 없이 `open`/`fopen`/`opendir`/`access`/`remove`/`sendfile` 로 간다. 디렉터리 목록 기능(`Index of`)이 있는지도 본다.
- **1차 탐색 (fwtriage)**:
  - fw_strings_hunt id: `comp-mini-httpd-version`, `foscam-uri-substring-delete`, `hienc-box-ini-password`(순회로 유출되는 대상)
  - 디렉터리 목록 템플릿은 patterns=["lit:Index of"] 로 찾는다.
- **REA 질의**: trace_feature(query="Index of"), trace_feature(query="/mnt/web")(XiongMai 웹 루트). 파일 서빙 함수를 procedure_pseudo_code 로 읽는다. 판정 기준은 `fn-path-ops-unnormalized` 다.
- **확인 형태 (match)**: 픽스처 모양이다. `sprintf(path, "/mnt/web%s", uri); f = fopen(path, "rb");`
  `..` 처리가 없고, 이 함수가 인증 검사 전(AH-05 분기)에 도달 가능하다.
- **반증·보류**: `realpath` 결과가 웹 루트 접두사로 시작하는지 검사한다. 이 경우 `no-match` 다.
- **CVE 계열**: CVE-2017-7577(uc-httpd), CVE-2019-20085, CVE-2020-24219, CVE-2018-6830(파일 삭제), CVE-2018-18778(mini_httpd).
- **기록**: 파일 읽기 피해면 `info-leak`, 자격증명 파일로 이어지면 `auth-bypass`.
  verification_plan 은 **정적 확인만** 적는다. 동적 순회 시험은 하지 않는다(cctv-vuln-patterns.md §7.1).

## AH-07 디버그·백도어 서비스 — P6 (XiongMai 9530 계열)

- **찾는 것**:
  - 특수 포트 데몬이 명령 문자열을 받으면 telnetd 를 켜거나 디버그 포트를 연다. 예: 9530 macGuarder/dvrHelper, 787 TelnetSwitch, 7788 maintain, 4567, 6789.
  - telnetd 가 부팅 때 무조건 기동된다. `telnetd -l /bin/sh` 처럼 무로그인 셸을 준다.
  - inittab 의 무로그인 콘솔 셸, `getty -l /bin/sh`.
  - `remserial` 로 UART 를 TCP 로 브리지한다.
  - 앱 콘솔(9527)의 `shell` 명령.
- **1차 탐색 (fwtriage)**:
  - fw_strings_hunt id:
    - XiongMai: `xm-opentelnet-cmd`, `xm-opentelnet-handshake`, `xm-telnetoempasswd`, `xm-default-psk`, `xm-backdoor-daemons`
    - 기타 벤더: `herospeed-telnetswitch`, `unv-maintain-daemon`, `unv-uvsh`, `tvt-nvms-anchors`, `tvt-4567-handshake-guid`
    - 일반: `gen-telnetd-launch`, `gen-telnetd-login-shell`, `gen-inittab-console-shell`, `gen-getty-autologin`, `gen-inetd-telnet`, `gen-debug-telnet-keywords`
  - fw_rootfs_audit 항목: `builtin-remserial`, `builtin-netcat-shell`, `builtin-socat-exec-shell`, `builtin-tcpsvd-shell`, `builtin-login-f-root`, `builtin-agetty-autologin`, `builtin-dropbear-blank-password`, `builtin-exec-from-writable-storage`, `builtin-world-writable-startup`. 응답의 `services[]` 도 본다.
- **REA 질의**:
  - trace_feature(query="OpenTelnet:OpenOnce"), trace_feature(query="TelnetOEMPasswd"), trace_feature(query="telnetd")
  - 데몬의 수신 루프를 analyze_function 으로 읽는다. bind/htons 인자 상수를 본다: 9530 = 0x253A, 9527 = 0x2537. 네트워크 바이트 순서로 저장되었으면 바이트가 뒤집혀 있다. 판정 기준은 `fn-debug-listener-ports` 다.
- **확인 형태 (match)**:
  - 수신 버퍼를 명령 문자열과 비교한 뒤 telnetd 실행이나 디버그 포트 개방으로 간다.
  - PSK 는 파일에서 읽고, 파일이 없으면 기본값(`xm-default-psk`)을 쓴다.
  - init 스크립트·inittab 줄은 부팅 체인(rcS → 하위 스크립트)에서 실제로 실행되는지 확인되면 그 자체로 `match`(`confirmed`)다.
- **반증·보류**:
  - 문자열만 있고 코드 참조가 없다. 이 경우 `inconclusive` 다. 픽스처에서 로드 세그먼트 밖 문자열이 이렇게 나왔다.
  - 스크립트가 어디서도 호출되지 않으면 `low` 로 낮춘다.
- **CVE 계열**: CVE-2020-22253(9530 무인증 telnet), CVE-2021-41506(macGuarder/dvrHelper 정적 root 자격증명), CVE-2021-45039(Uniview 7788 → telnetd). 기본 실행 telnetd 사례는 CVE-2017-8224, CVE-2020-24218 이다.
  다음은 CVE 미확인이다: Herospeed 787, TVT 4567, Dahua 6789, XiongMai 9527 콘솔.
- **기록**:
  - 무인증 원격 셸: `backdoor`, `critical`.
  - UART·로컬 콘솔 셸: `debug-interface`, `high`/`medium`.
  - verification_plan 은 포트 인벤토리(기기 자신의 리슨 목록)와 rootfs 문자열 검사만 적는다. **백도어 활성화는 시도하지 않는다.**

## AH-08 하드코딩·기본 계정 — P5

- **찾는 것**:
  - passwd/shadow 의 고정 DES·MD5-crypt 해시, 빈 비밀번호, root 외 UID 0 계정, 공개된 하드코딩 해시
  - 설정 DB 기본값: Sofia 계정 파일, 빈 admin, 숨은 default 계정
  - 시작 스크립트의 chpasswd 리터럴, httpd.conf 자격증명, telnetd 고정 계정
- **1차 탐색 (fwtriage)**:
  - fw_rootfs_audit 항목:
    - passwd/shadow 형태: `passwd-empty-password`, `passwd-hash-in-passwd`, `passwd-des-crypt`, `passwd-md5-crypt`, `passwd-extra-uid0`
    - 공개 해시: `known-hash-xm-root-xc3511`, `known-hash-tvt-root-a`, `known-hash-tvt-root-b`, `known-hash-hienc-root-unisheen`, `known-hash-hienc-root-neworang`, `known-hash-hienc-root-neworangetech`, `known-hash-wificam-root`
    - 설정 값: `sofia-empty-password-hash`, `config-weak-password-value`, `known-default-password-candidates`
    - 내장 규칙: `builtin-default-password`, `builtin-empty-password`, `builtin-weak-hash`, `builtin-chpasswd-literal`, `builtin-busybox-httpd-auth`, `builtin-config-password`, `builtin-xml-password`, `builtin-url-credential`
  - fw_strings_hunt id: `xm-default-user-tluafed`, `xm-empty-password-hash`, `xm-default-psk`, `tvt-hardcoded-web-password`
  - fw_crack_hashes(case_id=..., source_path="extract/rootfs-001/etc/passwd") 로 공개 기본 비밀번호 사전과 **오프라인** 대조한다. 응답의 평문은 마스킹된다. Sofia 8자 해시는 hash_type="xm-sofia" 를 준다.
- **REA 질의**: 로그인 함수에서 기본 계정 이름이나 해시 리터럴과 비교하는지 본다. trace_feature(query="<히트 문자열>") 를 쓴다.
- **확인 형태 (match)**: 실행되는 passwd/shadow 줄이나 설정 기본값 자체가 증거다. 그 계정이 **실제로 쓰이는 로그인 경로**가 있는지 AH-07 결과와 묶는다. 경로의 예는 telnetd, dropbear, login, 웹 로그인이다.
- **반증·보류**:
  - 해시가 잠긴 계정(`*`, `!`)이다.
  - 로그인 서비스가 없다. 이 경우 `medium` 이하다.
  - fw_crack_hashes 의 `not_cracked` 는 "안전함"이 아니다.
- **CVE 계열**: CVE-2021-41506(YAML 이 xc3511 고정 root 해시와 연결), CVE-2020-24218, CVE-2017-8224, CVE-2013-3612, CVE-2017-8226, CVE-2018-17919(숨은 default 계정), CVE-2021-45039(telnetd 고정 계정), CVE-2022-45045(NVD 설명의 기본 admin 해시).
  TVT 하드코딩 root 해시는 CVE 미확인이다.
- **기록**:
  - 고정 자격증명: `hardcoded-credential`.
  - 빈 기본 비밀번호: `insecure-default`.
  - 추가 UID 0: `backdoor`.
  - 비밀번호·해시는 evidence excerpt 에 마스킹해서 넣는다(예: `root:absxcf…`). reveal=true 는 운영자가 자기 기기 로그인에 꼭 필요할 때만 쓴다.

## AH-09 약하거나 예측 가능한 세션·nonce·토큰 — P7

- **찾는 것**:
  - `WWW-Authenticate` 포맷 문자열에 박힌 고정 Digest nonce
  - `srand(time())` → `rand()` 세션 ID
  - 서버 challenge 가 없어 재전송되는 로그인
  - WS-Security nonce 캐시와 `Created` 신선도 검사 부재
  - 저장 해시 자체가 자격증명 역할을 하는 구조(AH-03 과 교차)
  - MAC 파생 클라우드 ID
- **1차 탐색 (fwtriage)**: fw_strings_hunt id 는 `gen-static-digest-nonce`, `gen-onvif-wsse-anchors` 다.
  - REA 판정 기준: function_heuristics `fn-weak-token-generation`, `fn-login-hash-compare`. fw_strings_hunt 선택자가 아니다.
- **REA 질의**:
  - trace_feature(query="WWW-Authenticate"), trace_feature(query="nonce="), trace_feature(query="UsernameToken"), trace_feature(query="PasswordDigest")
  - 세션 생성 함수의 callees 에 시간·난수 함수 형태가 있는지 본다.
- **확인 형태 (match)**:
  - nonce 가 상수 리터럴이다.
  - 세션 ID 를 time/rand 로만 만든다.
  - ONVIF 다이제스트 비교 뒤에 `Created` 와 현재 시각의 차이 비교, nonce 재사용 검사가 없다.
- **반증·보류**: 서버 생성 난수(`/dev/urandom` 등)가 challenge 에 들어간다. 이 경우 `no-match` 다.
- **CVE 계열**: CVE-2022-30563(ONVIF 재전송), CVE-2022-30561(웹 로그인 재전송), CVE-2017-7927, CVE-2017-6343, CVE-2018-17917(MAC 파생 Cloud ID).
- **기록**: `auth-bypass` 또는 `weak-crypto`, 기본 `medium`. 재전송으로 관리자 생성까지 가능하면 `high`.

## AH-10 서명 없는 펌웨어 업데이트 경로 — P10

- **찾는 것**:
  - 업데이트 이미지를 적용하기 전에 서명 검증(RSA/ECDSA verify)이 없다.
  - 호환성·CRC 검사를 건너뛰게 하는 특수값이 있다(`SkipCheck`).
  - 업데이트 기술자의 명령이 실행된다(`InstallDesc`/`UpgradeCommand` 의 Script).
  - 업데이트 채널이 평문이다.
- **1차 탐색 (fwtriage)**: fw_strings_hunt id 는 `xm-upgrade-descriptor`, `xm-upgrade-skipcheck`, `xm-upgrade-server` 다.
  - REA 판정 기준: function_heuristics `fn-hardcoded-crypto-key`. fw_strings_hunt 선택자가 아니다.
  - **SD 카드 업데이트 경로**: `fw_sd_surface` 의 SD-02(카드에서 서명 없는 업데이트 — U-Boot `sdupdate`·`do_auto_update`·`au_check_cksum_valid`,
    사용자 공간의 카드 → `/dev/mtd*` 쓰기)와 SD-03(U-Boot 의 mmc 부팅·카드 스크립트, `verify=n`)을 같은 판정에 넣는다.
    `fit_security`의 서명/키 선언 존재·부재나 `verify=n` 환경값 하나로 match/pass를 정하지 않는다. 구조 검사 한계와 실제 빌드·키 신뢰·검증 호출 경로를 따로 확인한다.
    CRC 만 비교하고 쓰면 match 다. 물리 버튼·GPIO 로만 열리고 같은 파일에 원격 쓰기 경로가 없으면 심각도를 낮춘다.
    카드에 넣을 업데이트 파일·스크립트를 만들지 않는다(설계 docs/design/sd-forensics.md §1 범위 밖).
- **REA 질의**:
  - trace_feature(query="UpgradeCommand"), trace_feature(query="InstallDesc"), trace_feature(query="SkipCheck")
  - 검증 함수: find_xrefs_to_name(name="RSA_verify") 처럼 심볼이 있을 때만 쓴다. strip 되었으면 trace_feature(query="BEGIN PUBLIC KEY") 로 찾는다.
  - 업그레이드 파서 → 플래시 쓰기 경로의 호출 순서를 trace_call_path 로 본다.
- **확인 형태 (match)**:
  - 헤더 파싱 → CRC 만 비교 → 쓰기 순서이고, 그 사이에 검증 호출이 없다.
  - 특수값과 일치하면 검사 블록을 건너뛴다.
  - JSON 의 Script 값이 system 형 싱크로 간다(AH-04 와 교차).
  - 문자열 블랙리스트(`strstr(..., "telnetd")`)만 있는 것도 기록한다.
- **반증·보류**:
  - 업데이트 처리 바이너리가 rootfs 에 없다(별도 파티션·부트로더). 이 경우 `inconclusive` 이고 coverage_gaps 에 남긴다.
  - 서명 검증이 쓰기보다 먼저 일어난다. 이 경우 `no-match` 다.
- **CVE 계열**: CVE-2022-45045(Script 실행, SkipCheck), CVE-2018-17915(평문 업데이트 채널), CVE-2020-24217(업로드 스크립트 즉시 실행).
  "업데이트 무결성 미검사"(SEC Consult SA-20181009-0)와 Hikvision 의 난독화만 적용(Monte Crypto)은 별도 CVE 가 없다. 출처만 적는다.
- **기록**: `insecure-update`. 기술자 명령 실행은 `command-injection` 으로 따로 남긴다.
  verification_plan 에 조작된 업데이트 업로드를 넣지 않는다(벽돌화 위험). 정적 확인과 빌드 비교만 적는다.

## AH-11 ONVIF/RTSP 인증 누락·약화 — P9

- **찾는 것**:
  - RTSP `DESCRIBE`/`SETUP`/`PLAY` 를 인증 상태 확인 없이 처리한다.
  - 설정된 비밀 스트림 경로를 무시한다.
  - ONVIF 서비스별 인증 요구 수준이 다르다(스냅샷 URI 등).
  - 인증 없는 음성·영상 엔드포인트가 있다.
  - 재전송 가능한 WS-UsernameToken(AH-09 와 교차).
- **1차 탐색 (fwtriage)**: fw_strings_hunt id 는 `wificam-rtsp-av0`, `gen-onvif-wsse-anchors`, `dh-videotalk`, `hik-hikcgi-endpoints`(`/onvif-http/snapshot`) 다.
- **REA 질의**:
  - trace_feature(query="DESCRIBE"), trace_feature(query="RTSP/1.0"), trace_feature(query="GetSnapshotUri"), trace_feature(query="UsernameToken")
  - RTSP 메서드 디스패처를 procedure_pseudo_code 로 읽는다.
- **확인 형태 (match)**:
  - 메서드 분기에서 인증 함수 호출이 없거나 결과를 무시한다.
  - 스트림 경로 비교가 설정값을 쓰지 않는다.
  - ONVIF 핸들러 표에서 일부 서비스가 WS-Security 검사를 건너뛴다.
- **반증·보류**:
  - RTSP/ONVIF 문자열·코드가 분석한 어느 바이너리에도 없으면 `not-applicable` 이다(근거: strings-hunt 결과 경로).
  - 별도 스트리밍 데몬을 분석하지 못했으면 `inconclusive` 다.
- **CVE 계열**: CVE-2017-8223, CVE-2020-24216, CVE-2019-3948, CVE-2022-30563. RTSP 헤더 오버플로는 AH-12 에서 기록한다.
- **기록**: `auth-bypass`(무인증 스트림·제어), 스트림 열람만이면 `medium`/`high`.

## AH-12 인증 전 메모리 안전성 결함 기록 — P12 (보조)

- **찾는 것**:
  - 요청 파서가 URI, 헤더(CSeq, Range, Authorization), 로그인 필드, base64 디코드 결과를 고정 크기 스택·전역 버퍼에 길이 검증 없이 복사한다(`strcpy`/`sprintf`/폭 없는 `sscanf`).
  - 바이너리 보호기법(NX, 카나리, PIE)이 없다.
- **1차 탐색 (fwtriage)**: fw_elf_info 의 `elf.hardening`(nx, relro, pie, stack_canary), `risk.unbounded_scanf_formats`, 동적 링크면 위험 임포트를 본다. REA 단계의 판정 기준은 `fn-unsafe-copy`, `fn-unbounded-scanf`, `fn-base64-auth-decode` 다.
- **REA 질의**: AH-05·AH-06 에서 찾은 요청 파서와 로그인 함수를 analyze_function 으로 연다. 고정 버퍼(`auStack_88 [128]` 형태)에 요청 값이 sprintf·strcpy 형 호출로 들어가는지 기록한다.
- **확인 형태**: 버퍼 크기와 복사 길이 사이에 검사가 없다. 픽스처 예: `sprintf(path, "/mnt/web%s", uri)` → 256바이트 스택 버퍼.
- **반증·보류**:
  - `snprintf` 와 크기 인자가 맞다.
  - 앞단에 길이 검사가 있다.
  - **퍼징·크래시 재현은 하지 않으므로** 대부분 `likely`/`possible` 에 머문다.
- **CVE 계열**: CVE-2018-10088, CVE-2022-45460, CVE-2020-24214, CVE-2017-3223, CVE-2021-45039, CVE-2017-16725, CVE-2013-4977, CVE-2014-4880, CVE-2022-26259.
  CVE-2017-16725 와 CVE-2018-10088 은 버퍼 오버플로이며 하드코딩 자격증명 CVE 가 아니다(cctv-vuln-patterns.md §1).
- **기록**: `memory-corruption`. verification_plan 은 빌드 비교와 정적 확인만 적는다(장비 손상·watchdog 재부팅 위험).
