# Android 펌웨어와 논리 증거 분석

이 문서는 증분 D의 범위와 해석 한계를 설명한다. 도구 계약은 [architecture.md](../architecture.md) §6.6·§6.8이다.

## 입력 경계

펌웨어와 증거는 서로 다른 입구를 유지한다. 벤더 펌웨어나 소유 기기 덤프는 fwtriage로, 사람이 획득한 휴대폰 자료는 forensics 접수로 받는다. 증거를 펌웨어 폴더로 복사하는 연결은 제공하지 않는다.

| 입력 | 지원하는 작업 |
|---|---|
| 일반 케이스의 Android 펌웨어 | 형식 식별, raw GPT·LP 분할, 이미 추출된 설정의 AN 정적 점검 |
| 증거 TAR/ZIP | 멤버 목록·해시·선택 추출, 선택한 DB·정지 그림 분석 |
| 증거 FAT/exFAT | 기존 파일 목록·삭제 파일 후보, 선택한 DB·정지 그림 분석 |
| 증거 SQLite 파일 자체 | 구조·앱 기록 분석; WAL/journal이 필요하면 같은 아카이브·파일 시스템에 묶어 접수 |
| ext4/EROFS/F2FS, sparse-wrapped 분할 | 새 파일 시스템 엔진·sparse 펼치기는 제공하지 않음 |

E01·분할 묶음, 실기기 획득 자동화, 잠금·암호화 우회, 쓰기는 포함하지 않는다. 파일 내용 중 SMS·통화·연락처·브라우저 기록과 정지 이미지의 모델 전달은 허용한다. 영상·음성은 계속 사람이 확인한다.

## 펌웨어 형식과 AN 점검

`fw_identify`는 sparse의 저장 구조, Android boot v0–v4, vendor_boot v3/v4, init_boot 후보, vbmeta, LP, F2FS 후보를 식별한다. init_boot는 별도 매직이 없으므로 boot v4의 kernel 크기와 이름에 근거한 후보다. sparse의 확장 데이터 CRC는 검사하지 않았다고 기록하며, vbmeta 헤더·해시는 AVB 서명 검증이나 실제 Secure Boot 상태를 증명하지 않는다.

`fw_carve`의 `layout_source="auto"|"mtd"|"gpt"|"lp"`, `lp_slot=0`, `max_output_bytes="4G"`로 배치를 선택한다. 명시한 기존 partitions/mtdparts 인자는 유지한다. GPT는 기존 pweh.fs 파서를 재사용하고, LP는 펌웨어 범위의 LINEAR/ZERO extent를 스트리밍한다. 선택 슬롯을 활성 슬롯이라고 부르지 않는다. 외부 block device가 필요한 extent·손상된 표·metadata-only 이미지는 없는 데이터를 만들어 채우지 않는다. sparse로 감싼 GPT/LP의 분할은 미지원이다.

`fw_android_surface`는 이미지 또는 이미 추출된 rootfs를 읽고 다음을 기록한다. 코드·init 조건·SQL·APK를 실행하지 않는다.

| ID | 확인하는 근거 | 해석 범위 |
|---|---|---|
| AN-01 | ADB TCP·USB 설정·서비스 | 실제 접근 가능성은 미확인 |
| AN-02 | debuggable·secure·eng/userdebug | 기본 root 동작을 단정하지 않음 |
| AN-03 | test-keys 문자열 | 실제 서명 검증과 구분 |
| AN-04 | SELinux permissive 설정·명령 | compiled sepolicy는 미해석 |
| AN-05 | AVB 비활성화 flags | flags 0은 보호 동작의 증명이 아님 |
| AN-06 | init 서비스 권한·소켓·capability | root 서비스 자체는 정상일 수 있는 목록 근거 |
| AN-07 | OTA 키·검증 설정 단서 | 키 존재만으로 검증 강제를 확정하지 않음 |
| AN-08 | priv-app·partition별 권한 XML | 특권 앱 자체를 취약점으로 보지 않음 |
| AN-09 | 하드코딩 자격증명 후보 | 값은 마스킹하고 로그인하지 않음 |

`found/not-found/unknown`은 검사별 범위와 함께 읽는다. 입력 누락·오류·한도 때문에 보지 못한 부분은 unknown이다. not-found는 완전히 본 관련 입력에서 규칙이 없었다는 뜻이다.

형식 근거는 AOSP의 [boot header](https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h), [sparse](https://android.googlesource.com/platform/system/core/+/refs/heads/main/libsparse/sparse_format.h), [LP metadata](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/include/liblp/metadata_format.h), [AVB header](https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_vbmeta_image.h)다. 의미 점검은 [Android init](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md), [release signing](https://source.android.com/docs/core/ota/sign_builds), [privileged permission allowlist](https://source.android.com/docs/core/permissions/perms-allowlist)를 따른다.

## 아카이브와 제자리 참조

아카이브를 호스트 디렉터리에 그대로 풀지 않는다. 파일명·링크·sparse 항목·암호화·압축 방법·크기와 비율을 확인하고 선택한 일반 파일만 기존 recovered 출력 규칙으로 쓴다. ZIP central directory와 TAR 확장 헤더도 읽기 전에 상한을 확인한다. 중복 이름은 `arc:<ordinal>`로 구분하며 모호한 path는 거부한다. 목록의 멤버 SHA256을 끝까지 계산하지 못했으면 null·미검증 상태와 사유를 남긴다. 타임라인용 목록은 내용 해시를 계산하지 않는다. 형식 근거는 [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)다.

접수는 기본 `storage="copy"`다. `storage="reference"`는 `forensics.reference_roots`가 허용한 폴더에 있는 일반 파일과 실제 읽기 전용 마운트(`ST_RDONLY`)에서만 허용한다. 기본 허용 목록은 비어 있다. 외부 파일을 chmod·이동·삭제하지 않으며, 위치는 케이스의 접수 기록과 보관 기록에만 둔다. 열 때마다 현재 허용 목록·읽기 전용 상태·지문을 확인한다. 참조 증거를 포함한 evidence-list는 전체 재해시 job을 마친 뒤 확인서를 만든다. 정책상 더 읽을 수 없는 경우와 바이트 무결성 실패를 구분한다.

## SQLite·앱 기록

순수 파서가 [SQLite 파일 형식](https://www.sqlite.org/fileformat2.html)의 header, B-tree, record, overflow, freelist, WAL을 읽는다. 증거 DB를 SQLite 라이브러리로 열지 않고 SQL을 실행하지 않는다. DB/WAL/journal은 각각64MiB 이하, 한 호출은 선택·읽기부터45초다. 페이지·셀·스키마·payload·기록 수와 누적 TEXT 8 MiB·저장 JSON 16 MiB를 함께 제한한다. 파서 본문은 15 MiB로 제한해 출처·호출 인자 공간을 남긴다. BLOB은 길이와 해시만 반환한다.

`forensics_sqlite_inventory`는 구조·테이블별 행 수를 반환한다. 완주한 테이블만 row_count가 숫자이며, 손상·한도·미지원은 null과 count_complete=false다. 이 수는 도달 가능한 물리 레코드 수이며 SQL integrity_check·collation 검증을 대신하지 않는다. `forensics_android_artifacts`는 스키마가 맞는 SMS·통화·연락처·브라우저만 정형화한다. 프로필을 인식하지 못했다고 기록이 없다는 뜻은 아니다. 기본 반환 상한은500개, 요청 가능한 최대는10000개다.

WAL은 동일 EV·디렉터리의 대응 파일을 사용자가 선택한다. checksum·salt·마지막 유효 commit을 확인한 overlay와 과거 프레임 후보를 구분한다. checksum은 DB와의 암호학적 결속을 증명하지 않는다. 현재 DB에 옛 프레임을 덮어 과거 전체 snapshot을 재구성했다고 주장하지 않는다. freelist 후보는 소유 테이블·스키마를 모를 수 있으므로 삭제 확정이나 임의의 앱 필드로 해석하지 않는다. 조인은 같은 snapshot 안에서만 한다. 삭제 파일 복구 등 입력 DB 자체가 불확실하면 분석 상태와 기록·사건의 신뢰도에도 이를 전파한다. current는 선택한 DB snapshot 안의 상태이며 원본 매체에서 살아 있는 파일이라는 뜻이 아니다.

앱 스키마는 [AOSP TelephonyProvider](https://android.googlesource.com/platform/packages/providers/TelephonyProvider/+/refs/heads/main/src/com/android/providers/telephony/MmsSmsDatabaseHelper.java), [ContactsProvider](https://android.googlesource.com/platform/packages/providers/ContactsProvider/+/master/src/com/android/providers/contacts/ContactsDatabaseHelper.java), [CallLog](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/provider/CallLog.java), [Chromium history](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/history/core/browser/visit_database.cc)에 근거한다. 벤더·앱 버전 차이는 미지원으로 남길 수 있다. DDL은 제한된 문법으로만 매핑하며 표현식·기본값 타입 변환을 확정할 수 없으면 unknown으로 남긴다.

## 타임라인·보관 기록

파일 시각과 명시한 앱 분석 JSON의 사건을 합친다. 원시값·단위·epoch·time_basis와 출처를 보존한다. FAT·ZIP DOS처럼 시간대가 없는 값은 UTC로 추정하지 않고 undated_events에 둔다. Chromium의1601년 epoch microseconds와 Unix epoch milliseconds를 값의 자릿수로 추측하지 않는다. 한도에 걸린 관찰 사건을 전체 자료의 첫/마지막 사건이라고 하지 않는다.

새 분석 JSON은0444로 저장하고 `sqlite-inventory`·`android-artifacts`·`timeline` 보관 기록에 EV 입수 해시·선택 파일 해시·출력 해시를 결속한다. 커밋 직전 동일 fd와 현재 접수 기록을 다시 확인한다. 커밋 전 실패는 이번 출력만 지우고, 커밋 후 보조 색인 실패는 보존하며 경고한다. 타임라인이 읽는 분석도 같은 EV의 기록된 경로·크기·SHA256·스키마가 맞아야 한다. 미기록 JSON의 경로를 따라가지 않는다.

혼합 파티션 이미지에서 해석하지 못한 파티션은 `call.partitions_unexamined`와 `unsupported_partitions`로 센다. 결과가 불완전하면 “흔적 없음”으로 보고하지 않는다. 테스트는 합성 증거와 고정 구조를 사용하며 실제 휴대폰 표본에 대한 검증을 대신하지 않는다.
