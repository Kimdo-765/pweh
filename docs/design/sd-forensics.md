# 설계안: SD 카드 포렌식 (증거 분석 + 보안 분석)

> 상태: **F1 구현 및 C·D 확장, F2·F3 후속 설계**. 현재 도구 계약은 [architecture.md](../architecture.md) §6.8이며, 구현 범위와 남은 기능은 §4에 구분했다. 개요는 [README.md](README.md), 공통 기반은 [common-core.md](common-core.md).
> 근거: 2026-10-19 조사 네 갈래(이미징·쓰기 방지, 파일 시스템·복구 도구, CCTV SD 형식, 보안 분석·통합·법률)와 갈래마다 적대적 검증(사실 확인 124건 중 수정 31건, 반박 2건 반영).
> 개발 환경 에서 직접 확인한 것: FAT/exFAT 순수 파이썬 시제품(286줄)이 생성 이미지 6개·추출 20건에서 TSK 와 맞거나 더 정확했고, PhotoRec 7.1 을 헤드리스로 돌려 봤으며,
> 실제 Hikvision `index00.bin` 두 개(v2·v3)를 해석했다. 실제 카드는 열지 않았다.

## 0. 호스트 환경 주의 (UAC·interop·WSL root)

- **UAC 가 꺼진(EnableLUA=0) 관리자 계정 호스트**에서는 WSL 에서 interop 으로 띄운 Windows 프로그램이 모두 **관리자 권한(High IL)** 으로 돈다 — esptool.exe 도 마찬가지다.
  그런 호스트에서는 "관리자 권한이 없다"는 전제가 틀리고, Windows 쪽 헬퍼는 권한상 디스크 원시 쓰기까지 할 수 있다(시리얼 헬퍼 `pweh-serial-helper.exe` 는 문법상 COM 만 열게 만든다 — port-routing.md §5.2). 편의가 아니라 **위험 요소**로 다룬다.
- WSL 안의 root 도 비밀번호 없이 얻을 수 있다(`wsl.exe -u root`, docker 그룹 = root 와 같음). "sudo 가 없다"는 것이 아무것도 막지 못한다.
- 별도 OS 계정만으로 이 권한을 차단하지 못하는 구성이다. AGENTS.md 호스트 위험 규칙과 `.claude/settings.json` 거부 규칙 추가는 초기 제안이었으며 사용자 결정에 따라 적용하지 않았다(common-core §6). UAC 설정은 사용자의 결정이다(PWEH 는 바꾸지 않는다).

## 1. 범위

| 목적 | 하는 일 |
|---|---|
| (a) 증거 분석 | 사람이 쓰기 방지 상태로 만든 이미지를 받아 해시 검증·보관 기록 → 파티션·파일 시스템 해석 → 파일 목록·시각(시간대 근거 포함) → 삭제 파일 복구·카빙 → 녹화 인덱스·타임라인 → 증거 목록(해시 확인서 포함) |
| (b) 보안 분석 | ① 펌웨어가 SD 를 어떻게 다루는지(부팅·핫플러그 때 카드 내용 실행, 서명 없는 SD 업데이트, U-Boot 의 mmc 부팅·스크립트, 마운트 옵션) 정적·수동 분석 ② 카드에 남은 민감 정보(평문 자격증명·Wi-Fi 키·클라우드 토큰), 녹화 암호화 여부, 펌웨어가 실행할 파일이 카드에 있는지(침해 흔적) |

범위 밖: PWEH 가 원시 디스크를 열거나 카드를 마운트·수리·포맷하는 것, 암호화 녹화의 키 복구·인증 코드 추측·클라우드 키 획득, 복구한 자격증명으로 로그인(정보통신망법 제48조①),
얼굴·번호판 인식, 녹취 재생·전사, 클라우드 업로드, **공격 파일 제작**(업데이트 이미지·boot.scr·uEnv·트리거 파일·"무해한 시험 파일" 포함 — safety.md §1).

## 2. 구조

```
pweh-fwtriage (확장)   펌웨어 쪽 SD 공격 표면: fw_rootfs_audit 의 sd_surface, fw_uboot_env 의 sd_boot, sd-* 휴리스틱, fw_sd_surface(SD-01~09)
pweh-uart     (확장)   uart_capture_boot 의 sd_events(부팅 로그의 SD 탐색·업데이트·스크립트 줄), 장치에서 카드 식별 정보 읽기(sysfs cid/csd, /proc/mounts, date)
pweh-forensics(신규)   카드 이미지 전용: 접수·해시·보관 기록, 파티션·FAT/exFAT(ext4 는 나중), 복구·카빙, CCTV 인덱스, 타임라인, 증거 목록, 비밀 스캔, 암호화 판정, 침해 흔적 스캔
공통 코어             src/pweh/fs/ (MBR/GPT·FAT·exFAT 파서 — fwtriage 도 재사용), 증명·출처·마스킹(common-core)
```

fwtriage 에 넣지 않는 이유: fwtriage 는 `.claude/settings.json` 에서 자동 허용이고 케이스 승인 확인을 하지 않으며 외부 도구를 쓰지 않는다는 계약이 있다.
카드 이미지는 제3자 개인정보(녹화)를 담으므로 승인·목적·법적 근거 기록·보관 기록이 필요한 별도 서버가 맞다. 펌웨어 분석(개인정보 없음)은 fwtriage 에 남긴다.

## 3. 획득 (사람이 한다)

PWEH 는 원시 디스크를 열지 않는다. 표준 Windows 계정에서는 `\\.\PhysicalDriveN` 읽기가 막혀 있고(디스크 클래스 보안 설명자), `wsl --mount` 는 USB·SD 리더를 지원하지 않으며,
WSL 커널에는 MMC 계층이 없어 카드 CID 도 보이지 않는다. 권장 절차:

1. 케이스 생성(소유/허가) → 디스크 여유 공간(카드 크기의 2배 이상) 확인.
2. **하드웨어 쓰기 방지 장치**(NIST CFTT 시험을 거친 카드 리더 일체형: CRU Media WriteBlocker, UltraBlock USB3 Forensic Card Reader 등)를 준비하고,
   **희생용 카드로 그 장치를 먼저 검증**(폴더 만들기가 실패해야 함). 읽기/쓰기 모드 스위치·LED 를 확인한다. CRU Media WriteBlocker 는 SDSC/SDHC 만 문서화돼 있고 USB 2.0(최대 약 10 MB/s)이라
   CCTV 에 흔한 32–256 GB microSDXC(exFAT)는 지원 여부를 희생용 SDXC 로 확인하고 시간을 잡는다(128 GB 한 번에 3.5시간 이상).
3. 압수 시: 기기·카드 사진, (선택) UART 로 장치의 `date`·`/proc/mounts`·sysfs cid/csd 기록(INTERACT), 호스트 시계 기준 분리 시각·호스트 시간대·장치 시계 차이 기록.
   전원을 오래 켜 두지 않는다(루프 녹화가 오래된 영상을 덮어쓴다). 라벨·봉인·보관 기록 시작.
4. 쓰기 방지 장치를 먼저 연결하고 카드는 **그 장치에만** 넣는다. 자동 실행 닫기, "검사하지 않고 계속", **"디스크를 포맷하시겠습니까?"는 취소**, 탐색기로 열지 않는다.
5. `win_disk_list`(읽기 전용 WMI)로 크기·모델·시리얼을 확인 → FTK Imager(관리자, 무료)로 물리 드라이브 → E01 또는 raw + Verify(이미지를 다시 해시) → **원본을 한 번 더 읽어 해시 비교**.
6. 카드를 다시 봉인 → 보관 기록 갱신 → PWEH 가 이미지와 FTK 로그를 접수(§4).

쓰지 않는 것: Win32DiskImager(볼륨을 잠그고 해제하며 "할당된 파티션만"은 포렌식에 틀림), chkdsk·"검사 및 복구", 소프트웨어 쓰기 차단만 믿기(모두 관리자 필요·검증 안 됨 — 보조 수단으로만, 사람이 설정).
대체: 희생용 카드로 잠금 스위치 동작을 확인한 리더(약함, 기록), 장치 위 `dd | nc`(INTERACT, 약 2–10 MB/s 추정, 마운트된 채면 이미지가 번진다 — 녹화 중지·언마운트는 MODIFY 라 동의 필요), UART(32 GB 에 base64 약 44일 — 일부 범위만).
선택(§10 결정): GENERIC_READ 만 하는 PWEH Windows 원시 읽기 헬퍼(시리얼 헬퍼와 다른 실행 파일이고 interop 실행 허용 목록에 자기 항목이 필요하다 — port-routing.md §11) — UAC 설정에 따라 관리자 프롬프트 없이 돌 수도 있지만, 특권 코드라 대상 식별(버스 종류·크기·시리얼·사람 확인)·잠금/해제·쓰기 IOCTL 금지·시스템 디스크 거부가 필요하다. 1차에는 넣지 않는다.

## 4. 증거 분석 (pweh-forensics, 모두 오프라인)

- **접수**(`forensics_intake_start`): 케이스 승인 + 목적 + 법적 근거 + **설치 장소 유형·업무 목적·PWEH 의 역할(소유자/수탁자와 위탁 문서)** 기록을 요구한다(적용 법률이 달라진다, §7).
  일반 파일만 받는다(`/dev/*`, `\\.\*`, FIFO, 블록·문자 장치 거부). 한 번 읽으면서 sha256·md5·sha1 을 계산하고 FTK/ewfinfo/dc3dd 로그의 해시와 비교한다.
  기본은 케이스로 복사(`forensics/images/EV-NNNN/`, 파일 0444·디렉터리 0555), 큰 카드는 설정이 허용한 외부 읽기 전용 증거 폴더를 제자리 참조(§10 결정).
  보관 기록(`forensics/custody.jsonl`)은 해시 사슬로 이어지는 추가 전용 기록이며 감사 로그에도 남는다. 출처 원장(common-core §4)에 기록한다.
- **무결성**: 모든 도구가 열 때마다 빠른 지문을 확인하고(다르면 거부, fail closed), `forensics_verify_start` 가 전체를 다시 해시한다. 불일치면 그 증거는 integrity-failed 로 표시되고 내용 도구가 모두 거부한다.
- **오염 검사**(`forensics_image_check`): 보관 기간 안에 호스트가 만든 흔적 — 강함: `System Volume Information`(IndexerVolumeGuid, WPSettings.dat), `$RECYCLE.BIN`, macOS 점 파일 / 약함: 획득일과 같은 FAT 마지막 접근 날짜 / 애매함: dirty 비트(카메라가 전원 차단 뒤 남기기도 하고 Windows 는 기존 dirty 비트를 지우지 않는다).
- **파일 시스템**: 순수 파이썬 엔진(`src/pweh/fs/`)이 MBR/EBR/GPT/superfloppy, FAT12/16/32, exFAT 를 해석한다. ext4 는 2단계(디렉터리 항목 + jbd2 저널의 옛 inode·디렉터리 블록 — 커널 5.13 이상은 삭제 시 디렉터리 항목도 지운다).
  - 시각마다 원래 값과 `time_basis`(local-unknown-tz / local+offset / utc)를 둔다. **장치 시간대는 기본값을 두지 않는다** — 근거(마운트 옵션 `time_offset=`/`tz=`, init 스크립트 TZ, hwclock, DHAV 프레임 시각과의 비교)와 함께 가정으로만 기록.
  - 삭제 파일: FAT 은 시작 클러스터와 크기는 남고 체인은 지워지므로 "연속"과 "할당된 곳 건너뛰기" 두 후보를 신뢰도와 함께 낸다. exFAT 는 InUse·비트맵만 지우고 FAT 항목을 쓰지 않으므로(리눅스 5.7~6.12) 남은 체인을 따라간다 — 이 두 점에서 TSK 보다 정확했다.
  - exFAT ValidDataLength 뒤(미리 할당한 녹화기에서 흔함)는 파일 본문에서 자르고 이전 녹화의 잔여 데이터로 따로 카빙한다.
  - 깨끗하지 않게 뽑은 카드(전원 차단·녹화 중 분리 — 압수에서 흔함): FAT 상태·exFAT VolumeDirty 를 기록하고, 할당됐지만 참조되지 않는 클러스터와 크기·체인 불일치를 찾는다.
  - **discard/TRIM**: 마운트 옵션 `discard` 나 fstrim 이 있으면 지운 데이터가 SD ERASE 로 사라진다 → 펌웨어 감사(§5)의 마운트 옵션 결과에 따라 "복구 가능성 조건부"로 보고.
- **CCTV 형식** (깨끗한 재구현, GPL 코드는 사양으로만 참고):
  - 1층 — 파일 시스템과 무관한 프레임 카버: DHAV(Dahua/Amcrest, FFmpeg dhav.c 사양, 프레임마다 벽시계 시각), XM `00 00 01 Fx`(XiongMai — 너비·높이 상위 비트와 fps 마스크 주의), MPEG-PS(Hikvision/EZVIZ — 세그먼트 시작의 PSM `HK` 서술자에 절대 시각, 인덱스 없이도 시각 부여).
    PhotoRec 은 원시 Annex-B·IMKH+PS 를 못 찾았지만 저장소 안 카버는 정확히 복구했다(합성 데이터 약 260 MiB/s, 128 GB 에 CPU 약 8.5분).
  - 2층 — 인덱스: Hikvision `index00/01(p).bin` v2/v3(라이브 = 닫힌 파일의 `j ≤ segRecNums` + 열린 파일의 `j ≤ currFileRec.curSeg`, 그 밖의 오래된 레코드는 **복구 가능한 영상이 아니라 과거 녹화의 메타데이터**,
    파일 번호가 아니라 링 포인터 기준으로 순서), SQLite `record_db_index00`(읽기 전용·immutable 로 열기), Dahua `.idx`, 각 hiv 파일 끝의 정보 영역(영상으로 세지 않음), index00/01 사본 비교.
  - 3층 — 이름 규칙: Wyze `record/YYYYMMDD/HH/MM.mp4`, Xiaomi `MiJIA_RECORD_VIDEO/<YYYYMMDDHH>/`, Reolink `Mp4Record/…`(16진 플래그), Tapo 미리 할당 풀, Tuya `DCIM/…/<epoch>_<길이>/`, MP4 상자 해석.
  - 미리 할당 풀(Hikvision hiv 256 MiB, Tapo, VIGI)은 삭제 항목 복구로는 아무것도 안 나오고 파일 시각은 포맷 시각이다 → 장치마다 링 방식을 판정해 기대치를 적는다.
  - 감지 후 멈춤: Hikvision Ultra/DeepinView SD 암호화, EZVIZ 인증 코드 암호화, Tapo "microSD 암호화", Tuya encrypt_mode(클라우드 키), SwitchBot 기본 암호화 → "암호화됨, 분석 중단" 보고(우회 없음).
- **외부 도구(선택, 없으면 ToolMissing)**: The Sleuth Kit(ext4·NTFS 목록, 교차 확인 — exFAT UtcOffset·남은 체인·64비트 저널 태그 해석 오류를 주석으로), PhotoRec(일반 카빙 — 반드시 `/cmd <케이스 이미지> …`, 새 빈 작업 디렉터리, TERM 없음,
  **testdisk 는 절대 실행 안 함**(O_RDWR 로 열고 파티션 표를 다시 쓸 수 있음), `/cmd resume` 금지), ewf-tools(E01), ffprobe(카빙한 영상 검증). scripts/install.sh 선택 구성요소 `forensics`(기존 deb 받아 풀기 방식, jammy 에서 공유 라이브러리 누락 없음 확인).
  쓰지 않는 것: foremost(영상 결과 나쁨), extundelete·ext4magic(유지보수 끊김, 복구 0), dissect.*(AGPL, 삭제 항목 건너뜀), plaso(무거움), bulk_extractor(jammy/noble 패키지 없음).
- **산출**: `forensics/recovered|carved/<label>-NNN/`(파일 0444, 이름 정리, 원래 이름은 manifest, 실행 비트·심볼릭 링크·장치 노드 없음, 바이트·파일 수 상한), 타임라인(`forensics_timeline`, 출처별 시간 의미와 충돌 표시),
  **증거 목록**(`forensics_evidence_list`: EV 항목·해시·마지막 검증·보관 사슬 상태·파생 산출물 sha256·해시값 확인서 서식). 영상·음성 내용은 에이전트 문맥으로 돌려주지 않는다. 정지 그림은 C에서 구현한 [이미지 힌트 분석](image-hints.md)의 전용 도구에서 미리보기·OCR을 반환한다.

> **구현 상태 (I3b, 2026-10-21)**: 서버 `pweh-forensics` — 동작의 계약은 architecture §6.8, 안전 규칙과 알려진 한계는 safety.md §3.5·§3.6·§7.1 이다.
> - `forensics_intake_start`(job): 이미지 파일만 받는다 — 장치·FIFO·`/dev`·`\\.\` 경로, 케이스·상태 폴더 안의 파일, NUL 이 든 경로, 증거 디렉터리 예약 이름, E01 서명 거부. 목적·법적 근거·설치 장소 유형·업무 목적·역할 기록.
>   원본을 한 번 연 fd(`pweh.safeio`)로 확인한 크기만큼 읽으며 sha256·md5·sha1, 이미징 로그(FTK Imager·dc3dd·ewfacquire·ewfinfo·Guymager, 4 MiB 상한) 해시 대조, `forensics/images/EV-NNNN/<이름>.partial` 로 복사·재해시(`verify_copy`, 기본 켬)한 뒤
>   이름을 바꾼다(파일 0444, 디렉터리는 커밋 뒤 0555). 보관 기록이 깨졌으면 복사 전에 바로 `custody_broken`. 커밋 지점은 보관 기록의 `intake` 사건(빠른 지문·접수 기록 sha256 포함)이다 — 그 전의 실패·취소는 되돌리고,
>   그 뒤의 취소는 무시하며, 보조 기록(`integrity-failed` 사건·출처 원장·아티팩트 색인·같은 sha256 확인) 실패는 `post_commit_errors` 로 알린다(감사 로그 실패는 서버 로그에만). 서버가 커밋 전에 죽어 남은 디렉터리는 다음 접수·서버 시작 때 중단된 접수의 흔적(잡은 쪽이 없는 접수 잠금·빈 디렉터리·`*.partial`)이
>   있을 때만 `forensics/aborted-intakes/` 로 옮기고 `intake-aborted` 사건으로 번호를 소비한다(흔적이 없으면 `record-without-intake` 로 남긴다). EV 번호는 다시 쓰지 않는다.
> - **C·D 확장**: `forensics_image_hints`는 정지 그림을 검증해 미리보기·OCR·QR·구조 정보를 반환한다. D는 TAR/ZIP 논리 자료, 선택한 SQLite·WAL/journal과 SMS·통화·연락처·브라우저 기록, 파일 시각·선택 앱 기록의 `forensics_timeline`을 더했다. 녹화 형식·프레임 카빙·CCTV 인덱스 타임라인은 이 범위에 포함되지 않는다([android-analysis.md](android-analysis.md)).
> - `forensics_verify_start`(job — 지문을 본 같은 fd 를 재해시, 해시가 끝난 뒤의 취소는 무시), `forensics_acquisition_attest`(사람 증명 `write-blocker` — 장치 모델·희생용 카드 시험 여부·이미징 도구, 증거 id·sha256·크기에 묶임, 90일.
>   증거 목록은 증명 저장소의 지금 상태를 보인다).
> - 내용 도구의 입구: 보관 기록 → 접수 기록을 `intake` 사건과 대조 → 사본을 디렉터리 fd 로 한 번 열기 → 그 fd 로 빠른 지문. 해석도 같은 fd 로 한다(`ImageReader.from_fd`).
> - `forensics_partitions`(MBR/EBR·GPT·superfloppy, 60초, 같은 구간은 한 번·서로 다른 구간 64개까지), `forensics_image_check`(호스트 오염 흔적 strong/weak/ambiguous, 120초 고정), `forensics_fs_list`(FAT12/16/32·exFAT, 삭제 항목,
>   시각마다 `time_basis` — 전체 목록은 `forensics/analysis/` 의 JSON 에만). 앞의 셋은 job 이 아닌 동기 도구다. 오염 검사와 목록은 호출 하나의 한도(항목 200000·시간·파티션 64·경로 글자 수 2^28)와 볼륨마다 엔진 예산 하나를 쓰고,
>   불완전하면(한도, 끝까지 읽지 못한 디렉터리, 잘린 이미지 `image_truncated`, 파티션 표보다 큰 파일 시스템 `volume_exceeds_partition`) `truncated`·`truncated_reasons`·`call.volumes_failed` 로 알린다
>   (오염 검사는 그때와 본 볼륨이 없을 때 '흔적 없음'이라 하지 않는다).
> - `forensics_extract`(job 300초, 취소는 엔진 계산 중에도 받는다): ref 는 루트에서 검증한 디렉터리만 따라가는 확인 순회가 찾은 것만(못 찾으면 `bad_ref`, 순회가 잘렸으면 `refs_unverifiable`),
>   paths 는 이름이 정확히 같은 항목 먼저·없으면 글자 수를 바꾸지 않는 대소문자 무시(여럿이면 `ambiguous_path`. 끝까지 읽지 못한 디렉터리에서는 대소문자까지 정확히 같은 이름만). 삭제 파일 후보·신뢰도, exFAT ValidDataLength 뒤 잔여 영역,
>   `forensics/recovered/` 0444 + manifest(잘림 사유·`limit_reason`·`bytes_beyond_image`). 실패한 추출은 출력을 지우고, 보관 기록 `extract` 를 남긴 뒤에는 지우지 않는다.
> - `forensics_evidence_list`: 확인서 전에 사본 재확인, `status_label`, 중단된 접수(`aborted[]`), 파생 산출물 매니페스트를 보관 기록 `extract` 사건과 대조, 해시값 확인서 서식·고지.
>
> 코어: `src/pweh/fs/`(순수 파이썬, 공개 사양으로 새로 작성 — 이미지에 쓰지 않고 마운트·외부 도구 없음. 반복은 `Limits` 와 호출 예산 `Budget`(시간·볼륨 크기에 비례하는 단계 상한·취소)으로 묶는다.
> 디렉터리는 엄격한 검증을 통과한 단위만 해석하고(`unvalidated_dirs`), 깊이·슬롯 한도와 끝까지 읽지 못한 살아 있는 디렉터리는 잘림 사유와 `cut_dirs` 로 남긴다),
> `src/pweh/evidence.py`(보관 기록 해시 체인 `pweh.custody/v1` + 보호 위치 고정점 `<state_dir>/custody/` — 덧붙이기는 '기록 중' → 보관 기록 → 확정. 무결성 실패는 되돌리지 않는다),
> `src/pweh/safeio.py`(링크·장치·FIFO 를 열지 않는 읽기, 디렉터리 fd 기준 쓰기). 요약 스키마 `sd-forensics`, Skill `sd-card-forensics`, 보고서 §8.1(증거 목록·보관 기록 상태·고지).
> 다른 서버의 가드: `pweh-fwtriage` 는 케이스의 `forensics/` 와 그것을 품은 디렉터리를 읽지 않는다. `case_import_file` 은 어느 케이스의 `forensics/` 에서도 가져오지 않는다(링크를 풀기 전·후 경로 둘 다).
> `case_register_artifact`·`case_hash_file` 은 `forensics/` 를 거부하고 일반 파일만 연다(연 fd 의 실제 경로를 다시 확인). pweh-sigrok 입력도 `forensics/` 를 거부한다. 조회 전용 도구만 자동 허용이다.
> 설계와 다른 점: 기기에 보내는 동작이나 `safety.forensics.*` 설정은 없다. 도구는 소유/허가·무결성 입구와 목적·법적 근거 기록을 확인하고, 획득 방법은 사람 증명으로 남긴다.
> 저장은 `storage="copy"`가 기본이다. D의 `storage="reference"`는 비안전 설정 `forensics.reference_roots` 아래 실제 읽기 전용 마운트의 일반 파일만 제자리 참조하며 매번 정책·마운트를 재확인한다. 증거 목록의 전체 재해시가 끝나야 참조 EV의 성공 확인서를 만든다(§10 결정 2).
> `case.json` 의 `evidence[]` 색인 대신 보관 기록(`intake` 사건이 해시·크기·지문의 권위 값)을 다시 읽어 상태를 정하고 접수 기록 파일은 그것과 대조한다.
> 접수 아티팩트 kind는 사본의 `evidence-image`와 참조 기록의 `evidence-reference`다(추출물은 매니페스트로 센다). 발견사항 카테고리 `insecure-storage`·`privacy` 는 아직 없다. D의 `pweh-fwtriage` raw GPT 분할은 `pweh.fs`의 파티션 파서를 재사용한다(증거 파일 시스템 접근은 아님).
> 남음: F2 — CCTV 형식(프레임 카버·인덱스·이름 규칙), 카빙, 녹화 인덱스 타임라인, §5.2 의 카드 쪽 비밀 스캔·암호화 판정·침해 흔적 대조(지금은 `fw_sd_surface` 의 `sd_paths_referenced` 를 `forensics_fs_list` 목록과 대조한다), E01·외부 도구(TSK·PhotoRec·ewf·ffprobe).
> F3 — ext4(NTFS 목록도 없음), Windows 원시 읽기 헬퍼, 영상 내보내기. 장치에서 카드 식별 정보 읽기(sysfs cid/csd)도 아직 없다.
> 유지보수 보강 구현: 출력 커밋 전 신원 재확인, `pweh.safeio`의 중간 디렉터리 고정, 출처 원장의 안전한 접수 기록 읽기, 지정 케이스의 종료된 job 기록 정리,
> 동기 해석의 요청 취소, 증거 경계의 하드링크 거부, FAT12/16/32 디렉터리 교차 연결 검사. 같은 계정 경합·부분 FAT 색인 등 남은 범위는 safety.md §3.6에 적는다.

## 5. 보안 분석

### 5.1 펌웨어 쪽 (pweh-fwtriage, 카드 불필요)

| 점검 | 내용 | 실제 사례(예) |
|---|---|---|
| SD-01 | 부팅·핫플러그 때 카드 내용 실행(rcS·init.d·mdev.conf `@/$/*`·udev RUN+=·hotplug, 바이너리 문자열 + REA 교차 참조, 복호화 후 실행) | Tenda CP3 iu.sh(CVE-2023-30356), Victure PC420 enable_telnetd.dat→autoexec.sh(CVE-2023-41612), Sonix snx_autorun.sh, CVE-2019-16398, CVE-2024-13893 |
| SD-02 | 카드에서 서명 없는 펌웨어 업데이트(U-Boot `do_auto_update`·`sdupdate`·`au_check_cksum_valid`, FIT 서명 노드 없음, 사용자 공간 SD→/dev/mtd), 다운그레이드·키 파일 없을 때 검사 생략 | Ingenic sdupdate·HiSilicon hiupdate(CRC 만), Dafang/Wyze demo.bin, ezviz.dav(CVE-2018-12258), upgrade.sh(CVE-2018-10988), CVE-2025-65397 |
| SD-03 | U-Boot 가 mmc 를 먼저 부팅하거나 카드의 스크립트·환경을 읽음(boot.scr, uEnv, `env import`, `fatload mmc`), **`verify=n`**(FIT 서명 검사 꺼짐), 환경 쓰기 가능 여부 | 메인라인 distro boot |
| SD-04/05 | 카드 삽입 시 자동 실행, 카드에서 설정 가져오기(값이 system() 으로 흐르는지 AH-04 와 교차) | CVE-2020-27540, CVE-2025-65397, CVE-2020-19642 |
| SD-06/07 | 카드에 민감 정보 기록(syslogd -O, 로그 경로, core_pattern), 녹화 경로의 암호화 API 사용 여부 | Wyze 카드 로그의 UID·enr(0x90 XOR), CVE-2025-30124, CVE-2025-64305 |
| SD-08 | 약한 마운트 옵션(noexec/nosuid/nodev 없음, umask=000), `discard`·fstrim(복구 가능성) | — |
| SD-09 | 카드 내용이 네트워크로 노출(웹 루트가 SD 를 가리킴, 목록 CGI) | Wyze 2022, CVE-2019-12919 |

- 구현: `fw_rootfs_audit(..., sd_surface=True)`, `fw_uboot_env` 의 `sd_boot`(verify 필드, 환경 쓰기 가능성), YAML `sd-*` 휴리스틱(CVE 의 파일 이름을 침해 흔적 이름으로), `fw_sd_surface`(SD-01~09 체크리스트).
  기존 빈틈 수정: rootfs.py `_MOUNT_RX` 에 exfat/msdos/auto/ntfs3/sdcardfs 와 `-t` 없는 `/dev/mmcblk*` 마운트, `STARTUP_GLOBS` 에 mdev.conf·udev 규칙·hotplug.
- 물리 버튼·GPIO 로만 열리는 업데이트는 심각도를 낮추되, 같은 파일·위치에 원격 쓰기 경로가 없을 때만.
- 수동 동적 확인: `uart_capture_boot` 의 `sd_events`(카드 없음 vs **새 빈 시험 카드** — 사람 동의, 증거 카드는 절대 다시 넣지 않음). 검증 계획은 정적 코드 경로 + 수동 로그까지만.
- Skill 연결: firmware-static-analysis 4b 단계, cctv-auth-bypass-hunt 의 AH-10(업데이트) 확장과 SD 점검 항목.

> **구현 상태 (I3a, 2026-10-20)**: `fw_sd_surface`(SD-01~09 — found/not-found/unknown, `not-found` 는 필요한 입력을 끝까지 본 경우만, SD-07 은 found = 암호화 근거), `fw_rootfs_audit(sd_surface=True)`, `fw_uboot_env` 의 `sd_boot`, `sd-*` 휴리스틱 7개, rootfs 빈틈 수정(마운트 정규식·mdev/udev/hotplug 따라가기), `uart_capture_boot` 의 `sd_events`·`sd_summary`, firmware-static-analysis 4b·AH-10 문구(architecture §6.2·§6.6).
> 남음: FIT 서명 노드의 구조 해석(지금은 `key-name-hint` 문자열 표지만 본다), REA 교차 참조 자동화. 카드에 넣을 파일은 만들지 않는다(§1).

### 5.2 카드 쪽 (pweh-forensics)

- `forensics_scan_secrets`: fwtriage 자격증명 패턴 + 토큰 휴리스틱 + **1바이트 XOR 탐색**(Wyze 0x90). 결과는 마스킹된 지문만(평문 저장 안 함), 교체 권고.
- `forensics_encryption_assess`: "암호화 안 됨"은 **보호 신호가 없고**(encv/enca/sinf/schm/tenc/senc/pssh) **슬라이스 본문(앞 32바이트 이후)이 해석될 때만**. 그 밖은 "암호화됨/모름"(상자 구조와 NAL 헤더는 암호화돼도 남는다, 엔트로피는 결정적이지 않음).
- `forensics_sd_ioc_scan`: 카드 파일(삭제 포함)을 펌웨어 sd_surface 결과와 대조 — 펌웨어가 실행·플래시할 파일이 카드에 있으면 강한 침해 흔적.

### 5.3 장치 명령 분류기 강화 (유지보수자·사람이 결정 — 에이전트는 safety 설정을 바꾸지 않는다)

- `safety.persistent_paths` 에 흔한 SD 마운트 지점 추가 제안: `/media/mmcblk*`, `/mnt/mmc*`, `/mnt/sdcard`, `/tmp/sd`, `/mnt/tf*`, `/sdcard`, `/system/sdcard`(지금은 `/mnt/sd` 만 — 다른 경로 쓰기는 MODIFY 로 통과).
- DESTRUCTIVE 로 올릴 것: `fsck*`/`e2fsck`/`dosfsck`/`fsck.exfat` 의 복구 옵션(-a/-y/-p/-r 또는 -n 없음), `tune2fs`, `mkexfatfs`, mmc-utils 쓰기, `hdparm`, `blockdev --setrw`, SD 의 rw 마운트·재마운트,
  U-Boot `sdupdate`/`sdupgrade`(플래시를 지우고 쓰며 saveenv), `sysboot`/`bootflow`(매체 내용 실행). `ums` 는 계속 DESTRUCTIVE. ext4 는 `-o ro` 로도 저널을 재생(쓰기)하므로 SD 원본 마운트는 거부하거나 `ro,noload` 만.
- firmware-dump 스키마의 `uboot-fatwrite` 방법 값은 분류기가 fatwrite 를 거부하는 것과 어긋난다 — 유지/삭제 결정 필요.

## 6. 케이스 구조·스키마·Skill

- `cases/<id>/forensics/`(필요할 때 만듦): `images/EV-NNNN/`(원본 + EV-NNNN.json), `custody.jsonl`(해시 사슬), `analysis/`, `recovered/`, `carved/`, `evidence-list.{json,md}`. `case.json` 에 `evidence[]` 색인.
  분리하는 이유: fwtriage 문자열 탐색이 복구한 개인 영상을 건드리지 않게, 0444 원본과 보관 기록을 한곳에, 케이스 종료 때 보존·파기를 단순하게.
- 아티팩트 kind: `evidence-image`, `recovered-file`, `carved-file`(처음에는 `other` + `extra.type` 도 가능). 발견사항 카테고리 추가: `insecure-storage`, `privacy`(+ `sd-*` 태그).
- Skill 하나: `sd-card-forensics`(mode = evidence / security / both), 요약 스키마 `sd-forensics`(mode 에 따른 if/then, `audio_decoded`·`face_plate_processing`·`uploads` 는 항상 false 상수).
  SKILL_DATA_SCHEMAS 와 master-prompt §5 표에 함께 등록. 보고서에 증거 목록·보관 사슬·고지 섹션(report.py).

## 7. 법률·개인정보 (법률 자문 아님 — 2026-10-19 law.go.kr 원문 기준)

- **적용 범위가 설치 형태에 따라 다르다**: 개인정보 보호법 제25조④~⑧(안내판·녹음 금지 등)과 표준지침 영상 장(제35조 이하)은 공개된 장소에 설치하는 운영자(제25조①)와 업무 목적의 이동형(제25조의2)에 적용된다.
  법 전체는 업무 목적의 개인정보처리자(제2조5호)를 전제로 하므로 개인 가정용 카메라는 대부분 밖이지만, **통신비밀보호법 제3조·제14조·제16조는 그대로 적용**된다. 그래서 접수 때 설치 장소·업무 목적·역할을 기록하고 그 뒤에야 조문을 인용한다.
  복구도 "처리"다(제2조2호).
- **오디오**: 메타데이터만(있음·코덱·길이). 재생·전사·내보내기 금지(통비법 제3조①·제14조①·제16조①, 대법원 2020도1538·2006도8839, 개인정보 보호법 제25조⑤). 2023도8603(녹음 재생은 청취가 아님)이 있으므로 규칙의 근거를 "청취"에만 두지 않는다.
- **최소화**: 얼굴 신원 식별·번호판 조회 없음, 별도 외부 서비스·제3자 업로드 없음, 영상·음성 내용은 에이전트 문맥에 넣지 않음(정지 그림은 image-hints 전용 도구 허용), 보고서는 메타데이터 우선. PWEH 는 마스킹 기능이 없으므로 제3자 제공·열람 제공용 사본을 만들지 않는다(표준지침 제46조).
  사람이 보는 영상 내보내기는 1차에 넣지 않는다 — 복구한 파일은 케이스 안에 있으므로 사람이 자기 플레이어로 본다.
- 개인정보처리자라면 「개인정보의 안전성 확보조치 기준」(고시 제2026-9호): SD 는 보조저장매체(제2조14호), 저장 인증정보 암호화(제7조①)·보조저장매체 저장 시 암호화(제7조⑤) → SD-06 발견사항의 근거, PWEH 자신의 사본 보존·파기(제12조·제13조).
- **증거 무결성**: 대법원 2007도7257 → 2013도2511 → 2017도13263, 2011모1839, 형사소송법 제106조③④·제313조②. 경찰청훈령 제1178호·(구 대검찰청)예규 제1449호(2026-10-02 검찰청 폐지·공소청 전환, 승계 여부 미확인)는 수사기관용이며 PWEH 는 관행만 빌린다.
- **고지**(모든 보고서): PWEH 는 인증·검증된 포렌식 도구가 아니다. 법적 용도라면 원본 카드를 보존하고 원본·이미지·보관 기록을 자격 있는 전문가에게 넘긴다. 소유자·입회인 서명용 해시값 확인서를 제공한다.
- 복구한 Wi-Fi 키·클라우드 토큰·계정으로 어디에도 로그인하지 않는다(정보통신망법 제48조①).

## 8. 단계 계획 (새 하드웨어 전송이 필요 없어 게임·RF 트랙과 병렬 가능)

F1과 C·D의 추가 구현은 §4를 따른다. 아래의 `safety.forensics.*` 등 새 정책 키와 호스트 거부 규칙은 초기 제안으로, 현재 설정에 추가하거나 승인한 기능이 아니다.

| 단계 | 내용 | 하드웨어 없이 검증 |
|---|---|---|
| F0 | 공통 코어(증명: `write-blocker`·`provenance-import`, `safety.forensics.*`, master-prompt "SD 포렌식" 목표 분기), 에이전트 호스트 위험 규칙(§0) | 단위 테스트 |
| F1 | 보안(펌웨어): fwtriage SD 표면 SD-01~09 + 빈틈 수정 + `uart_capture_boot` sd_events. 증거 핵심: 접수·해시·보관 기록·검증·오염 검사, 파티션·FAT/exFAT 목록·추출·삭제 파일, 증거 목록, `sd-card-forensics`(security + 기본 evidence) | `mkfs.fat --invariant`+mtools(SOURCE_DATE_EPOCH)로 결정적 FAT, `mkfs.exfat`+시험용 주입기, 가짜 sysfs/부팅 로그, 해시 사슬 변조 시험, 원본 불변 확인 |
| F2 | 카빙(DHAV·XM·PS·Annex-B·MP4·JPEG), Hikvision·Dahua 인덱스, 이름 규칙, 녹화 인덱스 타임라인, 비밀 스캔·암호화 판정·침해 흔적, 외부 도구(TSK·PhotoRec·ewf·ffprobe) | ffmpeg testsrc 합성 영상(FFmpeg dhav.c 배치의 DHAV 포함), 합성 인덱스, `@pytest.mark.external` |
| F3 | ext4(디렉터리 + jbd2), (선택) Windows 원시 읽기 헬퍼, (선택) 한 번 쓰는 승인 기반 영상 내보내기 | `mke2fs -d`(원본 시각 고정 시 결정적) + debugfs |

## 9. 확인이 필요한 것

- 사용자 카메라가 SD 를 어떻게 포맷하는가(FAT32/exFAT/ext4/독자 형식, 파티션·클러스터), 커널 버전, exFAT 드라이버, FAT 시간대 → 실제 카드 이미지 또는 펌웨어의 마운트·mkfs 줄.
- 실제 샘플(본인 기기의 index00.bin·hiv*.mp4·.dav·.idx·로그) — 벤더 파서는 샘플 없이는 믿지 않는다.
- 사용할 쓰기 방지 장치가 SDXC/exFAT 를 지원하는지(희생용 카드로), 구매 가능 여부·가격.
- 희생용 카드로: Windows 가 삽입 때 무엇을 쓰는지(Process Monitor), exfat.sys 가 쓰기 금지 신호를 따르는지.

## 10. 결정이 필요한 것 (README 에도 모음)

1. **이미징 방법**: (권장) 하드웨어 쓰기 방지 장치 + 사람이 FTK Imager / 희생용 카드로 확인한 리더 잠금 스위치(약함) / PWEH Windows 원시 읽기 헬퍼(시리얼 헬퍼와 별개. 관리자 권한이 필요하고 특권 코드 위험 — 나중에).
2. **증거 저장(구현)**: 케이스로 복사가 기본이다(여유 공간 확인). D에서 제자리 참조를 추가했다. `forensics.reference_roots` 아래 실제 읽기 전용 마운트의 일반 파일만 받으며, 원본 권한·마운트 상태를 PWEH가 바꾸지 않는다.
3. **보고서 개인정보 수준**: (권장) 개수·범위·해시만(전체 목록은 forensics/ JSON) / 파일 이름·녹화 시각까지.
4. **분류기 강화와 persistent_paths 확장**(§5.3): safety 설정이라 사람이 승인해야 한다 — 적용할지.
5. **UAC·interop 위험(§0)**: 호스트 거부 규칙 추가 제안은 사용자 결정에 따라 적용하지 않았다. UAC 설정은 사용자 결정.
