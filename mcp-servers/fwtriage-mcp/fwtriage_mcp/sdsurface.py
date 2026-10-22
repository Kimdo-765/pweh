"""펌웨어 쪽 SD 카드 공격 표면 정적 점검 (fw_sd_surface, fw_rootfs_audit(sd_surface=True), fw_uboot_env 의 sd_boot).

docs/design/sd-forensics.md 5.1 의 SD-01~SD-09 를 카드·기기 없이 펌웨어만으로 본다 (펌웨어 안의 어떤 것도 실행하지 않음):

- SD-01 부팅·핫플러그 때 카드 내용 실행 (rcS·init.d·mdev.conf @/$/*·udev RUN+=·hotplug·cron, cd 뒤 상대 실행, 복사 뒤 실행, 복호화 뒤 실행, 바이너리 문자열)
- SD-02 카드에서 서명 없는 펌웨어 업데이트 (사용자 공간 flashcp/dd/mtd write/nandwrite/ubiupdatevol — 디렉터리로 복사한 뒤 포함,
  U-Boot do_auto_update·sdupdate·hiupdate·au_check_cksum_valid)
- SD-03 U-Boot 의 mmc 부팅·카드 스크립트/환경 (fatload/ext4load/load mmc, boot.scr, uEnv.txt, env import, verify, env 쓰기 가능성)
- SD-04 카드 삽입 처리기 목록 (mdev/udev/hotplug/자동 마운트/카드를 다루는 데몬)
- SD-05 카드에서 설정 가져오기 (값이 system() 으로 흐르는지는 REA — AH-04 와 교차)
- SD-06 카드에 민감 정보 기록 (syslogd -O, core_pattern, 패킷 캡처, 로그·설정 사본)
- SD-07 녹화 암호화 (found = 암호화 API·플래그 근거가 있음 — found_means="protection". 근거가 없으면 unknown)
- SD-08 약한 마운트 옵션 (noexec/nosuid/nodev 없음, umask=000, discard·fstrim 호출)
- SD-09 카드 내용 네트워크 노출 (웹·FTP·Samba·DLNA 루트, 웹 루트의 심볼릭 링크, 목록 CGI)

상태: found(근거 있음) / not-found(필요한 입력을 모두 끝까지 보았고 근거 없음) / unknown(입력이 없거나 시간·크기·줄 길이·히트 상한으로 일부만 봄).
안전·견고성:
- 경로: 펌웨어 안의 SD 경로는 호스트 경로가 아니다. rootfs 안에서만(resolve_in_root, by_rel) 해석하고, 링크 대상은 readlink 문자열로만 읽는다.
- 펌웨어가 준 정규식·glob(mdev.conf 장치 정규식, udev KERNEL 패턴)은 Python re 로 컴파일·실행하지 않는다 (리터럴 분류 + 정규식 없는 glob DP).
- 모든 정규식은 입력 길이에 선형이 되게 상한을 두고, 줄·토큰·env 펼침·문자열 히트에 상한을 둔다. 상한에 걸리면 그 단계를 잘림으로 표시해
  관련 점검을 not-found 가 아니라 unknown 으로 둔다. 시간 예산(Ctl)은 파일 사이뿐 아니라 줄·토큰 반복, 파일 전체 미리 계산(블록 구조·줄 플래그)·
  glob 비교, 문자열 히트 분류 안에서도 본다.
next_steps 는 정적 확인(REA)과 사람이 동의한 새 빈 시험 카드로 부팅 로그를 수동 관찰하는 것(uart_capture_boot 의 sd_events)까지만 안내한다
— 카드에 넣을 파일(boot.scr·uEnv·업데이트 이미지·트리거 파일)을 만들거나 그 방법을 안내하지 않는다.
"""

from __future__ import annotations

import bisect
import os
import posixpath
import re
from pathlib import Path
from typing import Any

from .common import Ctl, clip, hexs, mask_secret, severity_key
from .fit_security import not_examined_fit_security, scan_fit_security
from .fswalk import is_text, read_in_root, resolve_in_root
from .hunt import OVERLAP, HuntState, scan_buffer
from .patterns import PatternSet, StringHeuristic, required_literals
from .rootfs import (
    HOTPLUG_RX,
    MDEV_CMD_DIRS,
    READ_ONLY_FS,
    UDEV_CMD_DIRS,
    _SSD_CMD_END_RX,
    _SSD_STOP_RX,
    Auditor,
    _blank_comments,
    command_program,
    logical_pair,
    mask_credentials,
    parse_mdev_conf,
    parse_udev_rules,
    resolve_program,
    shell_syntax,
)

CHECK_IDS = ("SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-07", "SD-08", "SD-09")

#: 점검 정의. references 는 설계 표(docs/design/sd-forensics.md 5.1)에 적힌 CVE 만, examples 는 같은 표의 사례 문구다.
#: SD-04/05 와 SD-06/07 은 설계 표에서 한 행이라 사례를 함께 적는다.
CHECKS: dict[str, dict[str, Any]] = {
    "SD-01": {
        "title": "부팅·핫플러그 때 카드 내용 실행", "category": "backdoor", "baseline": "high", "found_means": "risk", "needs": ("rootfs",),
        "references": ["CVE-2023-30356", "CVE-2023-41612", "CVE-2019-16398", "CVE-2024-13893"],
        "examples": ["Tenda CP3 iu.sh (CVE-2023-30356)", "Victure PC420 enable_telnetd.dat→autoexec.sh (CVE-2023-41612)", "Sonix snx_autorun.sh"],
        "rationale": "SD 카드는 물리 접근만으로 내용을 바꿀 수 있다. 부팅 스크립트·핫플러그 처리기(mdev/udev/hotplug)·cron·데몬이 카드의 스크립트·바이너리·모듈을 "
                     "검사 없이 실행하거나 카드 파일의 존재로 원격 셸을 켜면 인증 없는 root 코드 실행(물리 백도어)이 된다. 복호화 뒤 실행도 키가 펌웨어 안에 있으면 보호가 아니다.",
        "next_steps": ["경로 문자열을 REA search_strings → xrefs → procedure_pseudo_code 로 따라가 카드 파일을 검사 없이 root 로 실행하는지 확인",
                       "부팅 로그 수동 관찰: uart_capture_boot 의 sd_events (카드 없음 vs 사람이 동의한 새 빈 시험 카드 — 증거 카드는 다시 넣지 않음)"],
    },
    "SD-02": {
        "title": "카드에서 서명 없는 펌웨어 업데이트", "category": "insecure-update", "baseline": "high", "found_means": "risk", "needs": ("rootfs", "image"),
        "references": ["CVE-2018-12258", "CVE-2018-10988", "CVE-2025-65397"],
        "examples": ["Ingenic sdupdate·HiSilicon hiupdate (CRC 만)", "Dafang/Wyze demo.bin", "ezviz.dav (CVE-2018-12258)", "upgrade.sh (CVE-2018-10988)"],
        "rationale": "카드의 이미지로 플래시를 쓰는 경로(사용자 공간 flashcp/dd/mtd write/nandwrite/ubiupdatevol, U-Boot do_auto_update·sdupdate·hiupdate)가 서명이 아니라 "
                     "CRC·이름·버전만 확인하면 카드만으로 펌웨어를 바꿀 수 있다(지속성). 물리 버튼·GPIO 로만 열리고 같은 파일·위치에 원격 쓰기 경로가 없을 때만 심각도를 낮춘다.",
        "next_steps": ["업데이트 루틴의 검증(서명 / CRC·해시 / 버전)을 REA 로 확인 — CRC·해시만이면 insecure-update 로 기록",
                       "U-Boot 쪽은 UART printenv 와 부팅 로그(uart_capture_boot 의 sd_events, 카드 없음 vs 사람이 동의한 새 빈 시험 카드)로 자동 업데이트 조건(버튼·파일 이름)을 수동 관찰"],
    },
    "SD-03": {
        "title": "U-Boot 의 mmc 부팅·카드 스크립트/환경", "category": "insecure-default", "baseline": "medium", "found_means": "risk", "needs": ("image",),
        "references": [], "examples": ["메인라인 distro boot"],
        "rationale": "U-Boot 가 mmc 에서 커널·boot.scr·uEnv.txt·env 를 읽거나 mmc 를 플래시보다 먼저 부팅하면 카드(또는 eMMC)의 내용이 부팅을 정한다. verify=n 은 verify 환경값이 비활성으로 설정된 관찰이다. "
                     "실제 해시·서명 검증의 적용/강제 여부는 U-Boot 빌드, 부팅 경로와 신뢰 키를 추가 확인해야 한다. CRC 가 맞는 env 가 플래시에 있으면 saveenv 로, "
                     "/etc/fw_env.config + fw_setenv 가 있으면 사용자 공간에서 env 를 바꿀 수 있다. "
                     "mmc 장치 번호만으로는 SD 슬롯과 eMMC 를 구분할 수 없다.",
        "next_steps": ["UART printenv 결과와 대조하고, bootcmd 의 mmc 장치가 SD 슬롯인지 eMMC 인지 보드에서 확인",
                       "부팅 로그 수동 관찰: uart_capture_boot 의 sd_events (카드 없음 vs 사람이 동의한 새 빈 시험 카드)"],
    },
    "SD-04": {
        "title": "카드 삽입 처리기", "category": "other", "baseline": "info", "found_means": "risk", "needs": ("rootfs",),
        "references": ["CVE-2020-27540", "CVE-2025-65397", "CVE-2020-19642"], "examples": ["설계 표 SD-04/05 공통 행의 사례"],
        "rationale": "카드가 들어올 때 root 로 실행되는 처리기(mdev.conf·udev·hotplug·자동 마운트·카드를 직접 다루는 데몬) 목록이다. 처리기 자체는 정보성이고, "
                     "카드 내용을 실행하면 SD-01, 설정을 가져오면 SD-05 로 따로 보고한다.",
        "next_steps": ["처리기 스크립트가 카드 삽입 때 하는 일(마운트·복사·실행)을 확인 — 카드 내용을 실행하면 SD-01"],
    },
    "SD-05": {
        "title": "카드에서 설정 가져오기", "category": "insecure-default", "baseline": "medium", "found_means": "risk", "needs": ("rootfs",),
        "references": ["CVE-2020-27540", "CVE-2025-65397", "CVE-2020-19642"], "examples": ["설계 표 SD-04/05 공통 행의 사례"],
        "rationale": "카드의 설정 파일(Wi-Fi·네트워크·클라우드·계정)을 읽거나 시스템 설정으로 복사하면 물리 접근만으로 장치 설정을 바꿀 수 있다. 읽은 값이 system()/popen 으로 "
                     "흐르면 명령 주입이 된다 — 정적으로는 후보이며 REA 확인이 필요하다.",
        "next_steps": ["카드에서 읽은 값이 system()/popen 으로 흐르는지 REA 로 확인 (cctv-auth-bypass-hunt 의 AH-04 와 교차)"],
    },
    "SD-06": {
        "title": "카드에 민감 정보 기록", "category": "info-leak", "baseline": "medium", "found_means": "risk", "needs": ("rootfs",),
        "references": ["CVE-2025-30124", "CVE-2025-64305"], "examples": ["Wyze 카드 로그의 UID·enr(0x90 XOR) (설계 표 SD-06/07 공통 행)"],
        "rationale": "시스템 로그(syslogd -O)·코어 덤프(core_pattern)·패킷 캡처·디버그 출력·설정 사본을 카드에 쓰면 카드를 뽑는 것만으로 자격증명·토큰·장치 식별자가 샌다.",
        "next_steps": ["카드 이미지가 있으면 pweh-forensics 의 forensics_fs_list 목록(결과 JSON 의 경로)에서 이 로그·덤프 경로의 파일이 카드에 있는지(크기·시각) 확인 — "
                       "내용(자격증명·토큰·식별자)의 자동 검사는 아직 없고 추출물은 에이전트가 열지 않는다(필요하면 사람이 확인)"],
    },
    "SD-07": {
        "title": "녹화 암호화", "category": "weak-crypto", "baseline": "info", "found_means": "protection", "needs": (),
        "references": ["CVE-2025-30124", "CVE-2025-64305"], "examples": ["Wyze 카드 로그의 UID·enr(0x90 XOR) (설계 표 SD-06/07 공통 행)"],
        "rationale": "녹화 경로에 암호화 API·플래그 근거가 있는지 본다. 이 점검만 found 가 '보호 근거 있음'이다(found_means=protection). 정적으로 평문 녹화를 단정하지 않으므로 "
                     "근거가 없으면 unknown 이다. 키가 고정값이거나 장치 식별자에서 나오면 보호가 약하다.",
        "next_steps": ["녹화 모듈의 암호화 API 호출과 키 출처를 REA 로 확인 — 카드 쪽 녹화 암호화 판정은 아직 없다(pweh-forensics 는 녹화 내용을 읽지 않는다)"],
    },
    "SD-08": {
        "title": "약한 마운트 옵션", "category": "insecure-default", "baseline": "low", "found_means": "risk", "needs": ("rootfs",),
        "references": [], "examples": [],
        "rationale": "SD 마운트에 noexec(ext 계열은 nosuid·nodev 도)가 없거나 umask/fmask/dmask=0 이면 카드 내용 실행·권한 상승이 쉬워진다. "
                     "discard 옵션·fstrim 은 지운 데이터를 SD ERASE 로 없애 포렌식 복구 가능성을 낮춘다(카드 분석의 기대치).",
        "next_steps": ["마운트를 데몬이 mount(2) 로 하면 REA 로 data 인자(옵션 문자열)를 확인",
                       "discard/fstrim 이 있으면 카드 분석 보고에 '삭제 데이터 복구 가능성 조건부'로 적는다"],
    },
    "SD-09": {
        "title": "카드 내용 네트워크 노출", "category": "info-leak", "baseline": "high", "found_means": "risk", "needs": ("rootfs",),
        "references": ["CVE-2019-12919"], "examples": ["Wyze 2022"],
        "rationale": "웹·FTP·Samba·DLNA 루트나 웹 루트 안의 심볼릭 링크가 카드를 가리키면 녹화·로그가 네트워크로 노출되고, 쓰기가 되면 카드를 원격으로 바꿀 수 있다"
                     "(SD-01·SD-02 와 결합).",
        "next_steps": ["웹·FTP·Samba 설정의 인증 여부와 노출 경로(녹화·로그)를 확인 — 쓰기가 되면 SD-01·SD-02 의 원격 경로로 기록"],
    },
}

#: 점검이 끝까지 본 단계에 기대는 관계 (단계가 잘리면 not-found 대신 unknown)
PHASE_DEPS: dict[str, tuple[str, ...]] = {
    "SD-01": ("rootfs_text", "rootfs_binary"), "SD-02": ("rootfs_text", "rootfs_binary", "image_env", "image_strings"),
    "SD-03": ("image_env", "image_strings"), "SD-04": ("rootfs_text", "rootfs_binary"), "SD-05": ("rootfs_text", "rootfs_binary"),
    "SD-06": ("rootfs_text", "rootfs_binary"), "SD-07": (), "SD-08": ("rootfs_text", "rootfs_binary"), "SD-09": ("rootfs_text", "rootfs_binary"),
}

#: 흔한 SD 마운트 지점 (발견된 마운트가 없어도 이 경로 아래는 카드로 본다). tf 는 tf·tf<숫자>·tfcard<숫자> 만(/mnt/tftpboot 는 아님), sd* 는 sdk 와
#: SCSI 디스크 이름(sda·sdb1·sdaa2 — DVR/NVR 의 SATA HDD·USB 디스크를 장치 이름 디렉터리에 마운트하는 관례) 제외
BUILTIN_SD_PATTERNS = ["/mnt/sd* (sdk·SCSI 디스크 이름 sd<글자>[숫자] 제외)", "/mnt/mmc*", "/mnt/tf, /mnt/tf<숫자>, /mnt/tfcard<숫자>", "/mnt/disc*", "/media/mmc*",
                       "/media/sd* (sdk·SCSI 디스크 이름 sd<글자>[숫자] 제외)", "/media/tf, /media/tf<숫자>, /media/tfcard<숫자>", "/tmp/sd", "/sdcard", "/system/sdcard"]
#: 경로 요소 전체가 SCSI 디스크 이름인 것 (sda, sdb1, sdz9, sdaa1 — 두 글자는 파티션 번호가 있을 때만이라 sdhc·sdxc 같은 카드 낱말은 아니다)
_SCSI_DISK_NAME = r"(?:sd[a-z]\d*|sd[a-z]{2}\d+)"
_SD_COMP = r"(?:(?!" + _SCSI_DISK_NAME + r"(?:/|$))sd(?!k)[\w.-]*|mmc[\w.-]*|tf(?:_?card)?\d*)"
_BUILTIN_SD_RX = re.compile(r"^(?:/mnt/(?:" + _SD_COMP + r"|disc[\w.-]*)|/media/" + _SD_COMP + r"|/tmp/sd|/sdcard|/system/sdcard)(?=/|$)")
#: 텍스트 파일 사전 필터: 카드 경로 리터럴과, 카드 경로 없이도 근거가 되는 줄(fw_setenv 로 U-Boot env 를 바꾸는 스크립트)
_SD_LITERALS = ("/mnt/sd", "/mnt/mmc", "/mnt/tf", "/mnt/disc", "/media/", "/tmp/sd", "/sdcard", "fw_setenv")
REMOVABLE_FS = {"vfat", "msdos", "fat", "exfat", "ntfs", "ntfs3", "sdcardfs", "auto", "fuseblk", "texfat", "tntfs"}
FAT_FS = {"vfat", "msdos", "fat", "exfat", "ntfs", "ntfs3", "texfat", "tntfs", "fuseblk"}
_HOTPLUG_DEV_RX = re.compile(r"\$\{?(?:MDEV|DEVNAME)\}?|%[kN]")
#: 핫플러그 처리기 안의 장치 이름 마운트 지점 ('/media/$MDEV', '/mnt/usb/$DEVNAME') — 마운트용 부모(/media·/mnt·/run/media …) 아래만
#: (/var/run/$MDEV·/var/lock/$MDEV 같은 상태 파일 경로는 아니다). 펌웨어의 mount 명령이 $MDEV 로 마운트한 지점은 self.mounts 로 따로 잡힌다. _norm 뒤라 ${X} 는 $X
_HOTPLUG_MP_RX = re.compile(r"^((?:/media|/mnt|/run/media|/var/run/media|/tmp/media|/tmp/mnt)(?:/[\w.+\-]{1,128}){0,6}/\$(?:MDEV|DEVNAME))(?=/|$)")
#: SD 같은 마운트 지점 이름 (경로 요소). SCSI 디스크 이름은 /dev/mmcblk 마운트일 때만 SD 이름으로 본다 (_SDLIKE_MMC_COMPONENT_RX).
#: 일반 이름(media·storage)은 따로(_GENERIC_MEDIA_RX) — FAT 계열 fs 일 때만 SD 후보 (eMMC 데이터 파티션·NVR HDD 는 ext4·f2fs·xfs)
_SDLIKE_NAMES = r"mmc[\w.-]*|tf(?:_?card)?\d*|[\w.-]*card[\w.-]*|disc[\w.-]*|usb[\w.-]*|extsd[\w.-]*"
_SDLIKE_COMPONENT_RX = re.compile(r"(?i)(?:^|/)(?:(?!" + _SCSI_DISK_NAME + r"(?:/|$))sd(?!k)[\w.-]*|" + _SDLIKE_NAMES + r")(?:/|$)")
_SDLIKE_MMC_COMPONENT_RX = re.compile(r"(?i)(?:^|/)(?:sd(?!k)[\w.-]*|" + _SDLIKE_NAMES + r")(?:/|$)")
_GENERIC_MEDIA_RX = re.compile(r"(?i)(?:^|/)(?:media|storage)(?:/|$)")
_SCSI_DISK_COMPONENT_RX = re.compile(r"(?i)(?:^|/)" + _SCSI_DISK_NAME + r"(?:/|$)")
#: 카드 아닌 디스크 경로 (YAML sd-* 경로 히트가 이것만 가리키면 카드 문맥이 아니다 — /mnt/sda1/log, /media/sdb2/record)
_SCSI_DISK_PATH_RX = re.compile(r"^/(?:mnt|media)/" + _SCSI_DISK_NAME + r"(?=/|$)")
_EXCLUDED_MP = ("/", "/proc", "/sys", "/dev", "/tmp", "/var", "/run")

# 경로 토큰 (변수 $X·${X}, glob *?, printf %s 포함). 앞 글자가 경로·단어 문자면 토큰 시작이 아니다
_TOKEN_RX = re.compile(r"(?:(?<![\w.\-/$%~])|(?<=\s-[A-Za-z]))/[\w.+\-*?$/{}~%]*")
_ASSIGN_RX = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_]\w*)=(\"[^\"\n]{0,1024}\"|'[^'\n]{0,1024}'|[^\s;&|`#]{0,1024})")
_FOR_RX = re.compile(r"\bfor\s+([A-Za-z_]\w{0,63})\s+in\s+(\S{1,1024})")
_VAR_RX = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
#: 명령 위치의 cd (인자는 _cd_target 이 토큰으로 본다 — 인자 없는 cd·'cd ~'·'cd -' 는 cwd 를 모름으로)
_CD_RX = re.compile(r"(?:^|[;&|(]|\b(?:then|do|else)\b)\s*cd(?=$|[\s;&|)])")
_REL_EXEC_RX = re.compile(r"(?:^|[;&|(]|\b(?:then|do|else)\b)\s*(?:(?P<sh>(?:/(?:usr/)?bin/)?(?:sh|ash|bash))\s+|(?P<src>\.|source)\s+|(?:exec|nohup)\s+)?"
                          r"\./(?P<rel>[\w.+-]{1,128}(?:/[\w.+-]{1,128}){0,8})"
                          r"|(?:^|[;&|(]|\b(?:then|do|else)\b)\s*(?P<sh2>(?:/(?:usr/)?bin/)?(?:sh|ash|bash))\s+(?P<rel2>[\w+][\w.+-]{0,127}(?:/[\w.+-]{1,128}){0,8})"
                          r"(?=$|[\s;&|)\"'])")
#: 'cp -r 카드디렉터리 /tmp' 처럼 대상이 늘 있는 디렉터리면 그 안에 원본 이름으로 복사된다 (이름 바꾸기로 보지 않는다)
_COMMON_DIRS = {"/tmp", "/var", "/var/tmp", "/var/run", "/run", "/mnt", "/media", "/etc", "/data", "/root", "/home", "/opt", "/usr", "/usr/local", "/usr/bin",
                "/usr/sbin", "/bin", "/sbin", "/lib", "/app", "/config", "/userdata", "/mnt/mtd", "/mnt/data"}

# 토큰 앞 문맥(끝에 고정)으로 실행 여부를 본다. 문맥은 _windows() 가 512자로 자른 조각이라 정규식 비용이 토큰마다 일정하다.
_CMDPOS = r"(?:^|[;&|(`]|\$\(|&&|\|\||\b(?:then|do|else|if|elif|while|until|exec|nohup|setsid|time|busybox)\b|!)\s*"
#: 바이너리 문자열용(괄호는 구분자가 아니다 — 로그 문구의 '(…/mnt/sd/…)' 오탐 방지)
_CMDPOS_STRICT = r"(?:^|;|&&|\|\||\||\b(?:then|do|else|exec|nohup|setsid|time|busybox)\b)\s*"
#: 셸이 따옴표 문자열을 명령으로 실행하는 자리 (명령 위치에서만): sh/ash/bash/dash/hush/ksh [옵션] -c '…', su/runuser … -c '…', eval '…'.
#: 여는 따옴표 바로 뒤가 명령 시작이다 (_relative_exec 의 cd — echo "cd …"·logger "…" 의 따옴표는 아니다)
_EXEC_QUOTE_OPEN_RX = re.compile(
    _CMDPOS + r"(?:(?:exec|nohup|setsid|time|busybox|sudo)\s+){0,4}"
    r"(?:(?:/(?:usr/)?bin/)?(?:sh|ash|bash|dash|hush|ksh)(?:\s+-[a-zA-Z]{1,16}){0,8}?\s+-[a-zA-Z]{0,8}c[a-zA-Z]{0,8}"
    r"|(?:/(?:usr/)?s?bin/)?(?:su|runuser)(?:\s+(?:-[\w-]{0,16}|[\w.@-]{1,64})){0,4}?\s+-c"
    r"|(?P<ev>eval))\s+[\"']")
_CD_HEAD_RX = re.compile(r"\s*cd(?=$|[\s;&|)\"'])")
#: 명령 앞의 변수 대입 접두 ('LD_LIBRARY_PATH=/mnt/sd/lib /mnt/sd/run.sh' — 셸은 대입 뒤의 낱말을 실행한다). 셸 문법 파일에만 쓴다
#: (shell_syntax — systemd 유닛의 'ExecStart=/usr/bin/app 인자' 는 대입이 아니라 프로그램과 인자다).
#: 따옴표 없는 값은 구분자(;&|()<>`)와 명령 시작 글자 '!' 에서 끝난다 — 셸 의미와 같고(값 안의 '!' 는 드물다), 값이 다음 명령 시작에서
#: 멈추므로 대입이 빽빽한 앞 문맥('x=!x=!…')에서도 토큰마다 비용이 문맥 길이에 비례한다
_ASSIGN_PREFIX = r"[A-Za-z_]\w{0,63}=(?:\"[^\"\n]{0,256}\"|'[^'\n]{0,256}'|[^\s;&|()<>`\"'!]{0,256})"


def _pre_sh_rx(assign: bool) -> re.Pattern[str]:
    """'sh 카드파일' 앞의 실행기 접두 (env [-i|-|--opt] [VAR=값…], assign 이면 변수 대입도 — 'env -i sh /mnt/sd/x', 'A=1 sh /mnt/sd/x')."""
    a = _ASSIGN_PREFIX + "|" if assign else ""
    return re.compile(_CMDPOS + r"(?:(?:exec|nohup|setsid|time|busybox|" + a + r"env(?:\s+-[\w-]{0,16}){0,4}(?:\s+[A-Za-z_]\w{0,63}=\S{0,256}){0,8})\s+){0,4}"
                      r"(?:/(?:usr/)?bin/)?(?:sh|ash|bash|dash|hush|ksh)(?:\s+-[a-zA-Z]+){0,8}\s+(?:<\s*)?[\"']?$")


_PRE_SH = _pre_sh_rx(True)
_PRE_SH_NOASSIGN = _pre_sh_rx(False)
_PRE_SH_STRICT = re.compile(_CMDPOS_STRICT + r"(?:(?:exec|nohup|setsid|time|busybox)\s+){0,4}(?:/(?:usr/)?bin/)?(?:sh|ash|bash|dash|hush|ksh)(?:\s+-[a-zA-Z]+){0,8}\s+[\"']?$")
_PRE_SOURCE = re.compile(r"(?:^|[;&|(]|&&|\|\||\b(?:then|do|else)\b)\s*(?:\.|source)\s+[\"']?$")
_PRE_SOURCE_STRICT = re.compile(r"(?:^|;|&&|\|\||\b(?:then|do|else)\b)\s*(?:\.|source)\s+[\"']?$")


def _pre_cmd_rx(assign: bool) -> re.Pattern[str]:
    """카드 경로를 프로그램으로 실행하는 명령 위치 (실행기 접두 4개까지, assign 이면 변수 대입도)."""
    a = _ASSIGN_PREFIX + "|" if assign else ""
    return re.compile(_CMDPOS + r"(?:(?:exec|nohup|setsid|time|busybox|eval|sudo|command|" + a + r"chroot\s+\S+|xargs(?:\s+-\S+){0,6}"
                      r"|timeout(?:\s+-\S+){0,4}\s+\d+(?:\.\d+)?[smhd]?|env(?:\s+-\S+){0,4}(?:\s+[A-Za-z_]\w{0,63}=\S{0,256}){0,8})\s+){0,4}[\"']?$")


_PRE_CMD = _pre_cmd_rx(True)
_PRE_CMD_NOASSIGN = _pre_cmd_rx(False)
#: start-stop-daemon … -x|--exec|--startas|-a 카드프로그램
_PRE_SSD = re.compile(r"\bstart-stop-daemon\b[^;&|\n]{0,256}?\s(?:-x|--exec|--startas|-a)\s+[\"']?$")


def _ssd_state(pre: str, post: str) -> bool | None:
    """앞 문맥 끝이 'start-stop-daemon … -x|--exec|--startas|-a' 인지와 그 명령이 경로를 실행하는지: None(start-stop-daemon 옵션 뒤가 아님) /
    True(실행) / False(같은 명령 — 경로 뒤 ; & | 줄바꿈 '--' 까지, 문맥 안 — 에 -K/--stop·-T/--status·-t/--test(묶인 꼴 포함)가 있어
    멈춤·상태·시험이라 경로를 실행하지 않음)."""
    if "start-stop-daemon" not in pre:
        return None
    m = _PRE_SSD.search(pre)
    if m is None:
        return None
    e = _SSD_CMD_END_RX.search(post)
    return not _SSD_STOP_RX.search(pre[m.start():] + " " + (post[:e.start()] if e else post))
#: 'grep -q 무엇 카드파일 && 명령' — 카드 파일 내용이 명령을 켠다 (_trigger 의 시험으로)
_PRE_GREP_Q = re.compile(r"\b[ef]?grep\s+(?:-[\w-]{1,16}\s+){0,4}?-[a-zA-Z]{0,8}q[a-zA-Z]{0,8}\s+(?:-[\w-]{1,16}\s+){0,4}(?:\"[^\"\n]{0,256}\"|'[^'\n]{0,256}'|[^\s\"']{1,256})\s+[\"']?$")
#: su/sudo/runuser -c '카드 스크립트' (셸이 문자열을 실행). 'sh -c' 는 _PRE_SH 가 본다
_PRE_SU_C = re.compile(_CMDPOS + r"(?:(?:exec|nohup|setsid|time|busybox)\s+){0,4}(?:\S{0,64}/)?(?:su|sudo|runuser)(?:\s+(?:-[\w-]{0,16}|[\w.@-]{1,64})){0,4}?\s+-c\s+[\"']?$")
#: find … -exec(dir) 카드프로그램 (카드 파일을 프로그램으로 실행)
_PRE_FIND_EXEC = re.compile(r"(?<!\S)-exec(?:dir)?\s+[\"']?$")
#: find 카드디렉터리 … -exec sh {} / -exec {} / | xargs sh (찾은 카드 파일을 실행)
_PRE_FIND_ROOT = re.compile(r"\bfind(?:\s+-[HLP])*\s+[\"']?$")
_POST_FIND_EXEC = re.compile(r"^[^;&|\n]{0,400}?(?<!\S)-exec(?:dir)?\s+(?:(?:\S{0,64}/)?(?:sh|ash|bash|dash)\s+(?:-\S+\s+){0,4})?[\"']?\{\}"
                             r"|^[^;&\n]{0,400}?\|\s*xargs(?:\s+-\S+){0,6}\s+(?:\S{0,64}/)?(?:sh|ash|bash|dash)\b")
#: case 갈래의 첫 명령 ('start) /mnt/sd/x ;;', 'case $1 in start) …')
_PRE_CASE = re.compile(r"(?:^|;;|\bin)\s*\(?[\w.*?|\"'\[\]$-]{1,64}\)\s*[\"']?$")
_ASSIGN_TAIL_RX = re.compile(r"=[\"']?$")
_PRE_CMD_STRICT = re.compile(_CMDPOS_STRICT + r"(?:(?:exec|nohup|setsid|time|busybox)\s+){0,4}[\"']?$")
_PRE_INSMOD = re.compile(r"\b(?:insmod|modprobe)(?:\s+-\S+)*\s+[\"']?$")
_PRE_PRELOAD = re.compile(r"\bLD_PRELOAD=[\"']?$")
_PRE_CHMOD_X = re.compile(r"\bchmod\s+(?:-\S+\s+)*(?:[0-7]*[1357][0-7]{0,2}|[ugoa]*\+[rwX]*x[rwX]*)\s+[\"']?$")
_PRE_TEST = re.compile(r"(?:\[\[?|\btest|\s-a)\s+(?:!\s+)?-[efsrxdhL]\s+[\"']?$")
_PRE_REDIRECT = re.compile(r"(?:^|[^<0-9&>])[12]?>>?\s*[\"']?$|\btee\s+(?:-a\s+)?[\"']?$")
#: 실행 키 뒤의 '/bin/sh [-옵션] [-c] ' 과 여는 따옴표 (udev RUN+=·systemd Exec*=·cron·inittab 의 명령 문자열)
_SH_C_PREFIX = r"(?:(?:/(?:usr/)?bin/)?(?:sh|ash|bash|dash)(?:\s+-[a-zA-Z]{1,8}){0,4}\s+(?:-c\s+)?)?[\"']?"
_PRE_INITTAB = re.compile(r"^[^:]*:[^:]*:[^:]*:\s*-?" + _SH_C_PREFIX + r"$")
_PRE_MDEV = re.compile(r"^\s*-?\S+\s+\S+:\S+\s+[0-7]{3,4}\s+(?:(?:[=>]\S*|!)\s+)?[@$*]\s*(?:(?:/(?:usr/)?bin/)?(?:sh|ash|bash)\s+)?$")
_PRE_UDEV = re.compile(r"\b(?:RUN|PROGRAM|IMPORT\{program\})(?:\{\w+\})?\+?=\s*\"" + _SH_C_PREFIX + r"$")
_PRE_SYSTEMD = re.compile(r"\bExec(?:Start(?:Pre|Post)?|Stop(?:Post)?|Reload)=[-@+!:]*" + _SH_C_PREFIX + r"$")
_PRE_CRON = re.compile(r"^\s*(?:@\w+|(?:\S+\s+){5})(?:[A-Za-z_]\w*\s+)?" + _SH_C_PREFIX + r"$")
#: 뒤 문맥의 파이프 단계(최대 4단, '||' 는 파이프가 아님) 끝이 셸인지 — 단계 경계가 '|' 로 고정돼 선형
_POST_PIPE_SH = re.compile(r"^(?:[^|\n]{0,256}\|(?!\|)){1,4}\s*(?:(?:/usr/bin/|/bin/)?xargs(?:\s+-[\w=-]{1,16}){0,4}\s+)?(?:/(?:usr/)?bin/)?(?:sh|ash|bash|dash)\b")
_DECRYPT_RX = re.compile(r"(?i)\b(?:openssl|gpg|ccrypt|aescrypt|\w{0,32}decrypt\w{0,32}|des3)\b")
_FLASH_CMD_RX = re.compile(r"\b(?:flashcp|nandwrite|ubiupdatevol|ubiformat|sysupgrade|flash_write|mtd_write|fw_upgrade|upgrade_firmware"
                           r"|mtd_debug\s{1,8}write|mtd(?:\s+-\S{1,16}){0,4}\s+write)\b")
_FLASH_DEV_RX = re.compile(r"/dev/(?:mtd|mtdblock|ubi|nand|mmcblk\d+boot)")
_POST_PIPE_FLASH = re.compile(r"^[^;&\n]{0,256}?\|\s*(?:\S{0,64}/)?(?:dd\b[^;&|\n]{0,256}?\bof=[\"']?/dev/(?:mtd|mtdblock|ubi|nand|mmcblk\d+boot)"
                              r"|(?:flashcp|nandwrite|flash_write|mtd_write)\b[^;&|\n]{0,256}?/dev/(?:mtd|ubi|nand))")
_FLASH_DEST_RX = re.compile(r"(?:\bof=|>\s*)/dev/(?:mtd|mtdblock|ubi|nand|mmcblk\d+boot)")
_FLASH_ERASE_RX = re.compile(r"\bflash_erase(?:all)?\b")
_UPDATE_NAME_RX = re.compile(r"(?i)(?:^|/)(?:[\w.-]{0,64}(?:update|upgrade|firmware|fw[_-]|uimage|rootfs|digicap)[\w.-]{0,64}|demo\.bin|ezviz\.dav|[\w.-]{1,128}\.(?:img|pkg))$")
_CONFIG_NAME_RX = re.compile(r"(?i)(?:\.(?:conf|cfg|ini|json|xml|txt|cnf|config|properties|dat)$|wpa_supplicant|wifi|wlan|hostapd|network|setting|account|passwd|shadow|token|cloud|(?:^|/)uid)")
_CONFIG_USE_RX = re.compile(r"\b(?:cp|mv|install|cat|grep|egrep|sed|awk|cut|head|tail|read|jq|wpa_supplicant|hostapd|nvram|cfg_?set|load_?config)\b|(?:^|\s)-c\s*$|--conf(?:ig)?(?:=|\s+)$|<\s*$")
_LOG_NAME_RX = re.compile(r"(?i)log|debug|dump|trace|dmesg|core|crash|messages|syslog|\.txt$")
_LOG_CMD_RX = re.compile(r"\b(?:dmesg|logread|syslogd|klogd|ps|ifconfig|printenv|fw_printenv|cat\s+/proc|top|netstat)\b")
_SENSITIVE_SRC_RX = re.compile(r"(?:^|\s)/(?:etc/(?:shadow|passwd|wpa_supplicant[\w.-]*|config\b|[\w./-]{0,128}\.(?:pem|key|crt))|mnt/mtd|mnt/config|config|data|etc/config)(?:\s|/|$)")
_RECORD_NAME_RX = re.compile(r"(?i)record|video|alarm|snap|\.(?:mp4|264|h264|265|h265|avi|dav|hiv|mkv|ts|jpg)$")
_ENC_FLAG_RX = re.compile(
    r"(?i)\b(?:sd_?card|sd|tf_?card|tf|card|record(?:ing)?|rec|video|storage|stream)[_-]?encrypt(?:ion|ed)?(?:[_-]?(?:mode|enable|enabled|flag|switch|type|key|status))?\b"
    r"|\bencrypt(?:ion|ed)?[_-]?(?:record(?:ing)?|sd_?card|sd|tf_?card|storage|video|stream)\w{0,32}"
)
#: 원격 셸·디버그 서비스 이름 (nc 리스너는 _nc_listener 가 토큰으로 본다 — '\bnc\s[^\n]*-l' 꼴은 '\nc nc nc…' 에서 O(n^2))
_SERVICE_START_RX = re.compile(r"(?:^|[\s;&|(/])(?:u?telnetd|dropbear|sshd|inetd|tcpsvd|remserial|adbd|debug_?shell|start_?telnetd?|busybox\s{1,8}telnetd)\b")
_SERVICE_NAME_RX = re.compile(r"(?:u?telnetd|dropbear|sshd|x?inetd|tcpsvd|remserial|adbd|debug_?shell|start_?telnetd?)")
_LAUNCH_PREFIX = {"exec", "nohup", "setsid", "time", "busybox", "sudo", "command", "!", "then", "do", "else", "{", "(", "nice", "ionice", "chrt", "taskset", "env",
                  "timeout", "chroot"}
#: 앞말 뒤의 인자 수 (chroot DIR, timeout N, nice -n N 은 _service_start 가 따로 건너뛴다)
_INIT_SCRIPT_RX = re.compile(r"^/etc/(?:init\.d|rc\.d(?:/init\.d)?)/[\w.+-]{0,64}$")


def _split_statements(text: str, limit: int = 4096) -> list[list[str]]:
    """셸 문구를 명령(낱말 목록)으로 나눈다: ; & | && || 줄바꿈 ( ) 에서 끊고 따옴표 안은 한 낱말 (따옴표 벗김). 한 번 훑기, 명령·낱말 수 상한."""
    out: list[list[str]] = []
    cur: list[str] = []
    i, n = 0, len(text)
    while i < n and len(out) < limit:
        c = text[i]
        if c in " \t\r":
            i += 1
            continue
        if c in ";&|()\n":
            if cur:
                out.append(cur)
                cur = []
            i += 1
            continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;&|("):
            k = text.find("\n", i)
            i = n if k < 0 else k
            continue
        j = i
        buf: list[str] = []
        while j < n and text[j] not in " \t\r\n;&|()":
            ch = text[j]
            if ch in "\"'`":
                k = text.find(ch, j + 1)
                if k < 0:
                    buf.append(text[j + 1:])
                    j = n
                    break
                buf.append(text[j + 1:k])
                j = k + 1
            elif ch == "\\" and j + 1 < n:
                buf.append(text[j + 1])
                j += 2
            else:
                buf.append(ch)
                j += 1
        if len(cur) < 64:
            cur.append("".join(buf))
        i = j
    if cur and len(out) < limit:
        out.append(cur)
    return out


def _service_start(text: str, depth: int = 0) -> str | None:
    """문구가 원격 셸·디버그 서비스를 '시작'하는지 — 명령의 첫 낱말(앞말 exec·nohup·busybox·env·timeout … 건너뜀)이 서비스이거나,
    start-stop-daemon -S … -x 서비스, /etc/init.d/서비스 start|restart, nc 리스너, socat … EXEC:셸, sh -c '…'(한 번 들어감).
    killall/pkill/kill/stop 이나 echo·logger 문구 안의 이름은 시작이 아니다. 반환: 시작한 명령의 짧은 표기 또는 None."""
    if not text or len(text) > MAX_LINE * 4:
        text = text[:MAX_LINE * 4]
    for words in _split_statements(text):
        k = 0
        while k < len(words) and words[k].rsplit("/", 1)[-1] in _LAUNCH_PREFIX:
            w = words[k].rsplit("/", 1)[-1]  # '/bin/busybox telnetd', '/usr/bin/nohup …'
            k += 1
            if w == "chroot" and k < len(words):
                k += 1
            elif w == "timeout":
                while k < len(words) and words[k].startswith("-"):
                    k += 1
                k += 1 if k < len(words) else 0
            elif w in ("nice", "ionice", "chrt", "taskset"):
                while k < len(words) and (words[k].startswith("-") or words[k].isdigit()):
                    k += 1
            elif w == "env":
                while k < len(words) and (words[k].startswith("-") or ("=" in words[k] and not words[k].startswith("/"))):
                    k += 1
        while k < len(words) and "=" in words[k] and not words[k].startswith(("/", "-")) and words[k].split("=", 1)[0].isidentifier():
            k += 1  # 'VAR=x 명령'
        if k >= len(words):
            continue
        w = words[k]
        base = w.rsplit("/", 1)[-1]
        rest = words[k + 1:]
        if _INIT_SCRIPT_RX.match(w):
            # /etc/init.d/서비스 start|restart (stop·status 는 시작이 아니다)
            if _SERVICE_NAME_RX.search(base.replace("telnet", "telnetd")) and (not rest or rest[0] in ("start", "restart", "force-reload")):
                return clip(" ".join(words[k:k + 2]), 80)
            continue
        if _SERVICE_NAME_RX.fullmatch(base):
            return clip(" ".join(words[k:k + 3]), 80)
        if base == "start-stop-daemon":
            if any(x in ("-K", "--stop") for x in rest):
                continue
            for a, b in zip(rest, rest[1:]):
                if a in ("-x", "--exec", "--startas", "-a") and _SERVICE_NAME_RX.fullmatch(b.rsplit("/", 1)[-1]):
                    return clip(f"start-stop-daemon {a} {b}", 80)
            continue
        if base in ("nc", "netcat") and any(len(u) > 1 and u[0] == "-" and u[1:].isalpha() and "l" in u[1:] for u in rest[:16]):
            return "nc 리스너"
        if base == "socat" and any("exec:" in u.lower() and re.search(r"\b(?:sh|ash|bash)\b", u) for u in rest[:16]):
            return "socat EXEC 셸"
        if base in ("sh", "ash", "bash", "dash") and depth == 0:
            for a, b in zip(rest, rest[1:]):
                if a == "-c":
                    r2 = _service_start(b, depth + 1)
                    if r2:
                        return r2
                    break
    return None
#: 업데이트를 여는 물리 버튼·GPIO '읽기' (echo 1 > …/value 같은 쓰기·LED 제어는 조건이 아니다)
_GPIO_READ_RX = re.compile(
    r"(?i)\bcat\s+/sys/class/gpio/gpio\d+/value\b|<\s*/sys/class/gpio/gpio\d+/value\b|\bgpio\s+(?:get|input|read|status)\b"
    r"|\b(?:gpio_?get(?:_?value)?|gpio_?read|getgpio|get_?gpio)\b|\bkey_?(?:press(?:ed)?|state|status)\b"
    r"|\b(?:get|read)_?(?:reset|setup|wps|func(?:tion)?|upgrade|update)_?(?:button|key|btn)(?:_?(?:state|status|value|pressed))?\b"
    r"|\b(?:get|read)_?(?:button|btn)(?:_?(?:state|status|value))?\b"
    r"|(?:\b|_)(?:reset|setup|wps|upgrade|update)[_-]?(?:button|key|btn)[_-]?(?:state|status|pressed|value)\b"
    r"|\b(?:cat|dd|read)\b[^;&|\n]{0,40}/dev/(?:gpio|key|button|input/event)\w*"
)
_HASH_ONLY_RX = re.compile(r"\b(?:md5sum|sha1sum|sha256sum|cksum|crc32)\b")
_IF_START_RX = re.compile(r"^\s*(?:if|elif|while|until)\b")
_STMT_KW_RX = re.compile(r"(?:^|[;&|]|\b(?:then|do|else)\b)\s*(?:if|elif|while|until)\b")
_BLOCK_END_RX = re.compile(r"^\s*(?:fi|done)\b")
_BLOCK_BRANCH_RX = re.compile(r"^\s*(?:else|elif)\b")
_FW_SETENV_RX = re.compile(r"\bfw_setenv\s+(?P<var>[A-Za-z_][\w.]{0,63})\s+(?P<val>.{1,4096})$")
_UEVENT_HELPER_RX = re.compile(r"(?:echo\s+(?P<a>\S{1,256})\s*>\s*/proc/sys/kernel/hotplug|sysctl\s+(?:-w\s+)?kernel\.hotplug\s*=\s*(?P<b>\S{1,256})|^\s*kernel\.hotplug\s*=\s*(?P<c>\S{1,256}))", re.M)
#: 저장 장치에 특정한 문맥: mmcblk·/dev/sdX·카드 낱말·흔한 카드 경로·/media|/mnt 아래의 $MDEV·이동식 fs 마운트.
#: '$MDEV'·'$DEVNAME'·'mount' 만으로는 아니다 (wlan·tty 처리기도 쓴다)
_STORAGE_TEXT_RX = re.compile(
    r"mmcblk|/dev/sd[a-z]|\b(?:sd|tf|micro ?sd)[ _-]?card\b|\bsdcard\b|\btfcard\b|(?:/media|/mnt|/run/media)/\$\{?(?:MDEV|DEVNAME)\b"
    r"|/mnt/(?:sd(?!k)|mmc|tf|disc)|/media/(?:sd(?!k)|mmc|tf)|/tmp/sd\b|/system/sdcard|-t\s{0,8}(?:vfat|msdos|fat|exfat|ntfs3?|sdcardfs)\b", re.I)


def _storage_specific(text: str) -> bool:
    return bool(_STORAGE_TEXT_RX.search(text))
_SERVER_ROOT_ARG_RX = re.compile(
    r"(?:^|[;&|(]|\b(?:then|do|else|exec|nohup)\b)\s*(?:(?:\S{0,64}/)?(?:tcpsvd|start-stop-daemon)\s[^;&|]{0,256}?\s)?(?:\S{0,64}/)?"
    r"(?:(?:httpd|uhttpd|lighttpd|thttpd|mini_httpd|boa|goahead)\b[^;&|]{0,256}?\s-[hdr]|(?:ftpd|vsftpd|bftpd)\b(?:\s+-[a-zA-Z]+){0,8})\s+[\"']?$")
_INETD_FTPD_RX = re.compile(r"\bftpd\b(?:\s+-[a-zA-Z]+){0,8}\s+$")
#: 서버 설정에서 '루트·공유 경로' 를 뜻하는 키 (로그 경로 같은 다른 키의 카드 경로는 SD-09 가 아니다)
_SERVE_KEY_RX = {
    "web": re.compile(r"(?i)(?:\bDocumentRoot|\bserver\.document-root|\bdocument[_-]?root|\balias(?:\.url)?|\bScriptAlias|^\s*root|\boption\s+home|^\s*home|^\s*dir|\bweb_?root)\b[^\n]*$"),
    "ftp": re.compile(r"(?i)(?:\blocal_root|\banon_root|\bDefaultRoot|\bftp_root|^\s*root|^\s*home)\b[^\n]*$"),
    "samba": re.compile(r"(?i)^\s*path\s*=\s*[\"']?$"),
    "dlna": re.compile(r"(?i)^\s*media_dir\s*=\s*(?:[AVP],)?[\"']?$"),
}
_LISTING_CMD_RX = re.compile(r"\b(?:ls|find|du|cat|tar|zip|opendir|readdir|scandir)\b")
_FSTRIM_CMD_RX = re.compile(r"(?:^|[;&|(]|\b(?:then|do|else)\b)\s*(?:\S{0,64}/)?fstrim\b")
_CRON_DIRS = ("/etc/crontabs/", "/var/spool/cron/", "/etc/cron.d/", "/etc/cron/")
#: 분류하지 않는 웹 콘텐츠(압축된 한 줄 JS 등): 업로드 파일 이름만 모은다
_WEB_CONTENT_EXT = (".js", ".html", ".htm", ".css", ".svg", ".map", ".po", ".md")

_WEB_CONF_NAMES = {"boa.conf", "lighttpd.conf", "httpd.conf", "thttpd.conf", "nginx.conf", "uhttpd", "goahead.conf", "mini_httpd.conf", "mongoose.conf", "civetweb.conf", "appweb.conf"}
_FTP_CONF_NAMES = {"vsftpd.conf", "proftpd.conf", "pure-ftpd.conf", "bftpd.conf"}
_SAMBA_CONF_NAMES = {"smb.conf"}
_DLNA_CONF_NAMES = {"minidlna.conf"}
DEFAULT_WEB_ROOTS = ("/var/www", "/www", "/web", "/webs", "/usr/www", "/home/www", "/usr/share/www", "/opt/www", "/app/www", "/mnt/web", "/home/web")

# U-Boot env 의 SD 신호
_ENV_FSLOAD_RX = re.compile(r"\b(?:fat|ext[24]|fs)?load\s{1,8}mmc\b|\b(?:fatls|ext4ls|fatsize)\s{1,8}mmc\b")
_ENV_SCRIPT_RX = re.compile(r"\bboot\.scr(?:\.uimg)?\b|\buEnv\.txt\b")
_ENV_SCRIPT_EXEC_RX = re.compile(r"\bsource\b|\benv\s{1,8}import\b|\bscript_?addr\b|\bsysboot\b|\bbootflow\b")
_ENV_DISTRO_RX = re.compile(r"\bdistro_bootcmd\b|\bbootcmd_mmc\d*\b|\bscan_dev_for_boot\b|\bmmc_?boot\b")
_ENV_RAWMMC_RX = re.compile(r"\bmmc\s{1,8}(?:read|dev|rescan|part|init)\b|\bmmcinfo\b")
#: 명시적인 SD 업데이트 명령·변수 이름. 일반 낱말 auto_update·autoupdate 는 세지 않는다 — TFTP 자동 업그레이드 도우미가 흔해서,
#: 펼친 값이 mmc 에서 읽고 플래시에 쓸 때(_ENV_FSLOAD_RX + _ENV_FLASHW_RX)만 카드 업데이트다
_ENV_UPDATE_RX = re.compile(r"\b(?:sdupdate|sdupgrade|hiupdate|do_auto_update|sd_update|update_from_sd)\b")
_ENV_FLASHW_RX = re.compile(r"\b(?:sf\s{1,8}(?:erase|write|update)|nand\s{1,8}(?:erase|write)|mtd\s{1,8}(?:erase|write)|flwrite|ubi\s{1,8}write)\b")
_ENV_FLASHLOAD_RX = re.compile(r"\bsf\s{1,8}(?:probe|read)\b|\bnand\s{1,8}read\b|\bubi\s{1,8}(?:part|read)\b|\bubifsload\b|\bmtd\s{1,8}read\b|\bnboot\b|\bspi\s{1,8}read\b")
#: boot.scr·uEnv.txt 를 읽는 출처 (run 펼침 뒤 값에서). mmc: fatload/ext2load/ext4load/load mmc·mmc dev/rescan/read·distro boot·devtype=mmc·
#: 장치가 변수인 'load ${devtype} …'(distro 어휘 — mmc 를 배제할 수 없다)·sysboot mmc. usb: usb start·load usb. 그 밖: 네트워크(tftp·dhcp·nfs·pxe)·
#: 내부 플래시(sf·nand·ubi·ubifsload·mtd)·다른 장치의 load
_ENV_MMC_SRC_RX = re.compile(_ENV_FSLOAD_RX.pattern + "|" + _ENV_RAWMMC_RX.pattern + "|" + _ENV_DISTRO_RX.pattern
                             + r"|\bdevtype\s{0,8}=\s{0,8}mmc\b|\bsetenv\s{1,8}devtype\s{1,8}mmc\b|\b(?:fat|ext[24]|fs)?load\s{1,8}\$\{?devtype\b|\bsysboot\s{1,8}mmc\b")
_ENV_USB_SRC_RX = re.compile(r"\busb\s{1,8}start\b|\b(?:fat|ext[24]|fs)?load\s{1,8}usb\b")
_ENV_OTHER_SRC_RX = re.compile(_ENV_FLASHLOAD_RX.pattern + r"|\b(?:tftp(?:boot)?|dhcp|bootp|rarpboot|nfs|pxe|wget)\b"
                               r"|\b(?:fat|ext[24]|fs)?load\s{1,8}(?:ubi|nand|sata|scsi|ide|nvme|virtio|host|hostfs|semihosting)\b")


def _env_load_source(ex: str) -> str | None:
    """env 값(run 펼침 뒤)이 파일을 어디서 읽는지: 'mmc' / 'usb' / 'other'(네트워크·내부 플래시 등) / None(출처가 보이지 않음).

    mmc 출처가 하나라도 있으면 'mmc' 다 ('if fatload mmc …; then …; else tftp …' 는 mmc 경로가 있다)."""
    if _ENV_MMC_SRC_RX.search(ex):
        return "mmc"
    if _ENV_USB_SRC_RX.search(ex):
        return "usb"
    if _ENV_OTHER_SRC_RX.search(ex):
        return "other"
    return None


def _env_card_update(ex: str) -> bool:
    """env 값(run 펼침 뒤)이 카드 업데이트인지: 명시적 SD 업데이트 명령(sdupdate·hiupdate·do_auto_update …)이거나 mmc 에서 읽어 플래시에 쓴다."""
    return bool(_ENV_UPDATE_RX.search(ex)) or bool(_ENV_FSLOAD_RX.search(ex) and _ENV_FLASHW_RX.search(ex))


#: 장치 자리의 변수('fatload ${bootdev} 0:1 … boot.scr' + 'bootdev=mmc', 'load ${interface} …' + 'interface=mmc')는 같은 env 의 값으로 바꿔 읽는다.
#: 값이 장치 이름 하나(_ENV_DEV_NAMES)인 변수만. devtype 은 distro 어휘라 따로 본다 ('load ${devtype}' 는 mmc 를 배제할 수 없다)
_ENV_DEVVAR_RX = re.compile(r"\b((?:fat|ext[24]|fs)?load|fatls|ext4ls|fatsize)(\s{1,8})\$(?:\{([A-Za-z_]\w{0,63})\}|([A-Za-z_]\w{0,63}))")
_ENV_DEV_NAMES = frozenset({"mmc", "usb", "ubi", "nand", "sata", "scsi", "ide", "nvme", "virtio", "host"})


def _env_dev_vars(env: dict[str, str]) -> dict[str, str]:
    """값이 장치 이름 하나인 env 변수 {이름: 장치} (devtype 제외, 앞 MAX_ENV_VARS 개만)."""
    out: dict[str, str] = {}
    for idx, (k, v) in enumerate(env.items()):
        if idx >= MAX_ENV_VARS:
            break
        if k != "devtype" and isinstance(v, str) and len(v) <= 16 and v.strip() in _ENV_DEV_NAMES:
            out[k] = v.strip()
    return out


def _subst_dev_vars(s: str, devs: dict[str, str]) -> str:
    """'load ${X}'·'fatls $X' 처럼 장치 자리의 변수를 devs 의 장치 이름으로 바꾼다 (한 번 훑기)."""
    if not devs or "$" not in s:
        return s

    def _rep(m: re.Match[str]) -> str:
        d = devs.get(m.group(3) or m.group(4))
        return m.group(1) + m.group(2) + d if d else m.group(0)

    return _ENV_DEVVAR_RX.sub(_rep, s)
_ENV_GPIO_RX = re.compile(r"(?i)\bgpio\s{1,8}(?:input|status|get|read)\b|\bbutton\b|\bkey_?(?:press|state)\b")
#: 'run' 명령이 있는지 보는 선형 사전 확인 (대상 이름은 _run_targets 가 토큰으로 자른다 — 게으른 정규식은 'run run … !' 에서 O(n^2))
_ENV_RUN_RX = re.compile(r"(?<![\w.-])run\s")
_ENV_SEP_SPLIT_RX = re.compile(r"(;|&&|\|\|)")
_RUN_TARGET_RX = re.compile(r"[\w.\-]{1,64}")
_ENV_KEYWORDS = {"then", "else", "do", "!", "if", "elif", "while", "until", "{", "}"}
#: run 펼침 상한: 변수 하나 16 KiB, env 한 벌 전체 2 MiB, 펼침 하나에서 run 대상 64개, 깊이 4. 넘으면 더 붙이지 않고 notes 에 적는다
EXPAND_PER_VAR = 16 << 10
EXPAND_TOTAL = 2 << 20
#: env 여럿(플래시 CRC env 최대 64 + 내장 기본 8)을 합친 run 펼침 출력 상한 — env 마다 2 MiB 를 따로 쓰면 ';' 홍수에서 1 MiB 이미지가 1분 걸렸다
EXPAND_SCAN_TOTAL = 4 << 20
#: 펼침 조각 이만큼마다 ctl(취소·시간 예산)을 본다
EXPAND_CTL_EVERY = 2048
EXPAND_RUNS = 64
EXPAND_DEPTH = 4
MAX_ENV_VARS = 20000

# 순위가 낮을수록 강한 근거 (evidence 정렬)
RULE_RANK = {
    "decrypt-then-exec": 1, "pipe-to-shell": 2, "sh": 3, "source": 3, "direct-exec": 4, "relative-exec": 4, "kernel-module": 4, "ld-preload": 4, "mdev-exec": 3,
    "udev-exec": 3, "inittab-exec": 3, "systemd-exec": 3, "cron-exec": 3, "copy-then-exec": 5, "trigger-service": 5, "autorun-name": 6,
    "binary-exec-string": 6, "chmod-x": 8, "binary-script-path": 9, "flash-write": 1, "copy-then-flash": 2, "trigger-flash": 2,
    "env-update-from-card": 1, "uboot-auto-update": 2, "fw_setenv-update": 3, "update-file": 6, "update-image-name": 7, "binary-update-file": 8,
    "env-fs-load": 2, "env-boot-script": 1, "env-distro-boot": 3, "fw_setenv-mmc": 3, "env-raw-mmc": 7, "uboot-boot-script-string": 8,
    "config-import": 1, "config-read": 2, "config-path": 5, "binary-config-path": 7, "syslogd-to-card": 1, "core-dump-to-card": 1,
    "packet-capture-to-card": 2, "sensitive-copy-to-card": 2, "log-to-card": 3, "log-path-config": 4, "write-to-card": 6, "binary-log-path": 7,
    "web-symlink": 1, "web-config-root": 1, "ftp-config-root": 1, "samba-share": 1, "dlna-media": 2, "server-root-arg": 1, "cgi-sd-write": 2,
    "cgi-sd-listing": 3, "cgi-sd-reference": 6, "cgi-binary-sd-reference": 7, "find-exec": 4,
}

MAX_EVIDENCE_STORED = 200
#: evidence extra 중 구조 값(경로·토큰·우리가 쓴 문구) — 나머지 문자열(expanded·options 등 펌웨어 원문)은 모두 마스킹한다
_STRUCTURAL_KEYS = {"sd_path", "copied_to", "link_target", "token", "triggered", "var", "storage", "env_offset_hex", "fs", "note", "gated_by",
                    "integrity_only", "severity_note", "cwd", "match_kind"}
MAX_SD_PATHS = 5000
MAX_PLAIN_REFS = 1000
#: 텍스트 한 줄에서 분류하는 길이(넘는 부분은 보지 않고 단계를 잘림으로 표시), 경로 토큰 길이 상한
MAX_LINE = 16384
MAX_TOKEN = 1024
#: 문자열 히트 상한 (바이너리는 파일마다, 이미지는 전체). 넘어서 버린 히트가 있으면 그 단계를 잘림으로 표시한다
BIN_HITS_PER_FILE = 5000
BIN_HITS_PER_PATTERN_FILE = 1000
IMAGE_HITS = 20000
#: 바이너리·이미지 문자열을 보는 청크 (hunt.CHUNK 16 MiB 보다 작게 — 짧은 문자열이 빽빽한 청크 하나의 문자열 목록 메모리를 줄인다). 겹침은 hunt.OVERLAP
SD_CHUNK = 2 << 20
IMAGE_HITS_PER_PATTERN = 5000
#: 문자열 히트 묶음을 분류하는 동안 이만큼마다 시간 예산·취소를 본다 (묶음 하나는 문맥 240자 — 토큰마다 마운트 지점 200개까지 비교)
HIT_GROUPS_CTL_EVERY = 32
#: 카드에서 복사한 대상 기억 상한 (파일마다): 대상 경로·대상 디렉터리·재귀 복사 대상 각 COPY_KEYS 개, 디렉터리마다 원본 이름 DIR_NAMES 개·
#: glob 원본 DIR_GLOBS 개 (중복 없이). 상한에 걸려 버린 복사가 있으면 rootfs_text 를 잘림으로 둔다 (복사 뒤 실행을 놓칠 수 있다)
COPY_KEYS = 200
DIR_NAMES = 64
DIR_GLOBS = 4
#: 파일 이름 길이 상한 (Linux NAME_MAX) — 더 긴 '이름' 은 glob 원본과 비교하지 않는다 (glob DP 비용 상한)
NAME_MAX = 255

_OPENSSL_OPT_RX = re.compile(r"(?<!\S)(-(?:k|K|iv|pass|passin|passout))(\s{1,8})(pass:|env:|file:|fd:)?(\"[^\"\n]{0,256}\"|'[^'\n]{0,256}'|[^\s;&|]{1,256})")


def _mask_openssl(text: str) -> str:
    """openssl 명령의 모든 키·IV·암호 옵션 값(-k/-K/-iv/-pass/-passin/-passout, 따옴표 값 전체)을 가린다. env:/file:/fd: 참조와 $변수는 그대로."""
    if "openssl" not in text:
        return text
    out: list[str] = []
    last = 0
    for m in _OPENSSL_OPT_RX.finditer(text):
        prefix, val = m.group(3) or "", m.group(4)
        if prefix in ("env:", "file:", "fd:") or val.startswith("$"):
            continue
        quoted = len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]
        inner = val[1:-1] if quoted else val
        masked = mask_secret(inner) or ""
        out.append(text[last:m.start(4)])
        out.append(val[0] + masked + val[0] if quoted else masked)
        last = m.end(4)
    out.append(text[last:])
    return "".join(out)


def _mask_excerpt(text: str, limit: int = 200) -> str:
    """발췌의 자격증명 모양 값(rootfs.mask_credentials: 비밀번호·PSK·URL 자격증명·따옴표 값, openssl 키 옵션 값)을 가린 뒤 자른다."""
    return clip(mask_credentials(_mask_openssl(text[: max(limit * 4, 1024)])).strip(), limit)


_NORM_CACHE: dict[str, str] = {}


def _norm(p: str) -> str:
    """경로 정규화 (문자열만 — 호스트 파일 시스템을 보지 않는다): ${X}→$X, //, 끝의 / . 정리, '..' 는 어휘적으로. 같은 토큰은 한 번만 계산."""
    hit = _NORM_CACHE.get(p)
    if hit is not None:
        return hit
    r = _norm_uncached(p)
    if len(_NORM_CACHE) < 65536 and len(p) <= MAX_TOKEN:
        _NORM_CACHE[p] = r
    return r


def _norm_uncached(p: str) -> str:
    p = re.sub(r"\$\{([A-Za-z_]\w*)\}", r"$\1", p).rstrip(".,:")
    if not p.startswith("/"):
        return p
    q = posixpath.normpath(p)
    return "/" if q in ("", ".") else q.replace("//", "/")


def _expand(line: str, local: dict[str, str], global_vars: dict[str, str], limit: int = MAX_LINE) -> str:
    """변수 펼침. 결과가 limit 를 넘게 될 참조는 펼치지 않는다 ('$A$A$A…' 로 메모리가 커지지 않게)."""
    if "$" not in line:
        return line
    budget = [max(0, limit - len(line))]

    def rep(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        v = local.get(name) or global_vars.get(name)
        if v is None or len(v) - len(m.group(0)) > budget[0]:
            return m.group(0)
        budget[0] -= max(0, len(v) - len(m.group(0)))
        return v

    return _VAR_RX.sub(rep, line)


_WIN = 512
_SEP_CHARS = ";&|\n"
#: 이보다 긴 공백 덧대기는 한 칸으로 접은 뒤 분류한다 ('sh' + 공백 600칸 + 카드 경로가 512자 문맥 창 밖으로 밀리지 않게, 보통 줄은 그대로)
_WS_LONG_RX = re.compile(r"[ \t]{32,}")


def _windows(L: str, a: int, b: int) -> tuple[str, str, str]:
    """토큰 L[a:b] 의 (앞 문맥, 뒤 문맥, 명령 조각). 긴 줄에서도 토큰마다 일정한 비용만 쓰게 앞뒤 512자로 자른다.

    앞 문맥을 자르면 맨 앞에 '\\x00' 를 붙여 '^'(줄 시작) 고정 정규식이 잘린 지점을 줄 시작으로 오인하지 않게 한다.
    명령 조각은 토큰을 둘러싼 ; & | 사이 (복사·플래시 명령 해석용)."""
    pre = L[max(0, a - _WIN):a]
    if a > _WIN:
        pre = "\x00" + pre
    post = L[b:b + _WIN]
    start = max(0, a - 4 * _WIN)
    lo = max([L.rfind(c, start, a) for c in _SEP_CHARS] + [start - 1]) + 1
    his = [i for i in (L.find(c, b, b + 4 * _WIN) for c in _SEP_CHARS) if i >= 0]
    hi = min(his) if his else min(len(L), b + 4 * _WIN)
    return pre, post, L[lo:hi]


_EXEC_QUOTE_HEAD_RX = re.compile(r"(?:(?<!\S)-c|\beval|\bexec|\bsystem\s*\(|\bpopen\s*\(|\b(?:RUN|PROGRAM|IMPORT\{program\})(?:\{\w+\})?\+?=)$")


def _quote_state(pre: str) -> tuple[bool, bool]:
    """앞 문맥 끝이 따옴표 안인지와, 그 따옴표가 실행 문자열(sh -c "…", eval "…", system("…"))인지.

    닫힌 따옴표 구간을 str.find 로 건너뛴다(선형). 잘린 문맥(\\x00 로 시작)은 줄 앞부분을 몰라 따옴표 밖으로 본다."""
    if pre.startswith("\x00") or ('"' not in pre and "'" not in pre):
        return False, False
    i = 0
    while True:
        cands = [k for k in (pre.find('"', i), pre.find("'", i)) if k >= 0]
        if not cands:
            return False, False
        j = min(cands)
        if j > 0 and pre[j - 1] == "\\":
            i = j + 1
            continue
        q = pre[j]
        k = j + 1
        while True:
            k = pre.find(q, k)
            if k < 0 or q == "'" or pre[k - 1] != "\\":
                break
            k += 1
        if k < 0:
            inner = pre[j + 1:]
            if not inner.strip():
                return False, False  # 'sh "/mnt/sd/x.sh"' 처럼 따옴표가 토큰을 감싸기 시작했을 뿐 (문구 안이 아님)
            if q == '"' and _in_cmd_subst(inner):
                return False, False  # "$(/mnt/sd/x)"·"`…`": 큰따옴표 안의 명령 치환은 다시 셸 명령 문맥이다 (작은따옴표 안은 아님)
            return True, bool(_EXEC_QUOTE_HEAD_RX.search(pre[:j].rstrip()))
        i = k + 1


def _in_cmd_subst(inner: str) -> bool:
    """큰따옴표 문구의 시작부터 토큰 앞까지(inner)에 닫히지 않은 '$(' 나 홀수 개의 역따옴표가 있는지 (한 번 훑기)."""
    depth = 0
    bt = False
    k = 0
    n = len(inner)
    while k < n:
        c = inner[k]
        if c == "\\":
            k += 2
            continue
        if c == "`":
            bt = not bt
        elif c == "$" and k + 1 < n and inner[k + 1] == "(":
            depth += 1
            k += 2
            continue
        elif c == ")" and depth > 0:
            depth -= 1
        k += 1
    return depth > 0 or bt


def _verify_off(raw: str | None) -> bool:
    """verify 환경값의 비활성 관찰 — env_get_yesno 기준 첫 글자가 1/y/Y/t/T 가 아니면 '아니오', 없으면 기본값.

    실제 검증 강제는 별도 확인한다. 오래된 U-Boot(env_get_yesno 이전)는 첫 글자 'n' 만 끔으로 본다 — notes 에 적는다."""
    return raw is not None and raw[:1] not in ("1", "y", "Y", "t", "T")


def _nc_listener(text: str) -> bool:
    """nc/netcat 리스너(-l, -lp, -vlp …)를 토큰으로 찾는다 (nc 마다 뒤 16개 토큰만 — 선형)."""
    if "nc" not in text and "netcat" not in text:
        return False
    for line in text.split("\n"):
        toks = line.split()
        for idx, t in enumerate(toks):
            if t.rsplit("/", 1)[-1] not in ("nc", "netcat"):
                continue
            for u in toks[idx + 1: idx + 17]:
                if u in (";", "&&", "||", "|", "&") or u.endswith((";", "&")):
                    break
                if len(u) > 1 and u[0] == "-" and u[1:].isalpha() and "l" in u[1:]:
                    return True
    return False


def _glob_match(pat: str, s: str) -> bool | None:
    """셸·udev glob(* ? [..] \\x) 일치 — 정규식으로 컴파일하지 않는 DP (패턴 128자 상한, 넘으면 None = 분류 불가)."""
    if len(pat) > 128:
        return None
    toks: list[tuple[Any, ...]] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            toks.append(("*",))
            i += 1
        elif c == "?":
            toks.append(("?",))
            i += 1
        elif c == "[":
            j = pat.find("]", i + 2)
            if j < 0:
                toks.append(("c", c))
                i += 1
                continue
            body = pat[i + 1:j]
            neg = body[:1] in ("!", "^")
            if neg:
                body = body[1:]
            ranges = []
            k = 0
            while k < len(body):
                if k + 2 < len(body) and body[k + 1] == "-":
                    ranges.append((body[k], body[k + 2]))
                    k += 3
                else:
                    ranges.append((body[k], body[k]))
                    k += 1
            toks.append(("[", neg, ranges))
            i = j + 1
        elif c == "\\" and i + 1 < len(pat):
            toks.append(("c", pat[i + 1]))
            i += 2
        else:
            toks.append(("c", c))
            i += 1
    n = len(s)
    cur = [False] * (n + 1)
    cur[0] = True
    for t in toks:
        nxt = [False] * (n + 1)
        if t[0] == "*":
            acc = False
            for j in range(n + 1):
                acc = acc or cur[j]
                nxt[j] = acc
        else:
            for j in range(n):
                if not cur[j]:
                    continue
                ch = s[j]
                if t[0] == "?":
                    ok = True
                elif t[0] == "c":
                    ok = ch == t[1]
                else:
                    ok = any(a <= ch <= b for a, b in t[2]) != t[1]
                if ok:
                    nxt[j + 1] = True
        cur = nxt
    return cur[n]


_MDEV_SAFE_CHARS_RX = re.compile(r"[A-Za-z0-9_\[\]\-.*+?^$|(){},!@:=/\\%#~]{1,128}")

#: 장치 이름 표본 (펌웨어 정규식·glob 을 이 표본에 '우리 해석기'로만 맞춰 본다). SD 쪽: SD·eMMC·USB 카드 리더, 다른 쪽: 흔한 비저장 장치.
#: eMMC 하드웨어 파티션(mmcblkNbootM·mmcblkNrpmb)은 어느 쪽 표본도 아니다 — SD 카드에는 없어서 그것만 맞추는 규칙(KERNEL=="mmcblk0boot[01]")은
#: SD 표본을 하나도 못 맞춰 'other' 가 되고, 'mmcblk*' 처럼 SD 표본도 맞추는 규칙은 그대로 'sd' 다 (다른 쪽 표본에 넣으면 'catch-all' 이 된다)
_SD_SAMPLES = tuple([f"mmcblk{n}" for n in (0, 1, 2, 3, 9)] + [f"mmcblk{n}p{k}" for n in (0, 1, 2, 3, 9) for k in (1, 2, 9)] + ["mmc0"]
                    + [f"sd{c}" for c in "abcz"] + [f"sd{c}{k}" for c in "abcz" for k in (1, 2, 9)])
_NON_SD_SAMPLES = ("null", "zero", "console", "tty", "tty0", "tty1", "ttyS0", "ttyAMA1", "ram0", "loop0", "mtd0", "mtdblock2", "watchdog", "random", "fb0",
                   "video0", "input/event0", "snd/pcmC0D0p", "ubi0_0", "i2c-0")
_SUBSYS_SAMPLES = ("mmc", "mmc_host", "block", "tty", "net", "input", "sound", "usb", "misc", "mtd", "video4linux")
_DEVPATH_SD = ("/devices/platform/soc/mmc0/mmc_host/mmc0/mmc0:0001/block/mmcblk0", "/devices/platform/soc/mmc0/mmc_host/mmc0/mmc0:0001/block/mmcblk0/mmcblk0p1",
               "/devices/platform/ehci/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0/block/sda/sda1")
_DEVPATH_NON_SD = ("/devices/virtual/tty/tty0", "/devices/virtual/mem/null", "/devices/virtual/net/lo", "/devices/platform/serial8250/tty/ttyS0")
_POSIX_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "lower": "a-z", "upper": "A-Z", "space": " \t\r\n\v\f", "xdigit": "0-9a-fA-F",
                  "punct": "!-/:-@[-`{-~", "print": " -~", "graph": "!-~", "blank": " \t", "word": "a-zA-Z0-9_"}
_ERE_MAX_STATES = 2000
_ERE_MAX_COUNT = 16


class _EreUnsupported(Exception):
    """우리 ERE 해석기가 다루지 않는 문법 (→ 분류 불가)."""


def _ranges_of(spec: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    k = 0
    while k < len(spec):
        if k + 2 < len(spec) and spec[k + 1] == "-":
            out.append((spec[k], spec[k + 2]))
            k += 3
        else:
            out.append((spec[k], spec[k]))
            k += 1
    return out


class _Ere:
    """mdev.conf 장치 정규식(POSIX ERE)을 '실행하지 않고' 표본 이름에 맞춰 보는 작은 해석기.

    리터럴·'.'·[..](범위·부정·[:class:])·( | )·* + ? {m,n}(16 이하)·^ $ 만 다루고, 톰슨 NFA 로 시뮬레이션한다 — 표본 길이 × 상태 수에
    비례(되돌아가기 없음)라 '(a|a)*'·'(.*){30}' 같은 패턴도 멈추지 않는다. 그 밖의 문법('(?:'·역참조·큰 반복 수)은 _EreUnsupported."""

    def __init__(self, pattern: str) -> None:
        self.p = pattern
        self.i = 0
        self.edges: list[list[tuple[str, Any, int]]] = []
        ast = self._alt()
        if self.i != len(self.p):
            raise _EreUnsupported("남은 문자")
        self.start, self.accept = self._build(ast)

    # -- 해석 ---------------------------------------------------------------
    def _peek(self) -> str:
        return self.p[self.i] if self.i < len(self.p) else ""

    def _alt(self) -> Any:
        branches = [self._cat()]
        while self._peek() == "|":
            self.i += 1
            branches.append(self._cat())
        return ("alt", branches) if len(branches) > 1 else branches[0]

    def _cat(self) -> Any:
        items: list[Any] = []
        while self._peek() not in ("", "|", ")"):
            items.append(self._repeat())
        return ("cat", items)

    def _repeat(self) -> Any:
        atom = self._atom()
        while self._peek() in ("*", "+", "?", "{"):
            c = self._peek()
            if c == "{":
                m = re.match(r"\{(\d{1,3})(,(\d{0,3}))?\}", self.p[self.i:])
                if not m:
                    raise _EreUnsupported("반복 수")
                lo = int(m.group(1))
                hi = lo if m.group(2) is None else (int(m.group(3)) if m.group(3) else None)
                if lo > _ERE_MAX_COUNT or (hi is not None and (hi > _ERE_MAX_COUNT or hi < lo)):
                    raise _EreUnsupported("큰 반복 수")
                self.i += m.end()
            else:
                self.i += 1
                lo, hi = {"*": (0, None), "+": (1, None), "?": (0, 1)}[c]
            atom = ("rep", atom, lo, hi)
        return atom

    def _atom(self) -> Any:
        c = self._peek()
        if c == "(":
            self.i += 1
            if self._peek() == "?":
                raise _EreUnsupported("(?")
            inner = self._alt()
            if self._peek() != ")":
                raise _EreUnsupported("괄호")
            self.i += 1
            return inner
        if c in ("*", "+", "?", "{"):
            raise _EreUnsupported("앞 원자 없는 반복")
        if c == "[":
            return self._bracket()
        self.i += 1
        if c == ".":
            return ("cls", True, [])
        if c == "^":
            return ("bol",)
        if c == "$":
            return ("eol",)
        if c == "\\":
            e = self._peek()
            if not e:
                raise _EreUnsupported("끝 역슬래시")
            self.i += 1
            if e == "d":
                return ("cls", False, [("0", "9")])
            if e == "w":
                return ("cls", False, _ranges_of(_POSIX_CLASSES["word"]))
            if e == "s":
                return ("cls", False, _ranges_of(_POSIX_CLASSES["space"]))
            if e.isalnum():
                raise _EreUnsupported("이스케이프")
            return ("cls", False, [(e, e)])
        return ("cls", False, [(c, c)])

    def _bracket(self) -> Any:
        j = self.i + 1
        neg = j < len(self.p) and self.p[j] == "^"
        if neg:
            j += 1
        ranges: list[tuple[str, str]] = []
        first = True
        while True:
            if j >= len(self.p):
                raise _EreUnsupported("닫히지 않은 [")
            c = self.p[j]
            if c == "]" and not first:
                j += 1
                break
            first = False
            if c == "[" and j + 1 < len(self.p) and self.p[j + 1] in ":=.":
                kind = self.p[j + 1]
                k = self.p.find(kind + "]", j + 2)
                if kind != ":" or k < 0 or self.p[j + 2:k] not in _POSIX_CLASSES:
                    raise _EreUnsupported("[: :]")
                ranges += _ranges_of(_POSIX_CLASSES[self.p[j + 2:k]])
                j = k + 2
                continue
            if j + 2 < len(self.p) and self.p[j + 1] == "-" and self.p[j + 2] != "]":
                ranges.append((c, self.p[j + 2]))
                j += 3
                continue
            ranges.append((c, c))
            j += 1
        self.i = j
        return ("cls", neg, ranges)

    # -- NFA ----------------------------------------------------------------
    def _new(self) -> int:
        if len(self.edges) >= _ERE_MAX_STATES:
            raise _EreUnsupported("상태 수")
        self.edges.append([])
        return len(self.edges) - 1

    def _build(self, node: Any) -> tuple[int, int]:
        kind = node[0]
        s = self._new()
        if kind == "cls":
            e = self._new()
            self.edges[s].append(("c", (node[1], node[2]), e))
            return s, e
        if kind in ("bol", "eol"):
            e = self._new()
            self.edges[s].append((kind, None, e))
            return s, e
        if kind == "cat":
            cur = s
            for it in node[1]:
                a, b = self._build(it)
                self.edges[cur].append(("e", None, a))
                cur = b
            return s, cur
        if kind == "alt":
            e = self._new()
            for br in node[1]:
                a, b = self._build(br)
                self.edges[s].append(("e", None, a))
                self.edges[b].append(("e", None, e))
            return s, e
        # rep
        _, sub, lo, hi = node
        cur = s
        for _k in range(lo):
            a, b = self._build(sub)
            self.edges[cur].append(("e", None, a))
            cur = b
        if hi is None:
            a, b = self._build(sub)
            e = self._new()
            self.edges[cur].append(("e", None, a))
            self.edges[cur].append(("e", None, e))
            self.edges[b].append(("e", None, a))
            self.edges[b].append(("e", None, e))
            return s, e
        e = self._new()
        self.edges[cur].append(("e", None, e))
        for _k in range(hi - lo):
            a, b = self._build(sub)
            self.edges[cur].append(("e", None, a))
            self.edges[b].append(("e", None, e))
            cur = b
        return s, e

    def _closure(self, states: set[int], pos: int, n: int) -> set[int]:
        out = set(states)
        stack = list(states)
        while stack:
            st = stack.pop()
            for kind, _pred, tgt in self.edges[st]:
                if tgt in out:
                    continue
                if kind == "e" or (kind == "bol" and pos == 0) or (kind == "eol" and pos == n):
                    out.add(tgt)
                    stack.append(tgt)
        return out

    def fullmatch(self, text: str) -> bool:
        n = len(text)
        cur = self._closure({self.start}, 0, n)
        for i, ch in enumerate(text):
            nxt: set[int] = set()
            for st in cur:
                for kind, pred, tgt in self.edges[st]:
                    if kind == "c":
                        neg, ranges = pred
                        if any(a <= ch <= b for a, b in ranges) != neg:
                            nxt.add(tgt)
            if not nxt:
                return False
            cur = self._closure(nxt, i + 1, n)
        return self.accept in cur


_ERE_CACHE: dict[str, Any] = {}


def _ere(pattern: str) -> _Ere | None:
    """해석기를 만들거나 None (다루지 않는 문법·상한 초과)."""
    if pattern in _ERE_CACHE:
        return _ERE_CACHE[pattern]
    try:
        e: _Ere | None = _Ere(pattern)
    except (_EreUnsupported, RecursionError):
        e = None
    if len(_ERE_CACHE) < 64:
        _ERE_CACHE[pattern] = e  # NFA 는 클 수 있어 조금만 (분류 결과는 _MDEV_CLASS_CACHE 가 패턴마다 기억한다)
    return e


def _sample_kind(match: Any, sd: tuple[str, ...], other: tuple[str, ...]) -> str | None:
    """표본으로 본 분류: SD 표본과 다른 표본을 모두 맞추면 'catch-all', SD 만이면 'sd', SD 를 하나도 못 맞추면 'other' (판단 불가면 None)."""
    hits_sd = [match(x) for x in sd]
    hits_other = [match(x) for x in other]
    if any(h is None for h in hits_sd + hits_other):
        return None
    if any(hits_sd):
        return "catch-all" if any(hits_other) else "sd"
    return "other"


def _env_restricts_to_non_block(env: list[str]) -> bool:
    """mdev 규칙 앞의 'VAR=정규식;' 조건이 장치 종류를 블록·MMC 밖으로 묶는지 (SUBSYSTEM=net 등). ACTION 같은 조건은 묶지 않는다."""
    for e in env:
        k, _, v = e.partition("=")
        if k.strip().upper() in ("SUBSYSTEM", "DEVPATH") and "block" not in v.lower() and "mmc" not in v.lower() and v.strip() not in (".*", ".+"):
            return True
    return False


_MDEV_CLASS_CACHE: dict[tuple[str, tuple[str, ...]], str] = {}
_UDEV_CLASS_CACHE: dict[tuple[tuple[str, str], ...], str] = {}


def classify_mdev_matcher(regex: str, env: list[str]) -> str:
    """classify_mdev_matcher 의 결과를 (정규식, 앞 조건)마다 기억한다 — 같은 패턴의 규칙이 많아도 표본 시뮬레이션은 한 번."""
    key = (regex or "", tuple(env))
    hit = _MDEV_CLASS_CACHE.get(key)
    if hit is None:
        hit = _classify_mdev_matcher(regex, env)
        if len(_MDEV_CLASS_CACHE) < 4096:
            _MDEV_CLASS_CACHE[key] = hit
    return hit


def _classify_mdev_matcher(regex: str, env: list[str]) -> str:
    """mdev.conf 장치 정규식을 '실행하지 않고' 분류한다: 'sd' / 'catch-all'(SD 를 포함한 여러 장치) / 'other' / 'unclassifiable'.

    펌웨어가 준 정규식을 re.compile 하면 역추적 폭발(ReDoS)·OverflowError·RecursionError 로 서버가 멈추거나 죽을 수 있어
    작은 POSIX ERE 해석기(_Ere, 톰슨 NFA)로 장치 이름 표본(SD 쪽·다른 쪽)에 '전체 일치'(BusyBox mdev 와 같음)로만 맞춰 본다.
    '$VAR=정규식' 은 장치 이름이 아니라 환경 변수에 맞추는 규칙이다: DEVNAME/MDEV 는 장치 이름으로, SUBSYSTEM·DEVPATH 는 그 표본으로,
    MODALIAS(모듈 자동 적재) 같은 나머지는 'other'. 해석기가 다루지 않는 문법은 SD 리터럴이 보이면 'sd', 아니면 분류 불가."""
    r = (regex or "").strip()
    env_l = " ".join(env).lower()
    if "mmc" in env_l:
        return "sd"
    if not r or len(r) > 128 or not _MDEV_SAFE_CHARS_RX.fullmatch(r):
        return "unclassifiable"
    m = re.fullmatch(r"@(\d{1,3}),\d{1,5}(?:-\d{1,5})?", r)
    if m:  # 주번호: 179 = MMC 블록(SD·eMMC), 8 = SCSI 디스크(USB 카드 리더)
        return "sd" if m.group(1) in ("179", "8") else "other"
    m = re.fullmatch(r"\$([A-Za-z_]\w{0,31})=(.{0,96})", r)
    if m:
        var, val = m.group(1).upper(), m.group(2)
        e = _ere(val)
        if var == "SUBSYSTEM":
            if e is None:
                return "unclassifiable"
            hits = {x for x in _SUBSYS_SAMPLES if e.fullmatch(x)}
            if hits and hits <= {"mmc", "mmc_host"}:
                return "sd"
            return "catch-all" if ("block" in hits or "mmc" in hits) else "other"
        if var == "DEVPATH":
            if e is None:
                return "sd" if "mmc" in val.lower() else "unclassifiable"
            return _sample_kind(e.fullmatch, _DEVPATH_SD, _DEVPATH_NON_SD) or "unclassifiable"
        if var not in ("DEVNAME", "MDEV"):
            return "other"  # MODALIAS·ACTION·PRODUCT … — 장치 이름 규칙이 아니다 (BusyBox 예제의 '$MODALIAS=.* … @modprobe')
        r = val
    e = _ere(r)
    if e is None:
        low = r.lower().replace("\\", "")
        if "mmc" in low or "tfcard" in low or re.search(r"(?:^|[^a-z])sd(?:[a-z0-9\[\].(|)*?+{]|$)", low):
            return "sd"
        return "unclassifiable"
    kind = _sample_kind(e.fullmatch, _SD_SAMPLES, _NON_SD_SAMPLES) or "unclassifiable"
    if kind == "catch-all" and _env_restricts_to_non_block(env):
        return "other"
    return kind


_REMOVABLE_FS_VALUES = ("vfat", "exfat", "msdos", "fat", "ntfs", "ntfs3", "texfat", "tntfs")
#: udev 표준 도우미 (모든 블록 장치에 붙는 식별·적재 도구 — 카드 내용을 다루는 처리기가 아니다)
_STOCK_UDEV_HELPERS = {"blkid", "ata_id", "scsi_id", "path_id", "usb_id", "cdrom_id", "mtd_probe", "modprobe", "kmod", "udevadm", "v4l_id", "input_id",
                       "edd_id", "collect", "vol_id", "firmware", "firmware.sh"}


def _udev_has_handler(rule: dict[str, Any]) -> bool:
    """udev 규칙이 실제 처리기를 부르는지: RUN/PROGRAM/IMPORT{program} 명령 중 표준 도우미(blkid·scsi_id·modprobe …)가 아닌 것이 있어야 한다."""
    for cmd in rule.get("run") or []:
        prog = command_program(cmd) or ""
        if prog and prog.rsplit("/", 1)[-1] not in _STOCK_UDEV_HELPERS:
            return True
    return False


def classify_udev_match(match: dict[str, str]) -> str:
    """_classify_udev_match 의 결과를 일치 키 묶음마다 기억한다."""
    key = tuple(sorted(match.items()))
    hit = _UDEV_CLASS_CACHE.get(key)
    if hit is None:
        hit = _classify_udev_match(match)
        if len(_UDEV_CLASS_CACHE) < 4096:
            _UDEV_CLASS_CACHE[key] = hit
    return hit


def _classify_udev_match(match: dict[str, str]) -> str:
    """udev 규칙의 일치 키로 SD 관련성: 'sd' / 'catch-all' / 'other' / 'unclassifiable'.

    KERNEL 같은 glob 은 정규식 없이 DP(_glob_match)로 SD 표본·다른 표본과 맞춘다. 키마다 분류한 뒤 가장 좁은 것을 쓴다:
    한 키라도 SD 를 배제하면 'other', SUBSYSTEM=="block"·KERNEL=="*" 처럼 SD 를 포함한 여러 장치면 'catch-all',
    mmcblk*·sd*·ENV{ID_BUS}==usb/mmc·SUBSYSTEM==mmc·ENV{ID_FS_TYPE}==vfat 류면 'sd'."""
    kinds: list[str] = []
    for k, v in match.items():
        if v.startswith("!"):
            continue
        ku = k.upper()
        if ku in ("KERNEL", "KERNELS", "NAME") or ku.startswith("ENV{DEVNAME") or ku.startswith("ENV{MDEV"):
            sub: list[str] = []
            for pat in v.split("|")[:16]:
                pat = pat.rsplit("/", 1)[-1]
                sub.append(_sample_kind(lambda x, pat=pat: _glob_match(pat, x), _SD_SAMPLES, _NON_SD_SAMPLES) or "unclassifiable")
            kinds.append("catch-all" if "catch-all" in sub else "sd" if "sd" in sub else "unclassifiable" if "unclassifiable" in sub else "other")
        elif ku.startswith("ENV{ID_BUS"):
            kinds.append("sd" if v in ("usb", "mmc") else "other")
        elif ku in ("SUBSYSTEM", "SUBSYSTEMS"):
            vals = v.split("|")[:16]
            if any(x in ("mmc", "mmc_host") for x in vals) and not any(x == "block" or x == "*" for x in vals):
                kinds.append("sd")
            elif any(x == "block" or x == "*" for x in vals):
                kinds.append("catch-all")
            else:
                kinds.append("other")
        elif ku.startswith("ENV{ID_FS_TYPE"):
            kinds.append("sd" if any(x in _REMOVABLE_FS_VALUES for x in v.split("|")) else "other")
    if "other" in kinds:
        return "other"
    if "unclassifiable" in kinds:
        return "unclassifiable"
    if "sd" in kinds:
        return "sd"
    return "catch-all" if kinds else "other"


# ---------------------------------------------------------------------------
# mount 명령 해석 (스크립트 줄, mdev/udev 명령, 바이너리 문자열 공통)
# ---------------------------------------------------------------------------

_CMD_SEP_RX = re.compile(r"\|\||&&|[;|&`]|\$\(|\)")
_CMD_PREFIX = {"busybox", "exec", "nohup", "if", "!", "then", "do", "else", "elif", "time", "command", "setsid", "while", "until", "("}


def iter_command_pieces(line: str) -> list[str]:
    return [p for p in _CMD_SEP_RX.split(line) if p and p.strip()]


def parse_mount_command(piece: str) -> dict[str, Any] | None:
    """mount 명령 한 조각 → {fs, options, device, mount_point, readonly}. bind/move/remount/-a 와 마운트 지점이 없는 줄은 None."""
    toks = [t.strip("\"'") for t in piece.split()[:64]]
    i = 0
    while i < len(toks) and (toks[i] in _CMD_PREFIX or ("=" in toks[i] and not toks[i].startswith(("/", "-")))):
        i += 1
    if i >= len(toks) or toks[i].rsplit("/", 1)[-1] != "mount":
        return None
    fs: str | None = None
    opts: list[str] = []
    pos: list[str] = []
    ro = special = False
    j = i + 1
    while j < len(toks):
        t = toks[j]
        if t.startswith((">", "<", "2>", "1>", "&>")):
            break
        if t in ("-t", "--types") and j + 1 < len(toks):
            fs = toks[j + 1]
            j += 2
            continue
        if t.startswith("-t") and not t.startswith("--") and len(t) > 2:
            fs = t[2:]
        elif t == "-o" and j + 1 < len(toks):
            opts += toks[j + 1].split(",")
            j += 2
            continue
        elif t.startswith("-o") and len(t) > 2:
            opts += t[2:].split(",")
        elif t in ("-r", "--read-only"):
            ro = True
        elif t in ("--bind", "--rbind", "--move", "-a", "--all", "-B", "-M", "-R"):
            special = True
        elif not t.startswith("-"):
            pos.append(t)
        j += 1
    opts = [o for o in opts if o][:32]
    if special or any(o in ("remount", "bind", "rbind", "move") for o in opts):
        return None
    if "ro" in opts:
        ro = True
    device = mp = None
    if len(pos) >= 2:
        device, mp = pos[0], pos[1]
    elif len(pos) == 1:
        mp = pos[0]
    if not mp or not mp.startswith("/"):
        return None
    return {"fs": fs, "options": opts, "device": device, "mount_point": mp, "readonly": ro}


def _is_sd_mount(fs: str | None, device: str | None, mp: str, *, hotplug: bool = False) -> tuple[bool, str | None]:
    """(SD 후보인지, 메모). eMMC 일 수 있는 /dev/mmcblk 마운트는 마운트 지점이 SD 같을 때만, 읽기 전용 fs·네트워크·플래시 장치는 SD 가 아니다.

    SD 같은 이름: sd*(sdk 제외)·mmc*·tf*·*card*·disc*·usb*·extsd* 경로 요소. SCSI 디스크 이름(sda1·sdb2)은 /dev/mmcblk 마운트일 때만 SD 이름이다
    (/dev/sdX 를 /mnt/sda1·/media/sdb2 에 마운트하는 건 DVR/NVR 의 SATA HDD·USB 디스크 관례). 일반 이름(media·storage)만 있으면 FAT 계열 fs
    (vfat·exfat·ntfs …)일 때만 SD 후보다 — SD 카드는 FAT/exFAT 로 쓰이고, eMMC 데이터 파티션('/userdata/media'·'/mnt/storage')·NVR HDD 는
    ext4·f2fs·xfs 다. fs 를 모르면(-t 없음·auto) 일반 이름만으로는 SD 로 보지 않는다 (메모로 남긴다)."""
    mpn = _norm(mp)
    if mpn in _EXCLUDED_MP:
        return False, None
    f = (fs or "").lower().split(",")[0] or None
    dev = device or ""
    mmc_dev = dev.startswith("/dev/mmcblk")
    if f in READ_ONLY_FS:
        return False, (f"읽기 전용 파일 시스템({f}) — 쓰기 가능한 SD 마운트가 아님" if mmc_dev else None)
    builtin = bool(_BUILTIN_SD_RX.match(mpn))
    named = builtin or bool((_SDLIKE_MMC_COMPONENT_RX if mmc_dev else _SDLIKE_COMPONENT_RX).search(mpn))
    generic = f in FAT_FS and bool(_GENERIC_MEDIA_RX.search(mpn)) and (mmc_dev or not _SCSI_DISK_COMPONENT_RX.search(mpn))
    sdlike = named or generic
    hot_dev = bool(dev) and bool(_HOTPLUG_DEV_RX.search(dev) or (hotplug and re.match(r"^/dev/\$", dev)))
    usb_dev = bool(re.match(r"^/dev/sd[a-z]", dev))
    label_dev = dev.startswith(("LABEL=", "UUID=", "PARTUUID="))
    if dev and not (hot_dev or mmc_dev or usb_dev or label_dev):
        return False, None  # mtdblock·ubi·NFS(host:/path)·CIFS(//nas/x)·tmpfs 등 — 카드가 아니다
    if hot_dev:
        return True, "핫플러그 장치 변수"
    if mmc_dev:
        if sdlike:
            return True, None
        return False, ("SD·eMMC 장치이지만 SD 같지 않은 마운트 지점(media·storage 같은 일반 이름은 FAT 계열 fs 일 때만 SD 후보) — eMMC·내장 저장소일 수 있음 "
                       "(mmc 장치 번호로는 구분 못 함)")
    if usb_dev:
        if sdlike:
            return True, None  # USB 저장장치·카드 리더 — 이동식
        return False, ("/dev/sdX 장치이지만 SD 같지 않은 마운트 지점(sda1 같은 장치 이름 디렉터리, FAT 계열이 아닌 media·storage) — "
                       "SATA·USB 디스크(DVR/NVR 의 HDD 등)일 수 있음")
    if builtin:
        return True, None
    if f in REMOVABLE_FS or f in (None, "auto"):
        return (True, None) if sdlike else (False, None)
    return False, None


# ---------------------------------------------------------------------------
# U-Boot env 의 SD 부팅 분석 (fw_uboot_env 의 sd_boot, fw_sd_surface 의 SD-02/SD-03)
# ---------------------------------------------------------------------------


def _run_targets(piece: str) -> list[str]:
    """명령 조각이 'run a b c' 면 대상 이름들 (if/then/else/do 같은 앞말은 건너뜀, ${x} 같은 동적 이름에서 멈춤, 64개 상한)."""
    toks = piece.split()
    i = 0
    while i < len(toks) and toks[i] in _ENV_KEYWORDS:
        i += 1
    if i >= len(toks) or toks[i] != "run":
        return []
    out: list[str] = []
    for t in toks[i + 1:i + 1 + EXPAND_RUNS]:
        if not _RUN_TARGET_RX.fullmatch(t):
            break
        out.append(t)
    return out


def _scan_left(budget: dict[str, Any]) -> bool:
    """스캔 전체 예산·시간 예산이 남았는지 (budget 의 'scan' 은 env 여럿이 함께 쓰는 dict, 'ctl' 은 작업 제어)."""
    scan = budget.get("scan")
    if scan is None:
        return True
    if scan["stopped"]:
        budget["truncated"] = True
        return False
    scan["ops"] += 1
    if scan["ops"] % EXPAND_CTL_EVERY == 0 and scan.get("ctl") is not None and scan["ctl"].expired():
        scan["stopped"] = True
        budget["truncated"] = True
        return False
    return True


def _take(s: str, budget: dict[str, Any]) -> str:
    n = budget["chars"]
    if n <= 0:
        budget["truncated"] = True
        return ""
    if len(s) > n:
        budget["truncated"] = True
        s = s[:n]
    budget["chars"] -= len(s)
    return s


def _expand_env_var(env: dict[str, str], name: str, budget: dict[str, Any] | None = None, depth: int = 0) -> str:
    """run 대상을 제자리에 펼친 값. budget = {chars, runs, truncated}: 붙이는 글자 수와 펼치는 run 대상 수의 상한 — 다 쓰면 더 붙이지 않는다.

    값은 남은 예산만큼만 앞에서 잘라 보므로 일은 출력 크기에 비례한다 (큰 env 에서도 메모리·시간이 상한 안)."""
    if budget is None:
        budget = {"chars": EXPAND_PER_VAR, "runs": EXPAND_RUNS, "truncated": False}
    val = env.get(name, "")
    if not isinstance(val, str) or budget["chars"] <= 0:
        return ""
    if len(val) > budget["chars"]:
        val = val[:budget["chars"]]
        budget["truncated"] = True
    if depth >= EXPAND_DEPTH or not _ENV_RUN_RX.search(val):
        return _take(val, budget)
    out: list[str] = []
    for part in _ENV_SEP_SPLIT_RX.split(val):
        if budget["chars"] <= 0 or not _scan_left(budget):
            budget["truncated"] = True
            break
        out.append(_take(part, budget))
        if part in (";", "&&", "||"):
            continue
        for t in _run_targets(part):
            if budget["runs"] <= 0 or budget["chars"] <= 0:
                budget["truncated"] = True
                break
            if t in env and t != name:
                budget["runs"] -= 1
                out.append(" { " + _expand_env_var(env, t, budget, depth + 1) + " } ")
    return "".join(out)


def sd_boot_analysis(env: dict[str, str], *, storage: str, scan: dict[str, Any] | None = None) -> dict[str, Any]:
    """env 한 벌의 SD 부팅 신호. storage: 'flash-crc'(CRC 가 맞는 플래시 env → saveenv 로 쓰기 가능) / 'embedded-default'(U-Boot 내장 기본 env).

    run 펼침은 변수당·env 전체·스캔 전체(scan: env 여럿이 함께 쓰는 {chars, ops, stopped, ctl}) 예산 안에서만 하고(넘으면 notes),
    변수는 MAX_ENV_VARS 개까지 본다. scan 의 ctl 은 펼침 조각 EXPAND_CTL_EVERY 개마다 확인한다 (시간 예산을 넘으면 더 펼치지 않음).

    boot.scr·uEnv.txt 이름은 그 값(run 펼침 뒤)이 mmc 에서 읽을 때만 SD 부팅 신호다(_env_load_source): UBI(ubifsload)·TFTP·NAND·SF 에서 읽으면
    세지 않고, USB 에서 읽으면 이동식 매체 메모만 남긴다. 읽는 장치가 보이지 않는 이름만의 변수('script=boot.scr')는 같은 env 에 mmc 에서 읽는
    경로(fs-load·distro boot)가 따로 있을 때만 그 스크립트로 센다 — 실제로 읽는 변수는 따로 판정되고, 평범한 SPI-NOR/NAND env 의 이름만으로는
    SD 를 주장하지 않는다. 업데이트도 명시적 SD 업데이트 명령이거나 mmc 에서 읽어 플래시에 쓸 때만 (일반 낱말 auto_update·autoupdate 는 아님).
    장치 자리의 변수('fatload ${bootdev} …' + 'bootdev=mmc')는 같은 env 에서 값이 장치 이름 하나면 그 장치로 읽는다 (_subst_dev_vars)."""
    signals: list[dict[str, Any]] = []
    fs_load = boot_script = distro = raw_mmc = update = False
    update_gpio: list[bool] = []
    notes: list[str] = []
    global_left = EXPAND_TOTAL
    expand_truncated = vars_truncated = False
    signals_total = 0
    script_bare: list[str] = []  # 이름만 있고 읽는 장치가 안 보이는 boot.scr·uEnv.txt 변수
    script_usb: list[str] = []
    script_other: list[str] = []
    kinded: set[str] = set()
    devs = _env_dev_vars(env)  # 장치 자리 변수 → 장치 이름 ('bootdev=mmc')
    for idx, (k, v) in enumerate(env.items()):
        if idx >= MAX_ENV_VARS:
            vars_truncated = True
            notes.append(f"변수가 {MAX_ENV_VARS}개를 넘어 나머지는 보지 않았다.")
            break
        if not isinstance(v, str):
            continue
        if _ENV_RUN_RX.search(v):
            scan_chars = scan["chars"] if scan is not None else EXPAND_TOTAL
            if global_left > 0 and scan_chars > 0 and not (scan is not None and scan["stopped"]):
                per = min(EXPAND_PER_VAR, global_left, scan_chars)
                budget = {"chars": per, "runs": EXPAND_RUNS, "truncated": False, "scan": scan}
                ex = _expand_env_var(env, k, budget)
                used = per - budget["chars"]
                global_left -= used
                if scan is not None:
                    scan["chars"] -= used
                expand_truncated |= budget["truncated"]
            else:
                ex = v
                expand_truncated = True
        else:
            ex = v
        # 장치 자리의 변수는 같은 env 의 장치 이름으로 읽는다 (표시는 원래 값)
        vd = _subst_dev_vars(v, devs)
        exd = _subst_dev_vars(ex, devs)
        kinds: list[str] = []
        if _ENV_FSLOAD_RX.search(vd):
            kinds.append("fs-load")
        if _ENV_SCRIPT_RX.search(v):
            src = _env_load_source(exd)
            if src == "mmc":
                kinds.append("boot-script")
            elif src is None:
                script_bare.append(k)
            else:
                (script_usb if src == "usb" else script_other).append(k)
        elif _ENV_SCRIPT_EXEC_RX.search(v) and _ENV_FSLOAD_RX.search(exd):
            kinds.append("boot-script")
        if _ENV_DISTRO_RX.search(k) or _ENV_DISTRO_RX.search(v) or (k == "boot_targets" and re.search(r"\bmmc", v)):
            kinds.append("distro-boot")
        if _ENV_RAWMMC_RX.search(v):
            kinds.append("raw-mmc")
        upd = bool(_ENV_UPDATE_RX.search(v)) or bool(_ENV_FSLOAD_RX.search(exd) and _ENV_FLASHW_RX.search(exd))
        if upd:
            kinds.append("update-from-card")
            update_gpio.append(bool(_ENV_GPIO_RX.search(ex)))
        if kinds:
            signals_total += 1
            kinded.add(k)
            if len(signals) < 24:
                signals.append({"var": k, "kinds": kinds, "value": _mask_excerpt(v, 200)})
            fs_load |= "fs-load" in kinds
            boot_script |= "boot-script" in kinds
            distro |= "distro-boot" in kinds
            raw_mmc |= "raw-mmc" in kinds
            update |= upd
    if script_bare and (fs_load or distro):
        # 이름만 있는 변수는 같은 env 에 mmc 에서 읽는 경로가 있을 때만 그 경로가 읽는 스크립트로 본다 (i.MX 'script=boot.scr' + 'load mmc … ${script}')
        boot_script = True
        for name in script_bare:
            sg = next((s for s in signals if s["var"] == name), None)
            if sg is not None:
                sg["kinds"].append("boot-script")
            elif name not in kinded:
                kinded.add(name)
                signals_total += 1
                if len(signals) < 24:
                    signals.append({"var": name, "kinds": ["boot-script"], "value": _mask_excerpt(env[name], 200)})
        script_bare = []
    if script_other:
        notes.append("boot.scr·uEnv.txt 를 mmc 가 아닌 곳(tftp·dhcp·ubi·ubifsload·nand·sf 등)에서 읽는 변수는 SD 부팅 신호로 세지 않았다: "
                     + ", ".join(clip(x, 64) for x in script_other[:8]))
    if script_usb:
        notes.append("USB 이동식 매체에서 boot.scr·uEnv.txt 를 읽는 변수: " + ", ".join(clip(x, 64) for x in script_usb[:8])
                     + " — SD 카드는 아니지만 물리 접근으로 바꿀 수 있는 매체다 (SD 점검에는 넣지 않음 — UART printenv·부팅 로그로 확인).")
    if script_bare:
        notes.append("boot.scr·uEnv.txt 이름만 있고 읽는 장치가 보이지 않는 변수(같은 env 에 mmc 에서 읽는 경로도 없음)는 SD 부팅 신호로 세지 않았다: "
                     + ", ".join(clip(x, 64) for x in script_bare[:8]))
    # bootcmd 가 mmc 를 플래시보다 먼저 시도하는지 (run 은 4단계까지 제자리에 펼침, boot_targets 의 첫 대상)
    mmc_first: bool | None = None
    if "bootcmd" in env:
        bb = {"chars": EXPAND_PER_VAR, "runs": EXPAND_RUNS, "truncated": False, "scan": scan}
        boot = _expand_env_var(env, "bootcmd", bb)
        expand_truncated |= bb["truncated"]
        bt = (env.get("boot_targets") or "")[:1024].split()
        if "distro_bootcmd" in boot and bt:
            mmc_first = bt[0].startswith("mmc")
        else:
            mi = [m.start() for rx in (_ENV_FSLOAD_RX, _ENV_RAWMMC_RX, _ENV_DISTRO_RX) for m in [rx.search(boot)] if m]
            fi = [m.start() for m in [_ENV_FLASHLOAD_RX.search(boot)] if m]
            if mi:
                mmc_first = not fi or min(mi) < min(fi)
            elif fi:
                mmc_first = False
    verify = env.get("verify")
    verify_off = _verify_off(verify)
    mmc_boot = fs_load or boot_script or distro or raw_mmc
    sev = None
    if fs_load or boot_script or distro:
        sev = "high" if (verify_off or mmc_first) else "medium"
    elif raw_mmc:
        sev = "low"
    if mmc_boot:
        notes.append("mmc 장치 번호만으로는 SD 슬롯과 eMMC 를 구분할 수 없다 (보드·부팅 로그로 확인).")
    if verify is None:
        notes.append("verify 변수 없음 — 일반 U-Boot 경로의 기본값은 yes다. 실제 해시·서명 검증의 적용/강제 여부는 U-Boot 빌드, 부팅 경로와 신뢰 키를 추가 확인해야 한다.")
    elif verify_off:
        notes.append(f"verify={clip(verify, 40)!r}: env_get_yesno 기준 '아니오'(첫 글자가 1/y/Y/t/T 가 아님) — verify 환경값이 비활성으로 설정됨. "
                     "실제 해시·서명 검증의 적용/강제 여부는 U-Boot 빌드, 부팅 경로와 신뢰 키를 추가 확인해야 한다. "
                     "오래된 U-Boot(env_get_yesno 이전)는 첫 글자 'n' 만 끔으로 본다.")
    if expand_truncated:
        notes.append("run 펼침 예산(변수당 16 KiB·env 전체 2 MiB·스캔 전체 4 MiB·run 대상 64개·깊이 4) 또는 시간 예산을 넘어 일부만 펼쳤다 — "
                     "mmc_first·업데이트 판정이 덜 정확할 수 있다.")
    return {
        "storage": storage,
        "persistent_writable": True if storage == "flash-crc" else None,
        "mmc_boot": mmc_boot,
        "fs_load": fs_load,
        "boot_script": boot_script,
        "distro_boot": distro,
        "raw_mmc_only": raw_mmc and not (fs_load or boot_script or distro),
        "mmc_first": mmc_first,
        "verify": verify[:256] if isinstance(verify, str) else verify,
        "verify_off": verify_off,
        "update_from_card": update,
        "update_gpio_gated": (all(update_gpio) if update_gpio else None),
        "signals": signals,
        "signals_total": signals_total,
        "expansion_truncated": expand_truncated,
        "vars_truncated": vars_truncated,
        "severity_hint": sev,
        "notes": notes,
    }


def attach_sd_boot(scan: dict[str, Any], ctl: Ctl | None = None) -> dict[str, Any]:
    """env_scan 결과의 envs[]·embedded_default_envs[] 에 sd_boot 를 붙이고 요약을 돌려준다.

    run 펼침은 env 여럿을 합쳐 EXPAND_SCAN_TOTAL 까지만 하고, ctl 이 있으면 시간 예산·취소를 펼침 중에도 본다 (fw_sd_surface)."""
    budget: dict[str, Any] = {"chars": EXPAND_SCAN_TOTAL, "ops": 0, "stopped": False, "ctl": ctl}
    for e in scan.get("envs") or []:
        e["sd_boot"] = sd_boot_analysis(e.get("env") or {}, storage="flash-crc", scan=budget)
    for d in scan.get("embedded_default_envs") or []:
        d["sd_boot"] = sd_boot_analysis(d.get("env") or {}, storage="embedded-default", scan=budget)
    allb = [x["sd_boot"] for x in (scan.get("envs") or []) + (scan.get("embedded_default_envs") or [])]
    return {
        "envs_with_mmc_boot": sum(1 for b in allb if b["mmc_boot"]),
        "envs_with_boot_script": sum(1 for b in allb if b["boot_script"]),
        "verify_off": sum(1 for b in allb if b["verify_off"]),
        "update_from_card": sum(1 for b in allb if b["update_from_card"]),
        "env_persistent": any(b["persistent_writable"] for b in allb),
    }


def compact_sd_boot(b: dict[str, Any]) -> dict[str, Any]:
    out = {k: b.get(k) for k in ("mmc_boot", "fs_load", "boot_script", "mmc_first", "verify", "verify_off", "update_from_card", "persistent_writable", "severity_hint")}
    out["signal_vars"] = [s["var"] for s in b.get("signals") or []][:8]
    return out


# ---------------------------------------------------------------------------
# 문자열 휴리스틱 (바이너리·이미지): YAML sd-* + 내부 보조 패턴 (모두 길이 상한 — 선형)
# ---------------------------------------------------------------------------

#: 카드 경로 문자열 (_BUILTIN_SD_RX 와 같은 이름 규칙 — SCSI 디스크 이름 /mnt/sda1·/media/sdb2 는 아니다)
_SD_STR_COMP = r"(?:(?!(?:sd[a-z]\d{0,32}|sd[a-z]{2}\d{1,32})(?:/|$|[\s\"']))sd(?!k)[\w.-]{0,32}|mmc[\w.-]{0,32}|tf(?:_?card)?\d{0,3}"
_SD_PATH_PATTERN = (r"(?:/mnt/" + _SD_STR_COMP + r"|disc[\w.-]{0,32})|/media/" + _SD_STR_COMP + r")"
                    r"|/tmp/sd|/system/sdcard|/sdcard)(?=/|$|[\s\"'])(?:/[\w.%*+-]{1,64}){0,16}")
_INTERNAL_STRING_HEURISTICS = [
    ("sdsurface-sd-path", _SD_PATH_PATTERN),
    ("sdsurface-sd-keyword", r"(?i)\b(?:sd|tf|micro ?sd)[ _-]?card\b|\bsdcard\b|\btfcard\b"),
    ("sdsurface-mmcblk", r"/dev/mmcblk\w{0,16}"),
    ("sdsurface-mount-cmd", r"\bmount\b[^\n]{0,160}?(?:-t\s{0,8}(?:vfat|msdos|fat|exfat|ntfs3?|auto|sdcardfs)\b|/dev/mmcblk)"),
    ("sdsurface-mount-data", r"(?:^|[,\s\"])(?:umask|fmask|dmask)=0{1,4}(?=[,\s\"]|$)|\bshortname=(?:mixed|lower|win95|winnt)\b|\biocharset=[\w-]{1,32}"),
    ("sdsurface-record-encrypt", _ENC_FLAG_RX.pattern),
    ("sdsurface-fstrim", r"\bfstrim\s{1,8}(?:-[\w-]{1,16}\s{1,8}){0,4}/[\w/.-]{0,128}"),
    ("sdsurface-discard", r"(?:^|[\s\",])discard(?=,)|,discard(?=$|[\s\",])"),
    ("sdsurface-uboot-fsload", r"\b(?:fat|ext[24])?load\s{1,8}mmc\b"),
    ("sdsurface-fit-keys", r"\bkey-name-hint\b"),
]
_SD_CONTEXT_IDS = {"sdsurface-sd-path", "sdsurface-sd-path-discovered", "sdsurface-sd-keyword"}
#: 카드 경로를 일치 문자열에 담는 YAML sd-* 히트 (일치가 SCSI 디스크 이름 경로만이면 카드 문맥이 아니다 — _consume_hits)
_YAML_SD_PATH_IDS = {"sd-card-script-path", "sd-card-update-file", "sd-log-to-card"}
_MOUNT_OPT_IDS = {"sdsurface-mount-data", "sdsurface-fstrim", "sdsurface-discard"}
_STATIC_NEEDLES = (
    b"/mnt/sd", b"/mnt/mmc", b"/mnt/tf", b"/mnt/disc", b"/media/", b"/tmp/sd", b"/sdcard", b"mmcblk", b"vfat", b"exfat", b"sdcardfs",
    b"sdupdate", b"sdupgrade", b"hiupdate", b"auto_update", b"au_check", b"demo.bin", b"ezviz.dav", b"snx_autorun", b"enable_telnetd",
    b"boot.scr", b"uEnv.txt", b"load mmc", b"core_pattern", b"syslogd", b"ncrypt", b"NCRYPT", b"fstrim", b"discard", b"umask=", b"fmask=", b"dmask=",
    b"key-name-hint", b"card", b"CARD", b"Card",
)


def _internal_heuristic(hid: str, pattern: str) -> StringHeuristic:
    rx = re.compile(pattern, re.MULTILINE)
    lits, ic = required_literals(pattern)
    return StringHeuristic(hid, pattern, "other", "info", "strings", "sdsurface", rationale="fw_sd_surface 내부 보조 패턴", rx=rx, literals=lits, ignorecase=ic)


def string_heuristics(patterns: PatternSet, extra_mount_points: list[str]) -> list[StringHeuristic]:
    """YAML 의 sd-* string_heuristics + 내부 보조 패턴(+ 발견된 비표준 SD 마운트 지점 리터럴)."""
    sel = [h for h in patterns.string_heuristics if h.id.startswith("sd-") and h.rx is not None]
    out = sel + [_internal_heuristic(hid, pat) for hid, pat in _INTERNAL_STRING_HEURISTICS]
    lits = [m for m in extra_mount_points if m.startswith("/") and "$" not in m and not _BUILTIN_SD_RX.match(m) and 4 <= len(m) <= 128]
    if lits:
        alt = "|".join(re.escape(m) for m in sorted(set(lits), key=len, reverse=True)[:32])
        out.append(_internal_heuristic("sdsurface-sd-path-discovered", rf"(?:{alt})(?=/|$|[\s\"'])(?:/[\w.%*+-]{{1,64}}){{0,16}}"))
    return out


# ---------------------------------------------------------------------------
# 파일 하나의 분류 상태
# ---------------------------------------------------------------------------


_FUNC_HEAD_RX = re.compile(r"^\s*(?:function\s+[A-Za-z_][\w.:-]{0,63}(?:\s*\(\s*\))?|[A-Za-z_][\w.:-]{0,63}\s*\(\s*\))\s*\{?\s*$")
_OPEN_KW = {"if": "if", "while": "loop", "until": "loop", "for": "loop", "select": "loop", "case": "case"}
_CLOSE_KW = {"fi": ("if",), "done": ("loop",), "esac": ("case",), "}": ("brace", "func")}
#: 다음 낱말도 명령 첫 낱말인 키워드
_HEAD_CHAIN = {"then", "do", "else", "elif", "if", "while", "until", "!", "{", "time", "exec", "nohup"}
_WS = " \t\r\f\v"
_WORD_STOP = _WS + ";&|()"


def _stmt_heads(line: str) -> list[tuple[str, int]]:
    """줄의 명령 첫 낱말과 위치 (블록 키워드 판정용). 따옴표·역따옴표 안과 '#' 주석은 건너뛴다 — 한 번 훑기."""
    out: list[tuple[str, int]] = []
    i, n = 0, len(line)
    at_head = True
    while i < n:
        c = line[i]
        if c in _WS:
            i += 1
            continue
        if c in ";&|()":
            at_head = True
            i += 1
            continue
        if c == "#":
            break
        j = i
        while j < n and line[j] not in _WORD_STOP:
            ch = line[j]
            if ch in "\"'`":
                k = line.find(ch, j + 1)
                j = n if k < 0 else k + 1
            elif ch == "\\":
                j += 2
            else:
                j += 1
        w = line[i:j]
        if at_head:
            out.append((w, i))
            at_head = w in _HEAD_CHAIN
        i = j
    return out


_FUNC_ONELINE_RX = re.compile(r"^\s*(?:function\s+([A-Za-z_][\w.:-]{0,63})\s*(?:\(\s*\))?|([A-Za-z_][\w.:-]{0,63})\s*\(\s*\))\s*\{(.{0,4096})\}\s*;?\s*$")
_FUNC_NAME_RX = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][\w.:-]{0,63})")


#: 파일 전체를 한 번 훑는 미리 계산(블록 구조·줄 플래그·다음 서비스/플래시 줄·서명 흔적)과 디렉터리 복사의 glob 비교는 이만큼의 일(대략 글자 수)마다
#: 시간 예산·취소를 본다 — 한 줄이 16 KiB 일 수 있어 줄 수가 아니라 일의 양으로 센다
_PRECOMP_CTL_WORK = 64 << 10


class _TextBudgetExpired(Exception):
    """파일 하나를 분류하는 중(미리 계산·glob 비교) 시간 예산이 끝났다 — 그 파일은 끝까지 보지 못한 것으로 하고, 부분 구조로 판단하지 않는다."""


class _Block:
    __slots__ = ("kind", "line", "pos", "close", "close_pos", "branches", "branch_kinds", "parent", "name")

    def __init__(self, kind: str, line: int, pos: int, parent: _Block | None) -> None:
        self.kind, self.line, self.pos, self.parent = kind, line, pos, parent
        self.close = -1
        self.close_pos = 0
        self.branches: list[tuple[int, int]] = []  # (줄, 위치) — 위치 순 (이분 탐색)
        self.branch_kinds: list[str] = []  # else / elif
        self.name: str | None = None  # 함수 이름 (kind == "func")


class _FileState:
    """텍스트 파일 하나를 분류하는 동안의 상태. 줄 플래그·블록 구조·서명 흔적은 처음 쓸 때 파일당 한 번만 계산한다 (토큰마다 파일 전체를 다시 보지 않게).

    lines 는 셸 논리 줄(이어쓰기로 이은 줄)이고 line_map[i] 는 논리 줄 i 의 첫 물리 줄 번호(1 부터)다 — 근거의 줄 번호는 ln(i) 로 낸다."""

    def __init__(self, rel: str, name: str, ctx: str, script_like: bool, lines: list[str], orig: list[str], web_kind: str | None,
                 sd_handler: bool = False, line_map: list[int] | None = None, shell: bool = True) -> None:
        self.rel, self.name, self.ctx, self.script_like = rel, name, ctx, script_like
        #: 셸 문법 파일인지(shell_syntax) — 아니면 명령 앞 'NAME=값' 대입을 건너지 않는다 (systemd 유닛의 'ExecStart=/usr/bin/app 인자')
        self.shell = shell
        self.pre_sh = _PRE_SH if shell else _PRE_SH_NOASSIGN
        self.pre_cmd = _PRE_CMD if shell else _PRE_CMD_NOASSIGN
        self.lines, self.orig, self.web_kind = lines, orig, web_kind
        self.sd_handler = sd_handler
        self.line_map = line_map
        self.local: dict[str, str] = {}
        self.copy_map: dict[str, tuple[str, str | None, int]] = {}  # 대상 경로 → (SD 원본, 마운트 지점, 줄)
        #: 대상 디렉터리 → ({원본 이름: (SD 원본, 마운트 지점, 줄)}, [glob 원본 (SD 원본, 마운트 지점, 줄)]) — 이름은 처음 복사만(중복 없음),
        #: 디렉터리마다 이름 DIR_NAMES 개·glob DIR_GLOBS 개 상한 (조회는 이름 O(1) + glob 몇 개)
        self.dir_map: dict[str, tuple[dict[str, tuple[str, str | None, int]], list[tuple[str, str | None, int]]]] = {}
        self.tree_map: dict[str, tuple[str, str | None, int]] = {}  # 재귀 복사 대상 디렉터리 → (SD 원본 디렉터리, 마운트 지점, 줄)
        self.ctl: Ctl | None = None  # _classify_lines 가 넣는다 (미리 계산·glob 비교의 시간 예산)
        self._work = 0
        self.cwd: str | None = None
        self.cwd_stack: list[str | None] = []  # 서브셸 '( … )'·'$( … )' 에 들어갈 때의 cwd
        self._flags: dict[str, list[bool]] | None = None
        self._sig: Any = False
        self._blocks: list[_Block] | None = None
        self._encl: list[_Block | None] = []
        self._encl_if: list[int | None] = []
        self._openers: dict[int, list[_Block]] = {}
        self._branch_owner: dict[int, _Block] = {}
        self.functions: dict[str, Any] = {}  # 함수 이름 → _Block(여러 줄) 또는 본문 문자열(한 줄 정의)
        self._next: dict[str, list[int]] = {}

    def ln(self, i: int) -> int:
        """논리 줄 i 의 첫 물리 줄 번호 (1 부터)."""
        if self.line_map is not None and 0 <= i < len(self.line_map):
            return self.line_map[i]
        return i + 1

    def _tick(self, work: int) -> None:
        """미리 계산·glob 비교의 일을 세고 _PRECOMP_CTL_WORK 마다 시간 예산·취소를 본다 (넘으면 _TextBudgetExpired, 취소면 Cancelled)."""
        self._work += work
        if self._work >= _PRECOMP_CTL_WORK:
            self._work = 0
            if self.ctl is not None and self.ctl.expired():
                raise _TextBudgetExpired()

    @property
    def flags(self) -> dict[str, list[bool]]:
        if self._flags is None:
            f: dict[str, list[bool]] = {"gpio_read": [], "hash_only": [], "flash_erase": []}
            for line in self.lines:
                self._tick(len(line) + 16)
                f["gpio_read"].append(bool(_GPIO_READ_RX.search(line)))
                f["hash_only"].append(bool(_HASH_ONLY_RX.search(line)))
                f["flash_erase"].append(bool(_FLASH_ERASE_RX.search(line)))
            self._flags = f
        return self._flags

    # -- 블록 구조 (if/while/until/for/case/{ } 를 스택 한 번으로) ---------------------------
    def _structure(self) -> None:
        """한 번 훑어 블록·갈래·함수·줄마다 감싸는 블록과 감싸는 if/loop 줄을 만든다 — 이후 조회는 모두 O(1)·O(log n).

        낱말마다 일이 일정하다: else/elif 는 스택 칸마다 기억한 '가장 안쪽 if'(near_if)로, 짝 없는 fi/done/esac/} 는 종류별 열린 블록 수(open_n)로
        O(1) 에 처리하고, 짝이 있는 닫기는 닫히는 블록만큼만 걷는다 (블록마다 한 번 — 전체 선형). 시간 예산·취소는 일 _PRECOMP_CTL_WORK 마다 보고
        넘으면 _TextBudgetExpired — 부분 구조는 남기지 않는다 (닫히지 않은 블록을 파일 끝까지로 보면 켜진 범위가 넓어져 근거가 틀릴 수 있다)."""
        if self._blocks is not None:
            return
        self._openers, self._branch_owner, self.functions = {}, {}, {}
        blocks: list[_Block] = []
        stack: list[_Block] = []
        near_if: list[_Block | None] = []  # near_if[k] = stack[:k+1] 안의 가장 안쪽 if (없으면 None)
        open_n: dict[str, int] = {}  # 스택 안의 종류별 블록 수
        encl: list[_Block | None] = []
        encl_if: list[int | None] = []
        iflike: list[_Block] = []  # 스택 안의 if/loop 블록 (가장 안쪽이 끝)
        func_pending: str | None = None
        for j, line in enumerate(self.lines):
            self._tick(len(line) + 16)
            # 줄을 시작할 때 감싸는 if/loop (같은 줄에서 여는 if 는 아래에서 j 로 덮어쓴다)
            encl_if.append(iflike[-1].line if iflike else None)
            heads = _stmt_heads(line) if line.strip() else []
            if heads:
                one = _FUNC_ONELINE_RX.match(line)
                if one and "{" in line:
                    if len(self.functions) < 4096:
                        self.functions.setdefault(one.group(1) or one.group(2), one.group(3))
            fh = bool(heads) and _FUNC_HEAD_RX.match(line) is not None
            if fh and heads[0][0] == "function" and line.rstrip().endswith("{") and not any(w == "{" for w, _ in heads):
                heads.append(("{", line.rstrip().rfind("{")))  # 'function name {' 의 '{' 는 이름 뒤라 명령 첫 낱말로 잡히지 않는다
            fname = None
            if fh:
                fm = _FUNC_NAME_RX.match(line)
                fname = fm.group(1) if fm else None
            for w, pos in heads:
                kind = _OPEN_KW.get(w)
                bname = None
                if kind is None and w == "{":
                    if fh or func_pending:
                        kind, bname = "func", (fname if fh else func_pending)
                    else:
                        kind = "brace"
                    func_pending = None
                if kind is not None:
                    b = _Block(kind, j, pos, stack[-1] if stack else None)
                    b.name = bname
                    blocks.append(b)
                    stack.append(b)
                    near_if.append(b if kind == "if" else (near_if[-1] if near_if else None))
                    open_n[kind] = open_n.get(kind, 0) + 1
                    self._openers.setdefault(j, []).append(b)
                    if kind in ("if", "loop"):
                        iflike.append(b)
                        encl_if[j] = j
                    if bname and len(self.functions) < 4096:
                        self.functions.setdefault(bname, b)
                elif w in ("else", "elif"):
                    b = near_if[-1] if near_if else None  # 스택에서 가장 안쪽 if (중괄호 수천 겹 아래여도 O(1))
                    if b is not None:
                        b.branches.append((j, pos))
                        b.branch_kinds.append(w)
                        self._branch_owner.setdefault(j, b)
                elif w in _CLOSE_KW:
                    kinds = _CLOSE_KW[w]
                    if any(open_n.get(x) for x in kinds):  # 짝 없는 닫기('{' 수천 겹 아래의 fi)는 스택을 걷지 않고 버린다
                        k = len(stack) - 1
                        while stack[k].kind not in kinds:
                            k -= 1
                        for b in stack[k:]:
                            b.close, b.close_pos = j, pos
                            open_n[b.kind] -= 1
                        del stack[k:]
                        del near_if[k:]
                        while iflike and iflike[-1].close >= 0:
                            iflike.pop()
            if fh and "{" not in line:
                func_pending = fname or "?"  # 'start()' 다음 줄의 '{' 가 함수 본문
            elif heads and not fh:
                func_pending = None
            encl.append(stack[-1] if stack else None)
        n = len(self.lines)
        for b in blocks:
            if b.close < 0:
                b.close, b.close_pos = n, 0
        self._blocks, self._encl, self._encl_if = blocks, encl, encl_if

    def opener(self, i: int, pos: int, kinds: tuple[str, ...]) -> _Block | None:
        """줄 i 에서 pos 앞에 있는 가장 가까운 여는 블록 (kinds 중)."""
        self._structure()
        best = None
        for b in self._openers.get(i, []):
            if b.pos <= pos and b.kind in kinds:
                best = b
        return best

    def if_for_branch(self, i: int) -> _Block | None:
        """줄 i 에 elif/else 갈래가 있는 if 블록 (줄→블록 표, O(1))."""
        self._structure()
        return self._branch_owner.get(i)

    def next_branch(self, blk: _Block, i: int, pos: int) -> tuple[int, int] | None:
        """blk 의 갈래 중 (i, pos) 다음에 오는 첫 갈래 (이분 탐색)."""
        k = bisect.bisect_right(blk.branches, (i, pos))
        return blk.branches[k] if k < len(blk.branches) else None

    def next_branch_kind(self, blk: _Block, i: int, pos: int) -> tuple[tuple[int, int], str] | None:
        """next_branch 와 같되 갈래 종류(else/elif)도 — 같은 이분 탐색 색인으로 (목록을 처음부터 찾지 않는다)."""
        k = bisect.bisect_right(blk.branches, (i, pos))
        return (blk.branches[k], blk.branch_kinds[k]) if k < len(blk.branches) else None

    def scope_end(self, i: int) -> int:
        """줄 i 다음 줄을 감싸는 가장 안쪽 블록의 닫는 줄 (없으면 파일 끝)."""
        self._structure()
        b = self._encl[i] if i < len(self._encl) else None
        return b.close if b is not None else len(self.lines)

    def enclosing_if(self, i: int) -> int | None:
        """줄 i 를 감싸는 if/while/until 블록의 여는 줄 (같은 줄의 여는 if 포함, 줄 수 상한 없음 — 줄마다 미리 계산한 표)."""
        self._structure()
        return self._encl_if[i] if 0 <= i < len(self._encl_if) else None

    def func_body(self, name: str) -> tuple[str, tuple[int, int] | None] | None:
        """정의된 셸 함수의 본문: (같은 줄 본문 문자열, (시작 줄, 끝 줄) 또는 None)."""
        self._structure()
        f = self.functions.get(name)
        if f is None:
            return None
        if isinstance(f, str):
            return f, None
        return "", (f.line + 1, f.close)

    def next_hit(self, what: str, start: int) -> int:
        """start 줄 이후 처음으로 서비스 '시작'('svc')·플래시('flash') 명령이 있는 줄 (없으면 줄 수) — 파일당 한 번 만든 배열에서 O(1)."""
        arr = self._next.get(what)
        if arr is None:
            n = len(self.lines)
            arr = [n] * (n + 1)
            nxt = n
            for j in range(n - 1, -1, -1):
                line = self.lines[j]
                self._tick(len(line) + 16)
                hit = bool(_service_start(line)) if what == "svc" else bool(_FLASH_CMD_RX.search(line) or _FLASH_DEST_RX.search(line))
                if hit:
                    nxt = j
                arr[j] = nxt
            self._next[what] = arr
        return arr[min(max(start, 0), len(arr) - 1)]

    @property
    def signature_hint(self) -> str | None:
        """서명 검사 흔적 (줄마다 선형: 앞말을 먼저 보고 같은 줄의 옵션을 본다)."""
        if self._sig is False:
            for line in self.lines:
                self._tick(len(line) + 16)
                low = line.lower()
                if "verify" not in low and "signify" not in low and "usign" not in low:
                    continue
                hit = None
                if "-verify" in line and re.search(r"\bopenssl\s{1,8}(?:dgst|rsautl|pkeyutl|smime)\b", line):
                    hit = "openssl … -verify"
                elif "--verify" in line and re.search(r"\bgpgv?\b", line):
                    hit = "gpg --verify"
                elif re.search(r"\b(?:usign|signify)\b", line) and re.search(r"(?<!\S)-V\b", line):
                    hit = "usign/signify -V"
                else:
                    m = re.search(r"(?i)\b(?:verify_?sig(?:nature)?|rsa_?verify|ecdsa_?verify)\b", line)
                    hit = m.group(0) if m else None
                if hit:
                    self._sig = hit
                    break
            else:
                self._sig = None  # 끝까지 보고 없음 (도중에 시간 예산이 끝나면 _TextBudgetExpired 로 그 파일 분류가 끝난다)
        return self._sig


_EXIT_HEADS = {"exit", "return"}
_QUIET_HEADS = {"echo", "logger", "printf", ":", "true", "exit", "return", "{", "}", "then"}


def _exit_only(text: str) -> bool:
    """명령 문구가 exit/return(과 echo·logger 같은 알림)뿐인지 — '|| exit 0', '|| { echo no card; exit 1; }'."""
    heads = [w for w, _ in _stmt_heads(text)]
    return any(w in _EXIT_HEADS for w in heads) and all(w in _QUIET_HEADS for w in heads)


def _first_cmd(tail: str) -> tuple[str, str]:
    """'&&'·'||' 뒤의 첫 명령과 나머지 ('{ … }' 묶음은 통째로, 닫히지 않으면 여러 줄 묶음의 시작)."""
    t = tail.lstrip()
    if t.startswith("{"):
        k = t.find("}")
        return (t, "") if k < 0 else (t[:k + 1], t[k + 1:])
    m = re.search(r"[;&|]", t)
    return (t[:m.start()], t[m.start():]) if m else (t, "")


def _paren_events(L: str) -> list[tuple[int, str]]:
    """따옴표 밖의 '(' ')' 위치 (서브셸·명령 치환 경계 — cwd 되돌리기용, 한 번 훑기)."""
    out: list[tuple[int, str]] = []
    q = ""
    k = 0
    n = len(L)
    while k < n:
        c = L[k]
        if q:
            if c == q:
                q = ""
            elif c == "\\" and q == '"':
                k += 1
        elif c in "\"'":
            q = c
        elif c == "\\":
            k += 1
        elif c in "()":
            out.append((k, c))
        k += 1
    return out


def _top_quote_spans(L: str) -> list[tuple[int, int]]:
    """맨 바깥 따옴표 문자열의 (여는 위치, 닫는 위치 — 닫히지 않으면 줄 끝). 역슬래시는 _paren_events 와 같게, 한 번 훑기."""
    out: list[tuple[int, int]] = []
    q = ""
    start = 0
    k = 0
    n = len(L)
    while k < n:
        c = L[k]
        if q:
            if c == q:
                out.append((start, k))
                q = ""
            elif c == "\\" and q == '"':
                k += 1
        elif c in "\"'":
            q, start = c, k
        elif c == "\\":
            k += 1
        k += 1
    if q:
        out.append((start, n))
    return out


def _exec_quote_events(L: str) -> list[tuple[int, str, Any]]:
    """셸이 실행하는 따옴표 문자열(sh -c '…'·su -c '…'·eval '…')의 cwd 사건 (_relative_exec 의 사건 목록에 더한다).

    여는 따옴표 바로 뒤의 cd 는 명령 시작이다 ('sh -c "cd /mnt/sd; ./run.sh"'). sh -c·su -c 는 자식 셸이라 문자열 안의 cd 는 닫는 따옴표에서
    되돌린다 (서브셸 괄호와 같게 — 다음 줄의 ./x 가 카드 디렉터리로 풀리지 않게). eval 은 지금 셸이라 cd 가 남는다. 다른 따옴표 문자열 안의
    'sh -c'(echo "…; sh -c '…'") 는 실행이 아니다 — 맨 바깥 따옴표만 본다. echo "cd …"·logger "…" 의 따옴표는 명령 시작이 아니다."""
    opens = {m.end() - 1: m for m in _EXEC_QUOTE_OPEN_RX.finditer(L)}
    if not opens:
        return []
    out: list[tuple[int, str, Any]] = []
    for qo, qc in _top_quote_spans(L):
        m = opens.get(qo)
        if m is None:
            continue
        if not m.group("ev"):
            out.append((qo, "(", None))
            out.append((qc, ")", None))
        cm = _CD_HEAD_RX.match(L, qo + 1)
        if cm:
            out.append((cm.end(), "cd", cm))
    return out


def _inert_quote_spans(L: str) -> list[tuple[int, int]]:
    """실행되지 않는 맨 바깥 따옴표 구간 [(여는 위치, 끝)] — echo "…"·logger '…' 의 문구 (_relative_exec 가 이 안의 cd·상대 실행을 버린다).

    실행 문자열(sh -c·su -c·eval '…')은 빼고, 큰따옴표 안에서 '$(' 나 백틱이 나오면 명령 치환일 수 있어 그 앞까지만 넣는다
    ('X="$(cd /mnt/sd && ./run.sh)"' 는 실행이다 — 중첩 따옴표를 맨 바깥으로 잘못 읽어도 예전처럼 사건을 남기는 쪽). 한 번 훑기."""
    spans = _top_quote_spans(L)
    if not spans:
        return []
    opens = {m.end() - 1 for m in _EXEC_QUOTE_OPEN_RX.finditer(L)} if ("sh" in L or "su" in L or "eval" in L) else set()
    out: list[tuple[int, int]] = []
    for qo, qc in spans:
        if qo in opens:
            continue
        end = qc
        if L[qo] == '"':
            for tok in ("$(", "`"):
                k = L.find(tok, qo + 1, end)
                if k >= 0:
                    end = k
        if end > qo + 1:
            out.append((qo, end))
    return out


def _cd_target(L: str, k: int) -> str | None:
    """cd 뒤의 대상 토큰 (옵션 -L/-P/-e/-@ 건너뜀, 따옴표 벗김). 없으면 None (인자 없는 cd = $HOME)."""
    m = re.match(r"[^;&|)\n]{0,1100}", L[k:k + 1100])
    for t in (m.group(0) if m else "").split()[:8]:
        t = t.strip("\"'")
        if t in ("-L", "-P", "-e", "-@"):
            continue
        return t or None
    return None


def _logical_lines(active: str, text: str, *, shell: bool = True) -> tuple[list[str], list[str], list[int] | None]:
    """주석을 지운 본문(active)과 원문(text)을 논리 줄로 나눈다 (rootfs.logical_pair 와 같은 이어쓰기 규칙 — shell=False 면 줄 끝 '\\' 만).

    반환: (논리 줄, 같은 범위의 원문 논리 줄(발췌용), 논리 줄마다 첫 물리 줄 번호 — 이어진 줄이 없으면 None)."""
    la, lt = logical_pair(active, text, shell=shell)
    if la is active:
        return active.split("\n"), text.split("\n"), None
    lines = la.split("\n")
    nl = [m.start() for m in re.finditer("\n", active)]
    starts: list[int] = []
    pos = 0
    for x in lines:
        starts.append(pos)
        pos += len(x) + 1
    lmap = [bisect.bisect_right(nl, st - 1) + 1 for st in starts]
    orig = [lt[st:st + len(x)].replace("\n", " ") for st, x in zip(starts, lines)]
    return lines, orig, lmap


def _copy_ops(piece: str) -> list[tuple[list[str], str]]:
    """명령 조각의 복사·복호화 연산 → [(원본들, 대상)] (cp/mv/install/rsync, cat src > dst, dd if= of=, openssl -in -out). 토큰 단위(선형)."""
    toks = [t.strip("\"'") for t in piece.split()[:128]]
    i = 0
    while i < len(toks) and toks[i] in _CMD_PREFIX:
        i += 1
    if i >= len(toks):
        return []
    cmd = toks[i].rsplit("/", 1)[-1]
    args = toks[i + 1:]
    out: list[tuple[list[str], str]] = []
    if cmd in ("cp", "mv", "install", "rsync"):
        pos = [a for a in args if a and not a.startswith(("-", ">", "<", "2>"))]
        if len(pos) >= 2:
            out.append((pos[:-1], pos[-1]))
    elif cmd == "cat":
        srcs: list[str] = []
        for k, a in enumerate(args):
            if a == ">" and k + 1 < len(args):
                out.append((srcs, args[k + 1]))
                break
            if a.startswith(">") and len(a) > 1:
                out.append((srcs, a.lstrip(">")))
                break
            if not a.startswith("-"):
                srcs.append(a)
    elif cmd == "dd":
        src = next((a[3:].strip("\"'") for a in args if a.startswith("if=")), None)
        dst = next((a[3:].strip("\"'") for a in args if a.startswith("of=")), None)
        if src and dst:
            out.append(([src], dst))
    elif cmd == "openssl":
        src = dst = None
        for k, a in enumerate(args[:-1]):
            if a == "-in":
                src = args[k + 1]
            elif a == "-out":
                dst = args[k + 1]
        if src and dst:
            out.append(([src], dst))
    return out


def _copy_recursive(piece: str) -> bool:
    """복사 명령이 디렉터리를 통째로 옮기는지: cp -r/-R/-a/--recursive/--archive, mv, rsync -r/-a (토큰 단위)."""
    toks = [t.strip("\"'") for t in piece.split()[:128]]
    i = 0
    while i < len(toks) and toks[i] in _CMD_PREFIX:
        i += 1
    if i >= len(toks):
        return False
    cmd = toks[i].rsplit("/", 1)[-1]
    if cmd == "mv":
        return True
    if cmd not in ("cp", "rsync"):
        return False
    letters = "rRa" if cmd == "cp" else "ra"
    for a in toks[i + 1:]:
        if a in ("--recursive", "--archive"):
            return True
        if len(a) > 1 and a[0] == "-" and a[1] != "-" and a[1:].isalpha() and any(c in a[1:] for c in letters):
            return True
    return False


def _has_glob(s: str) -> bool:
    return any(c in s for c in "*?[")


# ---------------------------------------------------------------------------
# 점검 수행
# ---------------------------------------------------------------------------


class SdSurface:
    """SD-01~09 근거 수집기. scan_rootfs()/scan_image() 를 (있는 입력만) 부른 뒤 result()."""

    def __init__(self, ctl: Ctl, patterns: PatternSet, *, max_evidence: int = 20, max_text_file: int = 1 << 20, max_binary_file: int = 64 << 20,
                 binary_budget: int = 1 << 30, image_budget: int = 1 << 30) -> None:
        self.ctl = ctl
        self.patterns = patterns
        self.max_evidence = max_evidence
        self.max_text_file = max_text_file
        self.max_binary_file = max_binary_file
        self.binary_budget = binary_budget
        self.image_budget = image_budget
        self.fit_security = not_examined_fit_security()
        self.ev: dict[str, list[dict[str, Any]]] = {c: [] for c in CHECK_IDS}
        self.ev_total: dict[str, int] = {c: 0 for c in CHECK_IDS}
        self._ev_keys: set[tuple[Any, ...]] = set()
        self.mounts: dict[str, dict[str, Any]] = {}
        self.other_mmc_mounts: list[dict[str, Any]] = []
        self.handlers: list[dict[str, Any]] = []
        self.unclassified_handlers = 0
        #: SD·모든 장치·분류 불가 규칙의 처리기 스크립트 — 그 안의 /media/$MDEV 같은 경로는 카드 마운트 지점이다
        self.sd_handler_files: set[str] = set()
        #: mount 명령·fstab 이 있는 텍스트 파일 (리터럴 사전 필터로 건너뛰지 않는다 — 변수로 만든 카드 경로를 펼쳐 볼 수 있게)
        self.mount_files: set[str] = set()
        self._mount_order: list[tuple[str, str]] = []
        self._mount_order_n = -1
        self._storage_cache: dict[str, bool] = {}
        self._prog_cache: dict[tuple[str, str], str | None] = {}
        self.sd_paths: dict[str, dict[str, Any]] = {}
        self._plain_refs = 0
        self.sd_paths_truncated = False
        self.phases: dict[str, str] = {}  # 단계 → complete / truncated
        self.limitations: list[str] = []
        self.context: dict[str, dict[str, Any]] = {c: {} for c in CHECK_IDS}
        self.env_found = False
        self.web_upload_names: dict[str, str] = {}
        self.root: Path | None = None
        self.aud: Auditor | None = None
        self.text_files: list[str] = []
        self.hotplug_files: set[str] = set()
        self.startup_set: set[str] = set()
        self.global_vars: dict[str, str] = {}
        self.emmc_devices: set[str] = set()
        self._overlong: list[str] = []
        self._text_cut = False
        self.stats: dict[str, Any] = {"text_files": 0, "binary_files_scanned": 0, "binary_bytes": 0, "image_bytes": 0, "skipped_large": [],
                                      "overlong_files": [], "hits_dropped_files": []}

    # -- 공통 기록 -------------------------------------------------------------
    def _add(self, check: str, rule: str, severity: str, *, source: str, excerpt: str, file: str | None = None, image: str | None = None,
             line: int | None = None, offset: int | None = None, ctx: str | None = None, sd_path: str | None = None, extra: dict[str, Any] | None = None) -> None:
        key = (check, rule, source, file or image, line if line is not None else excerpt[:512], sd_path)
        if key in self._ev_keys:
            return
        self._ev_keys.add(key)
        self.ev_total[check] += 1
        if len(self.ev[check]) >= MAX_EVIDENCE_STORED:
            return
        e: dict[str, Any] = {"source": source, "rule": rule, "severity": severity}
        if file:
            e["file"] = file
        if image:
            e["image"] = image
        if line is not None:
            e["line"] = line
        if offset is not None:
            e["offset_hex"] = hexs(offset)
        if ctx:
            e["context"] = ctx
        if sd_path:
            e["sd_path"] = sd_path
        e["excerpt"] = _mask_excerpt(excerpt)
        for k, v in (extra or {}).items():
            e[k] = _mask_excerpt(v, 240) if isinstance(v, str) and k not in _STRUCTURAL_KEYS else v
        self.ev[check].append(e)

    def _ref(self, path: str, mp: str | None, action: str, check: str | None, where: dict[str, Any]) -> None:
        if mp and mp not in self.mounts and _BUILTIN_SD_RX.match(mp):
            self._mount(mp, {"source": "builtin-pattern", **{k: v for k, v in where.items() if k in ("file", "image", "line", "offset_hex")}}, builtin=True)
        p = _norm(path)
        r = self.sd_paths.get(p)
        if r is None:
            # 점검에 쓰인 경로(실행·플래시·설정·로그·노출)가 단순 참조(녹화 파일 이름 등)에 밀려나지 않게 상한을 따로 둔다
            if (check is None and self._plain_refs >= MAX_PLAIN_REFS) or len(self.sd_paths) >= MAX_SD_PATHS:
                self.sd_paths_truncated = True
                return
            if check is None:
                self._plain_refs += 1
            rel = p[len(mp):].lstrip("/") if mp and (p == mp or p.startswith(mp.rstrip("/") + "/")) else None
            r = self.sd_paths[p] = {"path": p, "mount_point": mp, "card_relative": rel, "actions": [], "checks": [], "refs": []}
        if action not in r["actions"]:
            r["actions"].append(action)
        if check and check not in r["checks"]:
            r["checks"].append(check)
        if len(r["refs"]) < 5 and where not in r["refs"]:
            r["refs"].append(where)

    def _mount(self, mp: str, source: dict[str, Any], *, fs: str | None = None, device: str | None = None, options: list[str] | None = None,
               readonly: bool = False, hotplug: bool = False, builtin: bool = False) -> None:
        mpn = _norm(mp)
        if isinstance(source.get("excerpt"), str):
            source = {**source, "excerpt": _mask_excerpt(source["excerpt"], 160)}
        if options is not None:
            options = [_mask_excerpt(o, 120) for o in options]
        ok, note = (True, None) if builtin else _is_sd_mount(fs, device, mpn, hotplug=hotplug)
        if not ok:
            if device and device.startswith("/dev/mmcblk"):
                self.emmc_devices.add(device)
            if note and len(self.other_mmc_mounts) < 50:
                self.other_mmc_mounts.append({"mount_point": mpn, "device": device, "fs": fs, "readonly": readonly, "note": note,
                                              **{k: v for k, v in source.items() if k in ("source", "file", "line")}})
            return
        m = self.mounts.get(mpn)
        if m is None:
            if len(self.mounts) >= 200:
                return
            m = self.mounts[mpn] = {"path": mpn, "sources": [], "fs": [], "devices": [], "mount_commands": [], "builtin_pattern": bool(_BUILTIN_SD_RX.match(mpn)),
                                    "present_in_image": None}
        if len(m["sources"]) < 8 and source not in m["sources"]:
            m["sources"].append(source)
        if fs and fs not in m["fs"]:
            m["fs"].append(fs)
        if device and device not in m["devices"] and len(m["devices"]) < 8:
            m["devices"].append(device)
        if not builtin and source.get("source") != "builtin-pattern" and len(m["mount_commands"]) < 12:
            m["mount_commands"].append({"options": list(options or []), "fs": fs, "readonly": readonly, "options_visible": options is not None,
                                        **{k: v for k, v in source.items() if k in ("source", "file", "line", "image", "offset_hex", "excerpt")}})

    def _sd_root(self, token: str, sd_handler: bool = False) -> str | None:
        """토큰(정규화 전)이 SD 경로면 그 마운트 지점, 아니면 None.

        sd_handler: SD·모든 장치 핫플러그 규칙의 처리기 스크립트 안이면 '/media/$MDEV' 처럼 장치 이름 변수로 끝나는 디렉터리도 카드 마운트 지점으로 본다."""
        p = _norm(token)
        if not p.startswith("/") or p.startswith(("/dev/", "/proc/", "/sys/")):
            return None
        if self._mount_order_n != len(self.mounts):
            self._mount_order = [(mp, mp.rstrip("/") + "/") for mp in sorted(self.mounts, key=len, reverse=True)]
            self._mount_order_n = len(self.mounts)
        for mp, mps in self._mount_order:
            if p == mp or p.startswith(mps):
                return mp
        m = _BUILTIN_SD_RX.match(p)
        if m:
            return m.group(0)
        if sd_handler and "$" in p:
            mh = _HOTPLUG_MP_RX.match(p)
            if mh:
                return mh.group(1)
        return None

    def _phase(self, name: str, complete: bool) -> None:
        prev = self.phases.get(name)
        self.phases[name] = "truncated" if (prev == "truncated" or not complete) else "complete"

    def _limit(self, msg: str) -> None:
        if msg not in self.limitations and len(self.limitations) < 50:
            self.limitations.append(msg)

    # -- rootfs ---------------------------------------------------------------
    def scan_rootfs(self, aud: Auditor, startup: dict[str, Any], web: dict[str, Any]) -> None:
        aud.walk()
        self.aud = aud
        self.root = aud.root
        if aud.walk_truncated:
            # 보지 못한 파일에 근거가 있을 수 있다 → rootfs 단계를 모두 잘림으로 (not-found 를 주장하지 않는다)
            self._phase("rootfs_text", False)
            self._phase("rootfs_binary", False)
            self._limit("rootfs 항목 수 상한에 걸려 일부 파일을 보지 못했습니다 (rootfs 점검은 not-found 대신 unknown).")
        if not getattr(aud, "startup_scan_complete", True):
            # 시작 스크립트 큐가 시간·큐·크기 상한으로 덜 채워졌다 → 부팅 문맥 판단이 빠질 수 있어 not-found 를 주장하지 않는다
            self._phase("rootfs_text", False)
            self._limit("기본 감사의 시작 스크립트 검사가 끝나지 않았습니다 ([시작 스크립트 검사 미완료] — 부팅 문맥 점검은 not-found 대신 unknown).")
        for p in startup.get("startup_files") or []:
            r = resolve_in_root(aud.root, p)
            if r:
                self.startup_set.add(r)
        self._discover_hotplug(aud)
        self._discover_text(aud)
        self._classify_text(aud)
        self._scan_web_symlinks(aud, web)
        self._scan_binaries(aud)
        self._env_tools(aud)
        for m in self.mounts.values():
            r = resolve_in_root(aud.root, m["path"]) if "$" not in m["path"] else None
            m["present_in_image"] = bool(r and r in aud.by_rel)
        # 기본 감사의 builtin-exec-from-writable-storage 와 같은 줄이면 함께 적는다 (SD 마운트가 쓰기 가능 접두로 들어가 기본 감사에도 뜬다)
        rel_items = {(it.get("file"), it.get("line")) for it in aud.items if it.get("id") == "builtin-exec-from-writable-storage"}
        for e in self.ev["SD-01"]:
            if (e.get("file"), e.get("line")) in rel_items:
                e["related_rootfs_audit_item"] = "builtin-exec-from-writable-storage"

    def _prog(self, root: Path, cmd: str | None, dirs: tuple[str, ...]) -> str | None:
        """처리기 명령의 프로그램 경로 (rootfs 안에서 해석, 명령 문자열마다 한 번)."""
        if not cmd:
            return None
        key = (cmd[:512], dirs[0] if dirs else "")
        if key not in self._prog_cache:
            r = resolve_program(root, command_program(cmd), dirs)
            if len(self._prog_cache) < 20000:
                self._prog_cache[key] = r
            return r
        return self._prog_cache[key]

    def _storage_handler(self, root: Path, prog: str | None) -> bool:
        """처리기 스크립트(텍스트)가 저장 장치에 특정한 일(mmcblk·/dev/sdX·카드 경로·이동식 fs 마운트·/media/$MDEV)을 하는지 — 파일마다 한 번."""
        if not prog:
            return False
        if prog not in self._storage_cache:
            data, _ = read_in_root(root, prog, self.max_text_file)
            ok = bool(data) and is_text(data[:4096]) and _storage_specific(_blank_comments(data.decode("latin-1")))
            if len(self._storage_cache) < 20000:
                self._storage_cache[prog] = ok
            return ok
        return self._storage_cache[prog]

    def _discover_hotplug(self, aud: Auditor) -> None:
        """mdev.conf·udev 규칙·hotplug 스크립트 → SD 관련 처리기와 처리기 스크립트(핫플러그 문맥) 목록.

        장치 정규식·glob 은 실행하지 않는다 (classify_mdev_matcher / classify_udev_match, 분류는 패턴마다 캐시). 시간 예산은 규칙마다 본다.
        명령 없는 규칙(권한만)은 처리기가 아니다. 모든 장치·분류 불가 규칙의 처리기는 저장 장치에 특정한 내용이 있을 때만 SD 처리기로 본다
        ($MDEV·mount 만으로는 아님). 분류하지 못한 규칙(명령 있음)은 처리기로 적고 SD-04 를 unknown 쪽으로 둔다."""
        root = aud.root
        handler_scripts: list[str] = []
        complete = True
        for e in aud.entries:
            if e.kind not in ("file", "symlink") or not aud.match_globs(HOTPLUG_RX, e.rel):
                continue
            if self.ctl.expired():
                complete = False
                break
            data, final = read_in_root(root, e.rel, self.max_text_file)
            if data is None or not final or not is_text(data[:4096]):
                continue
            text = _blank_comments(data.decode("latin-1"))
            self.hotplug_files.add(final)
            if e.name == "mdev.conf":
                for rule in parse_mdev_conf(text):
                    if self.ctl.expired():
                        complete = False
                        break
                    kind = classify_mdev_matcher(rule["device_regex"], rule["env"])
                    prog = self._prog(root, rule["command"], MDEV_CMD_DIRS)
                    if prog:
                        handler_scripts.append(prog)
                    if not rule["command"] and kind != "other":
                        kind = "other"  # 권한만 정하는 규칙('mmcblk0p[0-9] 0:6 660', '.* 0:0 660')은 카드가 들어와도 아무것도 실행하지 않는다
                    if prog and (kind == "sd" or (kind in ("catch-all", "unclassifiable") and self._storage_handler(root, prog))):
                        self.sd_handler_files.add(prog)
                    if kind in ("sd", "catch-all", "unclassifiable") and len(self.handlers) < 300:
                        self.handlers.append({"kind": "mdev", "file": final, "line": rule["line"], "match": clip(rule["matcher"], 128), "match_kind": kind,
                                              "action": rule["action"], "command": _mask_excerpt(rule["command"], 300) if rule["command"] else None,
                                              "handler_script": prog})
                    if kind == "unclassifiable":
                        self.unclassified_handlers += 1
                        self._limit("mdev.conf 의 장치 정규식 일부를 정적으로 분류하지 못했습니다 (실행하지 않음 — 처리기로만 적고 SD-04 판단은 unknown 쪽).")
                    elif kind in ("sd", "catch-all"):
                        self._add("SD-04", "mdev-rule", "info", source="rootfs", file=final, line=rule["line"], excerpt=rule["text"], ctx="hotplug",
                                  extra={"match_kind": kind})
                        self._mount_from_command(rule["command"], {"source": "mdev", "file": final, "line": rule["line"]}, hotplug=True)
            elif "/udev/" in final and final.endswith(".rules"):
                for rule in parse_udev_rules(text):
                    if self.ctl.expired():
                        complete = False
                        break
                    kind = classify_udev_match(rule["match"])
                    if kind in ("sd", "catch-all") and not _udev_has_handler(rule):
                        kind = "other"  # SUBSYSTEM=="block"·KERNEL=="sd*" 의 blkid·scsi_id·modprobe 같은 표준 도우미는 카드 삽입 처리기가 아니다
                    progs = [self._prog(root, c, UDEV_CMD_DIRS) for c in rule["run"][:8]]
                    handler_scripts += [p for p in progs if p]
                    if not rule["run"]:
                        continue
                    for p in progs:
                        if p and (kind == "sd" or (kind in ("catch-all", "unclassifiable") and self._storage_handler(root, p))):
                            self.sd_handler_files.add(p)
                    if kind in ("sd", "catch-all", "unclassifiable") and len(self.handlers) < 300:
                        self.handlers.append({"kind": "udev", "file": final, "line": rule["line"], "match": {k: clip(v, 128) for k, v in list(rule["match"].items())[:8]},
                                              "match_kind": kind, "action": rule["match"].get("ACTION"), "command": _mask_excerpt("; ".join(rule["run"]), 300),
                                              "handler_script": next((p for p in progs if p), None)})
                    if kind == "unclassifiable":
                        self.unclassified_handlers += 1
                        self._limit("udev 규칙의 장치 패턴 일부를 정적으로 분류하지 못했습니다 (128자 초과 등 — SD-04 판단은 unknown 쪽).")
                    elif kind in ("sd", "catch-all"):
                        self._add("SD-04", "udev-rule", "info", source="rootfs", file=final, line=rule["line"], excerpt=rule["text"], ctx="hotplug",
                                  extra={"match_kind": kind})
                        for c in rule["run"][:8]:
                            self._mount_from_command(c, {"source": "udev", "file": final, "line": rule["line"]}, hotplug=True)
            else:
                m = _STORAGE_TEXT_RX.search(text)
                if m:
                    # /etc/hotplug* 의 스크립트: 저장 장치에 특정한 내용이 있을 때만 카드 처리기 (wlan 처리기가 $MDEV 를 쓰는 것만으로는 아님)
                    ln = text.count("\n", 0, m.start()) + 1
                    self.sd_handler_files.add(final)
                    if len(self.handlers) < 300:
                        self.handlers.append({"kind": "hotplug-script", "file": final, "line": ln, "match": None, "match_kind": "sd", "action": None, "command": None,
                                              "handler_script": final})
                    ls = text.rfind("\n", 0, m.start()) + 1
                    le = text.find("\n", m.start())
                    self._add("SD-04", "hotplug-script", "info", source="rootfs", file=final, line=ln, excerpt=text[ls:le if le >= 0 else len(text)][:MAX_LINE],
                              ctx="hotplug")
        # 커널 uevent helper (echo X > /proc/sys/kernel/hotplug, sysctl kernel.hotplug) — 시작 파일은 정렬해 결정적으로 모두 본다.
        # 빈 값(helper 끄기)·mdev 는 카드 처리기가 아니다. 다른 helper 는 저장 장치에 특정한 텍스트일 때만 SD-04 근거로 센다
        for p in sorted(self.startup_set) + ["/etc/sysctl.conf"]:
            if self.ctl.expired():
                complete = False
                break
            data, final = read_in_root(root, p, self.max_text_file)
            if not data or not final or not is_text(data[:4096]):
                continue
            text = _blank_comments(data.decode("latin-1"))
            if "hotplug" not in text:
                continue
            nl: list[int] | None = None
            for k, m in enumerate(_UEVENT_HELPER_RX.finditer(text)):
                if (k & 0xFF) == 0xFF and self.ctl.expired():
                    complete = False
                    break
                prog = (m.group("a") or m.group("b") or m.group("c") or "").strip("\"'")
                if not prog or prog.rsplit("/", 1)[-1] == "mdev":
                    continue
                if nl is None:
                    nl = [mm.start() for mm in re.finditer("\n", text)]
                li = bisect.bisect_right(nl, m.start() - 1) if m.start() else 0
                ln = li + 1
                rp = self._prog(root, prog, MDEV_CMD_DIRS)
                if rp and rp.rsplit("/", 1)[-1] != "mdev":
                    handler_scripts.append(rp)  # 모든 장치의 이벤트를 받으므로 핫플러그 문맥으로 따라간다
                if not self._storage_handler(root, rp):
                    continue
                self.sd_handler_files.add(rp)  # type: ignore[arg-type]
                if len(self.handlers) < 300:
                    self.handlers.append({"kind": "uevent-helper", "file": final, "line": ln, "match": None, "match_kind": "sd", "action": None,
                                          "command": _mask_excerpt(prog, 200), "handler_script": rp})
                ls = nl[li - 1] + 1 if li > 0 else 0
                le = nl[li] if li < len(nl) else len(text)
                self._add("SD-04", "uevent-helper", "info", source="rootfs", file=final, line=ln, excerpt=text[ls:le][:MAX_LINE], ctx="boot")
        # 처리기 스크립트와 그 스크립트가 부르는 스크립트(2단계)를 핫플러그 문맥으로
        frontier = [p for p in dict.fromkeys(handler_scripts) if p]
        for _depth in range(3):
            nxt: list[str] = []
            for p in frontier:
                if self.ctl.expired():
                    complete = False
                    break
                ent = aud.by_rel.get(p)
                if p in self.hotplug_files or not ent or ent.kind != "file":
                    continue
                data, _ = read_in_root(root, p, self.max_text_file)
                if not data or not is_text(data[:4096]):
                    continue
                self.hotplug_files.add(p)
                for m in re.finditer(r"(?<![\w.\-/$])(/(?:[\w.+\-]{1,128}/){0,16}[\w.+\-]{1,128}\.sh)\b", _blank_comments(data.decode("latin-1"))):
                    r = resolve_in_root(root, m.group(1))
                    if r and r not in self.hotplug_files:
                        nxt.append(r)
                        if p in self.sd_handler_files:
                            self.sd_handler_files.add(r)  # SD 처리기가 부르는 스크립트도 같은 $MDEV 를 물려받는다
                    if len(nxt) >= 50:
                        break
            frontier = nxt[:50]
        if not complete:
            self._phase("rootfs_text", False)
            self._limit("시간 예산 초과로 핫플러그 처리기를 일부만 보았습니다.")

    @staticmethod
    def _mdev_matches_sd(regex: str, env: list[str]) -> bool:
        """(호환) mdev 장치 정규식이 SD·모든 장치에 해당하는지 — 정규식을 실행하지 않는다 (classify_mdev_matcher)."""
        return classify_mdev_matcher(regex, env) in ("sd", "catch-all")

    def _mount_from_command(self, cmd: str, source: dict[str, Any], *, hotplug: bool = False) -> None:
        for piece in iter_command_pieces(cmd[:MAX_LINE]):
            mt = parse_mount_command(piece)
            if mt:
                self._mount(mt["mount_point"], {**source, "excerpt": clip(piece.strip(), 160)}, fs=mt["fs"], device=mt["device"], options=mt["options"],
                            readonly=mt["readonly"], hotplug=hotplug)

    def _file_ctx(self, rel: str, name: str, head: str) -> tuple[str, bool]:
        """(문맥, 스크립트처럼 실행되는 파일인지)."""
        if rel in self.hotplug_files:
            return "hotplug", True
        if rel in self.startup_set:
            return "boot", True
        if rel.startswith(_CRON_DIRS) or (name in ("crontab", "root") and "/cron" in rel):
            return "cron", True
        is_cgi = "/cgi-bin/" in rel or name.endswith((".cgi", ".fcgi"))
        script = head.startswith("#!") or name.endswith(".sh")
        if is_cgi:
            return "cgi", script
        return ("script" if script else "config"), script

    def _mark_overlong(self, rel: str) -> None:
        if rel not in self._overlong and len(self._overlong) < 20:
            self._overlong.append(rel)
        self._text_cut = True

    def _cap_line(self, rel: str, line: str) -> str:
        if len(line) <= MAX_LINE:
            return line
        self._mark_overlong(rel)
        return line[:MAX_LINE]

    def _discover_text(self, aud: Auditor) -> None:
        """1단계: 모든 작은 텍스트 파일에서 SD 마운트(fstab·mount 명령)와 시작 스크립트의 경로 변수를 찾는다."""
        root = aud.root
        complete = True
        gv: dict[str, set[str]] = {}
        for e in aud.entries:
            if e.kind != "file" or e.st.st_size == 0 or e.st.st_size > self.max_text_file:
                continue
            if self.ctl.expired():
                complete = False
                break
            data, _ = read_in_root(root, e.rel, self.max_text_file)
            if data is None or not is_text(data[:4096]):
                continue
            self.text_files.append(e.rel)
            text = data.decode("latin-1")
            if "mount" not in text and e.name != "fstab" and e.rel not in self.startup_set:
                continue
            active = _blank_comments(text)
            if e.name == "fstab":
                self.mount_files.add(e.rel)
                for ln, line in enumerate(active.split("\n"), 1):
                    f = self._cap_line(e.rel, line).split()
                    if len(f) >= 3 and f[1].startswith("/"):
                        opts = f[3].split(",")[:32] if len(f) > 3 else ["defaults"]
                        self._mount(f[1], {"source": "fstab", "file": e.rel, "line": ln, "excerpt": clip(line.strip(), 160)}, fs=f[2], device=f[0], options=opts,
                                    readonly="ro" in opts)
            if "mount" in active:
                local: dict[str, str] = {}
                # 셸 문법 파일만 줄 끝 |·||·&& 로 잇는다 (inittab·udev 규칙·systemd 유닛·crontab·설정 파일은 줄 끝 '\\' 만)
                dlines, _dorig, dmap = _logical_lines(active, text, shell=self._file_ctx(e.rel, e.name, text[:2])[1] and shell_syntax(e.rel, text[:2]))
                for di, line in enumerate(dlines):
                    ln = dmap[di] if dmap is not None else di + 1
                    if (di & 0x3FF) == 0x3FF and self.ctl.expired():
                        complete = False
                        break
                    line = self._cap_line(e.rel, line)
                    self._assign(line, local, {})
                    if "mount" not in line or ("umount" in line and "mount " not in line.replace("umount", "")):
                        continue
                    exp = _expand(line, local, {})
                    for piece in iter_command_pieces(exp):
                        mt = parse_mount_command(piece)
                        if mt:
                            self.mount_files.add(e.rel)
                            self._mount(mt["mount_point"], {"source": "script", "file": e.rel, "line": ln, "excerpt": clip(line.strip(), 160)}, fs=mt["fs"],
                                        device=mt["device"], options=mt["options"], readonly=mt["readonly"], hotplug=e.rel in self.hotplug_files)
            if e.rel in self.startup_set:
                local2: dict[str, str] = {}
                for line in active.split("\n"):
                    name = self._assign(line[:MAX_LINE], local2, {})
                    if name and name.isupper() and len(name) >= 3 and len(gv) < 500:
                        gv.setdefault(name, set()).add(local2[name])
        # 시작 스크립트에서 값이 하나뿐인 대문자 경로 변수만 다른 파일의 대체값으로 쓴다
        self.global_vars = {k: next(iter(v)) for k, v in gv.items() if len(v) == 1}
        self.stats["text_files"] = len(self.text_files)
        self._phase("rootfs_text", complete)
        if not complete:
            self._limit("시간 예산 초과로 텍스트 파일(스크립트·설정) 일부만 보았습니다 (SD 마운트 발견).")

    @staticmethod
    def _assign(line: str, local: dict[str, str], global_vars: dict[str, str]) -> str | None:
        m = _ASSIGN_RX.match(line)
        if m:
            val = m.group(2)
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            val = _expand(val, local, global_vars, limit=1024)
            if val.startswith("/") and " " not in val and len(val) <= 1024:
                local[m.group(1)] = val
                return m.group(1)
            return None
        m = _FOR_RX.search(line)
        if m:
            val = _expand(m.group(2), local, global_vars, limit=1024)
            if val.startswith("/") and len(val) <= 1024:
                local[m.group(1)] = val
                return m.group(1)
        return None

    def _classify_text(self, aud: Auditor) -> None:
        """2단계: 텍스트 파일의 줄마다 SD 경로(변수 펼침)와 그 앞뒤 문맥으로 점검을 나눈다."""
        root = aud.root
        complete = self.phases.get("rootfs_text") != "truncated"
        literals = list(_SD_LITERALS) + [m for m in self.mounts if "$" not in m] + [m.split("/$", 1)[0] + "/$" for m in self.mounts if "$" in m]
        literals += ["encrypt", "Encrypt", "ENCRYPT", "fstrim", "discard"]
        literals += [k for k, v in self.global_vars.items() if self._sd_root(v)]
        for rel in self.text_files:
            if self.ctl.expired():
                complete = False
                break
            data, _ = read_in_root(root, rel, self.max_text_file)
            if data is None:
                continue
            text = data.decode("latin-1")
            name = rel.rsplit("/", 1)[-1]
            low = name.lower()
            web_kind = ("web" if (low in _WEB_CONF_NAMES or (low.endswith(".conf") and ("httpd" in low or "lighttpd" in rel))) else
                        "ftp" if low in _FTP_CONF_NAMES else "samba" if low in _SAMBA_CONF_NAMES else "dlna" if low in _DLNA_CONF_NAMES else None)
            webish = ("/www/" in rel or "/web/" in rel or "/cgi-bin/" in rel or low.endswith((".cgi", ".asp", ".php", ".lua", ".js", ".html", ".htm")))
            if webish:
                for m in re.finditer(r"[\w.-]{1,128}\.(?:bin|img|pkg|dav|tar|tgz|zip)\b", text):
                    if len(self.web_upload_names) >= 2000:
                        break
                    self.web_upload_names.setdefault(m.group(0).lower(), rel)
            if low.endswith(_WEB_CONTENT_EXT):
                continue  # 웹 콘텐츠(압축된 JS·HTML)는 점검 근거로 쓰지 않는다
            ctx, script_like = self._file_ctx(rel, name, text[:2])
            # 사전 필터는 리터럴만 보므로 변수로 만든 카드 경로('SD=$MNT/sd; sh $SD/x')를 놓친다 → 스크립트처럼 실행되는 파일·SD 처리기·
            # mount 가 있는 파일·서버 설정은 늘 분류한다 (리터럴로 건너뛰는 건 변수를 펼치지 않는 설정 파일뿐)
            exempt = script_like or web_kind is not None or rel in self.sd_handler_files or rel in self.mount_files
            if not exempt and not any(lit in text for lit in literals):
                continue
            active = _blank_comments(text)
            sh = script_like and shell_syntax(rel, text[:2])
            llines, lorig, lmap = _logical_lines(active, text, shell=sh)
            fs = _FileState(rel, name, ctx, script_like, [self._cap_line(rel, x) for x in llines], lorig, web_kind,
                            sd_handler=rel in self.sd_handler_files, line_map=lmap, shell=sh)
            if not self._classify_lines(fs):
                complete = False
                break
        if self._text_cut:
            complete = False
            self.stats["overlong_files"] = list(self._overlong)
            self._limit(f"{MAX_LINE}자를 넘는 줄(또는 {MAX_TOKEN}자를 넘는 경로 토큰)은 앞부분만 보았습니다: {', '.join(self._overlong[:5])} (관련 점검은 not-found 대신 unknown).")
        self._phase("rootfs_text", complete)
        if not complete and self.ctl.timed_out:
            self._limit("시간 예산 초과로 텍스트 파일(스크립트·설정) 일부만 보았습니다 (분류).")

    def _classify_lines(self, fs: _FileState) -> bool:
        """파일 하나를 줄 단위로 분류. 시간 예산을 넘으면 False (단계를 잘림으로).

        블록 구조·줄 플래그 같은 파일 전체 미리 계산과 디렉터리 복사의 glob 비교도 시간 예산·취소를 본다(_FileState._tick) — 도중에 끝나면
        그 파일은 끝까지 보지 못한 것이다 (부분 구조로 판단하지 않고 False)."""
        fs.ctl = self.ctl
        try:
            return self._classify_file_lines(fs)
        except _TextBudgetExpired:
            return False

    def _classify_file_lines(self, fs: _FileState) -> bool:
        lines = fs.lines
        rel, name, ctx, script_like, web_kind = fs.rel, fs.name, fs.ctx, fs.script_like, fs.web_kind
        writes_remote = False
        if web_kind == "ftp":
            writes_remote = any(re.match(r"(?i)\s*(?:write_enable|anon_upload_enable)\s*=\s*yes\b", x) for x in lines)
        elif web_kind == "web":
            writes_remote = any(re.search(r"(?i)webdav\.activate\s*=\s*\"?enable|\bdav_methods\b", x) for x in lines)
        samba_section_rw = False
        hot = ctx in ("boot", "hotplug", "cron")
        ntok = 0
        for i, L0 in enumerate(lines):
            if (i & 0x7F) == 0x7F and self.ctl.expired():
                return False
            if not L0.strip():
                continue
            ln = fs.ln(i)
            if name == "mdev.conf":
                L0 = re.sub(r"(\s)([@$*])/", r"\1\2 /", L0)  # '$/x' 의 '$' 는 mdev 동작 표시라 경로 토큰을 막지 않게
            self._assign(L0, fs.local, self.global_vars)
            L = _expand(L0, fs.local, self.global_vars)
            excerpt = (fs.orig[i] if i < len(fs.orig) else L0)[:MAX_LINE]
            extra_exp = {"expanded": clip(L.strip(), 200)} if L != L0 else {}
            if len(L) > 64 and "                                " in L.replace("\t", " "):
                L = _WS_LONG_RX.sub(" ", L)
            if web_kind == "samba" and L.lstrip().startswith("["):
                samba_section_rw = False
                for x in lines[i + 1:i + 40]:
                    if x.lstrip().startswith("["):
                        break
                    if re.match(r"(?i)\s*(?:writ(?:e)?able\s*=\s*yes|read\s+only\s*=\s*no)\b", x):
                        samba_section_rw = True
                        break
            # fw_setenv 로 U-Boot env 를 바꾸는 줄 (SD-03/SD-02 의 사용자 공간 근거)
            if "fw_setenv" in L:
                fm = _FW_SETENV_RX.search(L)
                if fm:
                    val = fm.group("val")
                    # boot.scr·uEnv.txt 이름은 mmc 에서 읽을 때만, 업데이트는 명시적 SD 업데이트 명령이거나 mmc 에서 읽어 플래시에 쓸 때만 (sd_boot_analysis 와 같은 규칙)
                    if _ENV_FSLOAD_RX.search(val) or _ENV_DISTRO_RX.search(val) or (_ENV_SCRIPT_RX.search(val) and _env_load_source(val) == "mmc"):
                        self._add("SD-03", "fw_setenv-mmc", "medium", source="rootfs", file=rel, line=ln, excerpt=excerpt, ctx=ctx)
                    if _env_card_update(val):
                        self._add("SD-02", "fw_setenv-update", "high", source="rootfs", file=rel, line=ln, excerpt=excerpt, ctx=ctx)
            # cd 뒤의 상대 경로 실행 ('cd /mnt/sd && ./debug.sh'). 서브셸 괄호는 cwd 를 되돌리므로 괄호가 있는 줄도 본다
            if script_like and (fs.cwd is not None or fs.cwd_stack or "cd" in L or "(" in L or ")" in L):
                self._relative_exec(fs, L, ln, excerpt, extra_exp, hot)
            for m in _TOKEN_RX.finditer(L):
                ntok += 1
                if (ntok & 0xFF) == 0 and self.ctl.expired():
                    return False
                tok = m.group(0)
                if len(tok) > MAX_TOKEN:
                    self._mark_overlong(rel)  # 비정상 토큰 → 잘림 표시
                    continue
                mp = self._sd_root(tok, fs.sd_handler)
                path = _norm(tok)
                src = fs.copy_map.get(path) or ((self._dir_lookup(fs, path) or self._tree_lookup(fs, path)) if mp is None else None)
                if mp is None and src is None:
                    continue
                pre, post, piece = _windows(L, m.start(), m.end())
                where = {"source": "rootfs", "file": rel, "line": ln}
                if mp is None and src is not None:
                    # 카드에서 복사한 파일(파일 또는 디렉터리로 복사)을 실행·플래시
                    sd_src, smp, sln = src
                    inq, execq = _quote_state(pre)
                    if script_like and (not inq or execq) and (fs.pre_sh.search(pre) or _PRE_SOURCE.search(pre) or fs.pre_cmd.search(pre) or _PRE_INSMOD.search(pre)):
                        sev = "high" if hot else "medium"
                        self._add("SD-01", "copy-then-exec", sev, source="rootfs", file=rel, line=ln, excerpt=excerpt, ctx=ctx, sd_path=sd_src,
                                  extra={"copied_to": path, "copy_line": sln, **extra_exp})
                        self._ref(sd_src, smp, "exec", "SD-01", where)
                    if _FLASH_CMD_RX.search(piece) or _FLASH_DEST_RX.search(piece):
                        self._sd02(fs, i, pre, excerpt, sd_src, "copy-then-flash", "high", {"copied_to": path, "copy_line": sln, **extra_exp})
                        self._ref(sd_src, smp, "flash", "SD-02", where)
                    continue
                self._classify_token(fs, i, L, m.start(), m.end(), pre, post, piece, path, mp, excerpt, extra_exp, writes_remote or samba_section_rw, where)
                # 복사 대상 기록 (나중 조각·줄의 실행·플래시). 대상은 파일로도, 디렉터리로도 기억한다 (cp /mnt/sd/*.bin /tmp)
                # 기억 상한(COPY_KEYS·DIR_NAMES·DIR_GLOBS)에 걸려 버린 복사가 있으면 rootfs_text 를 잘림으로 둔다 (그 뒤의 복사-실행을 놓칠 수 있다)
                for srcs, dst in _copy_ops(piece):
                    if not dst.startswith("/") or not any(_norm(s) == path for s in srcs):
                        continue
                    nd = _norm(dst)
                    dropped = False
                    if not _has_glob(path):
                        if nd in fs.copy_map or len(fs.copy_map) < COPY_KEYS:
                            fs.copy_map[nd] = (path, mp, ln)
                        else:
                            dropped = True
                    if not self._remember_dir_copy(fs, nd, path, mp, ln):
                        dropped = True
                    if not _has_glob(path) and _copy_recursive(piece):
                        # 'cp -r /mnt/sd/update /tmp/' → /tmp/update/…, 대상이 새 이름이면('cp -r /mnt/sd/update /tmp/upd') /tmp/upd/… 도
                        tkeys = [(nd.rstrip("/") or "") + "/" + path.rstrip("/").rsplit("/", 1)[-1]]
                        if not dst.endswith("/") and nd not in _COMMON_DIRS and nd.count("/") >= 2:
                            tkeys.append(nd)
                        for tk in tkeys:
                            if tk in fs.tree_map or len(fs.tree_map) < COPY_KEYS:
                                fs.tree_map[tk] = (path, mp, ln)
                            else:
                                dropped = True
                    if dropped:
                        self._phase("rootfs_text", False)
                        self._limit(f"카드에서 복사한 대상이 기억 상한(파일마다 대상 {COPY_KEYS}개, 디렉터리마다 원본 이름 {DIR_NAMES}개·glob {DIR_GLOBS}개)을 넘어 "
                                    "일부 복사는 따라가지 못했습니다 (복사 뒤 실행·플래시 점검은 not-found 대신 unknown).")
            # 카드에 쓰지 않는 SD-07 근거(설정 키) / fstrim 호출 (SD-08)
            em = _ENC_FLAG_RX.search(L)
            if em:
                self._encryption_flag(fs, L, ln, em, excerpt)
            if script_like and "fstrim" in L and _FSTRIM_CMD_RX.search(L):
                self._add("SD-08", "fstrim", "info", source="rootfs", file=rel, line=ln, excerpt=excerpt, ctx=ctx)
        return True

    def _encryption_flag(self, fs: _FileState, L: str, ln: int, em: re.Match[str], excerpt: str) -> None:
        tokn = em.group(0)
        kv = re.match(r"[\"']?\s{0,8}[=:]\s{0,8}[\"']?([^\s\"';,]{1,256})", L[em.end():em.end() + 300])
        val = kv.group(1) if kv else None
        secretish = "key" in tokn.lower()
        ex7: dict[str, Any] = {"token": tokn}
        shown = excerpt
        if val is not None:
            if secretish:
                shown = excerpt.replace(val, mask_secret(val) or "")
                ex7["value"] = mask_secret(val)
            else:
                ex7["value"] = val
                lv = val.lower()
                if lv in ("1", "true", "on", "yes", "enable", "enabled"):
                    ex7["enabled"] = True
                elif lv in ("0", "false", "off", "no", "disable", "disabled"):
                    ex7["enabled"] = False
        self._add("SD-07", "encryption-flag", "info", source="rootfs", file=fs.rel, line=ln, excerpt=shown, ctx=fs.ctx, extra=ex7)

    def _relative_exec(self, fs: _FileState, L: str, ln: int, excerpt: str, extra_exp: dict[str, Any], hot: bool) -> None:
        """cd 로 카드 디렉터리에 들어간 뒤의 ./x·sh x 실행 (같은 줄의 앞쪽 cd, 없으면 앞 줄들의 마지막 cd).

        실행되지 않는 따옴표 문자열(echo "…; cd /mnt/sd; sh update.sh"·logger '…' 의 안내 문구) 안의 cd·실행은 보지 않는다 (_inert_quote_spans).
        cwd 는 서브셸 '( … )'·'$( … )' 와 자식 셸 문자열 'sh -c "…"'·'su -c "…"' 을 나오면 들어가기 전으로 되돌리고(eval "…" 은 지금 셸이라 남김),
        인자 없는 cd·'cd ~'·'cd -'·변수 대상은 모름(None)으로 둔다. 실행 문자열의 여는 따옴표 바로 뒤도 명령 시작이다 ("sh -c 'cd /mnt/sd && ./x'")."""
        events: list[tuple[int, str, Any]] = [(m.end(), "cd", m) for m in _CD_RX.finditer(L)]
        events += [(m.start("rel") if m.group("rel") else m.start("rel2"), "rel", m) for m in _REL_EXEC_RX.finditer(L)]
        if events and ('"' in L or "'" in L):
            inert = _inert_quote_spans(L)
            if inert:
                starts = [x for x, _ in inert]

                def _live(p: int) -> bool:
                    j = bisect.bisect_right(starts, p) - 1
                    return j < 0 or not (inert[j][0] < p < inert[j][1])

                events = [ev for ev in events if _live(ev[0])]
        if "(" in L or ")" in L:
            events += [(k, c, None) for k, c in _paren_events(L)]
        if "cd" in L and ("sh" in L or "su" in L or "eval" in L):
            events += _exec_quote_events(L)
        for _pos, kind, m in sorted(events, key=lambda x: x[0]):
            if kind == "(":
                if len(fs.cwd_stack) < 64:
                    fs.cwd_stack.append(fs.cwd)
                continue
            if kind == ")":
                if fs.cwd_stack:
                    fs.cwd = fs.cwd_stack.pop()
                continue
            if kind == "cd":
                tgt = _cd_target(L, m.end())
                if tgt is None or tgt.startswith(("~", "-", "$")):
                    fs.cwd = None
                elif tgt.startswith("/"):
                    fs.cwd = _norm(tgt)
                else:
                    fs.cwd = _norm(fs.cwd + "/" + tgt) if fs.cwd else None
                continue
            if not fs.cwd:
                continue
            mp = self._sd_root(fs.cwd, fs.sd_handler)
            if not mp:
                continue
            relp = m.group("rel") or m.group("rel2")
            path = _norm(fs.cwd + "/" + relp)
            rule = "sh" if (m.group("sh") or m.group("sh2")) else ("source" if m.group("src") else "relative-exec")
            self._add("SD-01", rule, "high" if hot else "medium", source="rootfs", file=fs.rel, line=ln, excerpt=excerpt, ctx=fs.ctx, sd_path=path,
                      extra={"cwd": fs.cwd, **extra_exp})
            self._ref(path, mp, "exec", "SD-01", {"source": "rootfs", "file": fs.rel, "line": ln})

    def _tree_lookup(self, fs: _FileState, path: str) -> tuple[str, str | None, int] | None:
        """재귀 복사(cp -r 카드디렉터리 대상)로 만들어진 경로인지: 가장 깊은 복사 대상 디렉터리를 찾아 카드 쪽 경로로 바꾼다."""
        if not fs.tree_map:
            return None
        p = path
        for _ in range(32):
            if "/" not in p.rstrip("/") or p in ("", "/"):
                return None
            p = p.rsplit("/", 1)[0] or "/"
            hit = fs.tree_map.get(p)
            if hit:
                src, smp, sln = hit
                return src.rstrip("/") + path[len(p):], smp, sln
        return None

    @staticmethod
    def _remember_dir_copy(fs: _FileState, nd: str, path: str, mp: str | None, ln: int) -> bool:
        """디렉터리 nd 로 복사한 카드 파일을 기억한다: 원본 이름은 처음 복사만(같은 이름의 복사가 수만 번이어도 한 칸), glob 원본은 중복 없이.
        상한(대상 디렉터리 COPY_KEYS 개, 디렉터리마다 이름 DIR_NAMES 개·glob DIR_GLOBS 개)에 걸려 버리면 False."""
        ent = fs.dir_map.get(nd)
        if ent is None:
            if len(fs.dir_map) >= COPY_KEYS:
                return False
            ent = fs.dir_map[nd] = ({}, [])
        names, globs = ent
        sbase = path.rsplit("/", 1)[-1]
        if _has_glob(sbase):
            if any(g[0] == path for g in globs):
                return True
            if len(globs) >= DIR_GLOBS:
                return False
            globs.append((path, mp, ln))
        elif sbase not in names:
            if len(names) >= DIR_NAMES:
                return False
            names[sbase] = (path, mp, ln)
        return True

    def _dir_lookup(self, fs: _FileState, path: str) -> tuple[str, str | None, int] | None:
        """디렉터리로 복사된 카드 파일인지: 대상 디렉터리 + (원본 이름 그대로 — 사전 조회 O(1), 또는 원본 glob 과 일치하는 이름 — glob DIR_GLOBS 개까지).

        glob 비교(DP — 패턴 길이 × 이름 길이)는 이름이 NAME_MAX 이하일 때만 하고 그 일을 세어 시간 예산·취소를 본다 (fs._tick)."""
        if not fs.dir_map or "/" not in path:
            return None
        d, base = path.rsplit("/", 1)
        ent = fs.dir_map.get(d or "/")
        if ent is None:
            return None
        names, globs = ent
        hit = names.get(base)
        if hit is not None:
            return hit
        if globs and len(base) <= NAME_MAX:
            for src, smp, sln in globs:
                sdir, sbase = src.rsplit("/", 1)
                fs._tick(len(sbase) * (len(base) + 1) // 4 + 1)
                if _glob_match(sbase, base):
                    return sdir + "/" + base, smp, sln
        return None

    def _classify_token(self, fs: _FileState, i: int, L: str, a: int, b: int, pre: str, post: str, piece: str, path: str, mp: str,
                        excerpt: str, extra_exp: dict[str, Any], remote_write: bool, where: dict[str, Any]) -> None:
        rel, name, ctx, script_like, web_kind = fs.rel, fs.name, fs.ctx, fs.script_like, fs.web_kind
        ln = fs.ln(i)
        hot = ctx in ("boot", "hotplug", "cron")
        base = path.rsplit("/", 1)[-1]
        deeper = path != mp  # 마운트 지점 자체가 아니라 카드 안의 파일·디렉터리
        trig: str | None = None
        ops = _copy_ops(piece)
        role = None
        for srcs, dst in ops:
            if _norm(dst) == path:
                role = "dst"
            elif any(_norm(s) == path for s in srcs):
                role = role or "src"
        tail = pre.rstrip(" \t\"'")  # 끝 고정 정규식이 맞을 수 있는지 O(1) 로 먼저 본다
        redirect = (tail.endswith(">") or tail.endswith("tee") or tail.endswith("-a")) and bool(_PRE_REDIRECT.search(pre))
        write_target = script_like and (redirect or role == "dst")
        pt = _PRE_TEST.search(pre) if (len(tail) >= 2 and tail[-2] == "-" and tail[-1] in "efsrxdhL") else None
        src_ctx = (tail.endswith(".") or tail.endswith("source")) and bool(_PRE_SOURCE.search(pre))
        inq, execq = _quote_state(pre)
        exec_ok = script_like and not write_target and (not inq or execq)
        matched = False

        def add(check: str, rule: str, sev: str, action: str, **extra: Any) -> None:
            nonlocal matched
            matched = True
            self._add(check, rule, sev, source="rootfs", file=rel, line=ln, excerpt=excerpt, ctx=ctx, sd_path=path, extra={**extra_exp, **extra})
            self._ref(path, mp, action, check, where)

        # SD-09: 서버 설정(루트·공유 키만)·서버 실행 인자·CGI
        if web_kind and _SERVE_KEY_RX[web_kind].search(pre):
            rule = {"web": "web-config-root", "ftp": "ftp-config-root", "samba": "samba-share", "dlna": "dlna-media"}[web_kind]
            add("SD-09", rule, "high" if web_kind != "dlna" else "medium", "serve", remote_write=remote_write)
        if script_like and not inq and (("httpd" in pre or "boa" in pre or "goahead" in pre or "ftpd" in pre) and _SERVER_ROOT_ARG_RX.search(pre)
                                        or (name == "inetd.conf" and _INETD_FTPD_RX.search(pre))):
            add("SD-09", "server-root-arg", "high", "serve", remote_write=bool(re.search(r"\bftpd\b(?:\s+-[a-zA-Z]+){0,8}\s+-[a-zA-Z]*w", pre)))
        if ctx == "cgi":
            if write_target or re.search(r"\bof=[\"']?$", pre):
                add("SD-09", "cgi-sd-write", "high", "write", remote_write=True)
            elif _LISTING_CMD_RX.search(piece):
                add("SD-09", "cgi-sd-listing", "medium", "serve")
            else:
                add("SD-09", "cgi-sd-reference", "low", "reference")
        # SD-01: 실행 (스크립트처럼 실행되는 파일만, 따옴표 안의 로그 문구는 아님)
        if exec_ok:
            sev_exec = "high" if hot else "medium"
            if "|" in post and _POST_PIPE_SH.search(post):
                if _DECRYPT_RX.search(piece) or _DECRYPT_RX.search(pre):
                    add("SD-01", "decrypt-then-exec", sev_exec, "exec", note="복호화 키가 펌웨어 안에 있으면 보호가 아니다 (REA 로 키 출처 확인)")
                else:
                    add("SD-01", "pipe-to-shell", sev_exec, "exec")
            if "sh" in pre and fs.pre_sh.search(pre):
                add("SD-01", "sh", sev_exec, "exec")
            elif src_ctx:
                add("SD-01", "source", sev_exec, "exec")
            elif ("insmod" in pre or "modprobe" in pre) and _PRE_INSMOD.search(pre):
                add("SD-01", "kernel-module", sev_exec, "exec")
            elif tail.endswith("LD_PRELOAD=") and _PRE_PRELOAD.search(pre):
                add("SD-01", "ld-preload", sev_exec, "exec")
            elif name == "inittab" and _PRE_INITTAB.search(pre):
                add("SD-01", "inittab-exec", "high", "exec")
            elif name == "mdev.conf" and _PRE_MDEV.search(pre):
                add("SD-01", "mdev-exec", "high", "exec")
            elif rel.endswith(".rules") and _PRE_UDEV.search(pre):
                add("SD-01", "udev-exec", "high", "exec")
            elif ctx == "cron" and _PRE_CRON.search(pre):
                add("SD-01", "cron-exec", "high", "exec")
            elif "Exec" in pre and _PRE_SYSTEMD.search(pre):
                add("SD-01", "systemd-exec", "high", "exec")
            elif "-c" in pre and _PRE_SU_C.search(pre):
                add("SD-01", "sh", sev_exec, "exec")
            elif deeper and not pt and not (pre.endswith("=") or pre.endswith("=\"") or pre.endswith("='")) and (ssd := _ssd_state(pre, post)) is not False and (
                    ssd or fs.pre_cmd.search(pre) or (tail.endswith(("-exec", "-execdir")) and _PRE_FIND_EXEC.search(pre)) or (tail.endswith(")") and _PRE_CASE.search(pre))):
                # start-stop-daemon 의 멈춤·상태·시험(-K·--stop …)은 경로를 실행하지 않는다 — '--stop --exec 경로' 의 'exec' 낱말이 명령 위치로 맞아도
                add("SD-01", "direct-exec", sev_exec, "exec")
            elif deeper and "chmod" in pre and _PRE_CHMOD_X.search(pre):
                add("SD-01", "chmod-x", "medium" if hot else "low", "exec")
            if "find" in pre and _PRE_FIND_ROOT.search(pre) and _POST_FIND_EXEC.search(post):
                add("SD-01", "find-exec", sev_exec, "exec")
            if deeper:
                tm = pt
                tkind = "test"
                if tm is None and "grep" in pre:
                    tm = _PRE_GREP_Q.search(pre)
                    tkind = "grep"
                if tm is not None:
                    # 시험 시작 위치를 그대로 넘긴다 (_trigger 가 더 짧은 창으로 다시 찾다 놓치지 않게)
                    sent = 1 if pre.startswith("\x00") else 0
                    tpos = a - (len(pre) - sent) + (tm.start() - sent)
                    trig = self._trigger(fs, i, L, a, b, path, mp, excerpt, extra_exp, where, tpos, tkind)
                    matched = True
        # SD-02: 플래시 쓰기 / 업데이트 파일 (카드가 원본일 때)
        piece_nq = piece.replace('"', "").replace("'", "")
        flash_src = ("/dev/" in piece_nq and ("if=" + path in piece_nq or "cat " + path in piece_nq) and _FLASH_DEST_RX.search(piece_nq) is not None) \
            or any(_FLASH_DEV_RX.match(d.strip("\"'")) for srcs, d in ops if any(_norm(x.strip("\"'")) == path for x in srcs)) \
            or ("|" in post and _POST_PIPE_FLASH.search(post) is not None)
        flash_cmd = any(k in piece for k in ("flash", "nand", "ubi", "upgrade", "mtd")) and _FLASH_CMD_RX.search(piece) is not None
        if not write_target and (flash_cmd or flash_src):
            self._sd02(fs, i, pre, excerpt, path, "flash-write", "high", extra_exp)
            self._ref(path, mp, "flash", "SD-02", where)
            matched = True
        elif not write_target and deeper and trig != "flash" and _UPDATE_NAME_RX.search(base[:256]):
            self._sd02(fs, i, pre, excerpt, path, "update-file", "medium", extra_exp)
            self._ref(path, mp, "update-file", "SD-02", where)
            matched = True
        # SD-05: 설정 가져오기 (카드가 원본, 셸로 읽는 .sh·source 는 SD-01, 로그 이름은 SD-06)
        if (deeper and not write_target and _CONFIG_NAME_RX.search(base) and not base.endswith(".sh") and not src_ctx
                and not _LOG_NAME_RX.search(base)):
            dests = [d for srcs, d in ops if any(_norm(s) == path for s in srcs)]
            if dests and any(d.startswith(("/etc", "/mnt/mtd", "/mnt/config", "/config", "/data", "/var/lib", "/usr/local", "/appfs", "/tmp")) for d in dests):
                add("SD-05", "config-import", "medium", "read-config", copied_to=dests[0])
            elif role == "src" or _CONFIG_USE_RX.search(pre) or re.search(r"\b(?:wpa_supplicant|hostapd)\b", piece):
                add("SD-05", "config-read", "medium", "read-config")
            elif not script_like and re.search(r"[=:]\s*[\"']?$", pre):
                add("SD-05", "config-path", "low", "read-config")
        # SD-06: 카드에 쓰기
        if "syslogd" in pre and re.search(r"\bsyslogd\b[^;&|]{0,480}\s-O\s*[\"']?$", pre):
            add("SD-06", "syslogd-to-card", "medium", "write-log")
        elif "core_pattern" in piece or "core_pattern" in pre:
            add("SD-06", "core-dump-to-card", "medium", "write-log")
        elif "tcpdump" in pre and re.search(r"\btcpdump\b[^;&|]{0,480}\s-w\s*[\"']?$", pre):
            add("SD-06", "packet-capture-to-card", "medium", "write-log")
        elif write_target and _SENSITIVE_SRC_RX.search(pre):
            add("SD-06", "sensitive-copy-to-card", "medium", "write")
        elif write_target:
            logish = bool(_LOG_NAME_RX.search(base)) or bool(_LOG_CMD_RX.search(pre))
            add("SD-06", "write-to-card", "medium" if logish else "low", "write")
        elif not script_like and deeper and (re.search(r"(?i)(?:log|debug|dump|core|trace)[\w.-]{0,64}\s*(?:[=:]\s*|\s+)[\"']?$", pre) or _LOG_NAME_RX.search(base)):
            add("SD-06", "log-path-config", "medium", "write-log")
        # SD-07: 녹화 파일의 암호화 확장자
        if base.endswith(".enc") and _RECORD_NAME_RX.search(path):
            add("SD-07", "encrypted-extension", "info", "record")
        if not matched:
            action = "record" if _RECORD_NAME_RX.search(path) else "reference"
            self._ref(path, mp, action, None, where)

    def _trigger(self, fs: _FileState, i: int, L: str, a: int, b: int, path: str, mp: str, excerpt: str, extra_exp: dict[str, Any],
                 where: dict[str, Any], tpos: int, tkind: str = "test") -> str | None:
        """카드 파일 존재(또는 'grep -q … 카드파일' 내용)가 켜는 동작. 반환: 'service' / 'flash' / None. tpos = 시험이 시작하는 L 위치.

        켜지는 범위: '[ -f 카드파일 ] && cmd (&& cmd…)' 와 '&& {' 여러 줄 묶음(줄 끝 && 뒤 다음 줄은 논리 줄로 이미 이어짐),
        'if/while [ -f … ]; then … fi'(블록 끝까지 — 줄 수 상한 없음), 가드 '[ -f … ] || exit/return' · '[ ! -f … ] && exit' ·
        'if [ ! -f … ]; then exit; fi' · 'while [ ! -f … ]; do …; done' 뒤의 나머지(감싸는 블록·함수·파일 끝까지), 'if [ ! -f … ]; then …; else 갈래'.
        부정은 반대 갈래만: '[ ! -f … ] || cmd' 는 cmd 가 켜지고, '[ -f … ] && exit' 와 '[ ! -f … ] || exit' 는 아니다.
        켜진 명령이 같은 파일의 셸 함수면 그 본문을 본다. 서비스는 '시작'만 센다 (_service_start — killall·stop 은 아님)."""
        inner_neg = False
        if tkind == "test":
            if L.startswith(" -a", tpos) or L.startswith("\t-a", tpos):
                bs = max(L.rfind("[", max(0, tpos - 1024), tpos), -1)
                if bs >= 0 and "]" not in L[bs:tpos]:
                    tpos = bs - 1 if bs > 0 and L[bs - 1] == "[" else bs  # '[ -d A -a -f B ]' → 괄호 시작부터
            inner_neg = "!" in L[tpos:a]
            if L.startswith("[[", tpos):
                close = L.find("]]", b)
                after = L[close + 2:] if close >= 0 else ""
            elif L.startswith("[", tpos):
                close = L.find("]", b)
                after = L[close + 1:] if close >= 0 else ""
            else:
                after = L[b:]
        else:
            after = L[b:]
        base = max(0, tpos - 256)
        before = L[base:tpos]
        after = after[:4096]
        neg = inner_neg != before.rstrip().endswith("!")
        n = len(fs.lines)
        shift = max(0, len(fs.lines[i]) - len(L)) if i < n else 0  # 변수 펼침으로 줄 길이가 달라진 만큼 (구조 위치는 펼치기 전 줄 기준)
        kw = None
        for km in _STMT_KW_RX.finditer(before):
            kw = km
        texts: list[str] = []
        ranges: list[tuple[int, int]] = []
        if kw is not None and not re.search(r"\b(?:then|do)\b", before[kw.end():]):
            wm = re.search(r"(?:elif|if|while|until)$", kw.group(0))
            word = wm.group(0) if wm else "if"
            kpos = base + kw.end() - len(word)
            if word == "until":
                neg = not neg  # 'until [ -f X ]' 의 본문은 X 가 없을 때 돈다
            blk = fs.opener(i, kpos + shift, ("if", "loop")) if word != "elif" else fs.if_for_branch(i)
            if not neg:
                t, r = self._block_body(fs, i, after, blk, tpos + shift)
                texts.append(t)
                ranges += r
            elif blk is not None and blk.close < n and (word in ("while", "until") or self._exit_only_body(fs, i, after, blk, tpos + shift)):
                # X 가 없으면 나가거나 기다린다 → 블록 뒤의 나머지는 X 가 있을 때만 돈다
                texts.append(fs.lines[blk.close][blk.close_pos:])
                ranges.append((blk.close + 1, fs.scope_end(blk.close)))
            elif blk is not None and blk.kind == "if" and word in ("if", "elif"):
                # 'if [ ! -f X ]; then A; else B; fi' → B 는 X 가 있을 때 돈다
                nbk = fs.next_branch_kind(blk, i, tpos + shift)
                nb = nbk[0] if nbk is not None else None
                if nbk is not None and nb is not None and nbk[1] == "else":
                    eb = fs.next_branch(blk, nb[0], nb[1])
                    end_l, end_p = (eb if eb is not None else (blk.close, blk.close_pos))
                    if end_l == nb[0]:
                        texts.append(fs.lines[nb[0]][nb[1]:end_p])
                    else:
                        texts.append(fs.lines[nb[0]][nb[1]:])
                        ranges.append((nb[0] + 1, end_l))
                        if end_l < n:
                            texts.append(fs.lines[end_l][:end_p])
                if not texts:
                    self._ref(path, mp, "trigger", None, where)
                    return None
            else:
                self._ref(path, mp, "trigger", None, where)
                return None
        else:
            rest = after.lstrip()
            op = rest[:2]
            if op not in ("&&", "||"):
                self._ref(path, mp, "trigger", None, where)
                return None  # 같은 줄에서 결과를 쓰지 않음
            gate = (op == "&&") != neg  # 참이면 뒤 명령은 X 가 있을 때 돈다
            cmd, remainder = _first_cmd(rest[2:])
            if _exit_only(cmd):
                if gate:
                    self._ref(path, mp, "trigger", None, where)
                    return None  # X 가 있으면 나간다 → 나머지는 X 가 없을 때
                texts.append(remainder)  # X 가 없으면 나간다 → 같은 줄 나머지와 블록·함수·파일 끝까지가 X 에 묶인다
                ranges.append((i + 1, fs.scope_end(i)))
            elif gate:
                texts.append(cmd)
                while remainder.lstrip().startswith("&&"):
                    cmd2, remainder = _first_cmd(remainder.lstrip()[2:])
                    texts.append(cmd2)
                if cmd.strip() == "{" or (cmd.lstrip().startswith("{") and "}" not in cmd):
                    blk = fs.opener(i, len(fs.lines[i]) if i < n else 0, ("brace",))
                    if blk is not None and blk.line == i:
                        ranges.append((i + 1, blk.close))
                        if blk.close < n:
                            texts.append(fs.lines[blk.close][:blk.close_pos])
            else:
                self._ref(path, mp, "trigger", None, where)
                return None
        # 켜진 명령이 이 파일의 셸 함수면 그 본문도 켜진 범위다 ('start_dbg(){ telnetd & }; [ -f 카드 ] && start_dbg')
        for t in list(texts)[:16]:
            for words in _split_statements(t)[:16]:
                if words:
                    fb = fs.func_body(words[0])
                    if fb is not None:
                        if fb[0]:
                            texts.append(fb[0])
                        if fb[1] is not None:
                            ranges.append(fb[1])
        hot = fs.ctx in ("boot", "hotplug", "cron")
        body = "\n".join(t for t in texts if t)
        triggered = _service_start(body)
        if triggered is None:
            for lo, hi in ranges:
                k = fs.next_hit("svc", lo)
                if k < min(hi, n):
                    triggered = _service_start(fs.lines[k]) or "서비스 시작"
                    break
        if triggered is not None:
            self._add("SD-01", "trigger-service", "high" if hot else "medium", source="rootfs", file=fs.rel, line=fs.ln(i), excerpt=excerpt, ctx=fs.ctx, sd_path=path,
                      extra={**extra_exp, "triggered": clip(triggered, 80)})
            self._ref(path, mp, "trigger", "SD-01", where)
            return "service"
        flash = bool(_FLASH_CMD_RX.search(body) or _FLASH_DEST_RX.search(body)) or any(fs.next_hit("flash", lo) < min(hi, n) for lo, hi in ranges)
        if flash:
            self._sd02(fs, i, before, excerpt, path, "trigger-flash", "high", extra_exp)
            self._ref(path, mp, "trigger", "SD-02", where)
            return "flash"
        self._ref(path, mp, "trigger", None, where)
        return None

    def _block_body(self, fs: _FileState, i: int, after: str, blk: _Block | None, tpos: int) -> tuple[str, list[tuple[int, int]]]:
        """if/while 조건 줄 i 의 본문: 같은 줄의 then/do 뒤(같은 줄에서 끝나면 거기까지) + 블록 구조로 찾은 다음 줄들(첫 else/elif 또는 fi/done 까지).

        반환: (같은 줄·끝 줄의 문구, [(시작 줄, 끝 줄)]). 블록 구조는 파일당 한 번 만들고 다음 갈래는 이분 탐색 — 본문 길이 상한 없이 파일 크기에 묶인다."""
        k = re.search(r"\b(?:then|do)\b", after)
        text = ""
        if k:
            rest = after[k.end():]
            fi = re.search(r"(?:^|[;&\s])(?:fi|done|else|elif)\b", rest)
            if fi:
                return rest[:fi.start()], []
            text = rest
        if blk is None:
            return text, []
        n = len(fs.lines)
        nb = fs.next_branch(blk, i, tpos)
        end, end_pos = nb if nb is not None else (blk.close, blk.close_pos)
        if end <= i:
            return text, []
        tail = fs.lines[end][:end_pos] if end < n else ""
        return text + "\n" + tail, [(i + 1, end)]

    def _exit_only_body(self, fs: _FileState, i: int, after: str, blk: _Block, tpos: int) -> bool:
        """if 블록의 then 갈래가 exit/return(과 알림)뿐인지 — 'if [ ! -f X ]; then echo no card; exit 0; fi'."""
        text, ranges = self._block_body(fs, i, after, blk, tpos)
        parts = [text]
        for lo, hi in ranges:
            if hi - lo > 16:
                return False
            parts += fs.lines[lo:hi]
        return _exit_only("\n".join(parts).replace("\n", "; "))

    def _sd02(self, fs: _FileState, i: int, pre: str, excerpt: str, path: str, rule: str, sev: str, extra: dict[str, Any]) -> None:
        """SD-02 근거 하나 (버튼 조건·서명·해시·flash_erase 는 파일당 한 번 계산한 줄 플래그로 — 토큰마다 파일 전체를 다시 보지 않는다)."""
        fl = fs.flags
        ex = dict(extra)
        cond = fs.enclosing_if(i)
        if (cond is not None and fl["gpio_read"][cond]) or _GPIO_READ_RX.search(pre):
            ex["gated_by"] = "button/gpio"
        lo, hi = max(0, i - 12), min(len(fs.lines), i + 13)
        sig = fs.signature_hint
        if sig:
            ex["signature_check_hint"] = sig
        elif any(fl["hash_only"][lo:hi]):
            ex["integrity_only"] = "CRC·해시 검사만 보임 (서명 아님)"
        if any(fl["flash_erase"][lo:hi]):
            ex["flash_erase_nearby"] = True
        self._add("SD-02", rule, sev, source="rootfs", file=fs.rel, line=fs.ln(i), excerpt=excerpt, ctx=fs.ctx, sd_path=path, extra=ex)

    def _scan_web_symlinks(self, aud: Auditor, web: dict[str, Any]) -> None:
        """웹 루트 안의 심볼릭 링크가 카드를 가리키는지 (링크 대상은 readlink 문자열만 — 따라가지 않는다)."""
        roots = set(DEFAULT_WEB_ROOTS)
        for r in (web or {}).get("web_roots") or []:
            if isinstance(r, dict) and r.get("path"):
                roots.add(r["path"])
        for cfg in (web or {}).get("configs") or []:
            for v in cfg.get("document_root") or []:
                v = str(v).strip("\"' ")
                if v.startswith("/"):
                    roots.add(_norm(v))
        roots_t = tuple(r.rstrip("/") + "/" for r in roots)
        for e in aud.entries:
            if e.kind != "symlink" or not e.rel.startswith(roots_t):
                continue
            try:
                target = os.readlink(e.path)
            except OSError:
                continue
            tabs = _norm(target if target.startswith("/") else posixpath.join(posixpath.dirname(e.rel), target))
            mp = self._sd_root(tabs)
            if mp:
                self._add("SD-09", "web-symlink", "high", source="rootfs", file=e.rel, excerpt=f"{e.rel} -> {target}", ctx="web", sd_path=tabs, extra={"link_target": target})
                self._ref(tabs, mp, "serve", "SD-09", {"source": "rootfs", "file": e.rel})

    def _env_tools(self, aud: Auditor) -> None:
        """/etc/fw_env.config + fw_setenv → 사용자 공간에서 U-Boot env 쓰기 가능 (SD-03 문맥)."""
        data, final = read_in_root(aud.root, "/etc/fw_env.config", 1 << 16)
        locs = []
        if data and is_text(data[:4096]):
            for ln, line in enumerate(_blank_comments(data.decode("latin-1")).split("\n"), 1):
                f = line[:1024].split()
                if len(f) >= 3 and f[0].startswith("/"):
                    locs.append({"line": ln, "device": f[0], "offset": f[1], "size": f[2]})
                if len(locs) >= 4:
                    break
        tools = sorted(e.rel for e in aud.entries if e.name in ("fw_setenv", "fw_printenv") and e.kind in ("file", "symlink"))
        info = {"fw_env_config": final if locs else None, "env_locations": locs[:4], "tools": tools[:6], "userspace_writable": bool(locs) and any(t.endswith("fw_setenv") for t in tools)}
        self.context["SD-03"]["env_userspace"] = info

    def _scan_binaries(self, aud: Auditor) -> None:
        """바이너리(작은 텍스트가 아닌 파일) 문자열에서 SD 경로·업데이트 표지·마운트 문자열을 찾는다 (YAML sd-* + 내부 보조 패턴).

        파일마다 새 HuntState 로 보고 바로 분류한다. 상한을 넘어 버린 히트가 있으면(counts > stored) 그 파일을 '일부만 봄' 으로 둔다."""
        root = aud.root
        heur = string_heuristics(self.patterns, list(self.mounts))
        needles = list(_STATIC_NEEDLES) + [m.encode("latin-1", "replace") for m in self.mounts if "$" not in m and len(m) >= 4]
        text_set = set(self.text_files)
        complete = True
        used = 0
        seen_ino: set[tuple[int, int]] = set()
        for e in aud.entries:
            if e.kind != "file" or e.rel in text_set or e.st.st_size < 16:
                continue
            if e.rel.endswith((".ko", ".ko.gz", ".ko.xz")) or e.rel.startswith("/lib/modules/"):
                continue  # 커널 모듈: fat.ko 의 옵션 이름표 같은 드라이버 문자열은 카드 처리 근거가 아니다
            ino = (e.st.st_dev, e.st.st_ino)
            if ino in seen_ino:
                continue
            seen_ino.add(ino)
            if self.ctl.expired():
                complete = False
                break
            if e.st.st_size > self.max_binary_file:
                self.stats["skipped_large"].append(e.rel)
                complete = False
                continue
            if used + e.st.st_size > self.binary_budget:
                complete = False
                self._limit("바이너리 문자열 검사 바이트 예산을 넘어 일부만 보았습니다.")
                break
            data, _ = read_in_root(root, e.rel, self.max_binary_file)
            if not data:
                continue
            used += len(data)
            if not any(nd in data for nd in needles):
                continue
            self.stats["binary_files_scanned"] += 1
            state = HuntState(heur, max_hits=BIN_HITS_PER_FILE, per_pattern_cap=BIN_HITS_PER_FILE, per_file_pattern_cap=BIN_HITS_PER_PATTERN_FILE)
            seen: set[tuple[str, int]] = set()
            pos = 0
            while pos < len(data):
                if pos and self.ctl.expired():
                    complete = False
                    break
                if seen:
                    seen = {k for k in seen if k[1] >= pos}
                if not scan_buffer(state, data[pos:pos + SD_CHUNK + OVERLAP], pos, (e.rel, e.rel), False, min_len=5, utf16=False, seen=seen,
                                   keep_from=pos + SD_CHUNK, ctl=self.ctl, stop_on_expiry=True):
                    complete = False
                    break
                pos += SD_CHUNK
            if sum(state.counts.values()) > len(state.hits):
                complete = False
                if len(self.stats["hits_dropped_files"]) < 20:
                    self.stats["hits_dropped_files"].append(e.rel)
            if not self._consume_hits(state.hits, source="rootfs"):
                complete = False  # 히트 분류 중 시간 예산이 끝났다
                break
        self.stats["binary_bytes"] = used
        if self.stats["skipped_large"]:
            self._limit(f"max_file_size 를 넘는 파일 {len(self.stats['skipped_large'])}개는 문자열을 보지 않았습니다: {', '.join(self.stats['skipped_large'][:5])}")
        if self.stats["hits_dropped_files"]:
            self._limit(f"문자열 히트 상한을 넘어 일부 문자열을 분류하지 못한 파일: {', '.join(self.stats['hits_dropped_files'][:5])} (관련 점검은 not-found 대신 unknown).")
        if not complete and self.ctl.timed_out:
            self._limit("시간 예산 초과로 바이너리 문자열을 일부만 보았습니다.")
        self._phase("rootfs_binary", complete)

    # -- 문자열 히트 분류 (rootfs 바이너리·이미지 공통) ---------------------------------
    def _consume_hits(self, hits: list[dict[str, Any]], *, source: str, image: str | None = None) -> bool:
        """문자열 히트를 (파일, 문맥)으로 묶어 분류한다. 묶음 HIT_GROUPS_CTL_EVERY 개마다 시간 예산·취소를 보고, 예산이 끝나면 남은 묶음은 분류하지 않고
        False (호출한 쪽이 단계를 잘림으로 둔다 — 이미지 히트 2만 묶음은 적대적 문맥에서 10초 넘게 걸렸다).

        YAML sd-* 경로 히트가 SCSI 디스크 이름 경로(/mnt/sda1·/media/sdb2 — SD 마운트로 발견되지 않음)만 가리키면 카드 문맥이 아니라 버린다."""
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        sd_ctx_files: set[str] = set()
        for idx, h in enumerate(hits):
            if (idx & 0x1FF) == 0x1FF and self.ctl.expired():
                return False
            pid = h["pattern_id"]
            if pid in _YAML_SD_PATH_IDS and self._disk_path_only(h.get("match") or ""):
                continue
            k = (h["path"], h["context"])
            g = groups.setdefault(k, {"ids": set(), "offset": h["offset"], "file": h.get("file"), "path": h["path"], "context": h["context"]})
            g["ids"].add(pid)
            g["offset"] = min(g["offset"], h["offset"])
            if pid in _SD_CONTEXT_IDS or pid.startswith("sd-"):
                sd_ctx_files.add(h["path"])
        for n, g in enumerate(groups.values()):
            if n and n % HIT_GROUPS_CTL_EVERY == 0 and self.ctl.expired():
                return False
            self._classify_string(g, source=source, image=image, sd_context=g["path"] in sd_ctx_files)
        return True

    def _disk_path_only(self, match: str) -> bool:
        """YAML sd-* 경로 히트의 일치 문자열이 카드 경로 없이 SCSI 디스크 이름 경로(/mnt/sda1·/media/sdb2 — 발견된 SD 마운트 아래가 아님)만 가리키는지.

        카드 같은 접두(/mnt/·/media/·/tmp/·/sdcard·/system/)의 앞 토큰 8개만 본다 (히트마다 비용 상한)."""
        if "/sd" not in match:
            return False
        disk = False
        for k, m in enumerate(_TOKEN_RX.finditer(match)):
            if k >= 8:
                break
            t = _norm(m.group(0))
            if not t.startswith(("/mnt/", "/media/", "/tmp/", "/sdcard", "/system/")):
                continue
            if self._sd_root(t):
                return False
            disk = disk or bool(_SCSI_DISK_PATH_RX.match(t))
        return disk

    def _has_sd_token(self, s: str) -> bool:
        """문자열에 카드 경로 토큰(발견된 SD 마운트 또는 흔한 카드 경로 아래)이 있는지."""
        return any(len(m.group(0)) <= MAX_TOKEN and self._sd_root(m.group(0)) for m in _TOKEN_RX.finditer(s))

    def _classify_string(self, g: dict[str, Any], *, source: str, image: str | None, sd_context: bool) -> None:
        s = g["context"]
        ids = g["ids"]
        rel = g["file"] if source == "rootfs" else None
        off = g["offset"]
        loc: dict[str, Any] = {"source": source, "excerpt": s, "offset": off}
        if source == "rootfs":
            loc["file"] = rel
        else:
            loc["image"] = image
        where = {"source": source, ("file" if source == "rootfs" else "image"): rel if source == "rootfs" else image, "offset_hex": hexs(off)}
        is_cgi = bool(rel) and ("/cgi-bin/" in rel or rel.endswith((".cgi", ".fcgi")))
        ctx = "binary" if source == "rootfs" else "image"

        def add(check: str, rule: str, sev: str, sd_path: str | None = None, **extra: Any) -> None:
            self._add(check, rule, sev, ctx=ctx, sd_path=sd_path, extra=extra or None, **loc)

        # 마운트 문자열 (system() 명령) → 마운트 발견 + 옵션
        if "sdsurface-mount-cmd" in ids or "sdsurface-mmcblk" in ids:
            for piece in iter_command_pieces(s):
                mt = parse_mount_command(piece)
                if mt:
                    self._mount(mt["mount_point"], {"source": "binary-string" if source == "rootfs" else "image-string", **({"file": rel} if rel else {"image": image}),
                                                    "offset_hex": hexs(off), "excerpt": clip(piece.strip(), 160)}, fs=mt["fs"], device=mt["device"], options=mt["options"], readonly=mt["readonly"])
        if "sdsurface-mmcblk" in ids and source == "rootfs" and sd_context:
            # 카드 문맥(카드 경로·'SD card' 문구)이 같은 바이너리에 있을 때만 — eMMC 전용 기기의 /dev/mmcblk0pN 은 카드 처리기가 아니다
            devs = set(re.findall(r"/dev/mmcblk\w{0,16}", s))
            if not devs or not devs <= self.emmc_devices:
                add("SD-04", "daemon-mmcblk", "info")
                if rel and not any(hd.get("file") == rel and hd["kind"] == "daemon" for hd in self.handlers) and len(self.handlers) < 300:
                    self.handlers.append({"kind": "daemon", "file": rel, "line": None, "match": "/dev/mmcblk", "match_kind": "sd", "action": None,
                                          "command": _mask_excerpt(s, 120), "handler_script": None})
        # 마운트 옵션 문자열(umask=0·shortname=·discard)은 드라이버의 옵션 이름표에도 있다 → 카드 문맥이 같은 바이너리에 있을 때만
        # (커널 모듈은 아예 보지 않는다). 이미지 문자열은 같은 문자열 안에 카드 장치·경로가 있을 때만
        opt_ok = bool(ids & _MOUNT_OPT_IDS) and ((sd_context and source == "rootfs") or (source != "rootfs" and ("mmcblk" in s or self._has_sd_token(s))))
        if "sdsurface-mount-data" in ids and opt_ok:
            add("SD-08", "binary-mount-data", "low", options=clip(s, 120))
        if "sdsurface-fstrim" in ids and opt_ok:
            add("SD-08", "fstrim", "info")
        if "sdsurface-discard" in ids and opt_ok:
            add("SD-08", "discard", "info")
        if "sdsurface-record-encrypt" in ids:
            em = _ENC_FLAG_RX.search(s)
            add("SD-07", "binary-encryption-string", "info", token=clip(em.group(0) if em else s, 60))
        if "sdsurface-fit-keys" in ids:
            self.context["SD-02"]["fit_signature_keys"] = True
            self.context["SD-03"]["fit_signature_keys"] = True
        if "sd-uboot-auto-update" in ids:
            crc = "au_check_cksum_valid" in s
            add("SD-02", "uboot-auto-update", "high" if source != "rootfs" else "medium",
                note=("au_check_cksum_valid: CRC 만 검사 (서명 아님)" if crc else "U-Boot SD 자동 업데이트 표지 — 검사 방식을 REA 로 확인"))
        if "sd-update-image-names" in ids:
            add("SD-02", "update-image-name", "medium")
        if "sd-uboot-card-boot-script" in ids or "sdsurface-uboot-fsload" in ids:
            add("SD-03", "uboot-boot-script-string", "low", note="env 밖 문자열 — 실제 부팅 경로인지 UART printenv·REA 로 확인")
        if "sd-log-to-card" in ids:
            add("SD-06", "log-to-card", "medium")
        if "sd-autorun-known-names" in ids:
            add("SD-01", "autorun-name", "high")
        # SD 경로 토큰을 같은 줄 분류기로 (바이너리 문자열은 괄호를 명령 구분자로 보지 않는 엄격한 문맥)
        for m in _TOKEN_RX.finditer(s):
            tok = m.group(0)
            if len(tok) > MAX_TOKEN:
                continue
            mp = self._sd_root(tok)
            if mp is None:
                continue
            path = _norm(tok)
            base = path.rsplit("/", 1)[-1]
            pre, post = s[:m.start()], s[m.end():]
            if is_cgi:
                add("SD-09", "cgi-binary-sd-reference", "low", sd_path=path)
                self._ref(path, mp, "serve", "SD-09", where)
            if (_POST_PIPE_SH.search(post) or _PRE_SH_STRICT.search(pre) or _PRE_SOURCE_STRICT.search(pre) or _PRE_INSMOD.search(pre) or _PRE_PRELOAD.search(pre)
                    or (pre.strip() == "" and post.strip() == "&") or (pre.strip() and _PRE_CMD_STRICT.search(pre) and not _PRE_TEST.search(pre))):
                rule = "decrypt-then-exec" if (_POST_PIPE_SH.search(post) and _DECRYPT_RX.search(s)) else "binary-exec-string"
                add("SD-01", rule, "high", sd_path=path)
                self._ref(path, mp, "exec", "SD-01", where)
            elif base.endswith((".sh", ".ko")):
                add("SD-01", "binary-script-path", "medium", sd_path=path)
                self._ref(path, mp, "exec?", "SD-01", where)
            elif _FLASH_CMD_RX.search(s) or _FLASH_DEST_RX.search(s):
                add("SD-02", "flash-write", "high", sd_path=path)
                self._ref(path, mp, "flash", "SD-02", where)
            elif _UPDATE_NAME_RX.search(base[:256]):
                add("SD-02", "binary-update-file", "medium", sd_path=path)
                self._ref(path, mp, "update-file", "SD-02", where)
            elif _CONFIG_NAME_RX.search(base):
                add("SD-05", "binary-config-path", "low", sd_path=path)
                self._ref(path, mp, "read-config", "SD-05", where)
            elif re.search(r"\bsyslogd\b[^;&|]{0,480}\s-O\s*$", pre) or "core_pattern" in s:
                add("SD-06", "log-to-card", "medium", sd_path=path)
                self._ref(path, mp, "write-log", "SD-06", where)
            elif _LOG_NAME_RX.search(base):
                add("SD-06", "binary-log-path", "low", sd_path=path)
                self._ref(path, mp, "write-log", "SD-06", where)
            else:
                self._ref(path, mp, "record" if _RECORD_NAME_RX.search(path) else "reference", None, where)

    # -- 이미지 ---------------------------------------------------------------
    def scan_image(self, buf: Any, size: int, image_rel: str, scan: dict[str, Any]) -> None:
        """env·문자열을 먼저 점검한 뒤 같은 잔여 예산으로 비압축 FDT의 서명 선언 구조를 관찰한다."""
        if "sd_boot_summary" not in scan:
            scan["sd_boot_summary"] = attach_sd_boot(scan, self.ctl)
        self.env_found = bool(scan.get("envs") or scan.get("embedded_default_envs"))
        envs_ctx = []
        for e in (scan.get("envs") or []) + (scan.get("embedded_default_envs") or []):
            b = e["sd_boot"]
            off = e.get("offset")
            envs_ctx.append({"offset_hex": hexs(off), "storage": b["storage"], "verify": b["verify"], "verify_off": b["verify_off"], "mmc_first": b["mmc_first"],
                             "persistent_writable": b["persistent_writable"]})
            for sg in b["signals"]:
                kinds = sg["kinds"]
                exc = f"{sg['var']}={sg['value']}"
                extra = {"var": sg["var"], "storage": b["storage"], "env_offset_hex": hexs(off)}
                if "update-from-card" in kinds:
                    ex2 = dict(extra)
                    if b["update_gpio_gated"]:
                        ex2["gated_by"] = "button/gpio"
                    self._add("SD-02", "env-update-from-card", "high", source="uboot-env", image=image_rel, offset=off, excerpt=exc, ctx="env", extra=ex2)
                rule = None
                if "boot-script" in kinds:
                    rule = "env-boot-script"
                elif "fs-load" in kinds:
                    rule = "env-fs-load"
                elif "distro-boot" in kinds:
                    rule = "env-distro-boot"
                elif "raw-mmc" in kinds:
                    rule = "env-raw-mmc"
                if rule:
                    sev = "low" if rule == "env-raw-mmc" else ("high" if (b["verify_off"] or b["mmc_first"]) else "medium")
                    self._add("SD-03", rule, sev, source="uboot-env", image=image_rel, offset=off, excerpt=exc, ctx="env",
                              extra={**extra, "verify_off": b["verify_off"], "mmc_first": b["mmc_first"]})
        self.context["SD-03"]["envs"] = envs_ctx[:16]
        self.context["SD-03"]["env_persistent"] = any(x["persistent_writable"] for x in envs_ctx)
        capped_env = [e for e in (scan.get("envs") or []) + (scan.get("embedded_default_envs") or [])
                      if e["sd_boot"].get("expansion_truncated") or e["sd_boot"].get("vars_truncated")]
        if capped_env:
            self._limit("U-Boot env 의 run 펼침·변수 수 상한에 걸려 일부만 분석했습니다 (SD-02·SD-03 은 not-found 대신 unknown).")
        self._phase("image_env", not self.ctl.timed_out and not capped_env)
        # 문자열
        heur = string_heuristics(self.patterns, list(self.mounts))
        state = HuntState(heur, max_hits=IMAGE_HITS, per_pattern_cap=IMAGE_HITS_PER_PATTERN, per_file_pattern_cap=IMAGE_HITS_PER_PATTERN)
        limit = min(size, self.image_budget)
        pos = 0
        complete = True
        seen: set[tuple[str, int]] = set()
        while pos < limit:
            if self.ctl.expired():
                complete = False
                break
            data = bytes(buf[pos:min(size, pos + SD_CHUNK + OVERLAP)])
            if not data:
                break
            if seen:
                seen = {k for k in seen if k[1] >= pos}  # 메모리를 겹침 구간에 묶는다 (앞 위치는 다시 나오지 않는다)
            if any(nd in data for nd in _STATIC_NEEDLES):
                if not scan_buffer(state, data, pos, (image_rel, None), False, min_len=5, utf16=False, seen=seen, keep_from=pos + SD_CHUNK, ctl=self.ctl,
                                   stop_on_expiry=True):
                    complete = False
                    break
            pos += SD_CHUNK
        self.stats["image_bytes"] = min(pos, size)
        if size > self.image_budget:
            complete = False
            self._limit(f"이미지가 {self.image_budget >> 20} MiB 를 넘어 앞부분만 문자열을 보았습니다.")
        if sum(state.counts.values()) > len(state.hits):
            complete = False
            self._limit("이미지 문자열 히트 상한을 넘어 일부 문자열을 분류하지 못했습니다 (관련 점검은 not-found 대신 unknown).")
        # 히트 분류도 시간 예산 안에서 (끝나면 남은 묶음은 분류하지 않고 단계를 잘림으로 — FIT 키 '없음' 도 주장하지 않는다)
        if not self._consume_hits(state.hits, source="image-strings", image=image_rel):
            complete = False
        if not complete and self.ctl.timed_out:
            self._limit("시간 예산 초과로 이미지 문자열을 일부만 보았습니다.")
        self._phase("image_strings", complete)
        if "fit_signature_keys" not in self.context["SD-02"]:
            self.context["SD-02"]["fit_signature_keys"] = False if complete else None
            self.context["SD-03"]["fit_signature_keys"] = self.context["SD-02"]["fit_signature_keys"]
        # 구조 관찰의 불완전성은 별도 coverage에만 남긴다. 기존 위험 phase·문자열 표지는 바꾸지 않는다.
        self.fit_security = scan_fit_security(buf, size, ctl=self.ctl, max_scan_bytes=self.image_budget)

    # -- 결과 -----------------------------------------------------------------
    def _status(self, cid: str, given: dict[str, bool]) -> tuple[str, str | None]:
        if self.ev[cid]:
            return "found", None
        if cid == "SD-07":
            return "unknown", "녹화 암호화는 정적으로 '없음'을 단정하지 않는다 (암호화 API·플래그 근거 없음)."
        missing = [n for n in CHECKS[cid]["needs"] if not given.get(n)]
        if missing:
            names = {"rootfs": "rootfs_dir(추출된 rootfs)", "image": "image_path(플래시 덤프·U-Boot 파티션)"}
            return "unknown", "입력 없음: " + ", ".join(names[m] for m in missing)
        partial = [p for p in PHASE_DEPS[cid] if self.phases.get(p) == "truncated" and ((p.startswith("rootfs") and given.get("rootfs")) or (p.startswith("image") and given.get("image")))]
        if partial:
            return "unknown", "시간·크기·줄 길이·히트 상한으로 일부만 검사: " + ", ".join(partial)
        if cid == "SD-03" and not self.env_found:
            return "unknown", "이미지에서 U-Boot env(CRC 유효·내장 기본)를 찾지 못했다 — U-Boot 파티션이 들어 있는 덤프인지 확인"
        if cid == "SD-04" and self.unclassified_handlers:
            return "unknown", f"핫플러그 규칙 {self.unclassified_handlers}개의 장치 패턴을 정적으로 분류하지 못했다 (hotplug_handlers 의 match_kind=unclassifiable)"
        if cid == "SD-08":
            visible = [mc for m in self.mounts.values() for mc in m["mount_commands"] if mc.get("options_visible") and not mc.get("readonly")]
            if not visible:
                return "unknown", "쓰기 가능한 SD 마운트의 옵션을 정적으로 보지 못함 (데몬이 mount(2) 로 마운트할 수 있음)"
        return "not-found", None

    def _evaluate_sd08(self) -> None:
        """발견된 SD 마운트 명령의 옵션 → SD-08 근거."""
        for m in self.mounts.values():
            for mc in m["mount_commands"]:
                if not mc.get("options_visible") or mc.get("readonly"):
                    continue
                opts = [o.lower() for o in mc["options"]]
                fs = (mc.get("fs") or "").lower()
                fat = fs in FAT_FS
                missing = [o for o in (("noexec",) if fat else ("noexec", "nosuid", "nodev")) if o not in opts]
                src = {k: v for k, v in mc.items() if k in ("file", "line", "image", "offset_hex")}
                source = "rootfs" if mc.get("file") else ("image-strings" if mc.get("image") else "rootfs")
                exc = mc.get("excerpt") or f"{m['path']} ({','.join(opts) or 'defaults'})"
                off = int(mc["offset_hex"], 16) if mc.get("offset_hex") else None
                common = {"source": source, "file": src.get("file"), "image": src.get("image"), "line": src.get("line"), "offset": off, "excerpt": exc,
                          "ctx": mc.get("source"), "sd_path": m["path"]}
                if missing:
                    self._add("SD-08", "weak-mount-options", "low", extra={"missing": missing, "options": ",".join(opts) or "defaults", "fs": mc.get("fs")}, **common)
                if any(re.fullmatch(r"(?:umask|fmask|dmask)=0{1,4}", o) for o in opts):
                    self._add("SD-08", "umask-zero", "low", extra={"options": ",".join(opts)}, **common)
                if "discard" in opts:
                    self._add("SD-08", "discard", "info", extra={"note": "discard: 지운 데이터를 SD ERASE 로 없앤다 (복구 가능성 낮음)"}, **common)

    def _sd02_adjust(self) -> dict[str, Any]:
        """물리 버튼·GPIO '읽기' 조건으로만 열리는 업데이트는, 같은 파일·위치에 원격 쓰기 경로가 보이지 않을 때만 심각도를 낮춘다."""
        evs = self.ev["SD-02"]
        info: dict[str, Any] = {"button_only": None, "remote_write_evident": None, "severity_adjusted": False}
        if not evs:
            return info
        update_like = [e for e in evs if e["rule"] in ("flash-write", "copy-then-flash", "trigger-flash", "env-update-from-card", "update-file", "uboot-auto-update", "fw_setenv-update")]
        gated = [e for e in update_like if e.get("gated_by")]
        button_only = bool(update_like) and len(gated) == len(update_like)
        remote: list[str] = []
        for e in self.ev["SD-09"]:
            if e.get("remote_write"):
                remote.append(f"SD-09 {e['rule']} ({e.get('file') or e.get('image')})")
        names = {e["sd_path"].rsplit("/", 1)[-1].lower() for e in evs if e.get("sd_path")}
        for nm in names:
            if nm in self.web_upload_names:
                remote.append(f"웹 파일 {self.web_upload_names[nm]} 이 같은 파일 이름({nm})을 참조")
        info["button_only"] = button_only
        info["remote_write_evident"] = bool(remote)
        info["remote_write_paths"] = remote[:8]
        if button_only and not remote:
            info["severity_adjusted"] = True
            for e in evs:
                if e["severity"] == "high":
                    e["severity"] = "medium"
                    e["severity_note"] = "물리 버튼·GPIO 읽기 조건에서만 실행되고 같은 파일·위치의 원격 쓰기 경로가 보이지 않아 한 단계 낮춤"
            info["reason"] = ("업데이트 근거가 모두 버튼·GPIO 읽기 조건(감싸는 if 조건 또는 같은 줄의 && 앞) 안에 있고, 카드의 네트워크 노출(SD-09)·웹 파일의 같은 파일 이름 참조가 없어 "
                              "한 단계 낮췄다. 바이너리(웹 서버) 안의 업로드 처리기는 보지 않았다 — REA 로 확인.")
        elif button_only and remote:
            info["reason"] = "버튼·GPIO 조건이지만 같은 파일·위치에 원격 쓰기 경로가 보여 높은 심각도를 유지한다."
        else:
            info["reason"] = ("업데이트 근거 중 버튼·GPIO 읽기 조건이 확인되지 않은 것이 있어 높은 심각도를 유지한다 "
                              "(GPIO 쓰기·LED 제어는 조건이 아니다. U-Boot 문자열 표지는 조건을 정적으로 알 수 없다 — UART 부팅 로그·REA 로 확인).")
        return info

    def result(self, *, rootfs_given: bool, image_given: bool) -> dict[str, Any]:
        given = {"rootfs": rootfs_given, "image": image_given}
        self._evaluate_sd08()
        self.context["SD-02"].update(self._sd02_adjust())
        # SD-07: 암호화 설정이 있지만 모두 꺼져 있으면(값 0/off/false) 보호가 기본으로 꺼진 것 → low
        e7 = self.ev["SD-07"]
        if e7 and any(e.get("enabled") is False for e in e7) and not any(e.get("enabled") is True for e in e7):
            for e in e7:
                if e.get("enabled") is False:
                    e["severity"] = "low"
                    e["note"] = "암호화 설정이 있지만 값이 꺼짐 — 기본으로 평문 녹화일 수 있다"
        if self.ev["SD-04"]:
            # 처리기가 카드를 쓰기 가능으로 마운트하면 low
            if any(mc.get("source") in ("mdev", "udev") or (mc.get("file") in self.hotplug_files) for m in self.mounts.values() for mc in m["mount_commands"] if not mc.get("readonly")):
                for e in self.ev["SD-04"]:
                    if e["rule"] in ("mdev-rule", "udev-rule", "hotplug-script"):
                        e["severity"] = "low"
        checks = []
        counts = {"found": 0, "not-found": 0, "unknown": 0}
        risk_found = []
        for cid in CHECK_IDS:
            meta = CHECKS[cid]
            status, reason = self._status(cid, given)
            evs = sorted(self.ev[cid], key=lambda e: (severity_key(e["severity"]), RULE_RANK.get(e["rule"], 50), e.get("file") or e.get("image") or "", e.get("line") or 0))
            if status == "found":
                sev = min((e["severity"] for e in evs), key=severity_key)
                basis = "evidence"
            else:
                sev = meta["baseline"]
                basis = "baseline"
            steps = list(meta["next_steps"])
            if status == "unknown" and reason and reason.startswith("입력 없음"):
                if "rootfs" in reason:
                    steps.insert(0, "rootfs_dir(추출된 rootfs, fw_extract_squashfs 의 output_dir)를 주고 다시 실행")
                if "image" in reason:
                    steps.insert(0, "image_path(플래시 덤프 또는 fw_carve 의 U-Boot·env 파티션)를 주고 다시 실행")
            c = {
                "id": cid, "title": meta["title"], "status": status, "severity_hint": sev, "severity_basis": basis, "category": meta["category"],
                "found_means": meta["found_means"], "evidence_total": self.ev_total[cid], "evidence": evs[: self.max_evidence],
                "rationale": meta["rationale"], "references": list(meta["references"]), "examples": list(meta["examples"]), "next_steps": steps,
            }
            if reason:
                c["unknown_reason"] = reason
            ctx = {k: v for k, v in self.context[cid].items() if v is not None}
            if ctx:
                c["context"] = ctx
            checks.append(c)
            counts[status] += 1
            if status == "found" and meta["found_means"] == "risk":
                risk_found.append(cid)
        mps = []
        for m in sorted(self.mounts.values(), key=lambda x: x["path"]):
            mps.append({k: m[k] for k in ("path", "sources", "fs", "devices", "builtin_pattern", "present_in_image")} | {"mount_commands": m["mount_commands"][:6]})
        refs = sorted(self.sd_paths.values(), key=lambda r: (0 if r["checks"] else 1, r["path"]))
        return {
            "checks": checks,
            "counts": counts,
            "risk_found": risk_found,
            "mount_points": mps,
            "builtin_sd_patterns": BUILTIN_SD_PATTERNS,
            "other_mmc_mounts": self.other_mmc_mounts,
            "hotplug_handlers": self.handlers[:200],
            "sd_paths_referenced": refs[:MAX_SD_PATHS],
            "sd_paths_total": len(self.sd_paths),
            "sd_paths_truncated": self.sd_paths_truncated,
            "inputs_analyzed": given,
            "phases": dict(self.phases),
            "stats": {**self.stats, "skipped_large": self.stats["skipped_large"][:20]},
            "limitations": list(self.limitations),
            "fit_security": self.fit_security,
        }


def compact_result(res: dict[str, Any], max_results: int) -> dict[str, Any]:
    """근거 앞 3개·마운트와 sd_paths만 축약한다. 별도 64 KiB 상한의 FIT metadata는 전부 보존한다."""
    n = max(0, int(max_results))
    checks = []
    for c in res["checks"]:
        cc = {k: c[k] for k in ("id", "title", "status", "severity_hint", "category", "found_means", "evidence_total")}
        cc["evidence"] = [{k: e[k] for k in ("source", "file", "image", "line", "offset_hex", "rule", "severity", "sd_path", "excerpt") if k in e} for e in c["evidence"][:3]]
        if c.get("unknown_reason"):
            cc["unknown_reason"] = c["unknown_reason"]
        if c["status"] != "not-found":
            cc["next_steps"] = c["next_steps"][:2]
        if c["id"] == "SD-02" and c.get("context", {}).get("reason") and c["status"] == "found":
            cc["severity_reason"] = c["context"]["reason"]
        checks.append(cc)
    mps = [{"path": m["path"], "sources": sorted({s.get("source") for s in m["sources"] if s.get("source")}), "fs": m["fs"], "present_in_image": m["present_in_image"]} for m in res["mount_points"][:n]]
    refs = [{k: r[k] for k in ("path", "card_relative", "actions", "checks")} for r in res["sd_paths_referenced"][:n]]
    return {
        "counts": res["counts"],
        "risk_found": res["risk_found"],
        "checks": checks,
        "mount_points": mps,
        "mount_points_total": len(res["mount_points"]),
        "sd_paths_referenced": refs,
        "sd_paths_total": res["sd_paths_total"],
        "sd_paths_truncated": res.get("sd_paths_truncated", False),
        "truncated": len(res["mount_points"]) > n or res["sd_paths_total"] > n,
        "limitations": res["limitations"][:10],
        "fit_security": res["fit_security"],
    }
