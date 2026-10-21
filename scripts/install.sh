#!/usr/bin/env bash
# PWEH 원클릭 설치: Python 환경 + 외부 도구 + REA 를 sudo 없이 한 번에 설치하고,
# 에이전트 클라이언트(Claude Code·Codex)에 MCP 서버와 Skill 을 연결한 뒤 점검한다.
#
#   ./scripts/install.sh                  # 전체 설치 + MCP 등록·Skill 링크·점검 (권장)
#   ./scripts/install.sh --minimal        # Python + sigrok + OpenOCD + squashfs/u-boot 도구만 (아래 단계는 하지 않음)
#   ./scripts/install.sh --only ghidra,jdk
#   ./scripts/install.sh --only qemu_esp,simavr   # 펌웨어 에뮬레이션(pweh-emu)의 선택 구성요소만: Espressif QEMU + simavr/pweh_avr_run
#   ./scripts/install.sh --only tesseract,zbar   # 정지 이미지 OCR(eng/kor)·QR, 검증된 배포판 잠금 자료만 사용
#   ./scripts/install.sh --skip rea,binwalk
#   ./scripts/install.sh --only mcp,skills,verify   # 도구는 다시 설치하지 않고 MCP 등록·Skill 링크·점검만
#   ./scripts/install.sh --dry-run        # 아무것도 바꾸지 않고 MCP 등록·Codex 신뢰가 바꿀 내용(diff)만 보여 줌
#   ./scripts/install.sh --check          # 설치·등록 상태만 점검 (아무것도 설치하거나 바꾸지 않음)
#   ./scripts/install.sh --list           # 구성요소·단계 목록
#
# 옵션
#   --prefix DIR   외부 도구 설치 위치 (기본: $PWEH_TOOLS_DIR 또는 ~/pweh-tools)
#   --cache DIR    내려받은 파일 캐시 (기본: <prefix>/_downloads)
#   --seed DIR     해시가 고정된 파일(압축 파일·휠·.deb)을 먼저 찾을 디렉터리 (그런 파일을 가리키는 심볼릭 링크도 쓴다). 이름과 해시가 맞을 때만 쓴다.
#                  pip·npm·cargo 의존성은 여전히 네트워크에서 받는다 (완전한 오프라인 설치는 아님).
#                  git 커밋으로 고정한 소스(erofs, simavr)는 seed 로 대신할 수 없다 (git 으로 받는다)
#   --venv DIR     pweh Python 가상환경 (기본: <저장소>/.venv). 아래 단계는 이 가상환경의 pweh 만 쓴다
#   --force        이미 설치된 구성요소도 다시 설치
#   --no-link      기본 위치가 아닐 때 저장소에 .pweh/tools-env.path 를 남기지 않음 (시험·CI 용)
#   --jobs N       빌드 병렬 수 (기본: CPU 수)
#
# 단계: 구성요소와 env.sh 다음에 이 순서로 돈다. 구성요소처럼 --only/--skip 으로 고른다 (--minimal 에는 없음)
#   mcp     Claude Code: 저장소의 .mcp.json 과 .claude/settings.json 의 enabledMcpjsonServers 를 확인만 한다 (~/.claude* 는 건드리지 않음).
#           Codex: `pweh mcp-config --client codex --write` 로 프로젝트 설정 <저장소>/.codex/config.toml (git 제외 생성물)을 만든다.
#           Codex 는 신뢰한 프로젝트의 설정만 읽는다. 감지한 Codex 홈($CODEX_HOME 또는 ~/.codex, WSL 모드 Codex 데스크톱 앱의
#           Windows 홈)에 이 저장소의 신뢰 항목([projects."<저장소>"] trust_level = "trusted")이 없으면, 바뀔 내용을 보여 주고
#           대화형 터미널에서 묻는다 (동의하면 `pweh codex-trust --yes`). 대화형이 아니면 묻지도 바꾸지도 않는다.
#           Cursor 는 --cursor 일 때만 <저장소>/.cursor/mcp.json (있으면 PWEH 항목만 바꿈).
#   skills  `pweh skills install --target claude-project` 와 `--target agents` (.claude/skills·.agents/skills 링크. 다시 해도 같음)
#   verify  `pweh doctor` + `pweh mcp-check --client all` (서버마다 initialize + tools/list 만 하고 도구는 부르지 않음)
#
# 단계 옵션
#   --no-mcp          mcp 단계를 건너뜀 (--skip mcp 와 같음). --no-verify 는 verify 단계를 건너뜀
#   --dry-run         구성요소·skills·verify 는 하지 않고 mcp 단계(Codex 설정·신뢰, --cursor)가 바꿀 내용만 diff 로 보여 줌
#   --codex-trust     묻지 않고 Codex 신뢰 항목을 더함 (그렇게 하겠다는 동의. `pweh codex-trust --yes`)
#   --no-codex-trust  Codex 신뢰 단계를 건너뜀 (--check 에서는 신뢰 점검을 끔)
#   --codex-global    프로젝트 설정 대신 Codex 홈의 config.toml 에 직접 등록 (`--scope global`, 바꾸기 전에 백업. 신뢰는 필요 없음)
#   --codex-home DIR  Codex 홈을 직접 지정 (여러 번 가능. pweh mcp-config·pweh codex-trust 에 그대로 넘김. 기본: 위의 자동 감지)
#   --cursor          Cursor 프로젝트 설정도 만듦
#
# 원칙
# - root/sudo 를 쓰지 않고, 시스템 디렉터리·셸 rc 파일을 바꾸지 않는다. 설치물은 <prefix> 와 가상환경 아래에만 둔다.
#   (예외: 시스템 cargo 를 쓰면 ~/.cargo 레지스트리 캐시, Ghidra 를 처음 실행하면 ~/.config/ghidra,
#    동의했을 때 Codex 홈의 config.toml — 바꾸기 전에 config.toml.bak-pweh-<UTC 시각> 으로 백업한다)
# - 사용자 설정은 동의 없이 바꾸지 않는다: Codex 신뢰는 대화형 확인이나 --codex-trust, Codex 홈 등록은 --codex-global 일 때만.
#   끝에 MCP·신뢰·skills 단계가 쓰거나 백업한 파일과 되돌리는 방법을 보여 준다 (되돌리기 명령은 보여 주기만 한다).
# - 스크립트가 직접 받는 파일(압축 파일, pip·unblob 휠, esptool 소스 배포판, rustup-init, sasquatch .deb)은 고정된 sha256 으로,
#   배포판 패키지는 apt 의 서명된 색인에 있는 해시로 검증한다. pip·npm 이 받는 의존성은 최상위 버전만 고정하고
#   해시는 고정하지 않으며 (npm 패키지의 설치 스크립트가 실행되고, esptool 소스 배포판을 빌드하는 setuptools 도 PyPI 에서 받음),
#   binwalk 의존성은 Cargo.lock(--locked) 의 체크섬으로 검증된다.
# - 압축 해제 전에 절대 경로, '..', 밖을 가리키는 링크, 장치 파일을 거부한다. 배포판 패키지의 설치 스크립트는 실행하지 않는다.
# - 이미 설치된 구성요소는 건너뛴다. 선택 구성요소(erofs, binwalk, rea, esptool, qemu_esp, simavr, tesseract, zbar)가 실패해도 나머지는 계속한다.
# - 이미지 OCR·QR의 .deb와 언어 모델은 scripts/image-tools-lock.json의 SHA256으로 고정한다.
#   지원 잠금 자료는 Ubuntu 22.04 x86_64이며 다른 환경을 임의 apt 버전으로 대체하지 않는다.
# - 펌웨어 에뮬레이션(pweh-emu) 구성요소는 선택이고 --minimal 에 없다:
#   qemu_esp  Espressif QEMU 릴리스 tar.xz 두 개(sha256 고정)를 <prefix>/qemu-esp/{xtensa,riscv32} 에 푼다 (bin/·share/qemu 함께).
#             공유 라이브러리가 없으면 개인 경로에 받지 않고, 빠진 라이브러리와 관리자용 배포판 패키지 목록을 알린다.
#   simavr    simavr 를 git 커밋으로 고정해 라이브러리만 빌드하고 PWEH 실행기 native/emu/pweh_avr_run.c 를 정적 링크한다
#             (C 컴파일러 또는 PWEH zig. run_avr 는 설치하지 않는다). 결과 실행 파일은 GPL-3.0 결합물이다 (배포하지 않음).
#   두 구성요소의 실행 파일은 PATH 에 넣지 않고 env.sh 의 PWEH_QEMU_XTENSA·PWEH_QEMU_RISCV32·PWEH_AVR_RUN(절대 경로)으로만 알린다.
# - 종료 코드: 필수 구성요소나 mcp·skills·verify 단계가 실패하면 1. 신뢰를 거절했거나 묻지 않은 것은 실패가 아니고,
#   REA(선택 구성요소)가 설치되지 않았을 때 rea 서버만 뜨지 않는 것도 경고로만 본다 (`pweh mcp-check --optional rea` — 다른 서버의 실패는 실패).
# - `rea setup` 은 실행하지 않는다 (다른 에이전트 클라이언트의 설정을 바꾼다).
# - 지원: Linux x86_64. 배포판 패키지(sigrok, squashfs, u-boot, 압축 해제 도구)는 Debian/Ubuntu(apt)에서만.
#   esptool 의 Windows 판(방법 A: WSL 에서 interop 으로 esptool.exe 를 실행해 Windows COM 포트를 씀)은 WSL interop 이 켜져 있을 때만 받는다.

set -Eeuo pipefail
umask 022
unset CDPATH   # cd 가 경로를 stdout 에 찍어 $(cd …; pwd) 결과가 두 줄이 되는 것을 막는다

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# 고정 버전과 체크섬 (docs/mcp-setup.md §1 과 맞춘다)
# ---------------------------------------------------------------------------
OPENOCD_VER=0.12.0-7
OPENOCD_URL="https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v${OPENOCD_VER}/xpack-openocd-${OPENOCD_VER}-linux-x64.tar.gz"
OPENOCD_SHA=94b3790983beaf8ed57e646c0620dd66d705fddae03d290823a6ed3b439468d6
ZIG_VER=0.17.0
ZIG_URL="https://ziglang.org/download/${ZIG_VER}/zig-x86_64-linux-${ZIG_VER}.tar.xz"
ZIG_SHA=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
JDK_DIR_NAME="jdk-21.0.12.1+1"
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
JDK_SHA=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
GHIDRA_VER=12.1.4
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_20260921.zip"
GHIDRA_SHA=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
SASQUATCH_URL="https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_amd64.deb"
SASQUATCH_SHA=efbc92bd27594e01211e1b582f105a463a0017360a0746a93de3f283906ade95
UNBLOB_VER=26.6.4
UNBLOB_WHL="unblob-${UNBLOB_VER}-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
UNBLOB_URL="https://files.pythonhosted.org/packages/33/c0/1a794c156f0f4dc88542357850decd0854e65dadd7f63da85fba5ad37dbe/${UNBLOB_WHL}"
UNBLOB_SHA=0fc16e9c7dc92fcf86b8b61475700c9dd16e1dddacf34467574ea965a5d3584e
BINWALK_VER=3.1.0
EROFS_TAG=v1.9.4
EROFS_COMMIT=f36cadb5c563995ab3aa8572a60ed6b721b9557d   # v1.9.4^{}
EROFS_GIT="https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"
REA_VER=6.5.0
NODE_VER=22.21.0
NODE_URL="https://nodejs.org/dist/v${NODE_VER}/node-v${NODE_VER}-linux-x64.tar.xz"
NODE_SHA=71a04f4b9144870c9407b8019fe912514229e50246bc706862eded3ac8e9025d
RUSTUP_VER=1.29.1
RUSTUP_URL="https://static.rust-lang.org/rustup/archive/${RUSTUP_VER}/x86_64-unknown-linux-gnu/rustup-init"
RUSTUP_SHA=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
RUST_TOOLCHAIN=1.98.0   # 시스템 cargo 가 없을 때 binwalk 를 빌드하는 개인 툴체인
PIP_VER=26.2.1          # 모든 가상환경의 pip (ensurepip·get-pip.py 대신 해시가 고정된 휠로 설치)
PIP_URL="https://files.pythonhosted.org/packages/f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/pip-${PIP_VER}-py3-none-any.whl"
PIP_SHA=71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e
ESPTOOL_VER=5.4.0
ESPTOOL_SDIST="esptool-${ESPTOOL_VER}.tar.gz"   # PyPI 에는 esptool 5.x 휠이 없고 소스 배포판만 있다 (순수 Python, setuptools 로 빌드)
ESPTOOL_URL="https://files.pythonhosted.org/packages/2c/43/1a2ae2dd8ae97bf1ec9991db097e52626d35b57d242f9687c9314eac5b57/${ESPTOOL_SDIST}"
ESPTOOL_SHA=fd756598db0a26c9975fa18511b08687c54bf2ce7322ede80cf1f5117dad1f50
ESPTOOL_WIN_ZIP="esptool-v${ESPTOOL_VER}-windows-amd64.zip"   # 방법 A: 공식 Windows 빌드 (의존성을 담은 단일 실행 파일들)
ESPTOOL_WIN_URL="https://github.com/espressif/esptool/releases/download/v${ESPTOOL_VER}/${ESPTOOL_WIN_ZIP}"
ESPTOOL_WIN_SHA=b7f6b9dd301a210b31f4829118c909c84aae23107f9ca1fdc14ccf4d7384be2e
# 펌웨어 에뮬레이션 (pweh-emu): Espressif QEMU 릴리스 asset 만 고정한다 (브랜치 esp-develop 는 강제 push 됨).
# pweh-emu 는 이 정확한 버전 문자열만 받는다 — 바꾸면 서버의 고정값·샌드박스 검토도 함께 바꿔야 한다.
QEMU_ESP_TAG=esp-develop-9.2.2-20260417
QEMU_ESP_VER=esp_develop_9.2.2_20260417
QEMU_XTENSA_URL="https://github.com/espressif/qemu/releases/download/${QEMU_ESP_TAG}/qemu-xtensa-softmmu-${QEMU_ESP_VER}-x86_64-linux-gnu.tar.xz"
QEMU_XTENSA_SHA=0eecb2a34a5586c0e59110f77b9343b7b336e82fdb0e1a30e1dc1bab8a547e35    # 15 619 396 B
QEMU_RISCV32_URL="https://github.com/espressif/qemu/releases/download/${QEMU_ESP_TAG}/qemu-riscv32-softmmu-${QEMU_ESP_VER}-x86_64-linux-gnu.tar.xz"
QEMU_RISCV32_SHA=547f03e04701a92cbb699f7f7d015adc1f5b5ef93cbb94c0dd9b7107e2d84e77   # 16 842 920 B
# simavr: 릴리스 asset 이 없어 커밋으로 고정한다 (erofs 처럼 rev-parse 로 확인). v1.8 에는 전체 플래시 이미지의 마지막 바이트
# 잘림(#589)·UART stdio 1바이트 힙 넘침(#588) 수정이 없다. git 소스라 --seed 로 대신할 수 없다.
SIMAVR_GIT="https://github.com/buserror/simavr.git"
SIMAVR_COMMIT=5b08da60497f7564f50941f74a549fe2851db030

ALL_COMPONENTS="python sigrok openocd squashfs uboot zig jdk ghidra unblob extractors erofs binwalk rea esptool qemu_esp simavr tesseract zbar"
MINIMAL_COMPONENTS="python sigrok openocd squashfs uboot"
OPTIONAL_COMPONENTS="erofs binwalk rea esptool qemu_esp simavr tesseract zbar"   # 실패해도 설치 전체를 실패로 보지 않는다 (경고만)
SKIP_RC=99   # install_* 가 이 값으로 끝나면 "건너뜀" (빌드 도구 같은 전제 조건이 없음). 실패로 세지 않는다

declare -A DESC=(
  [python]="pweh Python 가상환경 (.venv, pip install -e .[dev])"
  [sigrok]="sigrok-cli 0.7.2 + libsigrok/libsigrokdecode (배포판 패키지, 로직 애널라이저)"
  [openocd]="xPack OpenOCD ${OPENOCD_VER} + 하드웨어 없는 openocd-dummy (JTAG/SWD)"
  [squashfs]="squashfs-tools (mksquashfs/unsquashfs, 배포판 패키지)"
  [uboot]="u-boot-tools (mkimage/mkenvimage/dumpimage, 배포판 패키지)"
  [zig]="Zig ${ZIG_VER} (시뮬레이터 합성 펌웨어 빌드)"
  [jdk]="Eclipse Temurin JDK 21 (Ghidra 실행)"
  [ghidra]="Ghidra ${GHIDRA_VER} (REA 디컴파일 엔진)"
  [unblob]="unblob ${UNBLOB_VER} (REA 펌웨어 추출)"
  [extractors]="unblob 외부 압축 해제 도구 (7z, lz4, lzop, zstd, sasquatch, unar, simg2img …)"
  [erofs]="erofs-utils ${EROFS_TAG} 소스 빌드 (EROFS 추출, 선택)"
  [binwalk]="binwalk ${BINWALK_VER} (cargo 빌드, REA 영역 식별, 선택)"
  [rea]="REA rea-agents ${REA_VER} (npm, Ghidra 연동 MCP 서버, 선택)"
  [esptool]="esptool ${ESPTOOL_VER} (ESP32 계열 칩·보안 정보, 플래시 읽기) + WSL 이면 Windows esptool.exe (방법 A: interop 으로 COM 포트, 선택)"
  [qemu_esp]="Espressif QEMU 9.2.2 (${QEMU_ESP_VER}) — qemu-system-xtensa(ESP32·S3)·qemu-system-riscv32(C3), 펌웨어 에뮬레이션 (선택)"
  [simavr]="simavr(커밋 ${SIMAVR_COMMIT:0:12}) + PWEH AVR 실행기 pweh_avr_run 소스 빌드 (Arduino AVR 에뮬레이션, C 컴파일러 또는 PWEH zig, 선택)"
  [tesseract]="Tesseract + eng/kor/osd 언어 데이터 (SHA256 고정 .deb, Ubuntu 22.04 x86_64, 선택)"
  [zbar]="ZBar zbarimg (SHA256 고정 .deb, Ubuntu 22.04 x86_64, 정규화 이미지 QR·바코드, 선택)"
)
# 구성요소와 env.sh 다음에 이 순서로 도는 단계. 구성요소처럼 --only/--skip 으로 고르고, --minimal 에는 넣지 않는다
STEPS="mcp skills verify"
declare -A STEP_DESC=(
  [mcp]="MCP 서버 등록: Claude Code 확인(.mcp.json·enabledMcpjsonServers), Codex 프로젝트 설정 + 신뢰(동의할 때만), --cursor 면 Cursor"
  [skills]="Skill 링크: .claude/skills(Claude Code), .agents/skills(Codex·Cursor) — pweh skills install"
  [verify]="점검: pweh doctor + pweh mcp-check (서버마다 initialize + tools/list, 도구는 부르지 않음)"
)

# ---------------------------------------------------------------------------
# 인자
# ---------------------------------------------------------------------------
# 기본 위치는 src/pweh/toolsdir.py 의 tools_dir() 와 같은 순서:
#   PWEH_TOOLS_DIR → PWEH_TOOLS_ENV 의 디렉터리 → 저장소 포인터(가리키는 env.sh 가 있을 때) → ~/pweh-tools
POINTER="$REPO/.pweh/tools-env.path"
pointer_prefix() { local p; [ -f "$POINTER" ] && p="$(head -n 1 "$POINTER")" && [ -f "$p" ] && dirname "$p"; }
if [ -n "${PWEH_TOOLS_DIR:-}" ]; then PREFIX="$PWEH_TOOLS_DIR"
elif [ -n "${PWEH_TOOLS_ENV:-}" ]; then PREFIX="$(dirname "$PWEH_TOOLS_ENV")"
else PREFIX="$(pointer_prefix || echo "$HOME/pweh-tools")"; fi
CACHE=""
SEED=""
VENV="$REPO/.venv"
FORCE=0
LINK=1
MODE=install
ONLY=""
SKIP=""
JOBS="$(nproc 2>/dev/null || echo 4)"
DRYRUN=0            # --dry-run: 구성요소·skills·verify 는 하지 않고 mcp 단계가 바꿀 내용만 보여 준다
NO_MCP=0
NO_VERIFY=0
TRUST=ask           # Codex 신뢰 — ask: 대화형 터미널에서만 묻는다, yes: --codex-trust (동의), no: --no-codex-trust
CODEX_SCOPE=project # project: <저장소>/.codex/config.toml, global: Codex 홈의 config.toml (--codex-global)
CODEX_HOMES=()      # --codex-home (여러 번): pweh mcp-config·pweh codex-trust 에 그대로 넘긴다. 없으면 pweh 가 자동 감지
CURSOR=0

usage() { sed -n '2,/^$/{s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"; }   # 맨 위 주석 블록
need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 에 값이 필요합니다 (--help 참고)" >&2; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix|--cache|--seed|--venv|--only|--skip|--jobs|--codex-home) need_arg "$@" ;;
  esac
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --cache) CACHE="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --venv) VENV="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    --minimal) ONLY="${MINIMAL_COMPONENTS// /,}"; shift ;;
    --force) FORCE=1; shift ;;
    --no-link) LINK=0; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --check) MODE=check; shift ;;
    --list) MODE=list; shift ;;
    --dry-run) DRYRUN=1; shift ;;
    --no-mcp) NO_MCP=1; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    --codex-trust|--no-codex-trust)
      want=yes; [ "$1" = --codex-trust ] || want=no
      if [ "$TRUST" != ask ] && [ "$TRUST" != "$want" ]; then echo "--codex-trust 와 --no-codex-trust 는 함께 쓸 수 없습니다" >&2; exit 2; fi
      TRUST=$want; shift ;;
    --codex-global) CODEX_SCOPE=global; shift ;;
    --codex-home)
      case "$2" in -*) echo "--codex-home 에 디렉터리가 필요합니다 (받은 값: $2 — 다른 옵션처럼 보임)" >&2; exit 2 ;; esac
      case "$2" in /*) CODEX_HOMES+=("$2") ;; *) CODEX_HOMES+=("$PWD/$2") ;; esac; shift 2 ;;
    --cursor) CURSOR=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "알 수 없는 옵션: $1 (--help 참고)" >&2; exit 2 ;;
  esac
done

# 선택한 구성요소·단계
selected() {
  local c=$1
  if [ -n "$ONLY" ]; then case ",$ONLY," in *",$c,"*) ;; *) return 1 ;; esac; fi
  case ",$SKIP," in *",$c,"*) return 1 ;; esac
  if [ "$c" = mcp ] && [ "$NO_MCP" = 1 ]; then return 1; fi
  if [ "$c" = verify ] && [ "$NO_VERIFY" = 1 ]; then return 1; fi
  return 0
}
for c in ${ONLY//,/ } ${SKIP//,/ }; do
  case " $ALL_COMPONENTS $STEPS " in *" $c "*) ;; *) echo "알 수 없는 구성요소·단계: $c (--list 참고)" >&2; exit 2 ;; esac
done
if [ "$MODE" = list ]; then
  for c in $ALL_COMPONENTS; do
    tag=""; case " $MINIMAL_COMPONENTS " in *" $c "*) tag=" [minimal]" ;; esac
    case " $OPTIONAL_COMPONENTS " in *" $c "*) tag="$tag [선택]" ;; esac
    printf '  %-11s %s%s\n' "$c" "${DESC[$c]}" "$tag"
  done
  for c in $STEPS; do printf '  %-11s %s [단계]\n' "$c" "${STEP_DESC[$c]}"; done
  exit 0
fi
COMP_SELECTED=0   # 구성요소를 하나라도 골랐는가 (아니면 단계만 돈다: 도구를 다시 설치하지 않고 env.sh 도 그대로)
for c in $ALL_COMPONENTS; do if selected "$c"; then COMP_SELECTED=1; break; fi; done
# <prefix> 를 만들고 쓰는 것은 구성요소를 실제로 설치할 때뿐이다 (--check·--dry-run·단계만 고른 실행은 만들지 않음)
INSTALL_TOOLS=0
if [ "$MODE" = install ] && [ "$DRYRUN" = 0 ] && [ "$COMP_SELECTED" = 1 ]; then INSTALL_TOOLS=1; fi

# 래퍼·env.sh 는 경로를 따옴표 안에 그대로 넣는다: 따옴표·$·백슬래시·줄바꿈이 든 경로는 받지 않는다 (디렉터리를 만들기 전에)
check_prefix_chars() {
  case "$PREFIX" in *[\'\"\$\`\\]*|*$'\n'*) echo "--prefix 경로에 ' \" \$ \` \\ 나 줄바꿈을 쓸 수 없습니다: $PREFIX" >&2; exit 2 ;; esac
}
check_prefix_chars
if [ "$INSTALL_TOOLS" = 0 ]; then   # --check·--dry-run·단계만 고른 실행은 <prefix> 에 아무것도 만들지 않는다
  PREFIX="$(cd "$PREFIX" 2>/dev/null && pwd || echo "$PREFIX")"
  CACHE="${CACHE:-$PREFIX/_downloads}"
  LOG=/dev/null
  # 단계만 고른 설치는 이미 있는 pweh-tools 의 로그 디렉터리에만 로그를 남긴다
  if [ "$MODE" = install ] && [ "$DRYRUN" = 0 ] && [ -d "$PREFIX/_logs" ] && [ -w "$PREFIX/_logs" ]; then
    LOG="$PREFIX/_logs/install-$(date +%Y%m%d-%H%M%S).log"
  fi
else
  # 설치는 $PREFIX/node, $PREFIX/bin/* 등을 지우고 덮어쓴다: 다른 용도의 기존 디렉터리(예: --prefix ~)는 받지 않는다
  if [ -d "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ] && [ ! -e "$PREFIX/.state" ] && [ ! -e "$PREFIX/env.sh" ] && [ ! -e "$PREFIX/_downloads" ]; then
    echo "$PREFIX 는 비어 있지 않고 pweh-tools 디렉터리로 보이지 않습니다 (--prefix 확인)" >&2; exit 2
  fi
  PREFIX="$(mkdir -p "$PREFIX" && cd "$PREFIX" && pwd)"
  CACHE="${CACHE:-$PREFIX/_downloads}"
  mkdir -p "$CACHE" "$PREFIX/bin" "$PREFIX/_logs" "$PREFIX/_build" "$PREFIX/.state"
  CACHE="$(cd "$CACHE" && pwd)"
  LOG="$PREFIX/_logs/install-$(date +%Y%m%d-%H%M%S).log"
fi
check_prefix_chars   # 심볼릭 링크를 풀어 바뀐 실제 경로도 확인
case "$VENV" in /*) ;; *) VENV="$PWD/$VENV" ;; esac
if [ -n "$SEED" ]; then SEED="$(cd "$SEED" && pwd)"; fi
export PIP_CACHE_DIR="$PREFIX/_cache/pip" PIP_DISABLE_PIP_VERSION_CHECK=1
export npm_config_cache="$PREFIX/_cache/npm" npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false

exec 3>&1
: >"$LOG"
say()  { printf '%s\n' "$*" >&3; printf '%s\n' "$*" >>"$LOG"; }
info() { say "    $*"; }
warn() { say "  ! $*"; }



# ---------------------------------------------------------------------------
# 플랫폼
# ---------------------------------------------------------------------------
ARCH_OK=1
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then ARCH_OK=0; fi
HAVE_APT=0
if command -v apt-get >/dev/null && command -v apt-cache >/dev/null && command -v dpkg-deb >/dev/null && command -v dpkg-query >/dev/null; then HAVE_APT=1; fi
LIBDIR=x86_64-linux-gnu

find_python() {  # Python >= 3.10
  local p
  for p in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$p" >/dev/null && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      command -v "$p"; return 0
    fi
  done
  return 1
}
PY="$(find_python || true)"

# ---------------------------------------------------------------------------
# 내려받기·검증·해제
# ---------------------------------------------------------------------------
hash_ok() {  # hash_ok <file> <hex> [sha256|sha512]
  local f=$1 want=$2 algo=${3:-sha256} got
  got="$("${algo}sum" "$f" | cut -d' ' -f1)"
  [ "$got" = "$want" ]
}

fetch() {  # fetch <url> <dest> [hex] [sha256|sha512]  — 캐시·seed 재사용, 받은 뒤 해시 검증
  local url=$1 dest=$2 want=${3:-} algo=${4:-sha256} cand
  if [ -f "$dest" ] && { [ -z "$want" ] || hash_ok "$dest" "$want" "$algo"; }; then return 0; fi
  mkdir -p "$(dirname "$dest")"
  if [ -n "$SEED" ] && [ -n "$want" ]; then
    while IFS= read -r cand; do
      # 복사본을 검증한다 (검사 뒤 바뀐 seed·복사 실패를 성공으로 보지 않음)
      if cp "$cand" "$dest.part" 2>/dev/null && hash_ok "$dest.part" "$want" "$algo"; then mv -f "$dest.part" "$dest"; return 0; fi
      rm -f "$dest.part"
    done < <(find "$SEED" -name "$(basename "$dest")" \( -type f -o -xtype f \) 2>/dev/null)   # 일반 파일을 가리키는 링크도 (링크한 디렉터리 안으로는 들어가지 않음)
  fi
  info "내려받기: $url"
  if command -v curl >/dev/null; then
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 30 -o "$dest.part" "$url" || { rm -f "$dest.part"; echo "내려받기 실패: $url" >&2; return 1; }
  else
    wget -q -O "$dest.part" "$url" || { rm -f "$dest.part"; echo "내려받기 실패: $url" >&2; return 1; }
  fi
  if [ -n "$want" ] && ! hash_ok "$dest.part" "$want" "$algo"; then
    rm -f "$dest.part"; echo "체크섬 불일치: $url" >&2; return 1
  fi
  mv -f "$dest.part" "$dest"
}

SAFE_EXTRACT="$PREFIX/_build/safe_extract.py"
[ "$INSTALL_TOOLS" = 0 ] || cat >"$SAFE_EXTRACT" <<'PY'
"""압축 파일 안전 확인·해제: 절대 경로, '..', 밖을 가리키는 링크, 링크를 거쳐 가는 경로, 장치 파일이 있으면 거부한다."""
import os, posixpath, stat, sys, tarfile, zipfile

def bad(name):
    n = name.replace("\\", "/")
    return n.startswith("/") or any(p == ".." for p in n.split("/"))

def inside(dest, path):
    path = os.path.realpath(path)
    return path == dest or path.startswith(dest + os.sep)

def norm(name):
    return posixpath.normpath(name.replace("\\", "/")).lstrip("/")

def via_link(path, links):  # path 의 상위 경로 중에 아카이브 안 심볼릭 링크가 있는가 (링크 사슬 차단)
    parts = path.split("/")
    return any("/".join(parts[:k]) in links for k in range(1, len(parts)))

def link_escapes(name, target, links):  # 링크 위치에서 target 을 글자 그대로 따라갈 때 밖으로 나가거나 다른 링크를 거치는가
    if target.startswith("/"):
        return True
    cur = [p for p in posixpath.dirname(norm(name)).split("/") if p]
    comps = [p for p in target.split("/") if p not in ("", ".")]
    for k, p in enumerate(comps):
        if p == "..":
            if not cur:
                return True
            cur.pop()
        else:
            cur.append(p)
            if k < len(comps) - 1 and "/".join(cur) in links:
                return True
    return False

def main(archive, dest, mode):
    dest = os.path.realpath(dest)
    os.makedirs(dest, exist_ok=True)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            for i in infos:
                if bad(i.filename):
                    sys.exit(f"위험한 경로: {i.filename}")
                if stat.S_ISLNK(i.external_attr >> 16):  # unzip 과 아래 해제 코드 모두 링크 사슬을 막지 못하므로 받지 않는다
                    sys.exit(f"zip 안의 심볼릭 링크는 받지 않습니다: {i.filename}")
            if mode == "check":
                return
            for i in infos:
                target = os.path.join(dest, i.filename)
                st = i.external_attr >> 16
                z.extract(i, dest)
                if not i.is_dir() and st & 0o777:
                    os.chmod(target, st & 0o777)
    else:
        with tarfile.open(archive) as t:
            members = t.getmembers()
            links = {norm(m.name) for m in members if m.issym()}
            for m in members:
                if bad(m.name):
                    sys.exit(f"위험한 경로: {m.name}")
                if m.isdev() or m.isfifo():
                    sys.exit(f"장치/FIFO 파일: {m.name}")
                if via_link(norm(m.name), links):
                    sys.exit(f"링크를 거쳐 가는 경로: {m.name}")
                if m.issym() and (link_escapes(m.name, m.linkname, links) or not inside(dest, os.path.join(dest, os.path.dirname(m.name), m.linkname))):
                    sys.exit(f"밖을 가리키는 링크: {m.name} -> {m.linkname}")
                if m.islnk() and (bad(m.linkname) or via_link(norm(m.linkname), links) or norm(m.linkname) in links
                                  or not inside(dest, os.path.join(dest, m.linkname))):
                    sys.exit(f"밖을 가리키는 하드 링크: {m.name} -> {m.linkname}")
            if mode == "check":
                return
            try:
                t.extractall(dest, members=members, filter="tar")
            except TypeError:  # filter 인자가 없는 오래된 Python
                t.extractall(dest, members=members)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "extract")
PY

extract() {  # extract <archive> <destdir> — 안전 확인 뒤 해제 (빠른 시스템 tar/unzip 이 있으면 그것으로)
  local a=$1 d=$2
  mkdir -p "$d"
  "${PY:-python3}" "$SAFE_EXTRACT" "$a" "$d" check
  case "$a" in
    *.zip) { command -v unzip >/dev/null && unzip -q -o "$a" -d "$d"; } || "${PY:-python3}" "$SAFE_EXTRACT" "$a" "$d" ;;
    *) { tar --version >/dev/null 2>&1 && tar -xf "$a" -C "$d" --no-same-owner; } || "${PY:-python3}" "$SAFE_EXTRACT" "$a" "$d" ;;
  esac
}

# ---------------------------------------------------------------------------
# 배포판 패키지 (apt): 설치된 것을 뺀 의존성 닫힘을 받아 개인 루트에 dpkg-deb -x
# ---------------------------------------------------------------------------
DEB_EXCLUDE=" debconf debconf-2.0 cdebconf libdebian-installer4 libtextwrap1 dpkg libc6 libc-bin perl-base base-files "

deb_closure() {  # 이미 설치된 패키지를 뺀 재귀 의존성 (Recommends/Suggests 제외)
  local p
  apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances "$@" 2>/dev/null \
    | grep -E '^[a-z0-9]' | sed 's/:amd64$//' | grep -v ':' | sort -u | while read -r p; do
      case "$DEB_EXCLUDE" in *" $p "*) continue ;; esac
      if [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | cut -c1-2)" = "ii" ]; then continue; fi
      if apt-cache show --no-all-versions "$p" >/dev/null 2>&1; then echo "$p"; fi
    done
}

# 받을 수 있는 실제 패키지인가. apt-cache show 는 가상 패키지(Ubuntu 24.04 의 t64 개명 등)에도 0 을 돌려주지만
# apt-cache depends 는 그 이름으로 아무것도 내지 않으므로, 후보 버전이 있는지로 판단한다.
# (출력을 먼저 받는다: pipefail 아래에서 '… | grep -q' 는 앞 명령이 SIGPIPE(141)로 끝나 거짓 실패가 된다)
deb_has_candidate() {
  local out; out="$(LC_ALL=C apt-cache policy "$1" 2>/dev/null)" || return 1
  case "$out" in *$'\n  Candidate: ('*) return 1 ;; *$'\n  Candidate: '*) return 0 ;; *) return 1 ;; esac
}
deb_first_available() {  # 배포판마다 이름이 다른 패키지: 후보 중 처음 있는 것
  local p
  for p in "$@"; do
    if deb_has_candidate "$p"; then echo "$p"; return 0; fi
  done
  return 1
}

deb_fetch_extract() {  # deb_fetch_extract <cache-subdir> <root> <패키지...>
  local sub=$1 root=$2; shift 2
  local dir="$CACHE/$sub" pkgs uris line url file hash algo hex n=0 p
  mkdir -p "$dir" "$root"
  if [ "${1:-}" = --locked ]; then  # 이미지 도구: apt 후보 대신 저장소에 검증·고정한 계획만 쓴다
    local lock=$2 component=$3 plan version
    plan="$("$PY" "$REPO/scripts/image_tools_lock.py" plan "$component" --lock "$lock" --record "$root/install.json")" || return 1
    while IFS=$'\t' read -r p version url hex; do
      [ -n "$p" ] || continue
      file=${url##*/}
      fetch "$url" "$dir/$file" "$hex" sha256
      dpkg-deb -x "$dir/$file" "$root"
      n=$((n + 1))
    done <<<"$plan"
    info "고정한 배포판 패키지 ${n}개를 $root 에 풀었음 (시스템 런타임 재사용은 install.json 에 구분)"
    return 0
  fi
  for p in "$@"; do  # 색인이 비었거나 오래되면 닫힘이 비어 "모두 설치됨" 으로 잘못 보인다
    [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | cut -c1-2)" = ii ] || deb_has_candidate "$p" \
      || { echo "apt 색인에 받을 수 있는 '$p' 가 없습니다 (가상 패키지이거나 색인이 오래됨). 관리자가 'sudo apt-get update' 를 한 번 실행해야 할 수 있습니다." >&2; return 1; }
  done
  pkgs="$(deb_closure "$@" | tr '\n' ' ')"
  if [ -z "${pkgs// /}" ]; then info "필요한 배포판 패키지가 모두 시스템에 이미 설치되어 있음"; return 0; fi
  if ! uris="$(apt-get download --print-uris $pkgs 2>&1)"; then
    echo "$uris" >&2
    echo "apt 색인에서 패키지를 찾지 못했습니다. 관리자가 'sudo apt-get update' 를 한 번 실행해야 할 수 있습니다." >&2
    return 1
  fi
  while IFS= read -r line; do
    case "$line" in "'"*) ;; *) continue ;; esac
    url="${line%%\' *}"; url="${url#\'}"
    read -r _ file _ hash <<<"$line"
    algo="${hash%%:*}"; hex="${hash#*:}"
    case "$algo" in SHA512) algo=sha512 ;; SHA256) algo=sha256 ;; *) echo "알 수 없는 해시 형식: $hash" >&2; return 1 ;; esac
    fetch "$url" "$dir/$file" "$hex" "$algo"
    dpkg-deb -x "$dir/$file" "$root"
    n=$((n + 1))
  done <<<"$uris"
  info "배포판 패키지 ${n}개를 $root 에 풀었음"
}

make_wrapper() {  # make_wrapper <래퍼 경로> <실제 실행 파일> <개인 루트> [추가 export 줄...]
  local w=$1 real=$2 root=$3; shift 3
  {
    echo '#!/bin/bash'
    echo "# scripts/install.sh 가 만든 래퍼: 개인 경로에 푼 배포판 패키지의 라이브러리를 이 프로세스에만 붙인다."
    echo "R='$root'"
    echo 'export LD_LIBRARY_PATH="$R/usr/lib/'$LIBDIR':$R/lib/'$LIBDIR':$R/usr/lib/'$LIBDIR'/android:$R/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"'
    local extra; for extra in "$@"; do echo "$extra"; done
    echo "exec '$real' \"\$@\""
  } >"$w.tmp"
  chmod +x "$w.tmp"; mv -f "$w.tmp" "$w"
}

sys_tool() {  # sys_tool <이름> — PATH 에서 <prefix> 밖의 실행 파일 (env.sh 를 source 한 셸에서 자기 자신을 가리키는 링크 방지)
  local d IFS=:
  for d in $PATH; do
    case "$d" in ""|"$PREFIX"|"$PREFIX"/*) continue ;; esac
    if [ -x "$d/$1" ] && [ ! -d "$d/$1" ]; then printf '%s\n' "$d/$1"; return 0; fi
  done
  return 1
}
link_system() {  # link_system <bindir> <도구...> — 시스템 도구를 링크한다. 첫 도구가 없으면 1
  local d=$1 first=$2 t r; shift
  for t in "$@"; do
    if r="$(sys_tool "$t")"; then ln -sfn "$r" "$d/$t"; elif [ "$t" = "$first" ]; then return 1; fi
  done
}

# ---------------------------------------------------------------------------
# 구성요소별 확인(check_*)과 설치(install_*)
# ---------------------------------------------------------------------------
B="$PREFIX/bin"

# tomlkit 은 Codex 설정 명령(pweh mcp-config --client codex·codex-trust·mcp-check)에 필요하다 — 없던 가상환경(이전 판)이면 python 을 다시 설치한다
check_python() { [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import pweh, mcp, serial, yaml, jsonschema, pytest, tomlkit' 2>/dev/null; }
pip_older() {  # pip_older <python> — 그 환경에 pip 가 없거나 고정 버전(PIP_VER)보다 오래됐으면 0
  local rc=0
  "$1" -I - "$PIP_VER" <<'PY' 2>/dev/null || rc=$?
import sys
try:
    from importlib.metadata import version
    have = version("pip")
except Exception:
    sys.exit(0)
def key(s):
    return tuple(int(x) if x.isdigit() else 0 for x in s.split(".")[:3])
sys.exit(0 if key(have) < key(sys.argv[1]) else 3)
PY
  [ "$rc" -ne 3 ]
}
make_venv() {  # make_venv <dir> — 고정된 pip(PIP_VER 이상)가 있는 가상환경. ensurepip(python3-venv)가 없어도 된다
  local v=$1 w="$CACHE/python/pip-${PIP_VER}-py3-none-any.whl"
  if [ ! -x "$v/bin/python" ]; then
    # 가상환경이 아닌 기존 디렉터리는 건드리지 않는다 (사용자 파일을 덮어쓰지 않도록)
    if [ -e "$v" ] && [ ! -f "$v/pyvenv.cfg" ] && [ -n "$(ls -A "$v" 2>/dev/null)" ]; then echo "가상환경이 아닌 디렉터리입니다: $v (--venv 확인)" >&2; return 1; fi
    "$PY" -m venv --without-pip "$v"
  fi
  pip_older "$v/bin/python" || return 0
  fetch "$PIP_URL" "$w" "$PIP_SHA"
  if "$v/bin/python" -m pip --version >/dev/null 2>&1; then
    "$v/bin/python" -m pip install --no-warn-script-location "$w"
  else  # pip 휠은 스스로 실행할 수 있다 (python pip.whl/pip install pip.whl)
    "$v/bin/python" -I "$w/pip" install --no-index --no-warn-script-location "$w"
  fi
}
install_python() {
  [ -n "$PY" ] || { echo "Python 3.10 이상이 필요합니다 (python3 --version 확인)" >&2; return 1; }
  make_venv "$VENV"
  "$VENV/bin/python" -m pip install -e "${REPO}[dev]"
}
version_python() { "$VENV/bin/python" -c 'import sys, pweh; print("Python", sys.version.split()[0], "/ pweh", getattr(pweh, "__version__", "?"))' 2>/dev/null; }

check_sigrok() { [ -x "$B/sigrok-cli" ] && "$B/sigrok-cli" --version 2>/dev/null | head -1 | grep -q '^sigrok-cli 0\.7'; }
install_sigrok() {
  local root="$PREFIX/sigrok/root" pyhome extra=() sys
  if [ "$HAVE_APT" != 1 ]; then  # 다른 배포판: 시스템 패키지로 설치된 sigrok-cli 0.7 이 있으면 그것을 쓴다
    if sys="$(sys_tool sigrok-cli)" && "$sys" --version 2>/dev/null | head -1 | grep -q '^sigrok-cli 0\.7'; then ln -sfn "$sys" "$B/sigrok-cli"; return 0; fi
    echo "apt 가 없어 sigrok-cli 배포판 패키지를 받을 수 없습니다. 배포판 패키지 관리자로 sigrok-cli 0.7.2 를 설치한 뒤 다시 실행하세요." >&2; return 1
  fi
  if [ "$(dpkg-query -W -f='${db:Status-Abbrev}' sigrok-cli 2>/dev/null | cut -c1-2)" = ii ] && /usr/bin/sigrok-cli --version 2>/dev/null | head -1 | grep -q '^sigrok-cli 0\.7'; then
    info "시스템에 설치된 sigrok-cli 를 그대로 씀"
    ln -sfn /usr/bin/sigrok-cli "$B/sigrok-cli"
    return 0
  fi
  deb_fetch_extract debs-sigrok "$root" sigrok-cli sigrok-firmware-fx2lafw
  [ -d "$root/usr/share/libsigrokdecode/decoders" ] && extra+=('export SIGROKDECODE_DIR="$R/usr/share/libsigrokdecode/decoders"')
  [ -d "$root/usr/share/sigrok-firmware" ] && extra+=('export SIGROK_FIRMWARE_DIR="$R/usr/share/sigrok-firmware"')
  # libsigrokdecode 는 시스템 libpython 을 쓴다. 표준 라이브러리까지 개인 루트에 풀렸을 때만 PYTHONHOME 을 그쪽으로
  pyhome='unset PYTHONHOME PYTHONPATH'
  if compgen -G "$root/usr/lib/python3*/encodings" >/dev/null; then pyhome='unset PYTHONPATH; export PYTHONHOME="$R/usr"'; fi
  extra+=("$pyhome")
  make_wrapper "$B/sigrok-cli" "$root/usr/bin/sigrok-cli" "$root" "${extra[@]}"
}
version_sigrok() { "$B/sigrok-cli" --version 2>/dev/null | head -1; }

check_openocd() { [ -x "$B/openocd" ] && "$B/openocd" --version 2>&1 | grep -q '0\.12\.0'; }
install_openocd() {
  local a="$CACHE/openocd/xpack-openocd-${OPENOCD_VER}-linux-x64.tar.gz"
  fetch "$OPENOCD_URL" "$a" "$OPENOCD_SHA"
  rm -rf "$PREFIX/openocd/xpack-openocd-${OPENOCD_VER}"
  extract "$a" "$PREFIX/openocd"
  ln -sfn "$PREFIX/openocd/xpack-openocd-${OPENOCD_VER}/bin/openocd" "$B/openocd"
  cat >"$B/openocd-dummy" <<EOF
#!/bin/bash
# 하드웨어 없는 OpenOCD (xPack ${OPENOCD_VER}): dummy JTAG 어댑터 + TAP 1개 + testee 타깃. TCL RPC/telnet 은 127.0.0.1 에서만 듣는다.
# 포트: PWEH_OPENOCD_TCL_PORT (기본 6666), PWEH_OPENOCD_TELNET_PORT (기본 4444). 추가 인자는 init 뒤에 붙는다.
# 주의: testee 타깃에서 resume/step/bp 는 OpenOCD 를 SIGSEGV 로 죽인다.
TCL_PORT=\${PWEH_OPENOCD_TCL_PORT:-6666}
TELNET_PORT=\${PWEH_OPENOCD_TELNET_PORT:-4444}
exec "$PREFIX/openocd/xpack-openocd-${OPENOCD_VER}/bin/openocd" \\
  -c "adapter driver dummy" -c "transport select jtag" -c "adapter speed 1000" \\
  -c "jtag newtap dummy cpu -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass" \\
  -c "target create dummy.cpu testee -chain-position dummy.cpu" \\
  -c "tcl port \${TCL_PORT}" -c "telnet port \${TELNET_PORT}" -c "gdb port disabled" -c "init" "\$@"
EOF
  chmod +x "$B/openocd-dummy"
}
version_openocd() { "$B/openocd" --version 2>&1 | head -1; }

check_squashfs() { [ -x "$B/mksquashfs" ] && "$B/mksquashfs" -version 2>&1 | grep -q 'mksquashfs version'; }
install_squashfs() {
  if [ "$HAVE_APT" != 1 ]; then
    link_system "$B" mksquashfs unsquashfs sqfscat sqfstar && return 0
    echo "apt 가 없습니다. 배포판 패키지 관리자로 squashfs-tools 를 설치한 뒤 다시 실행하세요." >&2; return 1
  fi
  local root="$PREFIX/squashfs/root" t r
  deb_fetch_extract debs-squashfs "$root" squashfs-tools
  for t in mksquashfs unsquashfs sqfscat sqfstar; do
    if [ -x "$root/usr/bin/$t" ]; then make_wrapper "$B/$t" "$root/usr/bin/$t" "$root"
    elif r="$(sys_tool "$t")"; then ln -sfn "$r" "$B/$t"; fi
  done
}
version_squashfs() { "$B/mksquashfs" -version 2>&1 | head -1; }

check_uboot() { [ -x "$B/mkimage" ] && "$B/mkimage" -V 2>&1 | grep -q mkimage; }
install_uboot() {
  if [ "$HAVE_APT" != 1 ]; then
    link_system "$B" mkimage mkenvimage dumpimage && return 0
    echo "apt 가 없습니다. 배포판 패키지 관리자로 u-boot-tools 를 설치한 뒤 다시 실행하세요." >&2; return 1
  fi
  local root="$PREFIX/uboot/root" t r
  deb_fetch_extract debs-uboot "$root" u-boot-tools
  for t in mkimage mkenvimage dumpimage; do
    if [ -x "$root/usr/bin/$t" ]; then make_wrapper "$B/$t" "$root/usr/bin/$t" "$root"
    elif r="$(sys_tool "$t")"; then ln -sfn "$r" "$B/$t"; fi
  done
}
version_uboot() { "$B/mkimage" -V 2>&1 | head -1; }

check_zig() { [ -x "$B/zig" ] && [ "$("$B/zig" version 2>/dev/null)" = "$ZIG_VER" ]; }
install_zig() {
  local a="$CACHE/zig/zig-x86_64-linux-${ZIG_VER}.tar.xz"
  fetch "$ZIG_URL" "$a" "$ZIG_SHA"
  rm -rf "$PREFIX/zig/zig-x86_64-linux-${ZIG_VER}"
  extract "$a" "$PREFIX/zig"
  ln -sfn "$PREFIX/zig/zig-x86_64-linux-${ZIG_VER}/zig" "$B/zig"
}
version_zig() { echo "zig $("$B/zig" version 2>/dev/null)"; }

check_jdk() { [ -x "$PREFIX/jdk/$JDK_DIR_NAME/bin/java" ] && "$PREFIX/jdk/$JDK_DIR_NAME/bin/java" -version 2>&1 | grep -q '"21'; }
install_jdk() {
  local a="$CACHE/jdk/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
  fetch "$JDK_URL" "$a" "$JDK_SHA"
  rm -rf "$PREFIX/jdk/$JDK_DIR_NAME"
  extract "$a" "$PREFIX/jdk"
}
version_jdk() { "$PREFIX/jdk/$JDK_DIR_NAME/bin/java" -version 2>&1 | head -1; }

GHIDRA_HOME="$PREFIX/ghidra/ghidra_${GHIDRA_VER}_PUBLIC"
check_ghidra() { [ -x "$GHIDRA_HOME/support/analyzeHeadless" ] && [ -x "$GHIDRA_HOME/Ghidra/Features/Decompiler/os/linux_x86_64/decompile" ]; }
install_ghidra() {
  local a="$CACHE/ghidra/ghidra_${GHIDRA_VER}_PUBLIC_20260921.zip"
  fetch "$GHIDRA_URL" "$a" "$GHIDRA_SHA"
  rm -rf "$GHIDRA_HOME"
  extract "$a" "$PREFIX/ghidra"
  check_jdk || warn "Ghidra 는 JDK 21 이 필요합니다 (jdk 구성요소)"
}
version_ghidra() { echo "Ghidra ${GHIDRA_VER} ($GHIDRA_HOME)"; }

check_unblob() { [ -x "$B/unblob" ] && [ "$("$B/unblob" --version 2>/dev/null)" = "$UNBLOB_VER" ]; }
install_unblob() {
  [ -n "$PY" ] || { echo "Python 3.10 이상이 필요합니다" >&2; return 1; }
  local venv="$PREFIX/unblob/venv" whl="$CACHE/unblob/$UNBLOB_WHL"
  make_venv "$venv"
  fetch "$UNBLOB_URL" "$whl" "$UNBLOB_SHA"   # unblob 자체는 해시를 고정한 휠, 의존성은 PyPI 에서 (휠만)
  "$venv/bin/python" -m pip install --only-binary=:all: "$whl"
  # python-magic 은 시스템 libmagic 을 dlopen 한다. Debian/Ubuntu 최소 설치에는 없으므로 배포판 패키지를 개인 루트에 푼다
  local root="$PREFIX/unblob/root" libenv="" lm
  if ! "$venv/bin/python" -c 'import magic' >/dev/null 2>&1; then
    [ "$HAVE_APT" = 1 ] || { echo "libmagic 이 없습니다. 배포판 패키지 관리자로 libmagic(file) 을 설치한 뒤 다시 실행하세요." >&2; return 1; }
    lm="$(deb_first_available libmagic1t64 libmagic1)" || { echo "apt 색인에 libmagic1 이 없습니다" >&2; return 1; }
    deb_fetch_extract debs-unblob "$root" "$lm"
    if [ -e "$root/usr/lib/$LIBDIR/libmagic.so.1" ]; then
      libenv="export LD_LIBRARY_PATH=\"$root/usr/lib/$LIBDIR\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\""
      # 매직 DB(libmagic-mgc)가 시스템에 이미 있으면 닫힘에서 빠지므로 기본 경로를 그대로 쓴다
      if [ -f "$root/usr/lib/file/magic.mgc" ]; then libenv="$libenv MAGIC=\"$root/usr/lib/file/magic.mgc\""; fi
    fi
  fi
  cat >"$B/unblob.tmp" <<EOF
#!/bin/bash
# scripts/install.sh 가 만든 unblob ${UNBLOB_VER} 래퍼: 개인 압축 해제 도구와 venv 의 콘솔 스크립트를 PATH 앞에 둔다.
# 스스로는 아무것도 출력하지 않는다 (\`unblob --version\` 은 버전 문자열만).
T='$PREFIX'
export PATH="\$T/extractors/bin:\$T/unblob/venv/bin:\${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin"
unset PYTHONHOME PYTHONPATH
$libenv
exec "\$T/unblob/venv/bin/unblob" "\$@"
EOF
  chmod +x "$B/unblob.tmp"; mv -f "$B/unblob.tmp" "$B/unblob"
  "$B/unblob" --version >/dev/null   # 실행 확인: 실패하면 원인(Traceback)이 로그에 남는다 (check_unblob 은 stderr 를 버림)
}
version_unblob() { echo "unblob $("$B/unblob" --version 2>/dev/null)"; }

EXTRACTOR_TOOLS="7z lz4 lzop zstd lziprecover partclone.restore simg2img unar lsar sasquatch sasquatch-v4be"
loads() { local rc=0; timeout 20 "$@" >/dev/null 2>&1 </dev/null || rc=$?; [ "$rc" -ne 126 ] && [ "$rc" -ne 127 ]; }  # 실행 파일과 공유 라이브러리가 실제로 올라오는가
check_extractors() { local t; for t in 7z lz4 lzop zstd sasquatch unar simg2img; do [ -x "$PREFIX/extractors/bin/$t" ] && loads "$PREFIX/extractors/bin/$t" --help || return 1; done; }
install_extractors() {
  local root="$PREFIX/extractors/root" eb="$PREFIX/extractors/bin" p7 deb deps t real
  mkdir -p "$eb"
  if [ "$HAVE_APT" != 1 ]; then  # 다른 배포판: 시스템 패키지로 설치된 도구를 링크
    for t in $EXTRACTOR_TOOLS; do real="$(sys_tool "$t")" && ln -sfn "$real" "$eb/$t"; done
    check_extractors && return 0
    echo "apt 가 없습니다. 7z/lz4/lzop/zstd/sasquatch/unar/simg2img 를 배포판 패키지로 설치한 뒤 다시 실행하세요 ('unblob --show-external-dependencies' 참고)." >&2; return 1
  fi
  p7="$(deb_first_available p7zip-full 7zip)" || { echo "apt 색인에 p7zip-full/7zip 이 없습니다" >&2; return 1; }
  deb_fetch_extract debs-extractors "$root" "$p7" lz4 lzop zstd lziprecover partclone android-sdk-libsparse-utils unar
  deb="$CACHE/sasquatch/sasquatch_1.0_amd64.deb"
  fetch "$SASQUATCH_URL" "$deb" "$SASQUATCH_SHA"
  dpkg-deb -x "$deb" "$root"
  deps="$(dpkg-deb -f "$deb" Depends | tr ',' '\n' | sed 's/[(|].*//; s/ //g' | grep -v '^$' | tr '\n' ' ')"
  # shellcheck disable=SC2086
  [ -z "$deps" ] || deb_fetch_extract debs-extractors "$root" $deps
  # 7z: p7zip 의 /usr/bin/7z 는 /usr/lib/p7zip/7z 를 고정 경로로 부르는 스크립트라 실제 바이너리를 직접 부른다
  # Ubuntu 24.04·Debian 13 의 7zip 23.x 는 실제 바이너리가 /usr/lib/7zip/7z 이고 /usr/bin/7z 는 스크립트다
  for real in "$root/usr/lib/p7zip/7z" "$root/usr/lib/7zip/7z" "$root/usr/bin/7zz" "$root/usr/bin/7z" /usr/lib/p7zip/7z /usr/lib/7zip/7z /usr/bin/7z /usr/bin/7zz; do
    if [ -x "$real" ] && file_is_elf "$real"; then make_wrapper "$eb/7z" "$real" "$root"; break; fi
  done
  for t in lz4 lzop zstd partclone.restore simg2img unar lsar sasquatch sasquatch-v4be; do
    for real in "$root/usr/bin/$t" "$root/usr/sbin/$t"; do
      if [ -x "$real" ]; then make_wrapper "$eb/$t" "$real" "$root"; break; fi
    done
  done
  for real in "$root/usr/bin/lzip.lziprecover" "$root/usr/bin/lziprecover"; do
    if [ -x "$real" ]; then make_wrapper "$eb/lziprecover" "$real" "$root"; break; fi
  done
  # unblob venv 의 콘솔 스크립트 (jefferson, ubireader_*)
  for t in jefferson ubireader_display_info ubireader_extract_files ubireader_extract_images ubireader_list_files; do
    [ -x "$PREFIX/unblob/venv/bin/$t" ] && ln -sfn "$PREFIX/unblob/venv/bin/$t" "$eb/$t"
  done
  # 시스템에 이미 있으면 그것을 쓴다 (배포판 패키지가 이미 설치된 경우 닫힘에서 빠짐)
  for t in $EXTRACTOR_TOOLS; do
    if [ ! -e "$eb/$t" ] && real="$(sys_tool "$t")"; then ln -sfn "$real" "$eb/$t"; fi
  done
}
file_is_elf() { [ "$(head -c 4 "$1" 2>/dev/null | od -An -c | tr -d ' \n')" = '177ELF' ]; }
version_extractors() { local n; n="$(ls "$PREFIX/extractors/bin" 2>/dev/null | wc -l)"; echo "도구 ${n}개 ($PREFIX/extractors/bin)"; }

check_erofs() { [ -x "$PREFIX/extractors/bin/fsck.erofs" ] && "$PREFIX/extractors/bin/fsck.erofs" -V 2>&1 | grep -q '1\.9'; }
install_erofs() {
  local t
  for t in git make autoreconf libtoolize pkg-config cc; do
    command -v "$t" >/dev/null || { echo "erofs-utils 소스 빌드에 '$t' 가 필요합니다 (관리자: sudo apt-get install build-essential autoconf automake libtool pkg-config git)" >&2; return "$SKIP_RC"; }
  done
  local src="$PREFIX/_build/erofs-utils-src" dev="$PREFIX/_build/devroot-erofs" cflags="" libs="" uuid=""
  # erofs-utils 1.9 의 configure 는 libuuid(pkg-config uuid)를 요구한다. 개발 파일이 없으면 끈다 (mkfs 의 UUID 생성만 빠짐)
  pkg-config --exists uuid 2>/dev/null || uuid="--without-uuid"
  if ! pkg-config --exists liblz4 2>/dev/null; then
    [ "$HAVE_APT" = 1 ] || { echo "liblz4 개발 파일이 없습니다" >&2; return 1; }
    deb_fetch_extract debs-build "$dev" liblz4-dev
    fix_devroot "$dev"
    cflags="-I$dev/usr/include"; libs="-L$dev/usr/lib/$LIBDIR -llz4"
  fi
  rm -rf "$src"
  git clone --depth 1 --branch "$EROFS_TAG" "$EROFS_GIT" "$src"
  # 태그는 옮겨질 수 있으므로 커밋으로 확인한다
  [ "$(git -C "$src" rev-parse HEAD)" = "$EROFS_COMMIT" ] || { echo "erofs-utils $EROFS_TAG 커밋이 고정값($EROFS_COMMIT)과 다릅니다" >&2; return 1; }
  # shellcheck disable=SC2086
  ( cd "$src" && ./autogen.sh \
      && if [ -n "$cflags" ]; then liblz4_CFLAGS="$cflags" liblz4_LIBS="$libs" ./configure --prefix="$PREFIX/erofs" --disable-fuse --enable-lz4 --without-selinux $uuid;
         else ./configure --prefix="$PREFIX/erofs" --disable-fuse --enable-lz4 --without-selinux $uuid; fi \
      && make -j"$JOBS" && make install )
  mkdir -p "$PREFIX/extractors/bin"
  for t in fsck.erofs mkfs.erofs dump.erofs; do ln -sfn "$PREFIX/erofs/bin/$t" "$PREFIX/extractors/bin/$t"; done
}
version_erofs() { "$PREFIX/extractors/bin/fsck.erofs" -V 2>&1 | head -1; }

fix_devroot() {  # 개인 개발 루트: .pc 의 /usr 를 루트로 바꾸고, 시스템에 있는 실제 라이브러리를 가리키는 .so 링크를 고친다
  local root=$1 pc l tgt d
  while IFS= read -r pc; do sed -i -e "s#=/usr/#=$root/usr/#g" -e "s#^prefix=/usr\$#prefix=$root/usr#" "$pc"; done \
    < <(find "$root" -name '*.pc' 2>/dev/null)
  while IFS= read -r l; do
    [ -e "$l" ] && continue
    tgt="$(basename "$(readlink "$l")")"
    for d in "/usr/lib/$LIBDIR" "/lib/$LIBDIR"; do
      if [ -e "$d/$tgt" ]; then ln -sfn "$d/$tgt" "$l"; break; fi
    done
  done < <(find "$root" -type l -name '*.so' 2>/dev/null)
}

binwalk_build() {
  CARGO_TARGET_DIR="$PREFIX/_build/binwalk-target" "$1" install binwalk --version "$BINWALK_VER" --locked --root "$PREFIX/binwalk" --force
}
private_rust() {  # 개인 rustup + 고정 툴체인: <prefix>/_rust 아래 (셸 rc·PATH 는 건드리지 않음)
  export RUSTUP_HOME="$PREFIX/_rust/rustup" CARGO_HOME="$PREFIX/_rust/cargo" RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN"
  "$CARGO_HOME/bin/cargo" --version >/dev/null 2>&1 && return 0   # 끊긴 rustup-init 이 프록시만 남긴 경우는 다시 설치
  local ri="$CACHE/rust/rustup-init-${RUSTUP_VER}"
  fetch "$RUSTUP_URL" "$ri" "$RUSTUP_SHA"
  chmod +x "$ri"
  "$ri" -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
}
check_binwalk() { [ -x "$B/binwalk" ] && "$B/binwalk" --version 2>/dev/null | grep -q "^binwalk ${BINWALK_VER}"; }
install_binwalk() {
  command -v cc >/dev/null || { echo "binwalk 빌드에 C 컴파일러(cc)가 필요합니다 (관리자: sudo apt-get install build-essential)" >&2; return "$SKIP_RC"; }
  # 개발 파일 루트는 실행 중에도 쓴다 (시스템에 없는 런타임 라이브러리·글꼴): _build 가 아니라 binwalk 아래에 둔다
  local dev="$PREFIX/binwalk/root" need=() pkgs=() p
  pkg-config --exists fontconfig 2>/dev/null || need+=(fontconfig)
  pkg-config --exists freetype2 2>/dev/null || need+=(freetype)
  pkg-config --exists liblzma 2>/dev/null || need+=(lzma)
  command -v pkg-config >/dev/null || need+=(pkgconfig)
  if [ ${#need[@]} -gt 0 ]; then
    [ "$HAVE_APT" = 1 ] || { echo "binwalk 빌드에 필요한 개발 파일(${need[*]})이 없습니다" >&2; return 1; }
    info "개발 파일 ${need[*]} 를 개인 경로에 풀어 씀"
    for p in "${need[@]}"; do
      case "$p" in
        fontconfig) pkgs+=("$(deb_first_available libfontconfig-dev libfontconfig1-dev)") ;;
        freetype) pkgs+=("$(deb_first_available libfreetype-dev libfreetype6-dev)") ;;
        lzma) pkgs+=(liblzma-dev) ;;
        pkgconfig) pkgs+=("$(deb_first_available pkgconf pkg-config)") ;;
      esac
    done
    deb_fetch_extract debs-build "$dev" "${pkgs[@]}"
    fix_devroot "$dev"
    export PKG_CONFIG_PATH="$dev/usr/lib/$LIBDIR/pkgconfig:$dev/usr/share/pkgconfig:$dev/usr/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export LIBRARY_PATH="$dev/usr/lib/$LIBDIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
    export C_INCLUDE_PATH="$dev/usr/include${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
    export LD_LIBRARY_PATH="$dev/usr/lib/$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    if [ -x "$dev/usr/bin/pkg-config" ] && ! command -v pkg-config >/dev/null; then export PKG_CONFIG="$dev/usr/bin/pkg-config"; fi
  fi
  if ! { command -v cargo >/dev/null && binwalk_build "$(command -v cargo)"; }; then
    command -v cargo >/dev/null && info "시스템 cargo 로 빌드하지 못해 개인 rust 툴체인으로 다시 시도"
    private_rust
    binwalk_build "$CARGO_HOME/bin/cargo"
  fi
  local bin="$PREFIX/binwalk/bin/binwalk" deps fc=()
  deps="$(env -u LD_LIBRARY_PATH ldd "$bin" 2>/dev/null || true)"   # pipefail 아래 '… | grep -q' 의 SIGPIPE 를 피해 먼저 받는다
  case "$deps" in
    *"not found"*)
      # 시스템에 fontconfig 설정이 없으면 'binwalk -E'(엔트로피 그래프)가 sans-serif 글꼴을 못 찾아 패닉한다 → 개인 루트의 설정·글꼴
      if [ ! -e /etc/fonts/fonts.conf ] && [ -d "$dev/usr/share/fonts" ]; then
        mkdir -p "$PREFIX/binwalk/etc"
        printf '%s\n' '<?xml version="1.0"?>' '<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">' '<fontconfig>' \
          "  <dir>/usr/share/fonts</dir>" "  <dir>$dev/usr/share/fonts</dir>" "  <cachedir>$PREFIX/_cache/fontconfig</cachedir>" \
          "  <include ignore_missing=\"yes\">$dev/etc/fonts/conf.d</include>" '</fontconfig>' >"$PREFIX/binwalk/etc/fonts.conf"
        fc=("export FONTCONFIG_FILE='$PREFIX/binwalk/etc/fonts.conf'")
      fi
      make_wrapper "$B/binwalk" "$bin" "$dev" ${fc[@]+"${fc[@]}"}   # 시스템에 없는 런타임 라이브러리를 개인 루트에서
      ;;
    *) rm -f "$B/binwalk"; ln -sfn "$bin" "$B/binwalk" ;;
  esac
  rm -rf "$PREFIX/_build/binwalk-target"   # cargo 중간 산출물 (약 200 MB)
}
version_binwalk() { "$B/binwalk" --version 2>/dev/null | head -1; }

node_ok() {  # REA: node ^22.19 || ^24.11 || >=26
  local n=$1 v maj min
  v="$("$n" --version 2>/dev/null | tr -d v)" || return 1
  maj="${v%%.*}"; min="${v#*.}"; min="${min%%.*}"
  { [ "$maj" = 22 ] && [ "$min" -ge 19 ]; } || { [ "$maj" = 24 ] && [ "$min" -ge 11 ]; } || [ "$maj" -ge 26 ] 2>/dev/null
}
existing_rea() {  # 이미 설치된 REA 6.x (PWEH_REA, PATH, ~/.local/bin/rea 순)
  local r
  for r in "${PWEH_REA:-}" "$(command -v rea 2>/dev/null || true)" "$HOME/.local/bin/rea"; do
    [ -n "$r" ] && [ -x "$r" ] || continue
    if "$r" --version 2>/dev/null | grep -q '^6\.'; then echo "$r"; return 0; fi
  done
  return 1
}
rea_found() {  # REA 6.x 실행 파일 (이 설치, 또는 --force 가 아닐 때 기존 설치)
  local v
  if [ -x "$B/rea" ]; then
    v="$(PATH="$PREFIX/node/bin:$PATH" "$B/rea" --version 2>/dev/null || true)"
    case "$v" in 6.*) return 0 ;; esac
  fi
  [ "$FORCE" = 0 ] && existing_rea >/dev/null
}
# REA 의 Ghidra provider 는 자식 프로세스를 띄우기 전에 procps 의 ps 로 프로세스를 확인한다
# (없으면 'spawn ps ENOENT' 로 모든 Ghidra 분석이 실패). Debian 최소 설치(컨테이너 등)에는 procps 가 없다.
rea_ps_ok() { sys_tool ps >/dev/null || [ -x "$B/ps" ]; }
check_rea() { rea_found && rea_ps_ok; }
install_rea() {
  local node npm
  if [ "$FORCE" = 1 ] || ! rea_found; then
    if command -v node >/dev/null && command -v npm >/dev/null && node_ok "$(command -v node)"; then
      node="$(command -v node)"; npm="$(command -v npm)"
    else
      [ "$ARCH_OK" = 1 ] || { echo "개인 Node ${NODE_VER} 는 Linux x86_64 용입니다. node 22.19+ 와 npm 을 설치한 뒤 다시 실행하세요." >&2; return 1; }
      local a="$CACHE/node/node-v${NODE_VER}-linux-x64.tar.xz"
      fetch "$NODE_URL" "$a" "$NODE_SHA"
      rm -rf "$PREFIX/node" "$PREFIX/node-v${NODE_VER}-linux-x64"
      extract "$a" "$PREFIX"
      mv "$PREFIX/node-v${NODE_VER}-linux-x64" "$PREFIX/node"
      node="$PREFIX/node/bin/node"; npm="$PREFIX/node/bin/npm"
    fi
    PATH="$(dirname "$node"):$PATH" "$npm" install --global --prefix "$PREFIX/rea" "rea-agents@$REA_VER"
    ln -sfn "$PREFIX/rea/bin/rea" "$B/rea"
  fi
  if ! rea_ps_ok; then
    [ "$HAVE_APT" = 1 ] || { echo "REA 의 Ghidra 분석에 procps 의 ps 가 필요합니다 (배포판 패키지 관리자로 procps 설치)" >&2; return 1; }
    local root="$PREFIX/procps/root" real
    deb_fetch_extract debs-procps "$root" procps
    for real in "$root/usr/bin/ps" "$root/bin/ps"; do
      if [ -x "$real" ]; then make_wrapper "$B/ps" "$real" "$root"; break; fi
    done
    "$B/ps" -o pid= -p $$ >/dev/null   # 실행 확인 (<prefix>/bin 은 env.sh 가 PATH 에 넣는다)
  fi
}
version_rea() {
  if [ -x "$B/rea" ]; then echo "REA $(PATH="$PREFIX/node/bin:$PATH" "$B/rea" --version 2>/dev/null) ($B/rea)"
  else local r; r="$(existing_rea)" && echo "REA $("$r" --version 2>/dev/null) (기존 설치: $r)"; fi
}

# esptool (ESP32 계열): 두 부분을 따로 설치·확인한다.
# - Linux 판: 전용 venv(esptool/venv)에 sha256 을 고정한 PyPI 소스 배포판을 설치하고 bin/esptool 래퍼로 실행한다.
# - Windows 판(방법 A): WSL 에서 interop 으로 공식 Windows 빌드 esptool.exe 를 직접 실행해 Windows 의 COM 포트를 쓴다
#   (usbipd 없이). Linux 파일 시스템에 둔 exe 도 실행되고, 파일 경로는 `wslpath -w` 의 UNC 경로로 넘기면 된다.
ESPTOOL_WIN_EXE="$PREFIX/esptool-win/esptool-windows-amd64/esptool.exe"
WSL_BINFMT=/proc/sys/fs/binfmt_misc   # WSL 이 Windows 실행 파일(MZ)을 넘겨받는 등록: WSLInterop (받아 두기만 하는 이름: WSLInterop-late)
# WSL 에서 Windows 실행 파일을 직접 실행할 수 있는가. 판정은 이 함수 하나로만 한다 — pweh.hostenv 와 같은 감지 규칙에서
# smoke 와 설정 override(hostenv.disable)를 뺀 것: 컨테이너가 아니고(binfmt_misc 는 커널 전체라 WSL 위 docker 에도 등록이 보인다),
# WSLInterop 또는 WSLInterop-late 첫 줄이 enabled 이고, /init 이 있고, wslpath 가 실행된다(`wslpath -w /` — C: 마운트와 무관)
wsl_interop() {
  local f virt wp on=0
  { [ -e /.dockerenv ] || [ -e /run/.containerenv ] || [ -n "${container:-}" ]; } && return 1
  virt="$(systemd-detect-virt -c 2>/dev/null || true)"   # 컨테이너가 아니면 none(종료 코드 1), WSL 은 wsl
  case "$virt" in ""|none|wsl) ;; *) return 1 ;; esac
  for f in "$WSL_BINFMT/WSLInterop" "$WSL_BINFMT/WSLInterop-late"; do
    [ -r "$f" ] && [ "$(head -n 1 "$f" 2>/dev/null)" = enabled ] && on=1
  done
  [ "$on" = 1 ] && [ -e /init ] || return 1
  wp=/usr/bin/wslpath; [ -x "$wp" ] || wp=/bin/wslpath   # $PATH 가 아니라 고정 위치 (hostenv 와 같음)
  [ -x "$wp" ] && timeout 10 "$wp" -w / >/dev/null 2>&1 || return 1
  return 0
}
esptool_version() {  # esptool_version <실행 파일> — `esptool version` 의 마지막 줄 ("esptool v5.4.0" 다음 줄이 "5.4.0"). Windows 판의 CR 은 지운다
  local out
  out="$(timeout 60 "$1" version </dev/null 2>/dev/null)" || return 1   # interop 이 멈춰도 끝나도록 시간 제한, 터미널 입력은 넘기지 않는다
  out="${out//$'\r'/}"
  printf '%s\n' "${out##*$'\n'}"
}
esptool_linux_ok() { [ -x "$B/esptool" ] && [ "$(esptool_version "$B/esptool")" = "$ESPTOOL_VER" ]; }
esptool_win_ok() { [ -x "$ESPTOOL_WIN_EXE" ] && wsl_interop && [ "$(esptool_version "$ESPTOOL_WIN_EXE")" = "$ESPTOOL_VER" ]; }
check_esptool() { esptool_linux_ok && { ! wsl_interop || esptool_win_ok; }; }   # Windows 판은 WSL interop 에서만 요구한다
install_esptool_linux() {
  [ -n "$PY" ] || { echo "Python 3.10 이상이 필요합니다" >&2; return 1; }
  local venv="$PREFIX/esptool/venv" src="$CACHE/esptool/$ESPTOOL_SDIST"
  make_venv "$venv"
  fetch "$ESPTOOL_URL" "$src" "$ESPTOOL_SHA"
  # esptool 자체는 해시를 고정한 소스 배포판에서 빌드하고(빌드 백엔드 setuptools 는 PyPI 에서), 의존성은 PyPI 휠만 받는다 (컴파일러 불필요)
  "$venv/bin/python" -m pip install --only-binary=:all: --no-binary=esptool "$src"
  cat >"$B/esptool.tmp" <<EOF
#!/bin/bash
# scripts/install.sh 가 만든 esptool ${ESPTOOL_VER} 래퍼 (전용 venv). 스스로는 아무것도 출력하지 않는다.
unset PYTHONHOME PYTHONPATH
exec '$venv/bin/esptool' "\$@"
EOF
  chmod +x "$B/esptool.tmp"; mv -f "$B/esptool.tmp" "$B/esptool"
  "$B/esptool" version </dev/null   # 실행 확인: 실패하면 원인(Traceback)이 로그에 남는다
}
install_esptool_win() {
  local a="$CACHE/esptool/$ESPTOOL_WIN_ZIP" d="$PREFIX/esptool-win"
  fetch "$ESPTOOL_WIN_URL" "$a" "$ESPTOOL_WIN_SHA"
  rm -rf "$d/esptool-windows-amd64"
  extract "$a" "$d"
  chmod +x "$d"/esptool-windows-amd64/*.exe   # zip 안의 권한은 0644: interop(binfmt_misc)은 실행 권한이 있는 파일만 넘긴다
  timeout 120 "$ESPTOOL_WIN_EXE" version </dev/null   # interop 실행 확인 (Windows 보안 소프트웨어가 막으면 여기서 실패)
}
install_esptool() {  # 한쪽이 실패해도 다른 쪽은 설치한다 (env.sh 는 되는 쪽만 export). 각 부분은 첫 실패에서 멈춘다
  local lin=0 win=0
  set +e   # 조건 밖의 subshell 이라야 그 안의 set -e 가 산다 (run_component 와 같은 방식)
  if [ "$FORCE" = 1 ] || ! esptool_linux_ok; then
    echo "--- Linux esptool ---"
    ( set -Eeuo pipefail; install_esptool_linux ); lin=$?
  else
    info "Linux esptool ${ESPTOOL_VER} 은 이미 있음"
  fi
  if ! wsl_interop; then
    info "WSL interop(Windows 실행 파일 실행)을 쓸 수 없어 Windows esptool.exe(방법 A)는 건너뜀 — 실패 아님, Linux esptool 만 씀"
  elif [ "$FORCE" = 1 ] || ! esptool_win_ok; then
    echo "--- Windows esptool.exe (방법 A) ---"
    ( set -Eeuo pipefail; install_esptool_win ); win=$?
  else
    info "Windows esptool.exe ${ESPTOOL_VER} 은 이미 있음"
  fi
  set -e
  [ "$lin" -eq 0 ] || echo "Linux esptool 설치 실패 (종료 코드 $lin)" >&2
  [ "$win" -eq 0 ] || echo "Windows esptool.exe(방법 A) 설치 실패 (종료 코드 $win)" >&2
  [ "$lin" -eq 0 ] && [ "$win" -eq 0 ]
}
version_esptool() {
  local s
  s="esptool $(esptool_version "$B/esptool" || echo 없음)"
  if wsl_interop; then s="$s + Windows esptool.exe $(esptool_version "$ESPTOOL_WIN_EXE" || echo 없음) ($ESPTOOL_WIN_EXE)"
  else s="$s (Windows esptool.exe 는 WSL interop 에서만)"; fi
  printf '%s\n' "$s"
}

# 이미지 힌트 (Pillow 정규화 이미지 → Tesseract / zbarimg)
IMAGE_TOOLS_LOCK="$REPO/scripts/image-tools-lock.json"
image_lock_ok() {
  [ -n "$PY" ] && [ -f "$PREFIX/$1/lock.sha256" ] && [ -f "$IMAGE_TOOLS_LOCK" ] || return 1
  [ "$(cat "$PREFIX/$1/lock.sha256")" = "$(sha256sum "$IMAGE_TOOLS_LOCK" | cut -d' ' -f1)" ] || return 1
  "$PY" "$REPO/scripts/image_tools_lock.py" version "$1" --lock "$IMAGE_TOOLS_LOCK" >/dev/null
}
check_tesseract() {
  image_lock_ok tesseract && [ -x "$B/tesseract" ] && [ -n "$PY" ] || return 1
  local out
  out="$(timeout 10 "$B/tesseract" --version 2>/dev/null)" || return 1
  [ "${out%%$'\n'*}" = 'tesseract 4.1.1' ] || return 1
  "$PY" "$REPO/scripts/image_tools_lock.py" verify-models tesseract --lock "$IMAGE_TOOLS_LOCK" --models "$PREFIX/tesseract/tessdata" || return 1
  out="$(timeout 10 "$B/tesseract" --tessdata-dir "$PREFIX/tesseract/tessdata" --list-langs 2>/dev/null)" || return 1
  [[ $'\n'"$out"$'\n' == *$'\neng\n'* && $'\n'"$out"$'\n' == *$'\nkor\n'* ]]
}
install_tesseract() {
  [ -n "$PY" ] && [ "$HAVE_APT" = 1 ] || { echo "Python 3.10+ 와 dpkg-deb 가 필요합니다" >&2; return "$SKIP_RC"; }
  local root="$PREFIX/tesseract/root" data="$PREFIX/tesseract/tessdata" lang
  mkdir -p "$data"
  rm -f "$PREFIX/tesseract/lock.sha256"
  deb_fetch_extract debs-image-tools "$root" --locked "$IMAGE_TOOLS_LOCK" tesseract
  for lang in eng kor osd; do
    cp "$root/usr/share/tesseract-ocr/4.00/tessdata/$lang.traineddata" "$data/$lang.traineddata"
  done
  mkdir -p "$data/configs"
  printf 'tessedit_create_tsv 1\n' >"$data/configs/tsv"
  make_wrapper "$B/tesseract" "$root/usr/bin/tesseract" "$root" \
    "export TESSDATA_PREFIX='$data'" 'export OMP_THREAD_LIMIT=1'
  sha256sum "$IMAGE_TOOLS_LOCK" | cut -d' ' -f1 >"$PREFIX/tesseract/lock.sha256"
  check_tesseract
}
version_tesseract() { timeout 10 "$B/tesseract" --version 2>/dev/null | head -1; }
check_zbar() {
  image_lock_ok zbar && [ -x "$B/zbarimg" ] || return 1
  local out rc=0
  out="$(timeout 10 "$B/zbarimg" --version 2>/dev/null)" || return 1
  [ "$out" = 0.23.92 ] || return 1
  # 버전 조회만으로는 재배치한 ImageMagick 모듈을 검사하지 못한다. 합성 2×2 PGM 의 '코드 없음'(4)을 확인한다.
  printf 'P5\n2 2\n255\n\377\377\377\377' | timeout 10 "$B/zbarimg" --quiet --xml --nodbus --nodisplay PGM:- >/dev/null 2>&1 || rc=$?
  [ "$rc" = 4 ]
}
install_zbar() {
  [ -n "$PY" ] && [ "$HAVE_APT" = 1 ] || { echo "Python 3.10+ 와 dpkg-deb 가 필요합니다" >&2; return "$SKIP_RC"; }
  local root="$PREFIX/zbar/root" policy="$PREFIX/zbar/policy" coder
  mkdir -p "$policy"
  rm -f "$PREFIX/zbar/lock.sha256"
  deb_fetch_extract debs-image-tools "$root" --locked "$IMAGE_TOOLS_LOCK" zbar
  coder="$root/usr/lib/$LIBDIR/ImageMagick-6.9.11/modules-Q16/coders"
  [ -f "$coder/pnm.so" ] || { echo "고정 ImageMagick PNM 모듈이 없습니다: $coder" >&2; return 1; }
  # worker 가 만든 PNG/PGM 만 읽는다. 외부 delegate·필터는 필요하지 않다.
  cat >"$policy/policy.xml" <<'XML'
<policymap>
  <policy domain="delegate" rights="none" pattern="*"/>
  <policy domain="filter" rights="none" pattern="*"/>
  <policy domain="coder" rights="none" pattern="*"/>
  <policy domain="coder" rights="read" pattern="{PNG,PNM,PGM,PPM}"/>
  <policy domain="path" rights="none" pattern="@*"/>
  <policy domain="resource" name="memory" value="256MiB"/>
  <policy domain="resource" name="map" value="0"/>
  <policy domain="resource" name="disk" value="0"/>
  <policy domain="resource" name="width" value="16384"/>
  <policy domain="resource" name="height" value="16384"/>
  <policy domain="resource" name="thread" value="1"/>
</policymap>
XML
  make_wrapper "$B/zbarimg" "$root/usr/bin/zbarimg" "$root" \
    "export MAGICK_CODER_MODULE_PATH='$coder'" "export MAGICK_CONFIGURE_PATH='$policy'" \
    'unset MAGICK_HOME MAGICK_FILTER_MODULE_PATH DISPLAY DBUS_SESSION_BUS_ADDRESS' \
    'export OMP_THREAD_LIMIT=1'
  sha256sum "$IMAGE_TOOLS_LOCK" | cut -d' ' -f1 >"$PREFIX/zbar/lock.sha256"
  check_zbar
}
version_zbar() { timeout 10 "$B/zbarimg" --version 2>/dev/null; }

# 펌웨어 에뮬레이션 (pweh-emu, mcp-servers/emu-mcp). 실행 파일은 <prefix>/bin 에 링크하지 않는다 — 서버는 env.sh 의 절대 경로만 쓴다
# (배포판 QEMU 등 다른 실행 파일과 섞이지 않게). 위치 규칙은 src/pweh/toolsdir.py 의 emu_binary_candidates 와 같다.
QEMU_XTENSA_BIN="$PREFIX/qemu-esp/xtensa/qemu/bin/qemu-system-xtensa"
QEMU_RISCV32_BIN="$PREFIX/qemu-esp/riscv32/qemu/bin/qemu-system-riscv32"
QEMU_ESP_VERSION_LINE="QEMU emulator version 9.2.2 (${QEMU_ESP_VER})"
QEMU_ESP_ADMIN_PKGS="libgcrypt20 libglib2.0-0 libpixman-1-0 libsdl2-2.0-0 libslirp0"   # Espressif 가 안내하는 런타임 패키지
qemu_esp_version() {  # qemu_esp_version <실행 파일> — 설정 파일·기본 장치 없이 -version 의 첫 줄 (시간 제한, 터미널 입력 없음)
  local out
  out="$(timeout 20 "$1" -no-user-config -nodefaults -version </dev/null 2>/dev/null)" || return 1
  printf '%s\n' "${out%%$'\n'*}"
}
check_qemu_esp() {
  local b
  for b in "$QEMU_XTENSA_BIN" "$QEMU_RISCV32_BIN"; do
    [ -x "$b" ] && [ "$(qemu_esp_version "$b")" = "$QEMU_ESP_VERSION_LINE" ] || return 1
  done
}
qemu_esp_loads() {  # qemu_esp_loads <실행 파일> — 실행 파일과 공유 라이브러리가 실제로 올라오는가. 아니면 빠진 것과 관리자 안내
  local b=$1 rc=0 deps missing
  timeout 20 "$b" -no-user-config -nodefaults -version >/dev/null 2>&1 </dev/null || rc=$?
  deps="$(ldd "$b" 2>&1 || true)"   # pipefail 아래 '… | grep' 대신 먼저 받는다
  missing="$(printf '%s\n' "$deps" | awk '/not found/ {print $1}' | sort -u | tr '\n' ' ')"
  if [ "$rc" -ne 126 ] && [ "$rc" -ne 127 ] && [ -z "${missing// /}" ]; then return 0; fi
  echo "${b#"$PREFIX"/} 가 실행되지 않습니다 (종료 코드 $rc)." >&2
  if [ -n "${missing// /}" ]; then echo "  빠진 공유 라이브러리: $missing" >&2; fi
  echo "  관리자에게 Espressif 가 안내하는 런타임 패키지 설치를 요청하세요: sudo apt-get install $QEMU_ESP_ADMIN_PKGS" >&2
  echo "  (PWEH 는 개인 경로에 라이브러리를 받거나 LD_LIBRARY_PATH 를 쓰지 않는다. 선택 구성요소라 나머지 설치는 계속된다)" >&2
  return 1
}
install_qemu_esp() {
  local ax="$CACHE/qemu-esp/qemu-xtensa-softmmu-${QEMU_ESP_VER}-x86_64-linux-gnu.tar.xz"
  local ar="$CACHE/qemu-esp/qemu-riscv32-softmmu-${QEMU_ESP_VER}-x86_64-linux-gnu.tar.xz"
  fetch "$QEMU_XTENSA_URL" "$ax" "$QEMU_XTENSA_SHA"
  fetch "$QEMU_RISCV32_URL" "$ar" "$QEMU_RISCV32_SHA"
  # 두 압축 파일 모두 qemu/ 로 풀리므로 디렉터리를 나눈다. QEMU 는 ROM 을 <bin>/../share/qemu 에서 찾으므로 bin/·share/ 를 함께 둔다
  rm -rf "$PREFIX/qemu-esp/xtensa" "$PREFIX/qemu-esp/riscv32"
  extract "$ax" "$PREFIX/qemu-esp/xtensa"
  extract "$ar" "$PREFIX/qemu-esp/riscv32"
  local b bad=0
  for b in "$QEMU_XTENSA_BIN" "$QEMU_RISCV32_BIN"; do
    [ -x "$b" ] || { echo "압축 파일에 ${b#"$PREFIX"/} 가 없습니다" >&2; return 1; }
    qemu_esp_loads "$b" || bad=1
  done
  [ "$bad" = 0 ] || return 1
  check_qemu_esp || { echo "QEMU 버전이 고정값($QEMU_ESP_VERSION_LINE)과 다릅니다" >&2; return 1; }
}
version_qemu_esp() { echo "Espressif QEMU 9.2.2 (${QEMU_ESP_VER}) xtensa+riscv32 ($PREFIX/qemu-esp)"; }

AVR_RUN="$PREFIX/simavr/bin/pweh_avr_run"
AVR_RUN_SRC="$REPO/native/emu/pweh_avr_run.c"
avr_run_src_version() { sed -n 's/^#define PWEH_AVR_RUN_VERSION "\([^"]*\)".*/\1/p' "$AVR_RUN_SRC" 2>/dev/null | head -n 1; }
avr_run_version() {  # avr_run_version <실행 파일> — --version 한 줄
  local out
  out="$(timeout 10 "$1" --version </dev/null 2>/dev/null)" || return 1
  printf '%s\n' "${out%%$'\n'*}"
}
# 소켓 함수(socket/bind/listen/accept/connect)를 가져오지도(동적 링크) 담지도(정적 링크) 않았는가. GDB 서버 코드(sim_gdb.o)가
# 링크되지 않았다는 확인이다. nm 이 없으면 objdump, 둘 다 없거나 기호 표가 비면 확인하지 못한 것으로 보고 실패한다
avr_run_no_sockets() {
  local f=$1 syms=""
  if command -v nm >/dev/null; then
    syms="$( { nm -D --undefined-only "$f" 2>/dev/null || true; nm "$f" 2>/dev/null || true; } | awk 'NF {print $NF}' | sed 's/@.*//')"
  elif command -v objdump >/dev/null; then
    syms="$( { objdump -T "$f" 2>/dev/null || true; objdump -t "$f" 2>/dev/null || true; } | awk 'NF {print $NF}' | sed 's/@.*//')"
  else
    echo "nm 도 objdump 도 없어 pweh_avr_run 의 소켓 함수 검사를 할 수 없습니다 (binutils)" >&2; return 1
  fi
  [ -n "$syms" ] || { echo "pweh_avr_run 의 기호 표를 읽지 못해 소켓 함수 검사를 할 수 없습니다" >&2; return 1; }
  if grep -Eqx '(socket|bind|listen|accept|accept4|connect)' <<<"$syms"; then
    echo "pweh_avr_run 에 소켓 함수가 링크되어 있습니다 (GDB 서버 코드) — 쓰지 않습니다" >&2; return 1
  fi
}
avr_run_ok() {  # avr_run_ok <실행 파일> — 고정 simavr 커밋 + 저장소 소스의 PWEH_AVR_RUN_VERSION, 소켓 함수 없음
  local f=$1 want
  want="pweh_avr_run $(avr_run_src_version) simavr $SIMAVR_COMMIT"
  [ -x "$f" ] && [ "$(avr_run_version "$f")" = "$want" ] && avr_run_no_sockets "$f"
}
check_simavr() { avr_run_ok "$AVR_RUN"; }   # 저장소 소스의 버전이 바뀌면 설치된 것으로 보지 않는다 (다시 빌드)
simavr_build() {  # simavr_build <소스> <cc> <ar> <ranlib> <출력> — libsimavr.a(라이브러리만) + pweh_avr_run 정적 링크
  local src=$1 cc=$2 ar=$3 ranlib=$4 out=$5 obj
  # libelf·libdwarf 자동 감지를 끈다 (ELF 해석기 없음). V=1 은 쓰지 않는다 (/tmp/simavr_conf.log 를 쓴다). -DNDEBUG 도 쓰지 않는다
  local mk=(RELEASE=1 C_LIBELF= LD_LIBELF= C_LIBDWARF= LD_LIBDWARF= "CC=$cc" "AR=$ar" "RANLIB=$ranlib")
  rm -rf "$src"/simavr/obj-* "$src/simavr/sim_core_config.h" "$src/simavr/sim_core_decl.h"   # 앞 컴파일러의 산출물
  make -C "$src/simavr" "${mk[@]}" obj config
  obj="obj-$("$cc" -dumpmachine)"
  make -C "$src/simavr" -j"$JOBS" "${mk[@]}" "$obj/libsimavr.a"
  "$cc" -std=gnu99 -O2 -Wall -I"$src/simavr/sim" -I"$src/simavr/sim/avr" -I"$src/simavr" \
    -DPWEH_SIMAVR_COMMIT="\"$SIMAVR_COMMIT\"" "$AVR_RUN_SRC" "$src/simavr/$obj/libsimavr.a" -lm -o "$out"
}
zig_cc_wrappers() {  # zig_cc_wrappers <디렉터리> — PWEH zig 의 cc/ar/ranlib 래퍼 (캐시는 <prefix>/_build 아래, ~/.cache/zig 를 쓰지 않음)
  local d=$1 t
  mkdir -p "$d" "$PREFIX/_build/zig-cache"
  for t in cc ar ranlib; do
    printf '%s\n' '#!/bin/sh' "# scripts/install.sh 가 만든 zig $t 래퍼 (simavr 빌드용)" \
      "ZIG_GLOBAL_CACHE_DIR='$PREFIX/_build/zig-cache'; ZIG_LOCAL_CACHE_DIR='$PREFIX/_build/zig-cache'" \
      'export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR' "exec '$B/zig' $t \"\$@\"" >"$d/$t.tmp"
    chmod +x "$d/$t.tmp"; mv -f "$d/$t.tmp" "$d/$t"
  done
}
install_simavr() {
  local t
  for t in git make; do
    command -v "$t" >/dev/null || { echo "simavr 소스 빌드에 '$t' 가 필요합니다 (관리자: sudo apt-get install git make)" >&2; return "$SKIP_RC"; }
  done
  # 컴파일러: PWEH zig 가 있으면 먼저 (고정 판으로 simavr 의 -Werror 빌드가 확인됨), 없거나 실패하면 시스템 cc
  local comps=()
  if check_zig; then comps+=(zig); fi
  if command -v cc >/dev/null; then comps+=(cc); fi
  [ ${#comps[@]} -gt 0 ] || { echo "C 컴파일러(cc)도 PWEH zig 도 없습니다 (관리자: sudo apt-get install build-essential, 또는 ./scripts/install.sh --only zig)" >&2; return "$SKIP_RC"; }
  [ -f "$AVR_RUN_SRC" ] && [ -n "$(avr_run_src_version)" ] || { echo "$AVR_RUN_SRC 에서 PWEH_AVR_RUN_VERSION 을 찾지 못했습니다" >&2; return 1; }
  local src="$PREFIX/_build/simavr-src" out="$PREFIX/simavr/bin/pweh_avr_run.tmp" c ok=0
  rm -rf "$src"
  mkdir -p "$src" "$PREFIX/simavr/bin"
  git -C "$src" init -q
  git -C "$src" fetch -q --depth 1 "$SIMAVR_GIT" "$SIMAVR_COMMIT"
  git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
  # 커밋으로 확인한다 (git 이 받은 내용의 해시가 곧 고정값)
  [ "$(git -C "$src" rev-parse HEAD)" = "$SIMAVR_COMMIT" ] || { echo "simavr 커밋이 고정값($SIMAVR_COMMIT)과 다릅니다" >&2; return 1; }
  local tc rc
  for c in "${comps[@]}"; do
    rm -f "$out"
    if [ "$c" = zig ]; then zig_cc_wrappers "$PREFIX/_build/zigcc"; tc="$PREFIX/_build/zigcc/"; else tc=""; fi
    echo "--- simavr + pweh_avr_run: ${tc:+PWEH zig }cc ---"
    # 조건 밖의 subshell 이라야 그 안의 set -e 가 산다 (run_component 와 같은 방식): 첫 실패에서 멈추고 종료 코드만 받는다
    set +e
    ( set -Eeuo pipefail; simavr_build "$src" "${tc}cc" "${tc}ar" "${tc}ranlib" "$out" )
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && [ -x "$out" ]; then ok=1; break; fi
    echo "${tc:+PWEH zig }cc 로 빌드하지 못했습니다 (종료 코드 $rc)" >&2
  done
  [ "$ok" = 1 ] || { echo "simavr·pweh_avr_run 빌드 실패 (위 로그 참고)" >&2; return 1; }
  # 바꾸기 전에 새 실행 파일을 확인한다: 고정 커밋·소스 버전, 소켓 함수 없음
  avr_run_ok "$out" || { echo "새로 빌드한 pweh_avr_run 이 확인을 통과하지 못했습니다 ($(avr_run_version "$out" || echo '--version 실패'))" >&2; rm -f "$out"; return 1; }
  mv -f "$out" "$AVR_RUN"
}
version_simavr() { avr_run_version "$AVR_RUN"; }

# ---------------------------------------------------------------------------
# env.sh
# ---------------------------------------------------------------------------
write_env() {
  local f="$PREFIX/env.sh" d
  [ -f "$f" ] && ! grep -q 'scripts/install.sh' "$f" && cp "$f" "$f.bak-$(date +%Y%m%d-%H%M%S)"
  {
    echo "# PWEH 외부 도구 환경 — scripts/install.sh 가 만듦 ($(date -u +%Y-%m-%dT%H:%M:%SZ)). bash/zsh 에서 source 한다:"
    echo "#     . $PREFIX/env.sh"
    echo "# 여러 번 source 해도 PATH 는 한 번만 더해진다. LD_LIBRARY_PATH 는 전역으로 바꾸지 않는다 (래퍼 안에서만)."
    echo "PWEH_TOOLS_DIR='$PREFIX'"
    echo "export PWEH_TOOLS_DIR"
    echo
    echo "for _pweh_dir in \\"
    # 실제로 실행되는 것만 PATH 에 (깨진 node/java 가 시스템 것을 가리지 않도록)
    if "$PREFIX/node/bin/node" --version >/dev/null 2>&1; then echo "    '$PREFIX/node/bin' \\"; fi
    if check_jdk; then echo "    '$PREFIX/jdk/$JDK_DIR_NAME/bin' \\"; fi
    [ -d "$PREFIX/extractors/bin" ] && echo "    '$PREFIX/extractors/bin' \\"
    echo "    '$PREFIX/bin'; do"
    echo '  case ":${PATH}:" in'
    echo '    *":${_pweh_dir}:"*) ;;'
    echo '    *) PATH="${_pweh_dir}${PATH:+:${PATH}}" ;;'
    echo '  esac'
    echo 'done'
    echo 'unset _pweh_dir'
    echo 'export PATH'
    echo
    if check_jdk; then echo "export JAVA_HOME='$PREFIX/jdk/$JDK_DIR_NAME'"; fi
    if check_ghidra; then
      echo "export GHIDRA_INSTALL_DIR='$GHIDRA_HOME'"
      echo "export PWEH_GHIDRA_HEADLESS='$GHIDRA_HOME/support/analyzeHeadless'"
    fi
    if check_sigrok; then echo "export REA_SIGROK_COMMAND='$B/sigrok-cli'"; echo "export PWEH_SIGROK_CLI='$B/sigrok-cli'"; fi
    if check_binwalk; then echo "export REA_BINWALK_COMMAND='$B/binwalk'"; echo "export PWEH_BINWALK='$B/binwalk'"; fi
    if check_unblob; then echo "export REA_UNBLOB_COMMAND='$B/unblob'"; echo "export PWEH_UNBLOB='$B/unblob'"; fi
    if check_openocd; then
      echo "export PWEH_OPENOCD='$B/openocd'"
      echo "export PWEH_OPENOCD_SCRIPTS='$PREFIX/openocd/xpack-openocd-${OPENOCD_VER}/openocd/scripts'"
      echo "export PWEH_OPENOCD_DUMMY='$B/openocd-dummy'"
    fi
    if check_squashfs; then echo "export PWEH_MKSQUASHFS='$B/mksquashfs'"; echo "export PWEH_UNSQUASHFS='$B/unsquashfs'"; fi
    if check_uboot; then echo "export PWEH_MKIMAGE='$B/mkimage'"; echo "export PWEH_MKENVIMAGE='$B/mkenvimage'"; echo "export PWEH_DUMPIMAGE='$B/dumpimage'"; fi
    if check_zig; then echo "export PWEH_ZIG='$B/zig'"; fi
    # esp-mcp 서버의 tools.esptool / tools.esptool_win. 두 판을 따로 판정한다 (Windows 판은 WSL interop 에서 실제로 실행될 때만)
    if esptool_linux_ok; then echo "export PWEH_ESPTOOL='$B/esptool'"; fi
    if esptool_win_ok; then echo "export PWEH_ESPTOOL_WIN='$ESPTOOL_WIN_EXE'"; fi
    # emu-mcp 서버의 tools.qemu_xtensa / tools.qemu_riscv32 / tools.avr_run: 확인을 통과한 절대 경로만 (PATH 에는 넣지 않는다)
    if check_qemu_esp; then echo "export PWEH_QEMU_XTENSA='$QEMU_XTENSA_BIN'"; echo "export PWEH_QEMU_RISCV32='$QEMU_RISCV32_BIN'"; fi
    if check_simavr 2>/dev/null; then echo "export PWEH_AVR_RUN='$AVR_RUN'"; fi
    if check_tesseract 2>/dev/null; then
      echo "export PWEH_TESSERACT='$B/tesseract'"
      echo "export PWEH_TESSDATA_DIR='$PREFIX/tesseract/tessdata'"
    fi
    if check_zbar 2>/dev/null; then echo "export PWEH_ZBARIMG='$B/zbarimg'"; fi
    if [ -x "$B/rea" ]; then echo "export PWEH_REA='$B/rea'"; fi
    if [ -x "$PREFIX/extractors/bin/lz4" ]; then echo "export PWEH_LZ4='$PREFIX/extractors/bin/lz4'"; fi
  } >"$f.tmp"
  mv -f "$f.tmp" "$f"
  # 기본 위치가 아니면 저장소에 가리키는 파일을 남긴다 (scripts/mcp-launch.sh, pweh.toolsdir 가 읽음, git 제외)
  if [ "$LINK" = 0 ]; then
    :
  elif [ "$PREFIX" != "$HOME/pweh-tools" ]; then
    mkdir -p "$REPO/.pweh"; echo "$f" >"$POINTER"
    say "  저장소가 이 도구 위치를 쓰도록 $POINTER 를 남겼음 (--no-link 로 끔)"
  elif [ -f "$POINTER" ]; then
    say "  $POINTER ($(head -n 1 "$POINTER")) 를 지웠음 — 이제 저장소는 $f 를 씀"
    rm -f "$POINTER"
  fi
  # --venv 가 기본(<저장소>/.venv)이 아니면 scripts/mcp-launch.sh 가 서버를 찾도록 알려 둔다
  if [ "$LINK" = 1 ] && [ "$VENV" != "$REPO/.venv" ] && [ -x "$VENV/bin/python" ]; then
    mkdir -p "$REPO/.pweh"; echo "$VENV" >"$REPO/.pweh/venv.path"
  elif [ "$LINK" = 1 ] && [ "$VENV" = "$REPO/.venv" ]; then
    rm -f "$REPO/.pweh/venv.path"
  fi
}

# ---------------------------------------------------------------------------
# 단계 (mcp, skills, verify): 구성요소와 env.sh 다음. pweh 는 --venv 의 것만 쓴다 (PATH 의 다른 pweh 로 넘어가지 않음).
# 설정 파일은 pweh 가 직접 쓰고(백업·원자적 교체), 이 스크립트는 동의를 받고 결과를 모아 요약한다.
# ---------------------------------------------------------------------------
PWEH_BIN="$VENV/bin/pweh"
CODEX_PROJECT_CFG="$REPO/.codex/config.toml"
REPO_REAL="$(cd "$REPO" && pwd -P)"   # Codex 의 신뢰 키는 저장소의 실제 경로다 (pweh.clientcfg.trust_key)
CURSOR_CFG="$REPO/.cursor/mcp.json"
declare -A STEP_RESULT=() STEP_BAD=()
CUR_STEP=""
STEP_NOTES=()      # 지금 단계의 결과 조각 (결과 표의 한 줄로 합침)
CHANGED=()         # 바뀐 파일 "W<TAB>경로"(새로 생김)·"E<TAB>경로"(있던 파일)와 백업 "B<TAB>경로" — 요약에 되돌리는 방법과 함께
WRITE_OUTPUTS=()   # 쓰기 호출의 출력에서 바뀐 파일·백업이 나온 줄 (찾지 못하면 출력 전체) — 요약에 그대로 다시 보여 준다
NEW_LINKS=()       # skills 단계가 새로 만든 링크
TRUST_ADDED=0
CODEX_CFG_OK=0
PW_OUT=""
PW_RC=0

pweh_ok() { [ -x "$PWEH_BIN" ]; }
pweh_missing() { printf 'pweh 가 없습니다 (%s) — ./scripts/install.sh --only python 또는 --venv\n' "$PWEH_BIN"; }
# env.sh 를 읽은 subshell 에서 pweh 를 실행한다 (MCP 서버가 scripts/mcp-launch.sh 로 env.sh 를 읽는 것과 같게).
# 표준 입력은 /dev/null 이라 pweh 가 스스로 묻는 일은 없다 (동의는 이 스크립트가 받아 --yes 로 넘긴다).
# Codex 홈 감지는 WSL interop 을 거치므로 멈춰도 끝나도록 시간 제한을 둔다 (--foreground: Ctrl-C 가 pweh 에도 간다)
# PWEH_CONFIG 를 이 저장소의 설정으로 정한다(이미 정했으면 그대로): 다른 디렉터리에서 실행해도 doctor 가 그곳의 설정을 찾거나
# 그곳에 cases/·.pweh/state 를 만들지 않는다 (cd 하지 않는다 — 상대 경로 CODEX_HOME 의 뜻이 바뀌지 않게)
pweh_exec() {  # pweh_exec <초> <인자...>
  local limit=$1; shift
  ( set +eu
    if [ -f "$PREFIX/env.sh" ]; then . "$PREFIX/env.sh" >/dev/null 2>&1; fi
    if [ -z "${PWEH_CONFIG:-}" ] && [ -f "$REPO/orchestrator/pipeline-config.yaml" ]; then export PWEH_CONFIG="$REPO/orchestrator/pipeline-config.yaml"; fi
    exec timeout --foreground "$limit" "$PWEH_BIN" "$@" ) </dev/null
}
pweh_capture() {  # pweh_capture <초> <인자...> → PW_OUT (표준 출력과 오류), PW_RC
  PW_RC=0
  PW_OUT="$(pweh_exec "$@" 2>&1)" || PW_RC=$?
  shift
  printf '$ pweh %s → 종료 코드 %s\n' "$*" "$PW_RC" >>"$LOG"
}
pweh_unsupported() {  # 마지막 호출이 "모르는 명령·옵션"(argparse, 종료 코드 2)으로 끝났는가 — 가상환경의 pweh 가 이 저장소와 다른 판
  [ "$PW_RC" = 2 ] || return 1
  case "$PW_OUT" in *"invalid choice"*|*"unrecognized arguments"*) return 0 ;; esac
  return 1
}
pweh_why() {  # 마지막 호출이 실패한 까닭 (한 줄)
  if pweh_unsupported; then echo "pweh 가 이 명령·옵션을 모릅니다 — 가상환경의 pweh 가 이 저장소와 같은 판인지 확인: ./scripts/install.sh --only python --force"
  elif [ "$PW_RC" = 124 ]; then echo "시간 초과"
  else
    case "$PW_OUT" in
      *"tomlkit 이 없다"*|*ModuleNotFoundError*|*"No module named"*)
        echo "종료 코드 $PW_RC — 가상환경에 Python 패키지가 빠졌습니다 (이전 판으로 만든 가상환경): ./scripts/install.sh --only python --force" ;;
      *) echo "종료 코드 $PW_RC" ;;
    esac
  fi
}
step_failed() {  # step_failed <무엇> <명령> — 마지막 pweh 호출의 실패를 알리고 지금 단계를 실패로 센다
  warn "$1: pweh $2 실패 ($(pweh_why))"
  show_out "$PW_OUT" log
  STEP_BAD[$CUR_STEP]=1
  STEP_NOTES+=("$1 실패")
}
show_out() {  # show_out <텍스트> [log] — 들여 써서 화면에. log 이면 로그에도 (diff 에는 사용자 설정의 다른 줄이 섞일 수 있어 남기지 않는다)
  [ -n "$1" ] || return 0
  printf '%s\n' "$1" | sed 's/^/      | /' >&3
  if [ "${2:-}" = log ]; then printf '%s\n' "$1" | sed 's/^/      | /' >>"$LOG"; fi
}
has_diff() { case $'\n'"$1" in *$'\n+++ '*) return 0 ;; esac; return 1; }   # unified diff 가 있는가 (바뀔 파일마다 '+++ ' 줄)
only_path_diff() {  # 바뀌는 줄이 모두 서버 env 의 PATH 줄인가 — 실행한 셸의 PATH 를 담은 값이라 셸마다 다르다 (pweh doctor 도 최신 판정에서 뺀다)
  local l n=0
  while IFS= read -r l; do
    case "$l" in
      "+++ "*|"--- "*|"@@"*) ;;
      "+PATH = "*|"-PATH = "*) n=$((n + 1)) ;;
      [+-]*) return 1 ;;
    esac
  done <<<"$1"
  [ "$n" -gt 0 ]
}
diff_files() {  # diff_files <diff> — 바뀔 파일을 알리는 '+++ ' 줄만
  local l
  while IFS= read -r l; do case "$l" in "+++ "*) printf '%s\n' "$l" ;; esac; done <<<"$1"
}
ask_yes() {  # ask_yes <질문> — 표준 오류에 묻고 표준 입력에서 y/yes/예 면 0. 빈 입력·EOF 는 아니오
  local ans=""
  printf '\n  %s [y/N] ' "$1" >&2
  read -r ans || ans=""
  case "$ans" in y|Y|yes|Yes|YES|예|네) return 0 ;; esac
  return 1
}

# 쓰기 호출이 바꾼 파일 찾기 (시각·출력 형식에 기대지 않음):
# - 호출 전후로 후보 파일(프로젝트 설정, Cursor 설정, ~/.codex·$CODEX_HOME·--codex-home 의 config.toml)의 내용(sha256)을 비교한다.
# - 출력에 나온 *.bak-pweh-* 백업은 그 원본도 바뀐 파일로 본다 (자동 감지한 데스크톱 앱 홈처럼 후보 밖의 파일).
# 경로는 실제 경로로 푼다 (pweh 는 심볼릭 링크가 가리키는 파일을 백업하고 고친다)
SNAP_PY='
import hashlib, os, sys
for p in sys.argv[1:]:
    try:
        with open(p, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        h = "-"
    print(os.path.realpath(p) + "\t" + h)
'
snapshot() {  # snapshot → "실제 경로<TAB>sha256 또는 -" 줄 (Python 3.10 이 없으면 빈 출력)
  local h cand=("$CODEX_PROJECT_CFG" "$CURSOR_CFG" "$HOME/.codex/config.toml")
  if [ -n "${CODEX_HOME:-}" ]; then cand+=("$CODEX_HOME/config.toml"); fi
  for h in ${CODEX_HOMES[@]+"${CODEX_HOMES[@]}"}; do cand+=("$h/config.toml"); done
  if [ -n "$PY" ]; then "$PY" -I -c "$SNAP_PY" "${cand[@]}" 2>/dev/null || true; fi
}
# 인자: "N:<경로>"(새로 생김) / "C:<경로>"(있던 파일이 바뀜). 표준 입력: pweh 출력.
# 출력: "B<TAB>백업", "W<TAB>바뀐 파일", "E<TAB>바뀐 파일(전에 있었음)", "L<TAB>그런 파일이 나온 출력 줄"
CHANGES_PY='
import os, re, sys
start = re.compile(r"(?:^|(?<=[\s(\[:=\x27\x22`]))/")
def paths(line):
    for m in start.finditer(line):
        i, j = m.start(), len(line)
        while j > i + 1:
            cand = line[i:j].rstrip(" \t)].,;:\x27\x22`")
            if os.path.isfile(cand):
                yield cand, os.path.realpath(cand)
                break
            j = max(line.rfind(c, i + 1, j) for c in " \t()[]\x27\x22`,;")
text = sys.stdin.read().splitlines()
found = [list(paths(line)) for line in text]
written = [a[2:] for a in sys.argv[1:]]
existed = {a[2:] for a in sys.argv[1:] if a.startswith("C:")}
backups = []
for row in found:
    for cand, real in row:
        if ".bak-pweh-" in os.path.basename(cand) and real not in backups:
            backups.append(real)
for b in backups:
    orig = os.path.join(os.path.dirname(b), os.path.basename(b).split(".bak-pweh-")[0])
    existed.add(orig)
    if orig not in written and os.path.isfile(orig):
        written.append(orig)
for b in backups:
    print("B\t" + b)
for w in written:
    print(("E" if w in existed else "W") + "\t" + w)
marks = set(backups) | set(written)
for line, row in zip(text, found):
    if any(real in marks for _cand, real in row):
        print("L\t" + line)
'
RC_CHANGED=0   # 마지막 record_changes 가 바뀐 파일·백업을 찾았는가 (Python 이 없어 알 수 없으면 1)
record_changes() {  # record_changes <호출 전 snapshot> <출력> — CHANGED 와 WRITE_OUTPUTS(바뀐 파일·백업이 나온 줄)에 더한다
  local before=$1 text=$2 line e x dup said="" known=()
  RC_CHANGED=1
  if [ -n "$PY" ]; then
    RC_CHANGED=0
    while IFS= read -r line; do   # 호출 전후로 내용이 달라졌고 지금 있는 후보
      case "$line" in ""|*$'\t-') continue ;; esac
      case $'\n'"$before"$'\n' in
        *$'\n'"$line"$'\n'*) ;;
        *$'\n'"${line%%$'\t'*}"$'\t-\n'*) known+=("N:${line%%$'\t'*}") ;;
        *$'\n'"${line%%$'\t'*}"$'\t'*) known+=("C:${line%%$'\t'*}") ;;
        *) known+=("N:${line%%$'\t'*}") ;;
      esac
    done <<<"$(snapshot)"
    while IFS= read -r e; do
      case "$e" in
        L$'\t'*) said="${said:+$said$'\n'}${e#L?}"; continue ;;
        W$'\t'*|E$'\t'*|B$'\t'*) RC_CHANGED=1 ;;
        *) continue ;;
      esac
      dup=0
      for x in ${CHANGED[@]+"${CHANGED[@]}"}; do if [ "${x#?}" = "${e#?}" ]; then dup=1; fi; done
      if [ "$dup" = 0 ]; then CHANGED+=("$e"); fi
    done < <(printf '%s\n' "$text" | "$PY" -I -c "$CHANGES_PY" ${known[@]+"${known[@]}"} 2>/dev/null)
    # 내용이 바뀐 후보 파일도 출력에 나온 백업도 없으면 바뀐 것이 없다 (예: "변경 없음") — 요약에 넣지 않는다.
    # 후보 밖에서 바뀌는 파일은 모두 있던 파일이라 pweh 가 백업을 남기고 그 경로를 출력한다
    if [ "$RC_CHANGED" = 0 ]; then return 0; fi
  fi
  # 바뀐 파일이 나온 줄을 찾지 못했으면 출력 전체를 그대로 남긴다 (요약의 근거)
  if [ -n "$said" ]; then WRITE_OUTPUTS+=("$said"); elif [ -n "$text" ]; then WRITE_OUTPUTS+=("$text"); fi
}

# --- mcp: Claude Code ------------------------------------------------------
# 저장소의 .mcp.json·.claude/settings.json (그리고 settings.local.json 의 disabledMcpjsonServers)을 읽기만 한다 (~/.claude* 는 읽지 않음).
# 기대하는 서버는 `pweh mcp-config --client claude` 의 출력(있으면), 없으면 .mcp.json 자체. 출력 줄: "ok|bad|warn<TAB>내용"
CLAUDE_CHECK_PY='
import json, os, sys
repo, gen_text = sys.argv[1], sys.argv[2]
def load(rel):
    try:
        with open(os.path.join(repo, rel), encoding="utf-8") as f:
            return json.load(f), ""
    except FileNotFoundError:
        return None, rel + " 없음"
    except (OSError, ValueError) as exc:
        return None, rel + " 을 읽지 못함 (" + type(exc).__name__ + ")"
mcp, err = load(".mcp.json")
servers = mcp.get("mcpServers") if isinstance(mcp, dict) else None
if not isinstance(servers, dict) or not servers:
    print("bad\t" + (err or ".mcp.json 에 mcpServers 가 없음"))
    sys.exit(0)
problems, names, gen = [], list(servers), None
if "{" in gen_text:
    try:
        gen = json.JSONDecoder().raw_decode(gen_text, gen_text.index("{"))[0].get("mcpServers")
    except (ValueError, AttributeError):
        gen = None
if isinstance(gen, dict) and gen:
    names = list(gen)
    missing = [n for n in gen if n not in servers]
    differ = [n for n in gen if n in servers and servers[n] != gen[n]]
    if missing:
        problems.append(".mcp.json 에 없는 서버: " + ", ".join(missing))
    if differ:
        problems.append("pweh mcp-config --client claude 결과와 다른 서버: " + ", ".join(differ))
else:
    gen = None
settings, err = load(os.path.join(".claude", "settings.json"))
if not isinstance(settings, dict):
    problems.append(err or ".claude/settings.json 형식이 다름")
elif settings.get("enableAllProjectMcpServers") is not True:
    enabled = settings.get("enabledMcpjsonServers")
    off = [n for n in names if not isinstance(enabled, list) or n not in enabled]
    if off:
        problems.append("enabledMcpjsonServers 에 없는 서버: " + ", ".join(off))
local = load(os.path.join(".claude", "settings.local.json"))[0]
disabled = local.get("disabledMcpjsonServers") if isinstance(local, dict) else None
if problems:
    print("bad\t" + "; ".join(problems))
else:
    print("ok\t.mcp.json 의 서버 " + str(len(names)) + "개가 모두 enabledMcpjsonServers 에 있음" + (" (생성 결과와 같음)" if gen else ""))
off = [n for n in names if isinstance(disabled, list) and n in disabled]
if off:
    print("warn\t.claude/settings.local.json 의 disabledMcpjsonServers 가 끈 서버: " + ", ".join(off))
'
claude_status() {  # claude_status → CL_LINES ("ok|bad|warn<TAB>내용")
  local gen="" line
  CL_LINES=()
  if pweh_ok; then
    pweh_capture 120 mcp-config --client claude
    if [ "$PW_RC" = 0 ]; then gen="$PW_OUT"; fi
  fi
  if [ -z "$PY" ]; then   # Python 3.10 이 없으면 있는지만 본다
    if [ -f "$REPO/.mcp.json" ] && grep -q enabledMcpjsonServers "$REPO/.claude/settings.json" 2>/dev/null; then
      CL_LINES=("ok"$'\t'".mcp.json 과 enabledMcpjsonServers 가 있음 (Python 3.10 이 없어 내용은 확인하지 못함)")
    else
      CL_LINES=("bad"$'\t'".mcp.json 또는 .claude/settings.json 의 enabledMcpjsonServers 가 없음")
    fi
    return 0
  fi
  while IFS= read -r line; do if [ -n "$line" ]; then CL_LINES+=("$line"); fi; done < <("$PY" -I -c "$CLAUDE_CHECK_PY" "$REPO" "$gen" 2>&1)
  if [ ${#CL_LINES[@]} -eq 0 ]; then CL_LINES=("bad"$'\t'"확인하지 못함"); fi
}

# --- mcp: Codex --------------------------------------------------------------
codex_config_args() {  # CX_ARGS — 설치·--check·--dry-run 이 같은 대상을 보도록 한곳에서 만든다
  local h   # --codex-home 은 프로젝트 범위에도 넘긴다 (pweh 가 신뢰 항목이 없는 홈을 안내할 때 지정한 홈만 본다)
  CX_ARGS=(mcp-config --client codex --write)
  if [ "$CODEX_SCOPE" = global ]; then CX_ARGS+=(--scope global); fi
  for h in ${CODEX_HOMES[@]+"${CODEX_HOMES[@]}"}; do CX_ARGS+=(--codex-home "$h"); done
}
codex_home_args() {  # CH_ARGS — 신뢰의 --check·--dry-run·--yes 가 같은 대상을 보도록
  local h
  CH_ARGS=()
  for h in ${CODEX_HOMES[@]+"${CODEX_HOMES[@]}"}; do CH_ARGS+=(--codex-home "$h"); done
}
codex_config() {  # MCP 서버 등록: 프로젝트 설정(기본) 또는 Codex 홈의 config.toml (--codex-global — pweh 가 백업 후 고친다)
  local before where="$CODEX_PROJECT_CFG"
  [ "$CODEX_SCOPE" = project ] || where="Codex 홈의 config.toml (--codex-global)"
  codex_config_args
  if [ "$DRYRUN" = 1 ]; then
    pweh_capture 300 "${CX_ARGS[@]}" --dry-run
    if [ "$PW_RC" != 0 ]; then step_failed "Codex 설정" "${CX_ARGS[*]} --dry-run"; return 0; fi
    CODEX_CFG_OK=1
    if has_diff "$PW_OUT"; then info "Codex 설정: 바뀔 내용 — $where (dry-run 이라 쓰지 않음)"; STEP_NOTES+=("Codex 설정 바뀔 것 있음")
    else info "Codex 설정: 바뀔 것 없음 — $where"; STEP_NOTES+=("Codex 설정 최신"); fi
    show_out "$PW_OUT"
    return 0
  fi
  before="$(snapshot)"
  pweh_capture 300 "${CX_ARGS[@]}"
  if [ "$PW_RC" != 0 ]; then step_failed "Codex 설정" "${CX_ARGS[*]}"; return 0; fi
  if [ "$CODEX_SCOPE" = project ] && [ ! -f "$CODEX_PROJECT_CFG" ]; then
    warn "Codex 설정: pweh 가 $CODEX_PROJECT_CFG 를 만들지 않았습니다 (가상환경의 pweh 가 이 저장소의 것인지 확인)"
    show_out "$PW_OUT" log; STEP_BAD[mcp]=1; STEP_NOTES+=("Codex 설정 실패"); return 0
  fi
  CODEX_CFG_OK=1
  info "Codex 설정: $where"
  show_out "$PW_OUT" log
  record_changes "$before" "$PW_OUT"
  if [ "$RC_CHANGED" = 1 ]; then STEP_NOTES+=("Codex 설정 씀"); else STEP_NOTES+=("Codex 설정 최신"); fi
}
codex_trust() {  # Codex 가 프로젝트 설정을 읽도록 Codex 홈에 이 저장소의 신뢰 항목. 동의(대화형 확인·--codex-trust) 없이는 바꾸지 않는다
  local before
  if [ "$TRUST" = no ]; then info "Codex 신뢰: 건너뜀 (--no-codex-trust)"; STEP_NOTES+=("신뢰 건너뜀"); return 0; fi
  if [ "$CODEX_SCOPE" = global ] && [ "$TRUST" = ask ]; then info "Codex 신뢰: 필요 없음 (--codex-global 은 Codex 홈에 직접 등록)"; return 0; fi
  codex_home_args
  if [ "$DRYRUN" = 1 ]; then
    pweh_capture 300 codex-trust --dry-run ${CH_ARGS[@]+"${CH_ARGS[@]}"}
    if [ "$PW_RC" != 0 ]; then step_failed "Codex 신뢰" "codex-trust --dry-run"; return 0; fi
    if has_diff "$PW_OUT"; then info "Codex 신뢰: 바뀔 내용 (dry-run 이라 쓰지 않음 — 설치할 때는 대화형으로 묻거나 --codex-trust)"; STEP_NOTES+=("신뢰 바뀔 것 있음")
    else info "Codex 신뢰: 바뀔 것 없음"; STEP_NOTES+=("신뢰 바뀔 것 없음"); fi
    show_out "$PW_OUT"
    return 0
  fi
  pweh_capture 300 codex-trust --check ${CH_ARGS[@]+"${CH_ARGS[@]}"}
  case "$PW_RC" in
    0) info "Codex 신뢰: ✓ 이 저장소를 신뢰하지 않는 Codex 홈이 없음"; show_out "$PW_OUT" log; STEP_NOTES+=("신뢰 ✓"); return 0 ;;
    1) ;;
    *) step_failed "Codex 신뢰" "codex-trust --check"; return 0 ;;   # 확인할 수 없으면 묻지도 바꾸지도 않는다
  esac
  info "Codex 신뢰: 이 저장소를 신뢰하지 않는 Codex 홈이 있습니다. Codex 는 신뢰한 프로젝트의 .codex/config.toml 만 읽습니다"
  show_out "$PW_OUT" log
  if [ "$TRUST" = ask ]; then
    if ! [ -t 0 ] || ! [ -t 2 ]; then
      info "대화형 터미널이 아니라 묻지 않았고 아무것도 바꾸지 않았습니다. 동의하면: ./scripts/install.sh --only mcp --codex-trust"
      STEP_NOTES+=("신뢰 안 함 — 대화형이 아님 (--codex-trust 로 동의)")
      return 0
    fi
    pweh_capture 300 codex-trust --dry-run ${CH_ARGS[@]+"${CH_ARGS[@]}"}
    if [ "$PW_RC" != 0 ]; then step_failed "Codex 신뢰" "codex-trust --dry-run"; return 0; fi
    if ! has_diff "$PW_OUT"; then
      info "바뀔 내용(diff)을 받지 못해 묻지 않았고 아무것도 바꾸지 않았습니다"
      show_out "$PW_OUT"; STEP_NOTES+=("신뢰 안 함 — 바뀔 내용 없음"); return 0
    fi
    if [ -t 3 ]; then
      info "신뢰 항목을 더하면 다음처럼 바뀝니다 (바꾸기 전에 config.toml.bak-pweh-<UTC 시각> 으로 백업):"
      show_out "$PW_OUT"
    else   # 표준 출력이 파일·파이프(tee 등)면 묻는 화면(표준 오류)에 바뀔 내용을 보여 준다 — 보지 않고 동의하지 않도록
      info "신뢰 항목을 더할지 묻습니다 (바뀔 내용은 묻는 화면에 보여 줌)"
      { printf '\n    신뢰 항목을 더하면 다음처럼 바뀝니다 (바꾸기 전에 config.toml.bak-pweh-<UTC 시각> 으로 백업):\n'
        printf '%s\n' "$PW_OUT" | sed 's/^/      | /'; } >&2
    fi
    if ! ask_yes "위 Codex 홈의 config.toml 에 이 저장소의 신뢰 항목을 더할까요? (신뢰한 프로젝트에서는 Codex 가 .codex/config.toml 을 읽고 폴더 신뢰를 묻지 않음)"; then
      echo "Codex 신뢰: 사용자가 거절" >>"$LOG"
      info "바꾸지 않았습니다. 나중에 동의하면: ./scripts/install.sh --only mcp --codex-trust"
      STEP_NOTES+=("신뢰 안 함 — 거절"); return 0
    fi
    echo "Codex 신뢰: 사용자가 동의" >>"$LOG"
    info "동의함 — 신뢰 항목을 더합니다:"
  else
    info "--codex-trust 로 동의함 — 신뢰 항목을 더합니다 (바꾸기 전에 백업):"
  fi
  before="$(snapshot)"
  pweh_capture 300 codex-trust --yes ${CH_ARGS[@]+"${CH_ARGS[@]}"}
  if [ "$PW_RC" != 0 ]; then step_failed "Codex 신뢰" "codex-trust --yes"; return 0; fi
  show_out "$PW_OUT" log
  record_changes "$before" "$PW_OUT"
  TRUST_ADDED=1
  pweh_capture 300 codex-trust --check ${CH_ARGS[@]+"${CH_ARGS[@]}"}
  if [ "$PW_RC" != 0 ]; then
    warn "Codex 신뢰: 항목을 더했지만 다시 확인(codex-trust --check)이 실패했습니다 ($(pweh_why))"
    show_out "$PW_OUT" log; STEP_BAD[mcp]=1; STEP_NOTES+=("신뢰 확인 실패"); return 0
  fi
  info "Codex 신뢰: ✓ 더함"
  STEP_NOTES+=("신뢰 더함")
}

# --- mcp: Cursor (--cursor) ------------------------------------------------
# <저장소>/.cursor/mcp.json 이 없으면 만들고, 있으면 PWEH 항목만 바꾼다: 옛 pweh-* 는 빼고, 다른 서버와 사용자가 따로 둔 rea 는 그대로.
# 바꾸기 전에 .bak-pweh-<UTC 시각> 으로 백업하고 원자적으로 교체한다. 인자: 경로, 생성한 JSON, dry-run(0|1), 시각
CURSOR_PY='
import difflib, json, os, shutil, sys, tempfile
path, gen_text, dry, stamp = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4]
try:
    gen = json.JSONDecoder().raw_decode(gen_text, gen_text.index("{"))[0]["mcpServers"]
    if not isinstance(gen, dict) or not gen:
        raise ValueError
except (ValueError, KeyError, TypeError):
    sys.exit("pweh mcp-config --client cursor 의 출력을 읽지 못함")
old_text, kept = None, []
if os.path.lexists(path):
    if os.path.islink(path) or not os.path.isfile(path):
        sys.exit("일반 파일이 아니라 바꾸지 않음: " + path)
    with open(path, encoding="utf-8") as f:
        old_text = f.read()
    try:
        doc = json.loads(old_text)
    except ValueError:
        sys.exit("올바른 JSON 이 아니라 바꾸지 않음: " + path)
    if not isinstance(doc, dict) or not isinstance(doc.get("mcpServers", {}), dict):
        sys.exit("mcpServers 형식이 달라 바꾸지 않음: " + path)
    servers = dict(doc.get("mcpServers") or {})
    for name in [n for n in servers if n.startswith("pweh-") and n not in gen]:
        del servers[name]
    for name, spec in gen.items():
        if name == "rea" and "rea" in servers and servers["rea"] != spec:
            kept.append(name)
            continue
        servers[name] = spec
    new = dict(doc)
    new["mcpServers"] = servers
    if new == doc:
        print("최신")
        sys.exit(0)
else:
    new = {"mcpServers": gen}
new_text = json.dumps(new, ensure_ascii=False, indent=2) + "\n"
if dry:
    sys.stdout.writelines(difflib.unified_diff((old_text or "").splitlines(True), new_text.splitlines(True),
                                               path if old_text is not None else "/dev/null", path))
    sys.exit(0)
d = os.path.dirname(path)
os.makedirs(d, exist_ok=True)
mode = 0o644
if old_text is not None:
    mode = os.stat(path).st_mode & 0o7777
    bak, k = path + ".bak-pweh-" + stamp, 1
    while os.path.lexists(bak):
        k += 1
        bak = path + ".bak-pweh-" + stamp + "-" + str(k)
    shutil.copy2(path, bak)
    print("백업: " + bak)
fd, tmp = tempfile.mkstemp(dir=d, prefix=".mcp.json.")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(new_text)
os.chmod(tmp, mode)
os.replace(tmp, path)
print("작성: " + path)
for name in kept:
    print("사용자가 따로 둔 " + name + " 항목은 그대로 둠")
'
cursor_merge() {  # cursor_merge <dry-run 0|1> → CM_OUT, CM_RC
  CM_RC=0; CM_OUT=""
  if ! pweh_ok; then CM_RC=1; CM_OUT="$(pweh_missing)"; return 0; fi
  if [ -z "$PY" ]; then CM_RC=1; CM_OUT="Python 3.10 이상이 필요합니다"; return 0; fi
  pweh_capture 120 mcp-config --client cursor
  if [ "$PW_RC" != 0 ]; then CM_RC=1; CM_OUT="pweh mcp-config --client cursor 실패 ($(pweh_why))"$'\n'"$PW_OUT"; return 0; fi
  CM_OUT="$("$PY" -I -c "$CURSOR_PY" "$CURSOR_CFG" "$PW_OUT" "$1" "$(date -u +%Y%m%dT%H%M%SZ)" 2>&1)" || CM_RC=$?
}
cursor_config() {
  local before
  before="$(snapshot)"
  cursor_merge "$DRYRUN"
  if [ "$CM_RC" != 0 ]; then warn "Cursor: $CURSOR_CFG 를 바꾸지 않았습니다"; show_out "$CM_OUT" log; STEP_BAD[mcp]=1; STEP_NOTES+=("Cursor 실패"); return 0; fi
  if [ "$CM_OUT" = 최신 ]; then info "Cursor: ✓ 최신 ($CURSOR_CFG)"; STEP_NOTES+=("Cursor ✓"); return 0; fi
  if [ "$DRYRUN" = 1 ]; then info "Cursor: 바뀔 내용 (dry-run 이라 쓰지 않음)"; show_out "$CM_OUT"; STEP_NOTES+=("Cursor 바뀔 것 있음"); return 0; fi
  info "Cursor: $CURSOR_CFG"
  show_out "$CM_OUT" log
  record_changes "$before" "$CM_OUT"
  STEP_NOTES+=("Cursor 씀")
}

step_mcp() {
  local line st msg bad=0
  claude_status
  for line in "${CL_LINES[@]}"; do
    st="${line%%$'\t'*}"; msg="${line#*$'\t'}"
    case "$st" in
      ok) info "Claude Code: ✓ $msg" ;;
      warn) warn "Claude Code: $msg" ;;
      *) warn "Claude Code: $msg"
         info "  이 스크립트는 고치지 않습니다 — $PWEH_BIN mcp-config --client claude --write --force 와 .claude/settings.json 의 enabledMcpjsonServers 확인"
         bad=1 ;;
    esac
  done
  if [ "$bad" = 1 ]; then STEP_BAD[mcp]=1; STEP_NOTES+=("Claude 확인 필요"); else STEP_NOTES+=("Claude ✓"); fi
  if ! pweh_ok; then
    warn "Codex: $(pweh_missing)"; STEP_BAD[mcp]=1; STEP_NOTES+=("Codex 못 함 — pweh 없음")
  else
    codex_config
    if [ "$CODEX_CFG_OK" = 1 ]; then codex_trust
    else info "Codex 신뢰: Codex 설정을 쓰지 못해 묻지 않고 건너뜀"; fi
  fi
  if [ "$CURSOR" = 1 ]; then cursor_config; fi
}

# --- skills --------------------------------------------------------------
SKILLS_PY='
import json, sys
text = sys.stdin.read()
try:
    doc = json.JSONDecoder().raw_decode(text, text.index("{"))[0]
except ValueError:
    sys.exit(0)
for r in (doc.get("results") or []) if isinstance(doc, dict) else []:
    if isinstance(r, dict):
        print("\t".join(str(r.get(k, "")) for k in ("status", "skill", "path")))
'
skills_dest() { case "$1" in claude-project) echo "$REPO/.claude/skills" ;; *) echo "$REPO/.agents/skills" ;; esac; }
skills_status() {  # skills_status <디렉터리> → SK_COUNT ("링크됨/전체"), SK_MISSING. 모두 링크됐으면 0 (pweh 의 already-installed 와 같은 판정)
  local dest=$1 d name n=0 total=0
  SK_MISSING=""
  for d in "$REPO"/skills/*/; do
    [ -f "${d}SKILL.md" ] || continue
    name="$(basename "$d")"; total=$((total + 1))
    if [ -L "$dest/$name" ] && [ "$dest/$name" -ef "${d%/}" ]; then n=$((n + 1)); else SK_MISSING="$SK_MISSING $name"; fi
  done
  SK_COUNT="$n/$total"
  [ "$n" = "$total" ]
}
step_skills() {  # pweh 는 다른 파일·디렉터리가 있으면 덮어쓰지 않는다 (--force 는 넘기지 않음)
  local t dest st name path conflicts
  for t in claude-project agents; do
    dest="$(skills_dest "$t")"
    if [ "$DRYRUN" = 1 ]; then
      if skills_status "$dest"; then info "$t: ✓ $SK_COUNT 링크됨 ($dest)"
      else info "$t: $SK_COUNT 링크됨 — 설치할 때 만들 링크:$SK_MISSING (dry-run 이라 만들지 않음)"; fi
      STEP_NOTES+=("$t $SK_COUNT"); continue
    fi
    if ! pweh_ok; then warn "$t: $(pweh_missing)"; STEP_BAD[skills]=1; STEP_NOTES+=("$t 못 함"); continue; fi
    pweh_capture 120 skills install --target "$t"
    if [ "$PW_RC" != 0 ]; then step_failed "$t" "skills install --target $t"; continue; fi
    printf '%s\n' "$PW_OUT" >>"$LOG"
    conflicts=""
    if [ -n "$PY" ]; then
      while IFS=$'\t' read -r st name path; do
        case "$st" in
          installed) NEW_LINKS+=("$path") ;;
          exists*) conflicts="$conflicts $path" ;;
        esac
      done < <(printf '%s' "$PW_OUT" | "$PY" -I -c "$SKILLS_PY" 2>/dev/null)
    fi
    if skills_status "$dest"; then info "$t: ✓ $SK_COUNT 링크됨 ($dest)"; STEP_NOTES+=("$t $SK_COUNT")
    else
      warn "$t: $SK_COUNT 링크됨 — 링크되지 않은 Skill:$SK_MISSING"
      if [ -n "$conflicts" ]; then
        info "  같은 이름의 다른 파일·디렉터리가 있어 링크하지 않음:$conflicts"
        info "  확인한 뒤 바꾸려면: $PWEH_BIN skills install --target $t --force (기존 것을 지움)"
      fi
      STEP_BAD[skills]=1; STEP_NOTES+=("$t $SK_COUNT")
    fi
  done
}

# --- verify --------------------------------------------------------------
mcpcheck_args() {  # MC_ARGS — REA(선택 구성요소)가 설치되지 않았으면 rea 서버만 선택 서버로 넘긴다 (그 실패만 종료 코드에서 빠지고 다른 서버의 실패는 그대로)
  MC_ARGS=(mcp-check --client all)
  if ! check_rea >/dev/null 2>&1; then MC_ARGS+=(--optional rea); fi
}
mcpcheck_verdict() {  # 마지막 pweh mcp-check 결과 → MV (ok|rea|bad), MV_MSG. 판정은 pweh 의 종료 코드가 한다 (서버마다 — --optional rea 만 빼고)
  if [ "$PW_RC" = 0 ]; then
    case "$PW_OUT" in
      *"선택 서버 실패"*) MV=rea; MV_MSG="pweh mcp-check: PWEH 서버는 정상, rea 서버만 뜨지 않음 — REA 가 설치되지 않아 경고로만 봄 (선택 구성요소: ./scripts/install.sh --only rea)" ;;
      *) MV=ok; MV_MSG="pweh mcp-check: 모든 서버 정상" ;;
    esac
  else MV=bad; MV_MSG="pweh mcp-check 실패 ($(pweh_why))"; fi
}
step_verify() {
  local drc=0
  if [ "$DRYRUN" = 1 ]; then info "건너뜀 (dry-run)"; STEP_NOTES+=("건너뜀 (dry-run)"); return 0; fi
  if ! pweh_ok; then warn "$(pweh_missing)"; STEP_BAD[verify]=1; STEP_NOTES+=("못 함 — pweh 없음"); return 0; fi
  info "pweh doctor:"
  pweh_exec 600 doctor 2>&1 | tee -a "$LOG" | sed 's/^/      /' >&3 || drc=$?
  if [ "$drc" = 0 ]; then STEP_NOTES+=("doctor")
  else warn "pweh doctor 가 실패했습니다 (종료 코드 $drc)"; STEP_BAD[verify]=1; STEP_NOTES+=("doctor 실패"); fi
  info "pweh mcp-check --client all (서버마다 띄워 initialize + tools/list 만 함):"
  mcpcheck_args
  pweh_capture 900 "${MC_ARGS[@]}"
  if [ -n "$PW_OUT" ]; then printf '%s\n' "$PW_OUT" | sed 's/^/      /' >&3; printf '%s\n' "$PW_OUT" >>"$LOG"; fi
  mcpcheck_verdict
  case "$MV" in
    ok) info "✓ $MV_MSG"; STEP_NOTES+=("mcp-check ✓") ;;
    rea) warn "$MV_MSG"; STEP_NOTES+=("mcp-check 경고 — REA 없음 (rea 서버만 뜨지 않음)") ;;
    *) warn "$MV_MSG — 위 출력 참고"; STEP_BAD[verify]=1; STEP_NOTES+=("mcp-check 실패") ;;
  esac
}

run_step() {  # run_step <단계> — 조건 밖에서 부른다 (단계 함수 안의 set -e 가 살도록)
  local s=$1 n joined=""
  CUR_STEP=$s; STEP_NOTES=()
  say ""
  say "  - $s: ${STEP_DESC[$s]}"
  "step_$s"
  for n in ${STEP_NOTES[@]+"${STEP_NOTES[@]}"}; do joined="${joined:+$joined, }$n"; done
  if [ "${STEP_BAD[$s]:-0}" = 1 ]; then STEP_RESULT[$s]="실패${joined:+ — $joined}"
  elif [ "$DRYRUN" = 1 ]; then STEP_RESULT[$s]="dry-run${joined:+ — $joined}"
  else STEP_RESULT[$s]="완료${joined:+ — $joined}"; fi
}

# --- --check 의 단계 점검: 읽기만 한다 (--write 는 --dry-run 과 함께만, --yes·skills install 은 부르지 않음) ----
ck() {  # ck <ok|bad|skip> <이름> <내용> [바로잡는 방법]
  case "$1" in
    ok) say "  ✓ $2  $3" ;;
    bad) say "  ✗ $2  $3"; if [ -n "${4:-}" ]; then say "      → $4"; fi ;;
    *) say "  - $2  $3" ;;
  esac
}
check_mcp_claude() {
  local line st msg rc=0
  claude_status
  for line in "${CL_LINES[@]}"; do
    st="${line%%$'\t'*}"; msg="${line#*$'\t'}"
    case "$st" in
      ok) ck ok mcp:claude "$msg" ;;
      warn) ck skip mcp:claude "$msg" ;;
      *) ck bad mcp:claude "$msg" "$PWEH_BIN mcp-config --client claude --write --force, .claude/settings.json 의 enabledMcpjsonServers (이 스크립트는 바꾸지 않음)"; rc=1 ;;
    esac
  done
  return "$rc"
}
check_mcp_codex() {
  local fix="./scripts/install.sh --only mcp"
  [ "$CODEX_SCOPE" = project ] || fix="$fix --codex-global"
  if ! pweh_ok; then ck bad mcp:codex "확인하지 못함 — $(pweh_missing)"; return 1; fi
  codex_config_args
  pweh_capture 300 "${CX_ARGS[@]}" --dry-run
  if [ "$PW_RC" != 0 ]; then ck bad mcp:codex "확인하지 못함 — pweh ${CX_ARGS[*]} --dry-run ($(pweh_why))"; show_out "$PW_OUT"; return 1; fi
  local note=""
  if has_diff "$PW_OUT"; then
    if ! only_path_diff "$PW_OUT"; then ck bad mcp:codex "Codex 설정이 없거나 오래됨 — 바뀔 파일:" "$fix"; show_out "$(diff_files "$PW_OUT")"; return 1; fi
    note=" (서버 env 의 PATH 만 지금 셸과 다름 — 셸마다 다른 값이라 pweh doctor 처럼 비교에서 뺌. 지금 PATH 로 다시 쓰려면 $fix)"
  fi
  if [ "$CODEX_SCOPE" = project ]; then ck ok mcp:codex "$CODEX_PROJECT_CFG 최신$note"; else ck ok mcp:codex "Codex 홈의 config.toml 최신$note"; fi
}
check_mcp_trust() {
  if [ "$TRUST" = no ]; then ck skip mcp:codex-trust "점검하지 않음 (--no-codex-trust)"; return 0; fi
  if [ "$CODEX_SCOPE" = global ] && [ "$TRUST" = ask ]; then ck skip mcp:codex-trust "필요 없음 (--codex-global)"; return 0; fi
  if ! pweh_ok; then ck bad mcp:codex-trust "확인하지 못함 — $(pweh_missing)"; return 1; fi
  codex_home_args
  pweh_capture 300 codex-trust --check ${CH_ARGS[@]+"${CH_ARGS[@]}"}
  case "$PW_RC" in
    0) ck ok mcp:codex-trust "이 저장소를 신뢰하지 않는 Codex 홈이 없음"; show_out "$PW_OUT"; return 0 ;;
    1) ck bad mcp:codex-trust "이 저장소를 신뢰하지 않는 Codex 홈이 있음 — Codex 가 .codex/config.toml 을 읽지 않음" \
         "동의하면 ./scripts/install.sh --only mcp --codex-trust (또는 --codex-global. 이 점검을 끄려면 --no-codex-trust)"
       show_out "$PW_OUT"; return 1 ;;
    *) ck bad mcp:codex-trust "확인하지 못함 ($(pweh_why))"; show_out "$PW_OUT"; return 1 ;;
  esac
}
check_mcp_cursor() {
  cursor_merge 1
  if [ "$CM_RC" != 0 ]; then ck bad mcp:cursor "확인하지 못함"; show_out "$CM_OUT"; return 1; fi
  if [ "$CM_OUT" = 최신 ]; then ck ok mcp:cursor "$CURSOR_CFG 최신"; return 0; fi
  ck bad mcp:cursor "$CURSOR_CFG 이 없거나 PWEH 항목이 다름 — 바뀔 파일:" "./scripts/install.sh --only mcp --cursor"
  show_out "$(diff_files "$CM_OUT")"
  return 1
}
check_skills() {
  local t dest rc=0
  for t in claude-project agents; do
    dest="$(skills_dest "$t")"
    if skills_status "$dest"; then ck ok "skills:$t" "$SK_COUNT 링크됨 ($dest)"
    else ck bad "skills:$t" "$SK_COUNT 링크됨 — 빠진 Skill:$SK_MISSING" "./scripts/install.sh --only skills"; rc=1; fi
  done
  return "$rc"
}
check_verify() {
  if ! pweh_ok; then ck bad verify "확인하지 못함 — $(pweh_missing)"; return 1; fi
  mcpcheck_args
  pweh_capture 900 "${MC_ARGS[@]}"
  mcpcheck_verdict
  case "$MV" in
    ok) ck ok verify "$MV_MSG" ;;
    rea) ck skip verify "$MV_MSG" ;;
    *) ck bad verify "$MV_MSG" "아래 출력 확인 (REA 는 ./scripts/install.sh --only rea)" ;;
  esac
  show_out "$PW_OUT"
  [ "$MV" != bad ]
}
check_steps() {  # 하나라도 실패하면 1
  local rc=0
  if selected mcp; then
    check_mcp_claude || rc=1
    check_mcp_codex || rc=1
    check_mcp_trust || rc=1
    if [ "$CURSOR" = 1 ]; then check_mcp_cursor || rc=1; fi
  fi
  if selected skills; then check_skills || rc=1; fi
  if selected verify; then check_verify || rc=1; fi
  return "$rc"
}

# --- 요약: 쓰거나 백업한 파일과 되돌리는 방법 (명령은 보여 주기만 한다) -------------------------------
print_changes() {
  local e f b x y o w nb=0
  if [ ${#CHANGED[@]} -eq 0 ] && [ ${#WRITE_OUTPUTS[@]} -eq 0 ] && [ ${#NEW_LINKS[@]} -eq 0 ]; then return 0; fi
  say ""
  say "바꾼 파일과 되돌리는 방법 (되돌리기 명령은 보여 주기만 함):"
  for e in ${CHANGED[@]+"${CHANGED[@]}"}; do
    case "$e" in W$'\t'*|E$'\t'*) f="${e#??}" ;; *) nb=$((nb + 1)); continue ;; esac
    b=""   # 같은 파일을 두 번 바꿨으면(예: --codex-global 의 등록과 신뢰) 처음 백업이 이 스크립트를 돌리기 전의 상태
    for x in "${CHANGED[@]}"; do
      case "$x" in B$'\t'*) y="${x#??}"; if [ -z "$b" ] && [ "${y%.bak-pweh-*}" = "$f" ]; then b="$y"; fi ;; esac
    done
    if [ -n "$b" ]; then
      say "  씀    $f"
      say "        백업: $b"
      say "        되돌리기: cp -p $(printf %q "$b") $(printf %q "$f")"
    elif [ "$f" -ef "$CODEX_PROJECT_CFG" ]; then
      say "  씀    $f   (생성물, git 제외)"
      say "        되돌리기: rm $(printf %q "$f")   (다시 만들기: $PWEH_BIN mcp-config --client codex --write)"
    elif [ "${e%%$'\t'*}" = E ]; then   # 있던 파일인데 백업이 보이지 않음: 지우라고 하지 않는다
      say "  씀    $f   (있던 파일 — 이번 출력에서 백업을 찾지 못함, 위 pweh 출력 확인)"
    else
      say "  씀    $f   (새로 만든 파일)"
      say "        되돌리기: rm $(printf %q "$f")"
    fi
  done
  for e in ${CHANGED[@]+"${CHANGED[@]}"}; do   # 짝이 되는 바뀐 파일을 찾지 못한 백업
    case "$e" in B$'\t'*) y="${e#??}" ;; *) continue ;; esac
    o="${y%.bak-pweh-*}"; w=0
    for x in "${CHANGED[@]}"; do case "$x" in W$'\t'"$o"|E$'\t'"$o") w=1 ;; esac; done
    if [ "$w" = 0 ]; then say "  백업  $y"; say "        되돌리기: cp -p $(printf %q "$y") $(printf %q "$o")"; fi
  done
  if [ "$TRUST_ADDED" = 1 ]; then
    say "  Codex 신뢰 항목만 빼려면: 해당 config.toml 에서 [projects.\"$REPO_REAL\"] 표(trust_level = \"trusted\")를 지운다"
  fi
  if [ ${#NEW_LINKS[@]} -gt 0 ]; then
    say "  Skill 링크 ${#NEW_LINKS[@]}개를 새로 만듦 (되돌리기: rm <링크> — 링크만 지워지고 skills/ 원본은 그대로):"
    for x in "${NEW_LINKS[@]}"; do say "        $x"; done
  fi
  if [ ${#WRITE_OUTPUTS[@]} -gt 0 ]; then
    say "  pweh 가 알린 쓰기·백업 (출력 그대로):"
    for o in "${WRITE_OUTPUTS[@]}"; do show_out "$o" log; done
  fi
  if [ "$nb" -gt 0 ]; then say "  백업은 지우지 않았습니다 — 확인한 뒤 직접 지우세요."; fi
}

# ---------------------------------------------------------------------------
# 실행
# ---------------------------------------------------------------------------
declare -A RESULT
run_component() {
  local c=$1 t0=$SECONDS
  if [ "$FORCE" = 0 ] && "check_$c" >>"$LOG" 2>&1; then
    RESULT[$c]="이미 설치됨"; say "  - $c: 이미 설치됨 ($("version_$c" 2>/dev/null || true))"; return 0
  fi
  case "$c" in
    python|rea) ;;
    *) if [ "$ARCH_OK" = 0 ]; then RESULT[$c]="건너뜀 (Linux x86_64 아님)"; warn "$c: Linux x86_64 에서만 설치합니다"; return 0; fi ;;
  esac
  say "  - $c: 설치 중 … (${DESC[$c]})"
  echo "===== $c =====" >>"$LOG"
  # if/&&/|| 의 조건 안에서 부른 subshell 은 'set -e' 를 다시 켜도 무시된다 (bash 규칙).
  # 조건 밖에서 실행해 install_* 의 첫 실패에서 멈추게 하고, 종료 코드만 따로 받는다.
  local rc
  set +e
  ( set -Eeuo pipefail; "install_$c" ) >>"$LOG" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && "check_$c" >>"$LOG" 2>&1; then
    RESULT[$c]="설치함 ($((SECONDS - t0))초)"
    "version_$c" >"$PREFIX/.state/$c" 2>/dev/null || true
    say "    완료: $("version_$c" 2>/dev/null || true) ($((SECONDS - t0))초)"
  elif [ "$rc" -eq "$SKIP_RC" ]; then
    RESULT[$c]="건너뜀 (전제 조건 없음)"
    warn "$c 건너뜀 — $(tail -n 1 "$LOG")"
  else
    RESULT[$c]="실패"
    warn "$c 설치 실패 — 로그: $LOG"
    tail -n 12 "$LOG" | sed 's/^/      | /' >&3
  fi
}

say "PWEH 설치 — 저장소 $REPO"
say "  외부 도구: $PREFIX   캐시: $CACHE${SEED:+   seed: $SEED}   가상환경: $VENV"
if [ "$COMP_SELECTED" = 1 ]; then
  [ "$ARCH_OK" = 1 ] || warn "이 머신은 Linux x86_64 가 아닙니다. 외부 도구는 설치하지 않고 Python 환경만 준비합니다."
  [ "$HAVE_APT" = 1 ] || warn "apt 가 없습니다. 배포판 패키지 구성요소(sigrok, squashfs, uboot, extractors)는 직접 설치해야 합니다."
  for t in curl tar xz; do
    if ! command -v "$t" >/dev/null && { [ "$t" != curl ] || ! command -v wget >/dev/null; }; then warn "'$t' 가 없습니다 (관리자: sudo apt-get install curl tar xz-utils)"; fi
  done
fi
[ -n "$PY" ] || warn "Python 3.10 이상을 찾지 못했습니다."
if [ "$MODE" = install ] && [ "$DRYRUN" = 1 ]; then
  say "  dry-run: 아무것도 설치하거나 바꾸지 않고 MCP 등록·Codex 신뢰가 바꿀 내용만 보여 줍니다"
elif [ "$MODE" = install ] && [ "$COMP_SELECTED" = 0 ]; then
  say "  구성요소를 고르지 않아 단계만 실행합니다 (도구를 다시 설치하지 않고 env.sh 도 그대로 둠)"
fi

if [ "$MODE" = check ]; then
  rc=0
  for c in $ALL_COMPONENTS; do
    selected "$c" || continue
    if "check_$c" >>"$LOG" 2>&1; then say "  ✓ $c  $("version_$c" 2>/dev/null || true)"
    else say "  ✗ $c  (${DESC[$c]})"; case " $OPTIONAL_COMPONENTS " in *" $c "*) ;; *) rc=1 ;; esac; fi
  done
  if [ "$COMP_SELECTED" = 1 ]; then
    if [ -f "$PREFIX/env.sh" ]; then say "  env.sh: $PREFIX/env.sh"; else say "  env.sh 없음"; fi
  fi
  check_steps || rc=1
  exit "$rc"
fi

if [ "$INSTALL_TOOLS" = 1 ]; then
  for c in $ALL_COMPONENTS; do
    if selected "$c"; then run_component "$c"; fi   # 조건 밖에서 불러야 run_component 안의 set -e 가 산다
  done
  write_env
  say "  env.sh: $PREFIX/env.sh"
elif [ "$COMP_SELECTED" = 1 ]; then
  say "  구성요소: dry-run 이라 설치하지 않고 env.sh 도 쓰지 않음 (설치 상태는 --check)"
fi
for s in $STEPS; do
  if selected "$s"; then run_step "$s"; fi   # 조건 밖에서 불러야 단계 함수 안의 set -e 가 산다
done

say ""
say "결과:"
failed=0
if [ "$INSTALL_TOOLS" = 1 ]; then
  for c in $ALL_COMPONENTS; do
    selected "$c" || continue
    r="${RESULT[$c]:-선택 안 함}"
    say "  $(printf '%-11s' "$c") $r"
    if [ "$r" = 실패 ]; then case " $OPTIONAL_COMPONENTS " in *" $c "*) ;; *) failed=1 ;; esac; fi
  done
fi
for s in $STEPS; do
  selected "$s" || continue
  say "  $(printf '%-11s' "$s") ${STEP_RESULT[$s]:-선택 안 함}"
  if [ "${STEP_BAD[$s]:-0}" = 1 ]; then failed=1; fi
done
if [ "$DRYRUN" = 0 ]; then print_changes; fi
say ""
say "다음 단계:"
if [ "$DRYRUN" = 1 ]; then
  say "  위 내용대로 바꾸려면 같은 옵션에서 --dry-run 을 빼고 다시 실행 (Codex 신뢰는 대화형으로 묻거나 --codex-trust)"
else
  if [ -f "$PREFIX/env.sh" ]; then say "  . $PREFIX/env.sh            # 셸에서 외부 도구 쓰기 (MCP 서버는 scripts/mcp-launch.sh 가 자동으로 읽음)"; fi
  say "  $VENV/bin/pytest -q -m 'not slow'"
  say "  claude  →  /pweh-start <기기 설명>"
  say "  codex   →  \$pweh-start <기기 설명>   (이 저장소에서. 프로젝트 설정은 이 저장소를 신뢰한 Codex 홈에서만 읽힘)"
  say "  $PWEH_BIN mcp-check --client all   # MCP 서버 연결 점검 (도구는 부르지 않음)"
fi
if [ "$LOG" != /dev/null ]; then say "로그: $LOG"; fi
exit "$failed"
