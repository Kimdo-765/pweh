#!/usr/bin/env bash
# PWEH 원클릭 설치: Python 환경 + 외부 도구 + REA 를 sudo 없이 한 번에 설치한다.
#
#   ./scripts/install.sh                  # 전체 설치 (권장)
#   ./scripts/install.sh --minimal        # Python + sigrok + OpenOCD + squashfs/u-boot 도구만
#   ./scripts/install.sh --only ghidra,jdk
#   ./scripts/install.sh --skip rea,binwalk
#   ./scripts/install.sh --check          # 설치 상태만 점검 (아무것도 설치하지 않음)
#   ./scripts/install.sh --list           # 구성요소 목록
#
# 옵션
#   --prefix DIR   외부 도구 설치 위치 (기본: $PWEH_TOOLS_DIR 또는 ~/pweh-tools)
#   --cache DIR    내려받은 파일 캐시 (기본: <prefix>/_downloads)
#   --seed DIR     해시가 고정된 파일(압축 파일·휠·.deb)을 먼저 찾을 디렉터리. 이름과 해시가 맞을 때만 쓴다.
#                  pip·npm·cargo 의존성은 여전히 네트워크에서 받는다 (완전한 오프라인 설치는 아님)
#   --venv DIR     pweh Python 가상환경 (기본: <저장소>/.venv)
#   --force        이미 설치된 구성요소도 다시 설치
#   --no-link      기본 위치가 아닐 때 저장소에 .pweh/tools-env.path 를 남기지 않음 (시험·CI 용)
#   --jobs N       빌드 병렬 수 (기본: CPU 수)
#
# 원칙
# - root/sudo 를 쓰지 않고, 시스템 디렉터리·셸 rc 파일을 바꾸지 않는다. 설치물은 <prefix> 와 가상환경 아래에만 둔다.
#   (예외: 시스템 cargo 를 쓰면 ~/.cargo 레지스트리 캐시, Ghidra 를 처음 실행하면 ~/.config/ghidra)
# - 스크립트가 직접 받는 파일(압축 파일, pip·unblob 휠, esptool 소스 배포판, rustup-init, sasquatch .deb)은 고정된 sha256 으로,
#   배포판 패키지는 apt 의 서명된 색인에 있는 해시로 검증한다. pip·npm 이 받는 의존성은 최상위 버전만 고정하고
#   해시는 고정하지 않으며 (npm 패키지의 설치 스크립트가 실행되고, esptool 소스 배포판을 빌드하는 setuptools 도 PyPI 에서 받음),
#   binwalk 의존성은 Cargo.lock(--locked) 의 체크섬으로 검증된다.
# - 압축 해제 전에 절대 경로, '..', 밖을 가리키는 링크, 장치 파일을 거부한다. 배포판 패키지의 설치 스크립트는 실행하지 않는다.
# - 이미 설치된 구성요소는 건너뛴다. 선택 구성요소(erofs, binwalk, rea, esptool)가 실패해도 나머지는 계속한다.
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

ALL_COMPONENTS="python sigrok openocd squashfs uboot zig jdk ghidra unblob extractors erofs binwalk rea esptool"
MINIMAL_COMPONENTS="python sigrok openocd squashfs uboot"
OPTIONAL_COMPONENTS="erofs binwalk rea esptool"   # 실패해도 설치 전체를 실패로 보지 않는다 (경고만)
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

usage() { sed -n '2,/^$/{s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"; }   # 맨 위 주석 블록
need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 에 값이 필요합니다 (--help 참고)" >&2; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix|--cache|--seed|--venv|--only|--skip|--jobs) need_arg "$@" ;;
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
    -h|--help) usage; exit 0 ;;
    *) echo "알 수 없는 옵션: $1 (--help 참고)" >&2; exit 2 ;;
  esac
done

# 선택한 구성요소
selected() {
  local c=$1
  if [ -n "$ONLY" ]; then case ",$ONLY," in *",$c,"*) ;; *) return 1 ;; esac; fi
  case ",$SKIP," in *",$c,"*) return 1 ;; esac
  return 0
}
for c in ${ONLY//,/ } ${SKIP//,/ }; do
  case " $ALL_COMPONENTS " in *" $c "*) ;; *) echo "알 수 없는 구성요소: $c (--list 참고)" >&2; exit 2 ;; esac
done
if [ "$MODE" = list ]; then
  for c in $ALL_COMPONENTS; do
    tag=""; case " $MINIMAL_COMPONENTS " in *" $c "*) tag=" [minimal]" ;; esac
    case " $OPTIONAL_COMPONENTS " in *" $c "*) tag="$tag [선택]" ;; esac
    printf '  %-11s %s%s\n' "$c" "${DESC[$c]}" "$tag"
  done
  exit 0
fi

# 래퍼·env.sh 는 경로를 따옴표 안에 그대로 넣는다: 따옴표·$·백슬래시·줄바꿈이 든 경로는 받지 않는다 (디렉터리를 만들기 전에)
check_prefix_chars() {
  case "$PREFIX" in *[\'\"\$\`\\]*|*$'\n'*) echo "--prefix 경로에 ' \" \$ \` \\ 나 줄바꿈을 쓸 수 없습니다: $PREFIX" >&2; exit 2 ;; esac
}
check_prefix_chars
if [ "$MODE" = check ]; then   # --check 는 아무것도 만들지 않는다
  PREFIX="$(cd "$PREFIX" 2>/dev/null && pwd || echo "$PREFIX")"
  CACHE="${CACHE:-$PREFIX/_downloads}"
  LOG=/dev/null
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
    done < <(find "$SEED" -type f -name "$(basename "$dest")" 2>/dev/null)
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
[ "$MODE" = check ] || cat >"$SAFE_EXTRACT" <<'PY'
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

check_python() { [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import pweh, mcp, serial, yaml, jsonschema, pytest' 2>/dev/null; }
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
WSL_BINFMT=/proc/sys/fs/binfmt_misc   # WSL 이 Windows 실행 파일(MZ)을 넘겨받는 등록: WSLInterop (systemd 를 쓰면 WSLInterop-late 도)
wsl_interop() {  # WSL 에서 Windows 실행 파일을 직접 실행할 수 있는가 (interop 등록이 있고 켜져 있음). 판정은 이 함수 하나로만 한다
  local f
  for f in "$WSL_BINFMT"/WSLInterop*; do
    [ -r "$f" ] && [ "$(head -n 1 "$f" 2>/dev/null)" = enabled ] && return 0
  done
  return 1
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
[ "$ARCH_OK" = 1 ] || warn "이 머신은 Linux x86_64 가 아닙니다. 외부 도구는 설치하지 않고 Python 환경만 준비합니다."
[ "$HAVE_APT" = 1 ] || warn "apt 가 없습니다. 배포판 패키지 구성요소(sigrok, squashfs, uboot, extractors)는 직접 설치해야 합니다."
[ -n "$PY" ] || warn "Python 3.10 이상을 찾지 못했습니다."
for t in curl tar xz; do
  if ! command -v "$t" >/dev/null && { [ "$t" != curl ] || ! command -v wget >/dev/null; }; then warn "'$t' 가 없습니다 (관리자: sudo apt-get install curl tar xz-utils)"; fi
done

if [ "$MODE" = check ]; then
  rc=0
  for c in $ALL_COMPONENTS; do
    selected "$c" || continue
    if "check_$c" >>"$LOG" 2>&1; then say "  ✓ $c  $("version_$c" 2>/dev/null || true)"
    else say "  ✗ $c  (${DESC[$c]})"; case " $OPTIONAL_COMPONENTS " in *" $c "*) ;; *) rc=1 ;; esac; fi
  done
  [ -f "$PREFIX/env.sh" ] && say "  env.sh: $PREFIX/env.sh" || say "  env.sh 없음"
  exit "$rc"
fi

for c in $ALL_COMPONENTS; do
  if selected "$c"; then run_component "$c"; fi   # 조건 밖에서 불러야 run_component 안의 set -e 가 산다
done
write_env
say "  env.sh: $PREFIX/env.sh"

if [ -x "$VENV/bin/pweh" ]; then
  say ""
  say "pweh doctor:"
  ( set +e; . "$PREFIX/env.sh"; "$VENV/bin/pweh" doctor 2>&1 ) | tee -a "$LOG" | sed 's/^/  /' >&3 || true
fi

say ""
say "결과:"
failed=0
for c in $ALL_COMPONENTS; do
  selected "$c" || continue
  r="${RESULT[$c]:-선택 안 함}"
  say "  $(printf '%-11s' "$c") $r"
  if [ "$r" = 실패 ]; then case " $OPTIONAL_COMPONENTS " in *" $c "*) ;; *) failed=1 ;; esac; fi
done
say ""
say "다음 단계:"
say "  . $PREFIX/env.sh            # 셸에서 외부 도구 쓰기 (MCP 서버는 scripts/mcp-launch.sh 가 자동으로 읽음)"
say "  $VENV/bin/pytest -q -m 'not slow'"
say "  claude  →  /pweh-start <기기 설명>"
say "로그: $LOG"
exit "$failed"
