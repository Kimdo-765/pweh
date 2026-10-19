#!/usr/bin/env bash
# PWEH MCP 서버 런처.
#   사용: scripts/mcp-launch.sh <pweh-uart-mcp|pweh-case-mcp|...|rea> [인자...]
# 1) 외부 도구 환경(기본 ~/pweh-tools/env.sh, PWEH_TOOLS_ENV 로 변경)을 불러오고
# 2) PWEH_CONFIG 를 이 저장소의 orchestrator/pipeline-config.yaml 로 지정한 뒤
# 3) 저장소 .venv 의 서버(또는 rea --mcp)를 exec 한다.
# stdout 은 MCP 프로토콜 채널이므로 이 스크립트는 stdout 에 아무것도 쓰지 않는다.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 외부 도구 env.sh 찾기 (src/pweh/toolsdir.py 와 같은 순서):
#   PWEH_TOOLS_ENV → PWEH_TOOLS_DIR/env.sh → scripts/install.sh --prefix 가 남긴 .pweh/tools-env.path → ~/pweh-tools/env.sh
tools_env="${PWEH_TOOLS_ENV:-}"
if [ -z "$tools_env" ] && [ -n "${PWEH_TOOLS_DIR:-}" ]; then
  tools_env="$PWEH_TOOLS_DIR/env.sh"
fi
if [ -z "$tools_env" ] && [ -f "$here/.pweh/tools-env.path" ]; then
  tools_env="$(head -n 1 "$here/.pweh/tools-env.path")"
  [ -f "$tools_env" ] || tools_env=""   # 지워진 위치를 가리키면 무시 (toolsdir.py 와 같음)
fi
tools_env="${tools_env:-$HOME/pweh-tools/env.sh}"
# install.sh --venv 로 다른 가상환경을 썼으면 .pweh/venv.path 가 가리킨다
venv="$here/.venv"
if [ -f "$here/.pweh/venv.path" ]; then
  v="$(head -n 1 "$here/.pweh/venv.path")"
  if [ -x "$v/bin/python" ]; then venv="$v"; fi
fi
if [ -f "$tools_env" ]; then
  # shellcheck disable=SC1090
  . "$tools_env" >/dev/null 2>&1 || true
fi
export PWEH_CONFIG="${PWEH_CONFIG:-$here/orchestrator/pipeline-config.yaml}"
name="${1:?서버 이름이 필요합니다}"
shift
case "$name" in
  rea)
    rea_bin="${PWEH_REA:-$(command -v rea || echo "$HOME/.local/bin/rea")}"
    export REA_GHIDRA_STARTUP_TIMEOUT_MS="${REA_GHIDRA_STARTUP_TIMEOUT_MS:-600000}"
    exec "$rea_bin" --mcp "$@"
    ;;
  pweh-*-mcp)
    exec "$venv/bin/$name" "$@"
    ;;
  *)
    echo "알 수 없는 서버: $name" >&2
    exit 2
    ;;
esac
