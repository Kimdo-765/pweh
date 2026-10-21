#!/usr/bin/env bash
# 고정 espprobe 준비·오프라인 빌드·검증. 임의 idf.py action은 받지 않는다.
set -Eeuo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO/.venv/bin/python" -B "$REPO/scripts/firmware/build.py" "$@"
