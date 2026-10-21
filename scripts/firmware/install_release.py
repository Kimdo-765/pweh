"""install.sh의 사전 빌드 복사/점검 진입점. 다운로드·빌드·포트 기능은 없다."""
import argparse
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from pweh.firmwarebuild import BuildError, install_releases

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--prefix", type=Path, required=True)
parser.add_argument("--check", action="store_true")
parser.add_argument("--force", action="store_true")
args = parser.parse_args()
try:
    rc = install_releases(REPO / "src/pweh/data/espprobe-releases.json", REPO / "firmware/releases/espprobe",
                          args.prefix, check=args.check, force=args.force)
    if rc == 99:
        print("검증된 espprobe 사전 빌드가 아직 없어 건너뜁니다.")
    raise SystemExit(rc)
except (BuildError, OSError, ValueError) as exc:
    print(f"espprobe 사전 빌드 검증 실패: {exc}", file=sys.stderr)
    raise SystemExit(1)
