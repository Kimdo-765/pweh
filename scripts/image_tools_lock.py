#!/usr/bin/env python3
"""이미지 도구의 검증된 .deb 잠금 자료: 설치 계획·모델 지문. 네트워크 접근은 install.sh 가 담당한다."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path


def load_profile(lock: Path, os_release: Path, arch: str) -> dict:
    """지원하지 않는 배포판에서 임의 apt 버전으로 바꾸지 않는다."""
    fields = {}
    for line in os_release.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key] = value.strip().strip('"')
    key = f"{fields.get('ID', '')}-{fields.get('VERSION_ID', '')}-{arch}"
    data = json.loads(lock.read_text())
    if key not in data["profiles"]:
        raise ValueError(f"이미지 도구의 고정 패키지를 지원하지 않는 플랫폼: {key}; 지원: {', '.join(data['profiles'])}. 임의 버전으로 대체하지 않습니다.")
    return data["profiles"][key]


def installed_version(package: str) -> str | None:
    """기존 deb_fetch_extract 처럼 시스템 런타임 라이브러리를 재사용한다(주 패키지·모델은 제외)."""
    result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", package],
                            capture_output=True, text=True, timeout=10, check=False)
    return result.stdout.split("\t", 1)[1] if result.returncode == 0 and result.stdout.startswith("ii \t") else None


def plan(profile: dict, component: str) -> tuple[list[dict], list[dict]]:
    spec = profile["components"][component]
    selected, reused = [], []
    for name in spec["packages"]:
        row = profile["packages"][name]
        version = None if name in spec["always_extract"] else installed_version(name)
        if version:
            reused.append({"package": name, "version": version, "source": "system-runtime"})
        else:
            selected.append({"package": name, **row})
    return selected, reused


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "verify-models", "version"))
    parser.add_argument("component", choices=("tesseract", "zbar"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--os-release", type=Path, default=Path("/etc/os-release"))
    parser.add_argument("--arch", default=platform.machine())
    parser.add_argument("--record", type=Path)
    parser.add_argument("--models", type=Path)
    args = parser.parse_args()
    try:
        profile = load_profile(args.lock, args.os_release, args.arch)
        if args.action == "version":
            print(profile["components"][args.component]["version"])
            return 0
        if args.action == "verify-models":
            if args.models is None:
                raise ValueError("모델 디렉터리가 필요합니다")
            for name, row in profile["models"].items():
                if hashlib.sha256((args.models / name).read_bytes()).hexdigest() != row["sha256"]:
                    raise ValueError(f"언어 데이터 SHA256 불일치: {name}")
            return 0
        selected, reused = plan(profile, args.component)
        if args.record:
            args.record.write_text(json.dumps({"schema": "pweh.image-tool-install/v1", "component": args.component,
                "lock_sha256": hashlib.sha256(args.lock.read_bytes()).hexdigest(), "downloaded": selected,
                "system_runtime": reused, "models": profile["models"] if args.component == "tesseract" else {},
                "sources": profile["sources"]}, ensure_ascii=False, indent=2) + "\n")
        for row in selected:
            print("\t".join((row["package"], row["version"], row["url"], row["sha256"])))
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
