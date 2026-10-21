"""검토 가능한 고정 준비·빌드 CLI. source commit archive만 실행 입력으로 사용한다."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from pweh.firmwarebuild import (BOARD, COMPONENTS, DOCKER, IMAGE, PROFILE, BuildError, bounded_run,
                               extract_tar, inspect_image, inside, json_bytes, prepare_image, read_regular, sha256)
from pweh import firmwarebuild as F

SOURCE_PATHS = ("firmware/common", "firmware/espprobe", "scripts/firmware", "src/pweh/firmwarebuild.py",
                "src/pweh/espfmt.py", "src/pweh/__init__.py", "src/pweh/toolsdir.py", "firmware/dependencies-lock.json", "firmware/licenses")
GIT = ("git", "--no-replace-objects")


def source_archive(commit: str | None) -> tuple[bytes, str, int]:
    """release는 Git commit, API 확인용 preliminary는 제한된 현재 파일 사본만 내보낸다."""
    if commit:
        import re
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise BuildError("source commit은 full 40자리 hex여야 함")
        resolved = bounded_run([*GIT, "rev-parse", "--verify", commit + "^{commit}"], cwd=REPO).decode().strip()
        if resolved != commit:
            raise BuildError("source commit 불일치")
        listing = bounded_run([*GIT, "ls-tree", "-r", "-z", commit, "--", *SOURCE_PATHS], cwd=REPO)
        epoch = int(bounded_run([*GIT, "show", "-s", "--format=%ct", commit], cwd=REPO).strip())
        output = io.BytesIO()
        total = 0
        # commit의 blob을 직접 읽어 로컬 export-ignore/export-subst 속성 영향도 제외한다.
        with tarfile.open(fileobj=output, mode="w") as archive:
            for row in listing.split(b"\0"):
                if not row:
                    continue
                meta, path = row.split(b"\t", 1)
                mode, kind, oid = meta.split(b" ")
                if mode not in (b"100644", b"100755") or kind != b"blob":
                    raise BuildError("source archive link/gitlink/특수 mode 거부")
                blob = bounded_run([*GIT, "cat-file", "blob", oid.decode()], cwd=REPO, limit=32 * 1024 * 1024)
                total += len(blob)
                if total > 64 * 1024 * 1024:
                    raise BuildError("source archive 합계 크기 상한 초과")
                info = tarfile.TarInfo(path.decode("utf-8"))
                info.mode, info.size, info.mtime = int(mode, 8) & 0o777, len(blob), epoch
                archive.addfile(info, io.BytesIO(blob))
        return output.getvalue(), commit, epoch
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for rel in SOURCE_PATHS:
            root = REPO / rel
            if not root.exists():
                if rel == "firmware/dependencies-lock.json":
                    continue
                raise BuildError(f"필수 source 없음: {rel}")
            candidates = sorted(root.rglob("*")) if root.is_dir() else [root]
            for path in candidates:
                if path.is_symlink():
                    raise BuildError("preliminary source symlink 거부")
                if path.is_dir():
                    continue
                relative = path.relative_to(REPO)
                if ("__pycache__" in relative.parts or "build" in relative.parts or "managed_components" in relative.parts
                        or path.name in ("sdkconfig", "sdkconfig.old", "dependencies.lock") or path.suffix == ".pyc"):
                    continue
                blob = read_regular(path)
                info = tarfile.TarInfo(relative.as_posix())
                info.mode, info.size, info.mtime = 0o644, len(blob), 0
                archive.addfile(info, io.BytesIO(blob))
    return output.getvalue(), "0" * 40, 0


def verify_bundle(deps: Path, *, vendor: bool) -> dict:
    document = json.loads(read_regular(deps / "preparation.json", limit=4 * 1024 * 1024))
    if document.get("components") != COMPONENTS or document.get("image", {}).get("image") != IMAGE:
        raise BuildError("component bundle pin/image 불일치")
    for row in document["mirror"]["files"]:
        blob = read_regular(inside(deps / "mirror", row["path"]), limit=64 * 1024 * 1024)
        if len(blob) != row["size"] or sha256(blob) != row["sha256"]:
            raise BuildError("component mirror 무결성 불일치")
    if vendor:
        lock = json.loads(read_regular(deps / "dependencies-lock.json"))
        for row in lock["files"]:
            blob = read_regular(inside(deps / "vendor", row["path"]))
            if len(blob) != row["size"] or sha256(blob) != row["sha256"]:
                raise BuildError("component vendor 무결성 불일치")
        if {str(p.relative_to(deps / "vendor")) for p in (deps / "vendor").rglob("*") if p.is_file()} != {r["path"] for r in lock["files"]}:
            raise BuildError("component vendor 파일 집합 변경")
    return document


def run_build(deps: Path, output: Path, *, commit: str | None, mode: str) -> dict:
    """새 source export와 새 volume에서만 offline configure/build한다."""
    if output.exists():
        raise BuildError("빌드 출력은 새 디렉터리여야 함")
    inspect_image()  # build는 image가 없어도 pull로 전환하지 않는다.
    preparation = verify_bundle(deps, vendor=mode == "build")
    archive, identity, epoch = source_archive(commit)
    output.mkdir(parents=True)
    (output / "source.tar").write_bytes(archive)
    name = "pweh-i5-" + mode + "-" + uuid.uuid4().hex[:12]
    volumes = []
    try:
        with tempfile.TemporaryDirectory(prefix="pweh-i5-input-") as temporary:
            incoming = Path(temporary)
            extract_tar(archive, incoming / "source", limit=64 * 1024 * 1024)
            if commit is not None:
                locked = read_regular(incoming / "source/firmware/dependencies-lock.json")
                if locked != read_regular(deps / "dependencies-lock.json"):
                    raise BuildError("source commit의 component lock과 bundle이 다름")
            shutil.copytree(deps, incoming / "deps")
            source_volume = input_volume(incoming, name)
            volumes.append(source_volume)
        outgoing = output_volume(name)
        volumes.append(outgoing)
        argv = container_argv(name, output, output_volume=outgoing)
        argv += ["--mount", f"type=volume,src={source_volume},dst=/input,readonly", "--env", f"PWEH_BUILD_ACTION={mode}",
                 "--env", f"PWEH_SOURCE_COMMIT={identity}", "--env", f"SOURCE_DATE_EPOCH={epoch}", IMAGE,
                 "python", "-B", "/input/source/scripts/firmware/container_build.py"]
        run_container(argv, name, output, 2400)
        result = {"schema": "pweh.firmware-build/v1", "status": "preliminary" if commit is None else "built",
                  "git_commit": identity, "source_archive_sha256": sha256(archive), "source_date_epoch": epoch,
                  "image": preparation["image"], "mode": mode}
        (output / "build.json").write_bytes(json_bytes(result))
        return result
    finally:
        cleanup_volumes(volumes, output)


def lock_components(deps: Path, output: Path) -> None:
    run_build(deps, output, commit=None, mode="lock")
    import yaml
    lock = yaml.safe_load(read_regular(output / "dependencies.lock"))
    external = {name: row for name, row in lock["dependencies"].items() if name != "idf"}
    if {name: row["version"] for name, row in external.items()} != COMPONENTS:
        raise BuildError("offline dependencies.lock의 exact pin 불일치")
    if not str(lock["dependencies"]["idf"]["version"]).startswith("6.1.") and lock["dependencies"]["idf"]["version"] != "6.1.0":
        raise BuildError("dependencies.lock IDF 버전 불일치")
    vendor = output / "vendor"
    files = []
    total = 0
    for path in sorted(vendor.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise BuildError("vendor link/특수 파일 거부")
        if path.is_dir():
            continue
        blob = read_regular(path)
        total += len(blob)
        if total > 256 * 1024 * 1024 or len(files) >= 20000:
            raise BuildError("vendor 파일/크기 상한 초과")
        files.append({"path": path.relative_to(vendor).as_posix(), "size": len(blob), "sha256": sha256(blob)})
    document = {"schema": "pweh.firmware-dependencies/v1", "image": IMAGE, "components": external,
                "idf": lock["dependencies"]["idf"], "dependencies_lock_sha256": sha256(read_regular(output / "dependencies.lock")),
                "manager_version": json.loads(read_regular(deps / "preparation.json"))["mirror"]["manager_version"], "files": files}
    if (deps / "vendor").exists():
        raise BuildError("기존 vendor bundle 덮어쓰기 거부")
    shutil.copytree(vendor, deps / "vendor")
    (deps / "dependencies.lock").write_bytes(read_regular(output / "dependencies.lock"))
    (deps / "dependencies-lock.json").write_bytes(json_bytes(document))
    print(json.dumps({"status": "locked", "external_components": list(external), "files": len(files)}))


def reproduce(deps: Path, output: Path, commit: str) -> None:
    """고정 S의 독립 clean build 두 개가 완전히 일치할 때만 release 후보를 만든다."""
    if output.exists():
        raise BuildError("reproduce 출력은 새 디렉터리여야 함")
    output.mkdir(parents=True)
    first_meta = run_build(deps, output / "run1", commit=commit, mode="build")
    second_meta = run_build(deps, output / "run2", commit=commit, mode="build")
    first = {name: read_regular(output / "run1" / name) for name in F.RELEASE_NAMES}
    second = {name: read_regular(output / "run2" / name) for name in F.RELEASE_NAMES}
    proof = F.compare_builds(first, second, first_meta, second_meta)
    report = json.loads(first["build-check.json"])
    entry = F.manifest_entry(commit=commit, version=report["fw_version"], files=first, report=report,
                             source_sha256=first_meta["source_archive_sha256"],
                             dependencies=json.loads(first["dependencies-lock.json"]), reproducibility=proof)
    F.validate_release(entry, first)
    (output / "reproducibility.json").write_bytes(json_bytes(proof))
    (output / "release.json").write_bytes(json_bytes(entry))
    print(json.dumps({"status": "reproducible", "git_commit": commit, "image_sha256": entry["image_sha256"], "output": str(output)}))


def unchanged_source(commit: str) -> None:
    bounded_run([*GIT, "diff", "--exit-code", commit, "HEAD", "--", *SOURCE_PATHS], cwd=REPO, limit=1024 * 1024)
    bounded_run([*GIT, "diff", "--exit-code", "HEAD", "--", *SOURCE_PATHS], cwd=REPO, limit=1024 * 1024)


def publish(result: Path) -> None:
    """2회 출력과 source S를 다시 확인한 뒤 repository release 파일을 만든다. commit은 하지 않는다."""
    first_meta = json.loads(read_regular(result / "run1/build.json"))
    second_meta = json.loads(read_regular(result / "run2/build.json"))
    first = {name: read_regular(result / "run1" / name) for name in F.RELEASE_NAMES}
    second = {name: read_regular(result / "run2" / name) for name in F.RELEASE_NAMES}
    proof = F.compare_builds(first, second, first_meta, second_meta)
    entry = json.loads(read_regular(result / "release.json"))
    if proof != json.loads(read_regular(result / "reproducibility.json")):
        raise BuildError("재현 검증 기록 불일치")
    F.validate_release(entry, first)
    if entry["git_commit"] != proof["git_commit"] or entry["source_archive_sha256"] != proof["source_archive_sha256"]:
        raise BuildError("release의 source S 불일치")
    unchanged_source(entry["git_commit"])
    archive, _, _ = source_archive(entry["git_commit"])
    if sha256(archive) != entry["source_archive_sha256"]:
        raise BuildError("source archive SHA256 재확인 실패")
    directory = REPO / "firmware/releases/espprobe" / entry["fw_version"]
    if directory.exists():
        raise BuildError("기존 release 덮어쓰기 거부")
    catalog = REPO / "src/pweh/data/espprobe-releases.json"
    entries = F.load_releases(catalog)
    if any(item["fw_version"] == entry["fw_version"] for item in entries):
        raise BuildError("release version 중복")
    directory.mkdir(parents=True)
    for name, data in first.items():
        (directory / name).write_bytes(data)
    (directory / "release.json").write_bytes(json_bytes(entry))
    (directory / "reproducibility.json").write_bytes(json_bytes(proof))
    hashes = {**first, "release.json": json_bytes(entry), "reproducibility.json": json_bytes(proof)}
    (directory / "SHA256SUMS").write_text("".join(f"{sha256(data)}  {name}\n" for name, data in sorted(hashes.items())))
    catalog.write_bytes(json_bytes({"schema": "pweh.espprobe-releases/v1", "releases": [*entries, entry]}))
    print(json.dumps({"status": "published", "files": len(hashes), "git_commit": entry["git_commit"]}))


def verify_release() -> None:
    entries = F.load_releases(REPO / "src/pweh/data/espprobe-releases.json")
    if not entries:
        raise BuildError("등록된 release가 없음")
    for entry in entries:
        directory = REPO / "firmware/releases/espprobe" / entry["fw_version"]
        F.validate_release(entry, F.load_payloads(entry, directory))
        unchanged_source(entry["git_commit"])
        archive, _, _ = source_archive(entry["git_commit"])
        if sha256(archive) != entry["source_archive_sha256"]:
            raise BuildError("release source archive 불일치")
        if json.loads(read_regular(directory / "release.json")) != entry:
            raise BuildError("release catalog 사본 불일치")
        for line in read_regular(directory / "SHA256SUMS", limit=16384).decode().splitlines():
            expected, name = line.split("  ", 1)
            F.safe_name(name)
            if sha256(read_regular(inside(directory, name))) != expected:
                raise BuildError("release SHA256SUMS 불일치")
    print(json.dumps({"status": "verified", "releases": len(entries)}))


def container_argv(name: str, output: Path, *, network: bool = False, output_volume: str | None = None) -> list[str]:
    """자유 Docker flag를 받지 않는 공통 격리 argv."""
    output = output.resolve(strict=True)
    if "," in str(output) or "\n" in str(output):
        raise BuildError("Docker mount 경로 구분자 거부")
    memory = "1g" if network else "6g"
    work_size = "512m" if network else "3g"
    mount = f"type=volume,src={output_volume},dst=/out" if output_volume else f"type=bind,src={output},dst=/out"
    return [*DOCKER, "run", "--init", "--pull=never", "--platform=linux/amd64", "--name", name,
            "--network=bridge" if network else "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--no-healthcheck", "--pids-limit=64" if network else "--pids-limit=256", f"--memory={memory}",
            f"--memory-swap={memory}", "--cpus=2" if network else "--cpus=4", "--user", f"{os.getuid()}:{os.getgid()}", "--ipc=private",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
            "--tmpfs", f"/work:rw,nosuid,nodev,exec,size={work_size},uid={os.getuid()},gid={os.getgid()},mode=0700",
            "--mount", mount, "--workdir", "/work",
            "--env", "HOME=/tmp", "--env", "TZ=UTC", "--env", "LC_ALL=C.UTF-8",
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONHASHSEED=0",
            "--env", "IDF_CCACHE_ENABLE=0", "--env", "CCACHE_DISABLE=1", "--env", "IDF_BUILD_V2="]


def run_container(argv: list[str], name: str, output: Path, timeout: int) -> bytes:
    """실패/취소 시 이번 호출에만 속한 container를 회수한다."""
    error = None
    result = b""
    try:
        result = bounded_run(argv, timeout=timeout, log=output / "container.log")
    except BaseException as exc:
        error = exc
    try:
        # 실패한 빌드도 진단 파일을 보존하되 build.json/release 성공 상태를 만들지 않는다.
        archive = bounded_run([*DOCKER, "cp", name + ":/out/.", "-"], timeout=90, limit=288 * 1024 * 1024)
        extract_tar(archive, output)
    except BaseException as exc:
        if error is None:
            error = exc
    cleanup_errors = cleanup([[*DOCKER, "stop", "--time", "2", name], [*DOCKER, "rm", "--force", name]])
    if cleanup_errors:
        (output / "cleanup-errors.json").write_bytes(json_bytes(cleanup_errors))
        if error is None:
            error = BuildError("Docker cleanup 미완료: " + "; ".join(cleanup_errors))
    if error is not None:
        raise error
    return result


def cleanup(commands: list[list[str]]) -> list[str]:
    """앞 정리가 실패해도 남은 own container/volume 정리를 모두 시도한다."""
    errors = []
    for argv in commands:
        try:
            bounded_run(argv, timeout=15, limit=65536)
        except BaseException as exc:
            if "No such container" not in str(exc) and "No such volume" not in str(exc):
                errors.append(str(exc))
    if errors:
        print("Docker 정리 오류: " + "; ".join(errors), file=sys.stderr)
    return errors


def cleanup_volumes(volumes: list[str], output: Path) -> None:
    """각 volume을 독립 회수하고 미완료를 성공 결과로 남기지 않는다."""
    errors = cleanup([[*DOCKER, "volume", "rm", volume] for volume in volumes])
    if errors:
        (output / "volume-cleanup-errors.json").write_bytes(json_bytes(errors))
        (output / "build.json").unlink(missing_ok=True)
        if sys.exc_info()[0] is None:
            raise BuildError("Docker volume cleanup 미완료: " + "; ".join(errors))


def input_volume(source: Path, name: str) -> str:
    """daemon이 host 경로를 못 보는 WSL에서도 필요한 입력만 새 volume으로 전달한다."""
    volume = name + "-input"
    helper = name + "-copy"
    bounded_run([*DOCKER, "volume", "create", volume], limit=65536)
    try:
        bounded_run([*DOCKER, "create", "--name", helper, "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--mount", f"type=volume,src={volume},dst=/input",
                     IMAGE, "true"], limit=65536)
        bounded_run([*DOCKER, "cp", str(source) + "/.", helper + ":/input/"], timeout=90, limit=65536)
    except BaseException:
        cleanup([[*DOCKER, "rm", "--force", helper], [*DOCKER, "volume", "rm", volume]])
        raise
    finally:
        cleanup([[*DOCKER, "rm", "--force", helper]])
    return volume


def output_volume(name: str) -> str:
    volume = name + "-output"
    bounded_run([*DOCKER, "volume", "create", volume], limit=65536)
    helper = name + "-owner"
    try:
        # volume 소유자만 해당 uid로 바꾸는 고정 명령. host 파일/권한에는 닿지 않는다.
        bounded_run([*DOCKER, "run", "--rm", "--name", helper, "--network=none", "--read-only", "--cap-drop=ALL",
                     "--cap-add=CHOWN", "--security-opt=no-new-privileges", "--mount", f"type=volume,src={volume},dst=/out",
                     "--entrypoint", "/bin/chown", IMAGE, f"{os.getuid()}:{os.getgid()}", "/out"], limit=65536)
    except BaseException:
        cleanup([[*DOCKER, "rm", "--force", helper], [*DOCKER, "volume", "rm", volume]])
        raise
    finally:
        cleanup([[*DOCKER, "rm", "--force", helper]])
    return volume


def prepare(output: Path) -> None:
    if output.exists():
        raise BuildError("prepare 출력은 존재하지 않는 새 디렉터리여야 함")
    output.mkdir(parents=True)
    info = prepare_image(output)
    name = "pweh-i5-prepare-" + uuid.uuid4().hex[:12]
    script = REPO / "scripts/firmware/network_prepare.py"
    with tempfile.TemporaryDirectory(prefix="pweh-i5-network-input-") as temporary:
        shutil.copyfile(script, Path(temporary) / "network_prepare.py")
        shutil.copyfile(REPO / "scripts/firmware/components-lock.json", Path(temporary) / "components-lock.json")
        incoming = input_volume(Path(temporary), name)
    volumes = [incoming]
    try:
        outgoing = output_volume(name)
        volumes.append(outgoing)
        argv = container_argv(name, output, network=True, output_volume=outgoing)
        # 내려받는 단계에는 앱 source/CMake/Docker socket/기기를 전달하지 않는다.
        argv += ["--mount", f"type=volume,src={incoming},dst=/input,readonly", IMAGE,
                 "python", "-B", "/input/network_prepare.py"]
        run_container(argv, name, output, 900)
    finally:
        cleanup_volumes(volumes, output)
    downloaded = json.loads(read_regular(output / "mirror-files.json"))
    for row in downloaded["files"]:
        blob = read_regular(inside(output / "mirror", row["path"]), limit=64 * 1024 * 1024)
        if len(blob) != row["size"] or sha256(blob) != row["sha256"]:
            raise BuildError("component download 결과 변경")
    (output / "preparation.json").write_bytes(json_bytes({"schema": "pweh.firmware-preparation/v1",
        "status": "downloaded", "image": info, "components": COMPONENTS, "mirror": downloaded,
        "runner_sha256": sha256(read_regular(script))}))
    print(json.dumps({"status": "downloaded", "output": str(output), "manager_version": downloaded["manager_version"]}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--profile", choices=[PROFILE], default=PROFILE)
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--dry-run", action="store_true")
    lock_parser = sub.add_parser("lock")
    lock_parser.add_argument("--deps", type=Path, required=True)
    lock_parser.add_argument("--output", type=Path, required=True)
    build = sub.add_parser("build")
    build.add_argument("--deps", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    source = build.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-commit")
    source.add_argument("--preliminary", action="store_true")
    repeat = sub.add_parser("reproduce")
    repeat.add_argument("--deps", type=Path, required=True)
    repeat.add_argument("--output", type=Path, required=True)
    repeat.add_argument("--source-commit", required=True)
    release = sub.add_parser("publish")
    release.add_argument("--result", type=Path, required=True)
    sub.add_parser("verify-release")
    args = parser.parse_args()
    if args.action == "reproduce":
        reproduce(args.deps, args.output, args.source_commit)
    elif args.action == "publish":
        publish(args.result)
    elif args.action == "verify-release":
        verify_release()
    elif args.action == "lock":
        lock_components(args.deps, args.output)
    elif args.action == "build":
        print(json.dumps(run_build(args.deps, args.output, commit=args.source_commit, mode="build")))
    elif args.dry_run:
        print(json.dumps({"action": "prepare", "image": IMAGE, "platform": "linux/amd64", "components": COMPONENTS,
                          "download_only_network": True, "build_network": False, "devices": [], "output": str(args.output)}))
    else:
        prepare(args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, OSError, ValueError) as exc:
        print(f"펌웨어 작업 실패: {exc}", file=sys.stderr)
        raise SystemExit(1)
