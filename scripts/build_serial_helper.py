"""Windows 직렬 helper의 네트워크 없는 빌드·PE·릴리스 검사.

설치에서는 verify-release만 쓴다. build는 고정 Zig와 source commit을 사용하며
실행 파일을 Windows에서 실행하거나 새 도구를 받지 않는다.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import stat
import struct
import subprocess
import sys
import time

ZIG_VERSION = "0.17.0"
ZIG_ARCHIVE_SHA256 = "1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026"
LIMIT = 8 * 1024 * 1024
INPUTS = ("tools/winserial/pweh-serial-helper.c", "tools/winserial/win32-abi.h",
          "tools/winserial/test-native.c", "tools/winserial/test-win32.c", "scripts/build_serial_helper.py")
REL_BINARY = "tools/winserial/release/pweh-serial-helper.exe"
LOCK = "tools/winserial/build-lock.json"
FLAGS = ("-target", "x86_64-windows-gnu", "-std=c11", "-O2", "-fno-builtin",
         "-fno-stack-protector", "-Wall", "-Wextra", "-Werror", "-nostdlib", "-s",
         "-Wl,--entry,pweh_entry", "-Wl,--dynamicbase", "-Wl,--nxcompat", "-lkernel32")
ALLOWED_IMPORTS = frozenset("""CancelIoEx CancelSynchronousIo ClearCommBreak ClearCommError
CloseHandle CreateEventW CreateFileW CreateThread EnterCriticalSection EscapeCommFunction ExitProcess
GetCommModemStatus GetCommState GetCommandLineW GetCurrentProcess GetFileType GetLastError
GetOverlappedResult GetStdHandle GetTickCount64 InitializeCriticalSection LeaveCriticalSection
PurgeComm ReadFile ResetEvent SetCommBreak SetCommState SetCommTimeouts SetEvent Sleep
TerminateProcess WaitForSingleObject WriteFile""".split())


class BuildError(ValueError):
    """검증되지 않은 파일·빌드·릴리스를 거부한다."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, limit: int = LIMIT) -> bytes:
    """최종 링크/특수 파일을 열지 않고 단일 fd의 전후 지문을 확인한다."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise BuildError("일반 파일·단일 링크·크기 제한 위반")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(before) != fields(after) or len(data) != before.st_size:
            raise BuildError("읽는 동안 파일 변경/잘림")
        return bytes(data)
    finally:
        os.close(fd)


def _json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BuildError("JSON 중복 키")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def check_pe(path: Path | bytes, *, require_zero_timestamp: bool = True) -> dict:
    """AMD64 PE의 고정 import·entrypoint·정규화 timestamp·identity를 검사한다."""
    data = path if isinstance(path, bytes) else read_regular(Path(path))
    if not 64 <= len(data) <= LIMIT or data[:2] != b"MZ":
        raise BuildError("DOS 헤더/PE 크기 오류")

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise BuildError("PE 필드가 파일 범위를 벗어남")
        return struct.unpack_from(fmt, data, offset)

    pe, = unpack("<I", 60)
    if pe < 64 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise BuildError("PE signature 오류")
    machine, count, timestamp, _sym, _nsyms, opt_size, characteristics = unpack("<HHIIIHH", pe + 4)
    if machine != 0x8664 or not 1 <= count <= 96 or characteristics & 0x2000 or not characteristics & 2:
        raise BuildError("AMD64 실행 파일이 아님")
    if require_zero_timestamp and timestamp:
        raise BuildError("PE timestamp가 정규화되지 않음")
    opt = pe + 24
    if opt_size != 240 or unpack("<H", opt)[0] != 0x20B:
        raise BuildError("고정 PE32+ optional header가 아님")
    entry, = unpack("<I", opt + 16)
    subsystem, dll_flags = unpack("<HH", opt + 68)
    if subsystem != 3 or dll_flags & 0x160 != 0x160:
        raise BuildError("CUI/ASLR/NX/high-entropy 플래그 누락")
    num_dirs, = unpack("<I", opt + 108)
    if num_dirs != 16:
        raise BuildError("PE data directory 개수 오류")
    dirs = [unpack("<II", opt + 112 + i * 8) for i in range(16)]
    # export/resource/cert/TLS/bound/delay/CLR와 미사용 디렉터리를 지원하지 않는다.
    for i in (0, 2, 4, 7, 8, 9, 10, 11, 13, 14, 15):
        if dirs[i] != (0, 0):
            raise BuildError("미지원 PE directory")
    headers, = unpack("<I", opt + 60)
    section_start = opt + opt_size
    if not section_start + count * 40 <= headers <= len(data):
        raise BuildError("PE section/header 범위 오류")
    sections = []
    for i in range(count):
        off = section_start + 40 * i
        name, vsize, rva, size, raw, _rel, _ln, _nr, _nl, flags = unpack("<8sIIIIIIHHI", off)
        if rva == 0 or rva + max(vsize, size) > 0xFFFFFFFF or size and (raw < headers or raw + size > len(data)):
            raise BuildError("PE section 범위 오류")
        if flags & 0x20000000 and flags & 0x80000000:
            raise BuildError("쓰기 가능한 실행 section")
        row = (rva, max(vsize, size), raw, size, name.rstrip(b"\0"), flags)
        for old in sections:
            if rva < old[0] + old[1] and old[0] < rva + row[1]:
                raise BuildError("PE virtual section 겹침")
            if size and old[3] and raw < old[2] + old[3] and old[2] < raw + size:
                raise BuildError("PE raw section 겹침")
        sections.append(row)
    if not any(rva <= entry < rva + size and flags & 0x20000000 for rva, _v, _r, size, _n, flags in sections):
        raise BuildError("entrypoint가 실행 section 안에 없음")

    def mapped(rva, size):
        hits = [raw + rva - base for base, _v, raw, n, _name, _flags in sections
                if size > 0 and base <= rva and rva + size <= base + n]
        if len(hits) != 1:
            raise BuildError("PE RVA가 단일 파일 section 안에 없음")
        return hits[0]

    def cstring(rva):
        out = bytearray()
        for i in range(256):
            value = data[mapped(rva + i, 1)]
            if value == 0:
                if not out:
                    raise BuildError("빈 PE import 이름")
                return out.decode("ascii")
            if not 33 <= value <= 126:
                raise BuildError("PE import 이름 비ASCII")
            out.append(value)
        raise BuildError("PE import 이름 상한")

    for i in (1, 3, 5, 6, 12):
        rva, size = dirs[i]
        if bool(rva) != bool(size):
            raise BuildError("PE directory의 RVA/size 불일치")
        if rva:
            mapped(rva, size)
    import_rva, import_size = dirs[1]
    if not import_rva or not 40 <= import_size <= 64 * 20 or import_size % 20:
        raise BuildError("import 표 누락/상한")
    imports, dlls, terminated = [], [], False
    for i in range(import_size // 20):
        fields = unpack("<IIIII", mapped(import_rva + i * 20, 20))
        if fields == (0, 0, 0, 0, 0):
            terminated = True
            if i != import_size // 20 - 1:
                raise BuildError("import 종료 뒤 추가 descriptor")
            break
        lookup, stamp, forward, name, iat = fields
        dll = cstring(name).lower()
        if dll != "kernel32.dll" or dll in dlls or stamp or forward or not lookup or not iat:
            raise BuildError("허용되지 않은 DLL/import descriptor")
        dlls.append(dll)
        for j in range(513):
            entry64, = unpack("<Q", mapped(lookup + 8 * j, 8))
            iat64, = unpack("<Q", mapped(iat + 8 * j, 8))
            if entry64 != iat64:
                raise BuildError("import lookup/IAT 불일치")
            if entry64 == 0:
                break
            if j == 512 or entry64 >> 32:
                raise BuildError("ordinal/큰 import 또는 함수 상한")
            function = cstring(entry64 + 2)
            if function not in ALLOWED_IMPORTS or function in imports:
                raise BuildError("허용되지 않은/중복 import 함수")
            imports.append(function)
    if not terminated or set(imports) != ALLOWED_IMPORTS:
        raise BuildError("고정 import 집합 불일치")
    identity_sections = [(rva, size) for rva, _v, _raw, size, name, _f in sections if name == b".pweh"]
    if len(identity_sections) != 1:
        raise BuildError("build identity section 누락/중복")
    identity = data[mapped(identity_sections[0][0], 40):][:40]
    if identity[:8] != b"PWEHWIN1" or identity[28:] != bytes((0, 1, 0, 1, 0, 0, 64, 0, 0, 0, 0, 0)):
        raise BuildError("helper identity/protocol/version 불일치")
    if dirs[6] != (0, 0):
        rva, size = dirs[6]
        if size % 28 or size > 8 * 28:
            raise BuildError("debug directory 상한/구조 오류")
        for i in range(size // 28):
            debug_type, = unpack("<I", mapped(rva + 28 * i + 12, 4))
            if debug_type != 16:  # 경로를 넣는 CodeView는 strip해야 한다.
                raise BuildError("REPRO 이외 debug metadata 잔존")
    if b"/home/" in data or b"/tmp/" in data or b"\\Users\\" in data:
        raise BuildError("호스트 경로가 PE에 남음")
    return {"machine": "amd64", "timestamp": timestamp, "imports": sorted(imports),
            "dlls": dlls, "source_commit": identity[8:28].hex(), "version": [0, 1, 0],
            "protocol": [1, 0], "size": len(data), "sha256": sha(data), "entrypoint": entry}


def normalize_pe(data: bytes) -> bytes:
    """명시한 COFF timestamp 네 바이트만 0으로 한다. 다른 byte는 건드리지 않는다."""
    check_pe(data, require_zero_timestamp=False)
    pe, = struct.unpack_from("<I", data, 60)
    result = bytearray(data)
    result[pe + 8:pe + 12] = b"\0" * 4
    check_pe(bytes(result))
    return bytes(result)


def bounded(argv: list[str], *, cwd: Path, env: dict | None = None, timeout: float = 120, limit: int = 2**20) -> bytes:
    """소유 그룹을 제한 시간·출력 상한 안에서 거두는 빌드용 subprocess."""
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray(); deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            while sel.get_map():
                if time.monotonic() >= deadline:
                    raise BuildError("빌드 명령 시간 제한")
                for key, _ in sel.select(min(.1, deadline - time.monotonic())):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > limit:
                            raise BuildError("빌드 명령 출력 상한")
        exited = None
        while time.monotonic() < deadline:
            exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None:
                break
            time.sleep(.01)
        if exited is None:
            raise BuildError("빌드 명령 종료 시간 제한")
        if exited.si_code != os.CLD_EXITED or exited.si_status != 0:
            raise BuildError("빌드 명령 실패: " + bytes(output[-4000:]).decode("utf-8", "replace"))
        return bytes(output)
    finally:
        # 이 실행의 세션 그룹만 정리한다. leader를 거두기 전 timeout 경로를 처리한다.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        if proc.stdout:
            proc.stdout.close()


def inputs_at(root: Path, commit: str | None = None) -> dict[str, bytes]:
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BuildError("source commit은 완전한 소문자 SHA-1이어야 함")
    result = {}
    for name in INPUTS:
        result[name] = (bounded(["git", "show", f"{commit}:{name}"], cwd=root, timeout=10)
                        if commit else read_regular(root / name))
    return result


def _pin(root: Path) -> dict:
    tree = ast.parse(read_regular(root / "src/pweh/winserial/pin.py", 16384))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values[node.target.id] = ast.literal_eval(node.value)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            values[node.targets[0].id] = ast.literal_eval(node.value)
    return values


def verify_release(repo_root: Path, binary_path: Path | None = None) -> dict:
    """installer용 정적 release 검사. 미준비 S는 실행·설치 불가다."""
    root = Path(repo_root)
    lock = _json(read_regular(root / LOCK, 65536))
    artifact = lock.get("artifact")
    if not isinstance(artifact, dict):
        raise BuildError("helper release 미준비: source S는 fail closed")
    pin = _pin(root)
    digest, commit = pin.get("PINNED_SHA256"), pin.get("EXPECTED_SOURCE_COMMIT")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BuildError("helper runtime pin 미준비/형식 오류")
    if pin.get("HELPER_VERSION") != (0, 1, 0) or pin.get("PROTOCOL_VERSION") != (1, 0):
        raise BuildError("runtime version/protocol pin 불일치")
    expected_inputs = {name: sha(data) for name, data in inputs_at(root).items()}
    if lock.get("schema") != "pweh.winserial-build/v1" or lock.get("inputs") != expected_inputs:
        raise BuildError("source inputs 해시 불일치")
    if lock.get("zig") != {"version": ZIG_VERSION, "archive_sha256": ZIG_ARCHIVE_SHA256} or lock.get("flags") != list(FLAGS):
        raise BuildError("고정 toolchain/레시피 불일치")
    if artifact.get("source_commit") != commit or artifact.get("sha256") != digest or artifact.get("reproducibility") != "matched" or artifact.get("runs") != 2:
        raise BuildError("artifact/runtime pin/두 빌드 증거 불일치")
    runs = artifact.get("builds")
    if not isinstance(runs, list) or len(runs) != 2 or any(not isinstance(x, dict) or x.get("sha256") != digest or x.get("source_commit") != commit or x.get("inputs") != expected_inputs for x in runs):
        raise BuildError("독립 build report 누락/불일치")
    ids = set()
    for run in runs:
        run_id = run.get("run_id")
        if (run.get("schema") != "pweh.winserial-build-run/v1" or run.get("preliminary") is not False
            or not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or run_id in ids or run.get("flags") != list(FLAGS) or run.get("zig") != lock["zig"]
            or run.get("normalization") != "coff-timestamp-zero-4bytes"
            or not isinstance(run.get("raw_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", run["raw_sha256"])
            or not isinstance(run.get("pe"), dict) or run["pe"].get("source_commit") != commit
            or run["pe"].get("sha256") != digest or run["pe"].get("timestamp") != 0):
            raise BuildError("preliminary/중복/불완전 build report")
        ids.add(run_id)
    # Git 이력 없는 배포는 고정 입력 해시와 commit 결속을 보존한다. 이력이 있으면 S 원문도 대조한다.
    if (root / ".git").exists():
        source_inputs = {name: sha(data) for name, data in inputs_at(root, commit).items()}
        if source_inputs != expected_inputs:
            raise BuildError("source S와 release R의 빌드 입력이 다름")
    sums = read_regular(root / "tools/winserial/SHA256SUMS", 4096).decode("ascii")
    if sums != f"{digest}  pweh-serial-helper.exe\n":
        raise BuildError("SHA256SUMS/runtime pin 불일치")
    path = Path(binary_path) if binary_path is not None else root / REL_BINARY
    if path.name != "pweh-serial-helper.exe":
        raise BuildError("helper basename 오류")
    report = check_pe(path)
    if report["sha256"] != digest or report["source_commit"] != commit:
        raise BuildError("PE 해시/build identity pin 불일치")
    return {"status": "verified", "binary": str(path), **report}


def build(repo_root: Path, source_commit: str, output_dir: Path, zig: Path, *, preliminary=False) -> dict:
    root, out, zig = Path(repo_root).resolve(), Path(output_dir).absolute(), Path(zig).absolute()
    if out.exists():
        raise BuildError("빌드 출력 디렉터리는 새 경로여야 함")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise BuildError("source commit 형식 오류")
    inputs = inputs_at(root, None if preliminary else source_commit)
    lock = _json(read_regular(root / LOCK, 65536))
    hashes = {name: sha(data) for name, data in inputs.items()}
    if not preliminary and (lock.get("inputs") != hashes or inputs["scripts/build_serial_helper.py"] != read_regular(Path(__file__))):
        raise BuildError("source S lock/checker 입력 불일치")
    if bounded([str(zig), "version"], cwd=root, timeout=10).decode().strip() != ZIG_VERSION:
        raise BuildError("고정 Zig 버전 불일치")
    out.mkdir(parents=True)
    src = out / "src"; src.mkdir()
    for name, data in inputs.items():
        (src / Path(name).name).write_bytes(data)
    identity = b"PWEHWIN1" + bytes.fromhex(source_commit) + bytes((0, 1, 0, 1, 0, 0, 64, 0, 0, 0, 0, 0))
    (src / "pweh-build-id.h").write_text("/* 고정 source S 식별자: 자기 PE 해시가 아니다. */\nstatic volatile const unsigned char PWEH_BUILD_ID[40] __attribute__((section(\".pweh\"), used)) = {" + ",".join(str(x) for x in identity) + "};\n")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0",
           "ZIG_GLOBAL_CACHE_DIR": str(out / "cache-global"), "ZIG_LOCAL_CACHE_DIR": str(out / "cache-local")}
    binary = out / "pweh-serial-helper.exe"
    argv = [str(zig), "cc", *FLAGS, "-I.", "pweh-serial-helper.c", "-o", str(binary)]
    bounded(argv, cwd=src, env=env, timeout=180)
    raw = read_regular(binary)
    normalized = normalize_pe(raw)
    binary.write_bytes(normalized)
    report = {"schema": "pweh.winserial-build-run/v1", "run_id": secrets.token_hex(16),
              "preliminary": bool(preliminary), "source_commit": source_commit,
              "inputs": hashes, "zig": lock["zig"], "flags": list(FLAGS), "raw_sha256": sha(raw),
              "sha256": sha(normalized), "normalization": "coff-timestamp-zero-4bytes", "pe": check_pe(normalized)}
    (out / "build-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-pe"); check.add_argument("path", type=Path)
    verify = sub.add_parser("verify-release"); verify.add_argument("--repo-root", type=Path, required=True); verify.add_argument("--binary", type=Path)
    compile_cmd = sub.add_parser("build")
    for name in ("repo-root", "output-dir", "zig"):
        compile_cmd.add_argument("--" + name, type=Path, required=True)
    compile_cmd.add_argument("--source-commit", required=True); compile_cmd.add_argument("--preliminary", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "check-pe": result = check_pe(args.path)
        elif args.command == "verify-release": result = verify_release(args.repo_root, args.binary)
        else: result = build(args.repo_root, args.source_commit, args.output_dir, args.zig, preliminary=args.preliminary)
    except (BuildError, OSError, ValueError, SyntaxError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
