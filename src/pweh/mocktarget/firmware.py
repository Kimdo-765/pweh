"""합성 16MiB SPI NOR 펌웨어 이미지 빌더.

``build_image(profile, out_path)`` 는 프로필의 mtdparts 배치대로 다음을 채운 이미지를 만들고
``<out_path>.manifest.json`` 에 매니페스트(파티션, env, uImage, rootfs 파일 목록, planted_issues 정답)를 쓴다.

- boot   : 가짜 U-Boot 블롭 (버전 문자열, 기본 env 텍스트, 프롬프트 등 문자열 + 결정적 의사 코드 바이트)
- env    : ``pweh.formats.build_uboot_env`` 로 만든 CRC 가 맞는 env 블록 (bootargs/mtdparts, bootcmd, ...)
- kernel : ``pweh.formats.build_uimage_header`` legacy uImage + 작은 가짜 커널 (프로필 압축 방식: none/lzma/gzip)
- rootfs : mksquashfs(xz) 로 만든 BusyBox 카메라 레이아웃 squashfs (없으면 gzip cpio 로 대체하고 기록)
- app    : 설정 파일이 든 두 번째 squashfs (없으면 gzip cpio)

/usr/sbin/httpd 와 /bin/busybox 는 ``firmware_src/*.c`` 를 Zig(arm-linux-musleabi / mipsel-linux-musleabi,
정적, 심볼 유지)로 빌드한다. Zig 가 없으면 셸 스크립트 CGI 로 대체하고 매니페스트에 기록한다.
모든 산출물에 ``PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE`` 표식이 들어간다.
빌드는 결정적이다 (같은 프로필/소스/도구 → 같은 바이트). 결과는 캐시 디렉터리에 재사용된다.

벤더 스타일 변형 프로필(예: ``hikvision-like``, ``dahua-like``)은 ``firmware:`` 아래의 선택 키로 rootfs 를 넓힌다.
키가 없는 프로필의 이미지는 바이트 단위로 그대로다.
- ``extra_binaries: [{source, dest, cflags?}]`` : ``profiles/`` 기준 상대 경로의 C 소스를 같은 Zig 설정으로 빌드해
  ``dest`` 에 넣는다 (빠른 빌드나 Zig 가 없으면 생략).
- ``extra_dirs: [경로]``, ``extra_files: [{path, content | append, mode?}]`` : 디렉터리/텍스트 파일 추가, 기존 파일 뒤에 덧붙이기.
- ``extra_planted_issues: [...]`` : 그 변형의 정답(ground truth). ``file`` 이 빌드된 트리에 실제로 있을 때만
  매니페스트 ``planted_issues`` 뒤에 붙는다.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import Any, Mapping

from ..errors import ConfigError, ToolMissing
from ..formats import build_uboot_env, build_uimage_header, parse_uboot_env, parse_uimage_header
from ..fsutil import atomic_write_bytes, atomic_write_json
from . import rootfs
from .profiles import PROFILE_DIR, SYNTHETIC_MARKER, load_profile, partition

log = logging.getLogger("pweh.mocktarget")

FORMAT = "pweh-mocktarget-firmware/1"
SRC_DIR = Path(__file__).resolve().parent / "firmware_src"
_BUILDER_VERSION = "1"


# ---------------------------------------------------------------------------
# 외부 도구 찾기
# ---------------------------------------------------------------------------
def find_tool(name: str, env_var: str) -> str | None:
    """환경변수 → PATH → ~/pweh-tools/bin 순서로 찾는다."""
    val = os.environ.get(env_var)
    if val and Path(val).is_file() and os.access(val, os.X_OK):
        return val
    found = shutil.which(name)
    if found:
        return found
    cand = Path.home() / "pweh-tools" / "bin" / name
    if cand.is_file() and os.access(cand, os.X_OK):
        return str(cand)
    return None


def cache_dir() -> Path:
    base = os.environ.get("PWEH_CACHE_DIR")
    if base:
        return Path(base).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg).expanduser() if xdg else Path.home() / ".cache") / "pweh"


def _run(cmd: list[str], *, env: dict[str, str] | None = None, timeout: float = 600.0, cwd: str | None = None) -> subprocess.CompletedProcess:
    log.debug("run: %s", cmd)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout, cwd=cwd,
                          check=False, start_new_session=True)


def _tool_version(tool: str | None, args: list[str]) -> str | None:
    if not tool:
        return None
    try:
        res = _run([tool, *args], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (res.stdout or res.stderr).decode("utf-8", "replace").strip().splitlines()
    return text[0] if text else None


# ---------------------------------------------------------------------------
# Zig 빌드
# ---------------------------------------------------------------------------
def build_binaries(profile: Mapping[str, Any], zig: str, work: Path) -> dict[str, Any]:
    """httpd / busybox 대용 / 도구 스텁을 빌드. 반환 {"files": {경로: bytes}, "info": [...]}."""
    target = profile.get("firmware", {}).get("zig_target") or (
        "arm-linux-musleabi" if profile["arch"] == "arm" else "mipsel-linux-musleabi")
    zcache = cache_dir() / "zig"
    env = dict(os.environ)
    env["ZIG_GLOBAL_CACHE_DIR"] = str(zcache / "global")
    env["ZIG_LOCAL_CACHE_DIR"] = str(zcache / "local")
    (zcache / "global").mkdir(parents=True, exist_ok=True)
    (zcache / "local").mkdir(parents=True, exist_ok=True)
    banner = profile["linux"].get("busybox_banner", "BusyBox")
    jobs = [
        ("httpd.c", profile.get("firmware", {}).get("web_server", "/usr/sbin/httpd"), []),
        ("busybox_stub.c", "/bin/busybox", [f'-DPWEH_BUSYBOX_BANNER="{banner}"']),
    ]
    files: dict[str, bytes] = {}
    info = []
    builds = [(SRC_DIR / src, dest, extra, f"firmware_src/{src}", Path(dest).name + ".elf") for src, dest, extra in jobs]
    # 벤더 스타일 변형 프로필의 추가 바이너리 (firmware.extra_binaries, 없으면 빈 목록)
    builds += [(ex["src"], ex["dest"], ex["cflags"], ex["label"], f"extra{i}-{Path(ex['dest']).name}.elf")
               for i, ex in enumerate(_extra_binary_specs(profile))]
    for src_path, dest, extra, label, out_name in builds:
        out = work / out_name
        cmd = [zig, "cc", "-target", target, "-static", "-O2", "-fno-inline", "-Wall", *extra,
               "-o", str(out), str(src_path)]
        res = _run(cmd, env=env, timeout=900)
        if res.returncode != 0 or not out.is_file():
            raise ToolMissing(f"zig 빌드 실패 ({label}): {res.stderr.decode('utf-8', 'replace')[-2000:]}")
        data = out.read_bytes()
        files[dest] = data
        info.append({"path": dest, "source": label, "target": target, "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(), "elf_machine": _elf_machine(data)})
    # mtd-utils/u-boot-tools 자리: busybox 스텁을 재사용 (argv[0] 로 이름 표시)
    for tool in ("flash_erase", "mtd_debug", "fw_printenv", "fw_setenv"):
        files[f"/usr/sbin/{tool}"] = files["/bin/busybox"]
    return {"files": files, "info": info, "target": target}


def _elf_machine(data: bytes) -> str | None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    little = data[5] == 1
    mach = int.from_bytes(data[18:20], "little" if little else "big")
    return {40: "ARM", 8: "MIPS", 62: "x86-64", 3: "x86", 183: "AArch64"}.get(mach, str(mach))


# ---------------------------------------------------------------------------
# 벤더 스타일 변형 프로필의 추가 구성 (firmware.extra_*) — 키가 없으면 아무것도 하지 않는다
# ---------------------------------------------------------------------------
def _extra_binary_specs(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    """firmware.extra_binaries → [{src(Path), dest, cflags, label}]. 소스는 profiles/ 안의 파일만 허용한다."""
    out: list[dict[str, Any]] = []
    root = PROFILE_DIR.resolve()
    for ent in (profile.get("firmware") or {}).get("extra_binaries") or []:
        rel = str(ent.get("source") or "")
        dest = str(ent.get("dest") or "")
        src = (root / rel).resolve()
        if not rel or root not in src.parents or not src.is_file():
            raise ConfigError(f"firmware.extra_binaries 의 source 는 profiles/ 안의 C 파일이어야 합니다: {rel!r}")
        if not dest.startswith("/") or ".." in dest.split("/"):
            raise ConfigError(f"firmware.extra_binaries 의 dest 는 rootfs 절대 경로여야 합니다: {dest!r}")
        out.append({"src": src, "dest": dest, "cflags": [str(x) for x in ent.get("cflags") or []],
                    "label": f"profiles/{rel}"})
    return out


def _tree_mkdir(tree: dict[str, rootfs.Node], path: str) -> None:
    cur = ""
    for part in [p for p in path.split("/") if p]:
        cur += "/" + part
        if cur not in tree:
            tree[cur] = rootfs.Node("dir", rootfs.S_IFDIR | 0o755)


def _apply_profile_extras(profile: Mapping[str, Any], tree: dict[str, rootfs.Node],
                          binaries: Mapping[str, bytes]) -> dict[str, rootfs.Node]:
    """firmware.extra_dirs / extra_binaries(빌드된 것만) / extra_files 를 트리에 더한다. 키가 없으면 트리를 그대로 돌려준다."""
    fw = profile.get("firmware") or {}
    if not any(fw.get(k) for k in ("extra_dirs", "extra_binaries", "extra_files")):
        return tree
    for d in fw.get("extra_dirs") or []:
        _tree_mkdir(tree, str(d))
    for ex in _extra_binary_specs(profile):
        data = binaries.get(ex["dest"])
        if data is None:  # 빠른 빌드 / zig 없음: 자리표시자를 넣지 않는다 (정답 목록에서도 빠진다)
            continue
        _tree_mkdir(tree, ex["dest"].rsplit("/", 1)[0] or "/")
        tree[ex["dest"]] = rootfs.Node("file", rootfs.S_IFREG | 0o755, data=data)
    for ent in fw.get("extra_files") or []:
        path = str(ent.get("path") or "")
        if not path.startswith("/"):
            raise ConfigError(f"firmware.extra_files 의 path 는 절대 경로여야 합니다: {path!r}")
        if "append" in ent:
            node = tree.get(path)
            if node is None or node.kind != "file":
                raise ConfigError(f"firmware.extra_files: 덧붙일 파일이 트리에 없습니다: {path}")
            node.data = node.data + str(ent["append"]).encode("utf-8")
            continue
        _tree_mkdir(tree, path.rsplit("/", 1)[0] or "/")
        mode = int(str(ent.get("mode", "0644")), 8)
        tree[path] = rootfs.Node("file", rootfs.S_IFREG | mode, data=str(ent.get("content") or "").encode("utf-8"))
    return dict(sorted(tree.items()))


def _extra_planted_issues(profile: Mapping[str, Any], tree: Mapping[str, rootfs.Node]) -> list[dict[str, Any]]:
    """firmware.extra_planted_issues 중 file 이 빌드된 트리에 실제로 있는 항목만 (정답이 이미지와 어긋나지 않게)."""
    out: list[dict[str, Any]] = []
    for ent in (profile.get("firmware") or {}).get("extra_planted_issues") or []:
        node = tree.get(str(ent.get("file") or ""))
        if node is None or node.kind != "file" or node.meta.get("placeholder"):
            continue
        item = dict(ent)
        item.setdefault("function", None)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 파일시스템 이미지
# ---------------------------------------------------------------------------
def _materialize(tree: Mapping[str, rootfs.Node], root: Path) -> list[str]:
    """트리를 디렉터리에 풀어 쓴다 (장치 노드는 mksquashfs pseudo 정의로). 반환: pseudo 정의 목록."""
    pseudo = []
    for path, node in tree.items():
        if path == "/":
            continue
        dest = root / path.lstrip("/")
        if node.kind == "dir":
            dest.mkdir(parents=True, exist_ok=True)
        elif node.kind == "file":
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(node.data)
        elif node.kind == "symlink":
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(node.target, dest)
        elif node.kind in ("chr", "blk"):
            pseudo.append(f"{path} {'c' if node.kind == 'chr' else 'b'} {node.mode & 0o7777:o} 0 0 {node.major} {node.minor}")
    # 권한은 마지막에 (디렉터리 쓰기 권한 문제 방지: 깊은 경로부터)
    for path, node in sorted(tree.items(), key=lambda kv: -kv[0].count("/")):
        if path == "/" or node.kind not in ("dir", "file"):
            continue
        os.chmod(root / path.lstrip("/"), node.mode & 0o7777)
    return pseudo


def build_squashfs(tree: Mapping[str, rootfs.Node], mksquashfs: str, *, epoch: int, comp: str = "xz",
                   work: Path) -> bytes:
    root = Path(tempfile.mkdtemp(prefix="sqroot-", dir=work))
    pseudo = _materialize(tree, root)
    out = work / (root.name + ".sqfs")
    cmd = [mksquashfs, str(root), str(out), "-noappend", "-all-root", "-comp", comp, "-b", "131072",
           "-mkfs-time", str(epoch), "-all-time", str(epoch), "-no-progress", "-quiet", "-processors", "1"]
    for p in pseudo:
        cmd += ["-p", p]
    res = _run(cmd, timeout=300)
    # 디렉터리 권한 원복 (임시 디렉터리를 지울 수 있게)
    for dirpath, dirnames, _ in os.walk(root):
        for d in dirnames:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(dirpath, d), 0o755)
    if res.returncode != 0 or not out.is_file():
        raise ToolMissing(f"mksquashfs 실패: {res.stderr.decode('utf-8', 'replace')[-2000:]}")
    return out.read_bytes()


def build_cpio_gz(tree: Mapping[str, rootfs.Node], *, epoch: int) -> bytes:
    """SVR4 newc cpio + gzip (squashfs 도구가 없을 때의 대체 rootfs)."""
    buf = io.BytesIO()
    ino = 1

    def entry(name: str, mode: int, data: bytes, rdev: tuple[int, int] = (0, 0)) -> None:
        nonlocal ino
        nb = name.encode() + b"\0"
        hdr = "070701" + "".join(f"{v:08X}" for v in (
            ino, mode, 0, 0, 1, epoch, len(data), 0, 0, rdev[0], rdev[1], len(nb), 0))
        buf.write(hdr.encode() + nb)
        buf.write(b"\0" * ((4 - (110 + len(nb)) % 4) % 4))
        buf.write(data)
        buf.write(b"\0" * ((4 - len(data) % 4) % 4))
        ino += 1

    for path, node in tree.items():
        name = "." if path == "/" else path.lstrip("/")
        if node.kind == "symlink":
            entry(name, node.mode, node.target.encode())
        elif node.kind in ("chr", "blk"):
            entry(name, node.mode, b"", (node.major, node.minor))
        else:
            entry(name, node.mode, node.data if node.kind == "file" else b"")
    entry("TRAILER!!!", 0, b"")
    raw = buf.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=epoch, compresslevel=9) as gz:
        gz.write(raw)
    return out.getvalue()


# ---------------------------------------------------------------------------
# 각 파티션 내용
# ---------------------------------------------------------------------------
def _noise(seed: str, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{ctr}".encode()).digest()
        ctr += 1
    return bytes(out[:n])


def build_boot_blob(profile: Mapping[str, Any], size: int) -> bytes:
    ub = profile["uboot"]
    version = f"{ub.get('version', '')}{ub.get('version_tag', '') or ''}"
    strings = [
        version, SYNTHETIC_MARKER, ub.get("prompt", ""), "Hit any key to stop autoboot: %2d ",
        "## Booting kernel from Legacy Image at %08lx ...", "Starting kernel ...", "Unknown command '%s' - try 'help'",
        "*** Warning - bad CRC, using default environment", "Saving Environment to %s...",
        "CRC32 for %08lx ... %08lx ==> %08lx", "Environment size: %d/%ld bytes",
    ]
    if ub.get("spl_version"):
        strings.insert(0, ub["spl_version"])
    default_env = b"".join(f"{k}={v}".encode() + b"\0" for k, v in (ub.get("default_env") or {}).items()) + b"\0"
    head = bytearray()
    # 리셋 벡터처럼 보이는 머리 (ARM: b reset / MIPS: j 형태) — 실행되지 않음
    if profile["arch"] == "arm":
        head += struct.pack("<8I", *([0xEA000016] + [0xE59FF014] * 7))
    else:
        head += struct.pack("<8I", *([0x0BC00100] + [0x00000000] * 7))
    head += b"\0" * 32
    body = b"\0".join(s.encode() for s in strings) + b"\0\0" + default_env
    code_len = min(size - len(head) - len(body) - 4096, 160 * 1024)
    blob = bytes(head) + _noise(f"boot:{profile['name']}", max(0, code_len)) + body
    if len(blob) > size:
        raise ConfigError("boot 파티션이 너무 작습니다.")
    return blob


def build_kernel(profile: Mapping[str, Any]) -> tuple[bytes, bytes]:
    """(uImage 전체, 압축 전 가짜 vmlinux)."""
    kn = profile["kernel"]
    fw = profile.get("firmware", {})
    version_line = kn.get("version_line", f"Linux version {kn['version']}")
    text = (f"{version_line}\n{SYNTHETIC_MARKER}\nKernel command line: %s\nCreating %d MTD partitions on \"%s\":\n"
            "VFS: Mounted root (%s filesystem)%s on device %u:%u.\nFreeing unused kernel memory: %ldK\n").encode()
    vmlinux = _noise(f"vmlinux:{profile['name']}", 384 * 1024) + text + bytes(1024 * 1024)
    comp = kn.get("compression", "none")
    if comp == "lzma":
        payload = lzma.compress(vmlinux, format=lzma.FORMAT_ALONE, preset=6)
        comp_name = "lzma"
    elif comp == "gzip":
        bio = io.BytesIO()
        with gzip.GzipFile(fileobj=bio, mode="wb", mtime=int(fw.get("epoch", 0)), compresslevel=9) as gz:
            gz.write(vmlinux)
        payload = bio.getvalue()
        comp_name = "gzip"
    else:
        # zImage 형태: 매직 0x016F2818 @0x24 + 압축된 본체
        hdr = bytearray(0x40)
        struct.pack_into("<I", hdr, 0x00, 0xE1A00000)
        struct.pack_into("<III", hdr, 0x24, 0x016F2818, 0, 0)
        bio = io.BytesIO()
        with gzip.GzipFile(fileobj=bio, mode="wb", mtime=int(fw.get("epoch", 0)), compresslevel=6) as gz:
            gz.write(vmlinux)
        zimg = bytearray(hdr) + bio.getvalue()
        struct.pack_into("<I", zimg, 0x2C, len(zimg))
        payload = bytes(zimg)
        comp_name = "none"
    header = build_uimage_header(payload, name=kn["image_name"], load=kn["load_addr"], entry=kn["entry"],
                                 arch="arm" if profile["arch"] == "arm" else "mips", comp=comp_name,
                                 timestamp=int(fw.get("epoch", 0)))
    return header + payload, vmlinux


def stored_env(profile: Mapping[str, Any]) -> dict[str, str]:
    env = dict(profile["uboot"].get("env") or {})
    return env


# ---------------------------------------------------------------------------
# 이미지 조립
# ---------------------------------------------------------------------------
def _cache_key(profile: Mapping[str, Any], fast: bool, tools: Mapping[str, Any]) -> str:
    h = hashlib.sha256()
    prof = {k: v for k, v in profile.items() if k not in ("source", "_normalized")}
    h.update(json.dumps(prof, sort_keys=True, default=str).encode())
    h.update(f"fast={fast};builder={_BUILDER_VERSION}".encode())
    for p in sorted(SRC_DIR.glob("*.c")):
        h.update(p.read_bytes())
    for ex in _extra_binary_specs(profile):  # 변형 프로필의 추가 소스 (없으면 아무것도 더하지 않음)
        h.update(ex["src"].read_bytes())
    for mod in ("firmware.py", "rootfs.py"):
        h.update((Path(__file__).resolve().parent / mod).read_bytes())
    h.update(json.dumps(tools, sort_keys=True, default=str).encode())
    return h.hexdigest()[:24]


def _build(profile: dict[str, Any], *, fast: bool, zig: str | None, mksquashfs: str | None) -> tuple[bytes, dict[str, Any]]:
    fl = profile["flash"]
    size = fl["size"]
    image = bytearray(b"\xff" * size)
    fw = profile.get("firmware", {})
    epoch = int(fw.get("epoch", 1577836800))
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "marker": SYNTHETIC_MARKER,
        "synthetic": True,
        "note": "pweh.mocktarget 합성 테스트 펌웨어 (실제 벤더 펌웨어 아님). planted_issues 는 분석 파이프라인 정답.",
        "profile": profile["name"],
        "arch": profile["arch"],
        "endianness": profile.get("endianness", "little"),
        "flash": {"type": fl.get("type"), "model": fl.get("model"), "size": size, "erase_size": fl["erase_size"],
                  "page_size": fl["page_size"], "mtdparts": fl["mtdparts"], "mtd_id": fl.get("mtd_id")},
        "build": {"fast": fast, "epoch": epoch, "date": fw.get("build_date"), "builder": _BUILDER_VERSION},
        "tools": {},
        "fallbacks": [],
        "partitions": [],
    }
    with tempfile.TemporaryDirectory(prefix="pweh-fw-") as tmp:
        work = Path(tmp)
        binaries: dict[str, bytes] = {}
        bin_info: list[dict[str, Any]] = []
        httpd_kind = "script"
        if not fast and zig:
            try:
                res = build_binaries(profile, zig, work)
                binaries = res["files"]
                bin_info = res["info"]
                httpd_kind = "elf"
                manifest["tools"]["zig"] = {"path": zig, "version": _tool_version(zig, ["version"]), "target": res["target"]}
            except (ToolMissing, OSError, subprocess.TimeoutExpired) as exc:
                manifest["fallbacks"].append({"component": "httpd", "reason": f"zig 빌드 실패 → 셸 CGI 대체: {exc}"})
        elif not fast:
            manifest["fallbacks"].append({"component": "httpd", "reason": "zig 를 찾을 수 없음 → 셸 스크립트 CGI 로 대체"})
        else:
            manifest["fallbacks"].append({"component": "httpd", "reason": "fast 모드: zig 빌드 생략 → 셸 스크립트 CGI"})
        tree = rootfs.build_tree(profile, binaries=binaries, httpd_kind=httpd_kind)
        tree = _apply_profile_extras(profile, tree, binaries)
        if httpd_kind == "script":
            # 이미지에 자리표시자 ELF 를 넣지 않는다: 셸 스크립트로 교체
            for path, node in list(tree.items()):
                if node.kind == "file" and node.meta.get("placeholder"):
                    node.data = f"#!/bin/sh\n# {SYNTHETIC_MARKER}\n# placeholder for {path} (zig 미사용 빌드)\nexit 1\n".encode()

        def place(name: str, data: bytes, content: str, **extra: Any) -> dict[str, Any]:
            part = partition(profile, name)
            if part is None:
                raise ConfigError(f"mtdparts 에 '{name}' 파티션이 없습니다.")
            if len(data) > part["size"]:
                raise ConfigError(f"'{name}' 내용({len(data)})이 파티션 크기({part['size']})보다 큽니다.")
            image[part["offset"] : part["offset"] + len(data)] = data
            ent = {"name": name, "offset": part["offset"], "size": part["size"], "used": len(data),
                   "content": content, "sha256": hashlib.sha256(data).hexdigest(), **extra}
            return ent

        parts_out = []
        # boot
        boot_part = partition(profile, "boot")
        assert boot_part is not None
        parts_out.append(place("boot", build_boot_blob(profile, boot_part["size"]), "u-boot-blob (synthetic)"))
        # env
        ub = profile["uboot"]
        env = stored_env(profile)
        env_block = build_uboot_env(env, size=ub["env_size"], redundant=bool(ub.get("env_redundant")))
        env_off = ub["env_offset"]
        image[env_off : env_off + len(env_block)] = env_block
        env_part = partition(profile, "env")
        parsed_env = parse_uboot_env(env_block)
        manifest["env"] = {"offset": env_off, "size": ub["env_size"], "redundant": bool(ub.get("env_redundant")),
                           "crc": parsed_env["crc"] if parsed_env else None, "crc_ok": parsed_env is not None,
                           "vars": env}
        if env_part is not None:
            parts_out.append({"name": "env", "offset": env_part["offset"], "size": env_part["size"],
                              "used": len(env_block), "content": "u-boot-env", "sha256": hashlib.sha256(env_block).hexdigest()})
        # kernel
        uimage, _vmlinux = build_kernel(profile)
        kinfo = parse_uimage_header(uimage)
        parts_out.append(place("kernel", uimage, "uimage", uimage=kinfo))
        manifest["kernel"] = {"offset": partition(profile, "kernel")["offset"], "uimage": kinfo}  # type: ignore[index]
        # rootfs
        rootfs_name = next((p["name"] for p in profile["partitions"] if p["name"] in ("rootfs", "root")), "rootfs")
        comp = fw.get("squashfs_comp", "xz")
        if not fast and mksquashfs:
            try:
                rootfs_img = build_squashfs(tree, mksquashfs, epoch=epoch, comp=comp, work=work)
                rtype = "squashfs"
                manifest["tools"]["mksquashfs"] = {"path": mksquashfs, "version": _tool_version(mksquashfs, ["-version"])}
            except (ToolMissing, OSError, subprocess.TimeoutExpired) as exc:
                manifest["fallbacks"].append({"component": "rootfs", "reason": f"mksquashfs 실패 → gzip cpio: {exc}"})
                rootfs_img = build_cpio_gz(tree, epoch=epoch)
                rtype = "cpio.gz"
        else:
            if not fast:
                manifest["fallbacks"].append({"component": "rootfs", "reason": "mksquashfs 를 찾을 수 없음 → gzip cpio(newc)"})
            else:
                manifest["fallbacks"].append({"component": "rootfs", "reason": "fast 모드: gzip cpio(newc)"})
            rootfs_img = build_cpio_gz(tree, epoch=epoch)
            rtype = "cpio.gz"
        parts_out.append(place(rootfs_name, rootfs_img, rtype))
        files = []
        for path, node in tree.items():
            ent: dict[str, Any] = {"path": path, "type": node.kind, "mode": f"{node.mode & 0o7777:04o}"}
            if node.kind == "file":
                ent["size"] = len(node.data)
                ent["sha256"] = hashlib.sha256(node.data).hexdigest()
            elif node.kind == "symlink":
                ent["target"] = node.target
            elif node.kind in ("chr", "blk"):
                ent["dev"] = [node.major, node.minor]
            files.append(ent)
        manifest["rootfs"] = {"partition": rootfs_name, "offset": partition(profile, rootfs_name)["offset"],  # type: ignore[index]
                              "type": rtype, "compression": comp if rtype == "squashfs" else "gzip",
                              "size": len(rootfs_img), "magic": rootfs_img[:4].hex(), "files": files}
        # app (마지막 파티션)
        app_part = profile["partitions"][-1]
        if app_part["name"] not in ("boot", "env", "kernel", rootfs_name):
            atree = rootfs.app_tree(profile)
            if rtype == "squashfs" and mksquashfs:
                app_img = build_squashfs(atree, mksquashfs, epoch=epoch, comp=comp, work=work)
                atype = "squashfs"
            else:
                app_img = build_cpio_gz(atree, epoch=epoch)
                atype = "cpio.gz"
            parts_out.append(place(app_part["name"], app_img, atype))
            manifest["app"] = {"partition": app_part["name"], "offset": app_part["offset"], "type": atype,
                               "size": len(app_img), "files": sorted(atree)}
    manifest["partitions"] = sorted(parts_out, key=lambda p: p["offset"])
    web = fw.get("web_server", "/usr/sbin/httpd")
    hnode = tree.get(web)
    manifest["httpd"] = {"path": web, "kind": httpd_kind,
                         "elf_machine": _elf_machine(hnode.data) if hnode is not None else None,
                         "sha256": hashlib.sha256(hnode.data).hexdigest() if hnode is not None else None,
                         "source": "firmware_src/httpd.c" if httpd_kind == "elf" else "rootfs.py fallback CGI scripts"}
    manifest["binaries"] = bin_info
    manifest["planted_issues"] = rootfs.planted_issues(profile, httpd_kind=httpd_kind) + _extra_planted_issues(profile, tree)
    lg = profile["linux"]["login"]
    manifest["credentials"] = {
        "console_login": {"username": lg.get("username", "root"), "password": lg.get("password", "")},
        "web_admin": {"username": rootfs.ADMIN_USER, "password": rootfs.ADMIN_PASS},
        "backdoor_token": rootfs.BACKDOOR_TOKEN,
    }
    data = bytes(image)
    manifest["image"] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                         "crc32": f"0x{zlib.crc32(data) & 0xFFFFFFFF:08x}"}
    return data, manifest


def _resolve_tools(fast: bool, zig: str | None, mksquashfs: str | None) -> tuple[str | None, str | None]:
    if fast:
        return None, None
    return (zig or find_tool("zig", "PWEH_ZIG"), mksquashfs or find_tool("mksquashfs", "PWEH_MKSQUASHFS"))


def build_image_bytes(profile: str | os.PathLike[str] | Mapping[str, Any] = "hisilicon-like", *, fast: bool = False,
                      use_cache: bool = True, zig: str | None = None, mksquashfs: str | None = None,
                      overrides: Mapping[str, Any] | None = None) -> tuple[bytes, dict[str, Any]]:
    """이미지를 메모리에 만든다 (캐시 사용). (bytes, manifest)."""
    prof = load_profile(profile, overrides)
    zig_p, sq_p = _resolve_tools(fast, zig, mksquashfs)
    tools = {"zig": _tool_version(zig_p, ["version"]) if zig_p else None,
             "mksquashfs": bool(sq_p)}
    key = _cache_key(prof, fast, tools)
    cdir = cache_dir() / "mocktarget" / "images"
    bin_path = cdir / f"{prof['name']}-{key}.bin"
    man_path = cdir / f"{prof['name']}-{key}.bin.manifest.json"
    if use_cache and bin_path.is_file() and man_path.is_file():
        try:
            data = bin_path.read_bytes()
            manifest = json.loads(man_path.read_text(encoding="utf-8"))
            if manifest.get("image", {}).get("sha256") == hashlib.sha256(data).hexdigest():
                return data, manifest
        except (OSError, ValueError):
            pass
    data, manifest = _build(prof, fast=fast, zig=zig_p, mksquashfs=sq_p)
    if use_cache:
        try:
            atomic_write_bytes(bin_path, data)
            atomic_write_json(man_path, manifest)
        except OSError as exc:  # 캐시는 선택 사항
            log.debug("firmware cache write failed: %s", exc)
    return data, manifest


def build_image(profile: str | os.PathLike[str] | Mapping[str, Any] = "hisilicon-like",
                out_path: str | os.PathLike[str] = "firmware.bin", *, fast: bool = False, use_cache: bool = True,
                zig: str | None = None, mksquashfs: str | None = None,
                overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """합성 펌웨어 이미지를 out_path 에 쓰고 매니페스트(dict)를 돌려준다 (``<out>.manifest.json`` 에도 저장)."""
    data, manifest = build_image_bytes(profile, fast=fast, use_cache=use_cache, zig=zig, mksquashfs=mksquashfs,
                                       overrides=overrides)
    out = Path(os.fspath(out_path)).expanduser().resolve()
    manifest = json.loads(json.dumps(manifest))
    manifest["image"]["path"] = str(out)
    atomic_write_bytes(out, data)
    atomic_write_json(out.with_name(out.name + ".manifest.json"), manifest)
    return manifest


__all__ = ["FORMAT", "build_cpio_gz", "build_image", "build_image_bytes", "build_squashfs", "cache_dir", "find_tool"]
