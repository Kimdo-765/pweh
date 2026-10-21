"""Android 추출 트리·부트 이미지의 정적 AN 점검. 실행 상태를 추정하지 않는다."""

from __future__ import annotations

import os
import re
import shlex
import stat
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from pweh.errors import ValidationFailed

from .androidformats import boot_info, vendor_boot_info, vbmeta_info, mask_text as mask_secret
from .common import Ctl, read_regular_file

CHECKS = (
    ("AN-01", "ADB 통신·인증 설정", "debug-interface", "medium", "risk", ("properties", "init")),
    ("AN-02", "디버그·root 빌드 설정", "insecure-default", "medium", "risk", ("properties",)),
    ("AN-03", "공개 test-keys 빌드 단서", "weak-crypto", "medium", "risk", ("properties",)),
    ("AN-04", "SELinux permissive 설정", "insecure-default", "medium", "risk", ("init", "boot")),
    ("AN-05", "AVB 검증 비활성 플래그", "insecure-update", "high", "risk", ("vbmeta",)),
    ("AN-06", "init 서비스 권한", "other", "info", "inventory", ("init",)),
    ("AN-07", "OTA 검증 구성 단서", "insecure-update", "info", "inventory", ("ota",)),
    ("AN-08", "특권 APK·권한 허용 목록", "other", "info", "inventory", ("privapp",)),
    ("AN-09", "하드코딩 자격증명 후보", "hardcoded-credential", "medium", "risk", ("text",)),
)
ADB_REF = "https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/daemon/main.cpp"
INIT_REF = "https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md"
REFS = {"AN-01": ADB_REF, "AN-02": ADB_REF, "AN-03": "https://source.android.com/docs/core/ota/sign_builds",
        "AN-04": "https://source.android.com/docs/security/features/selinux/implement",
        "AN-05": "https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_vbmeta_image.h",
        "AN-06": INIT_REF, "AN-07": "https://source.android.com/docs/core/ota/sign_builds",
        "AN-08": "https://source.android.com/docs/core/permissions/perms-allowlist"}
PROP = re.compile(r"^([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")
CREDENTIAL = re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|access[_-]?token|secret|psk)\s*[:=]\s*[\"']?([^\s\"',;<>]+)")
SELINUX = re.compile(r"\bandroidboot\.selinux\s*=\s*[\"']?permissive\b")


class AndroidSurface:
    def __init__(self, ctl: Ctl, *, max_evidence: int = 20, max_file_size: int = 1 << 20) -> None:
        self.ctl, self.max_evidence, self.max_file_size = ctl, max_evidence, max_file_size
        self.evidence: dict[str, list[dict[str, Any]]] = {c[0]: [] for c in CHECKS}
        self.hits = dict.fromkeys(self.evidence, 0)
        self.seen: set[str] = set()
        self.incomplete: set[str] = set()
        self.limitations: list[str] = []
        self.root_given = self.image_given = False
        self.root_entries = self.text_files = 0
        self.imports: list[tuple[str, str]] = []
        self.paths: set[str] = set()
        self.parsed_init_paths: set[str] = set()

    def limit(self, message: str, *kinds: str) -> None:
        self.incomplete.update(kinds or ("properties", "init", "ota", "privapp", "text"))
        if len(self.limitations) < 100:
            self.limitations.append(message)

    def add(self, cid: str, rule: str, excerpt: str, *, file: str | None = None, line: int | None = None,
            image: str | None = None, offset: int | None = None, **extra: Any) -> None:
        self.hits[cid] += 1
        if len(self.evidence[cid]) >= self.max_evidence:
            return
        # 값 전체를 먼저 가린 뒤 길이를 제한한다. 잘린 key/value의 뒷부분 유출을 막는다.
        masked = CREDENTIAL.sub(lambda m: m.group(1) + "=<masked>", mask_secret(excerpt))[:500]
        ev: dict[str, Any] = {"source": "image" if image else "rootfs", "rule": rule, "excerpt": masked, **extra}
        for key, value in (("file", file), ("line", line), ("image", image), ("offset_hex", hex(offset) if offset is not None else None)):
            if value is not None:
                ev[key] = value
        self.evidence[cid].append(ev)

    def properties(self, value: str, where: dict[str, Any]) -> None:
        match = PROP.match(value)
        if not match:
            return
        key, val = match.groups()
        if key in ("service.adb.tcp.port", "persist.adb.tcp.port") and val.isdecimal() and 0 < int(val[:10]) <= 65535:
            self.add("AN-01", "adb-tcp-port", value, **where)
        elif key == "service.adb.listen_addrs" and val:
            self.add("AN-01", "adb-listen-address", value, **where)
        elif key in ("persist.sys.usb.config", "sys.usb.config") and "adb" in val.split(","):
            self.add("AN-01", "adb-usb-config", value, **where)
        elif key == "ro.adb.secure" and val == "0":
            self.add("AN-01", "adb-auth-disabled-candidate", value, condition="debuggable/unlocked 등 실제 적용 조건 미확인", **where)
        if (key == "ro.debuggable" and val == "1") or (key == "ro.secure" and val == "0") or (key == "ro.build.type" and val in ("eng", "userdebug")):
            self.add("AN-02", "debug-build-setting", value, **where)
        if key in ("ro.build.tags", "ro.build.fingerprint", "ro.build.description") and "test-keys" in val:
            self.add("AN-03", "test-keys-tag", value, **where)

    def _init(self, lines: list[tuple[int, str]], rel: str) -> None:
        service: dict[str, Any] | None = None

        def finish() -> None:
            if service is not None:
                self.add("AN-06", "init-service", f"{service['name']}: user={service['user']} argv={service['argv']}",
                         file=rel, line=service["line"], user=service["user"], capabilities=service["capabilities"],
                         sockets=service["sockets"], condition="실행 여부·SELinux 정책 미확인")

        for number, line in lines:
            if self.ctl.expired():
                self.limit("init 해석 시간 예산 초과", "init")
                break
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError:
                self.limit(f"{rel}:{number}: init 토큰 해석 실패", "init")
                continue
            if not tokens:
                continue
            op = tokens[0]
            if op in ("service", "on", "import"):
                finish()
                service = None
            if op == "service" and len(tokens) >= 3:
                service = {"name": tokens[1], "argv": mask_secret(" ".join(tokens[2:]))[:250], "user": "root",
                           "capabilities": [], "sockets": [], "line": number}
                if Path(tokens[2]).name == "adbd":
                    self.add("AN-01", "adbd-service", line, file=rel, line=number, condition="서비스 선언; 실제 시작·인증 미확인")
            elif op == "import" and len(tokens) == 2:
                self.imports.append((rel, tokens[1]))
            elif service is not None:
                if op == "user" and len(tokens) == 2:
                    service["user"] = tokens[1][:80]
                elif op == "capabilities":
                    service["capabilities"] = tokens[1:33]
                elif op == "socket":
                    service["sockets"].append(" ".join(tokens[1:])[:160])
                    service["sockets"] = service["sockets"][:32]
            if op == "setenforce" and tokens[1:] == ["0"]:
                self.add("AN-04", "init-setenforce", line, file=rel, line=number)
            if op == "setprop" and len(tokens) >= 3:
                self.properties(tokens[1] + "=" + tokens[2], {"file": rel, "line": number})
        finish()

    def _xml(self, data: bytes, rel: str) -> None:
        self.seen.add("privapp")
        try:
            decoded = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            self.limit(f"{rel}: UTF-8 XML만 지원", "privapp")
            return
        if "\0" in decoded or "<!DOCTYPE" in decoded.upper() or "<!ENTITY" in decoded.upper():
            self.limit(f"{rel}: XML DTD/entity는 해석하지 않음", "privapp")
            return
        try:
            tree = ET.fromstring(decoded)
        except (ET.ParseError, ValueError):
            self.limit(f"{rel}: XML 해석 실패", "privapp")
            return
        count = 0
        for node in tree.iter():
            if self.ctl.expired():
                self.limit("XML 해석 시간 예산 초과", "privapp")
                break
            count += 1
            if count > 10000:
                self.limit(f"{rel}: XML 노드 상한", "privapp")
                break
            if node.tag == "privapp-permissions":
                package = node.get("package", "")[:200]
                perms = [x.get("name", "")[:200] for x in node if x.tag in ("permission", "deny-permission")][:100]
                self.add("AN-08", "privapp-allowlist", f"package={package}; permissions={perms}", file=rel,
                         partition=rel.split("/")[1] if rel.count("/") > 1 else "unknown")

    def scan_rootfs(self, root: Path) -> None:
        self.root_given = True
        todo = [(root, "", 0)]
        seen_inodes: set[tuple[int, int]] = set()
        text_bytes = 0
        while todo:
            if self.ctl.expired():
                self.limit("rootfs 시간 예산 초과")
                break
            directory, relative, depth = todo.pop()
            if depth > 64:
                self.limit("rootfs 디렉터리 깊이 상한")
                continue
            try:
                iterator = os.scandir(directory)
            except OSError:
                self.limit(f"{relative}: 디렉터리를 읽지 못함")
                continue
            with iterator:
                for item in iterator:
                    self.root_entries += 1
                    if self.root_entries > 100000 or self.ctl.expired():
                        self.limit("rootfs 항목/시간 상한")
                        todo.clear()
                        break
                    rel = relative + "/" + item.name
                    self.paths.add(rel)
                    try:
                        st = item.stat(follow_symlinks=False)
                    except OSError:
                        self.limit(f"{rel}: stat 실패")
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        self.limit(f"{rel}: 심볼릭 링크 내용은 검사하지 않음")
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        todo.append((Path(item.path), rel, depth + 1))
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if "/priv-app/" in rel and rel.lower().endswith(".apk"):
                        self.seen.add("privapp")
                        self.add("AN-08", "privileged-apk-path", rel, file=rel)
                    if item.name in ("otacerts.zip", "update-payload-key.pub.pem") or rel == "/res/keys":
                        self.seen.add("ota")
                        self.add("AN-07", "ota-key-file", "검증 키 파일 존재; 서명 강제 여부 미확인", file=rel)
                    suffix = Path(item.name).suffix.lower()
                    if suffix not in (".prop", ".rc", ".xml", ".conf", ".cfg", ".ini", ".json", ".properties", ".sh", ".txt"):
                        continue
                    kinds = ("init",) if suffix == ".rc" else ("properties",) if suffix in (".prop", ".properties") else ("text",)
                    if item.name.startswith("privapp-permissions"):
                        kinds = ("privapp",)
                    self.seen.update(kinds)
                    if st.st_size > self.max_file_size or text_bytes + st.st_size > (64 << 20):
                        self.limit(f"{rel}: 파일/텍스트 합계 크기 상한", *kinds, "text")
                        continue
                    inode = (st.st_dev, st.st_ino)
                    if inode in seen_inodes:
                        continue
                    seen_inodes.add(inode)
                    try:
                        # 한 바이트 더 읽어 stat 뒤에 자란 파일도 '완료'로 표시하지 않는다.
                        data = read_regular_file(Path(item.path), self.max_file_size + 1)
                    except (OSError, ValidationFailed):
                        self.limit(f"{rel}: 파일 읽기 실패", *kinds, "text")
                        continue
                    if data is None or len(data) != st.st_size:
                        self.limit(f"{rel}: 파일을 완전히 읽지 못했거나 읽는 중 크기가 바뀜", *kinds, "text")
                        continue
                    text_bytes += len(data)
                    self.text_files += 1
                    if item.name.startswith("privapp-permissions") and suffix == ".xml":
                        self._xml(data, rel)
                        continue
                    try:
                        decoded = data.decode("utf-8")
                    except UnicodeDecodeError:
                        self.limit(f"{rel}: UTF-8 텍스트 해석 실패", *kinds, "text")
                        continue
                    self.seen.add("text")
                    lines: list[tuple[int, str]] = []
                    pending, first = "", 0
                    for number, line in enumerate(decoded.splitlines(), 1):
                        if self.ctl.expired():
                            self.limit("텍스트 시간 예산 초과", *kinds, "text")
                            break
                        if len(line) + len(pending) > 16384:
                            self.limit(f"{rel}:{number}: 줄 길이 상한", *kinds, "text")
                            pending = ""
                            continue
                        if not pending:
                            first = number
                        pending += line
                        if suffix == ".rc" and pending.endswith("\\"):
                            pending = pending[:-1] + " "
                            continue
                        line, pending = pending.strip(), ""
                        if not line or line.startswith("#"):
                            continue
                        lines.append((first, line))
                        where = {"file": rel, "line": first}
                        if suffix in (".prop", ".properties"):
                            self.properties(line, where)
                        if CREDENTIAL.search(line):
                            self.add("AN-09", "credential-assignment", line, **where)
                        if suffix != ".rc" and SELINUX.search(line):
                            self.add("AN-04", "selinux-permissive-text", line, **where)
                    if pending:
                        self.limit(f"{rel}: 끝나지 않은 줄 이어쓰기", *kinds)
                    if suffix == ".rc":
                        self._init(lines, rel)
                        self.parsed_init_paths.add(rel)
        for rel, imported in self.imports:
            if any(c in imported for c in "$*?[") or imported not in self.paths:
                self.limit(f"{rel}: 미해결 import", "init")
            elif imported not in self.parsed_init_paths:
                self.limit(f"{rel}: import 대상의 init 문법은 검사하지 못함", "init")

    def scan_image(self, buf: Any, size: int, name: str) -> None:
        self.image_given = True
        parser = boot_info if bytes(buf[:8]) == b"ANDROID!" else vendor_boot_info if bytes(buf[:8]) == b"VNDRBOOT" else vbmeta_info if bytes(buf[:4]) == b"AVB0" else None
        offset = 0
        parse_limit = size
        if parser is None and size >= 64 and bytes(buf[size - 64:size - 60]) == b"AVBf":
            footer = bytes(buf[size - 64:size])
            major, minor, original, offset, length = struct.unpack_from(">IIQQQ", footer, 4)
            if major == 1 and original <= offset and offset + length <= size - 64 and length >= 256:
                parser = vbmeta_info
                parse_limit = offset + length
            else:
                self.limit("AVB footer 범위/version 검증 실패", "vbmeta")
        if parser is None:
            self.limit("입력 이미지에서 지원하는 boot/vendor_boot/vbmeta 구조를 확인하지 못함", "boot", "vbmeta")
            return
        kind = "vbmeta" if parser is vbmeta_info else "boot"
        self.seen.add(kind)
        try:
            info = parser(buf, offset, parse_limit, self.ctl)
        except ValidationFailed as exc:
            self.limit(str(exc), kind)
            return
        if info.get("truncated"):
            self.limit("이미지의 선언된 section 범위를 끝까지 읽을 수 없음", kind)
            return
        if kind == "vbmeta":
            if info["unknown_flags"]:
                self.limit("알 수 없는 AVB flags", "vbmeta")
            if info["flags"] & 3:
                self.add("AN-05", "avb-disabled-flags", f"flags={info['flags']}; signature_status=not-verified", image=name, offset=offset)
        else:
            if info.get("selinux_permissive"):
                self.add("AN-04", "boot-selinux-permissive", "androidboot.selinux=permissive (cmdline/bootconfig 구조에서 확인)", image=name, offset=offset)
            if info["kind"] == "android-vendor-boot" and info["header_version"] == 4 and info.get("bootconfig") is None:
                self.limit("vendor bootconfig 내용은 크기/범위 제한으로 보지 못함", "boot")

    def result(self) -> dict[str, Any]:
        checks = []
        for cid, title, category, severity, meaning, needs in CHECKS:
            status = "found" if self.hits[cid] else "not-found" if any(n in self.seen for n in needs) and not any(n in self.incomplete for n in needs) else "unknown"
            checks.append({"id": cid, "title": title, "status": status, "found_means": meaning,
                           "severity_hint": severity, "category": category, "evidence": self.evidence[cid],
                           "evidence_total": self.hits[cid], "evidence_suppressed": max(0, self.hits[cid] - len(self.evidence[cid])),
                           "rationale": "제공된 펌웨어의 정적 단서입니다. 실행 상태·네트워크 도달 가능성·서명 강제 여부는 확인하지 않았습니다.",
                           "references": [REFS[cid]] if cid in REFS else [],
                           "next_steps": ["필요한 partition/설정과 대조하고 관련 코드의 적용 조건을 정적으로 확인"]})
        return {"checks": checks, "counts": {s: sum(c["status"] == s for c in checks) for s in ("found", "not-found", "unknown")},
                "risk_found": any(c["status"] == "found" and c["found_means"] == "risk" for c in checks),
                "coverage": {"rootfs_given": self.root_given, "image_given": self.image_given,
                             "scope": "제공된 파일/트리만; 빠진 partition과 실행 상태는 미확인", "seen": sorted(self.seen),
                             "incomplete": sorted(self.incomplete), "root_entries": self.root_entries, "text_files": self.text_files},
                "limitations": self.limitations, "timed_out": self.ctl.timed_out}
