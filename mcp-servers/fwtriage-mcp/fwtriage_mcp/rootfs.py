"""추출된 rootfs 감사 (fw_rootfs_audit).

점검 항목 (각 항목: 파일 경로, 줄/발췌, category(finding 스키마 어휘), severity 힌트, 근거):
- 계정: passwd/shadow — 빈 비밀번호, 해시 알고리즘(DES/MD5 약함), uid 0 추가 계정, 공개된 하드코딩 해시,
  내장 기본 비밀번호 사전과 일치(오프라인), passwd/shadow 가 쓰기 가능한 저장소로의 링크인지
- 부팅: inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트 — telnetd(+ -l /bin/sh), dropbear -B, nc -e 셸,
  getty 자동 로그인/콘솔 셸, remserial(UART 브리지), 쓰기 가능한 영구 저장소의 스크립트 실행, world-writable 시작 스크립트
- 웹: 웹 서버/메인 앱 바이너리, 설정(boa/lighttpd/BusyBox httpd/thttpd/uhttpd/nginx), CGI, 웹 루트
- setuid/setgid (fw_extract_squashfs 매니페스트가 있으면 원본 모드/소유자 기준)
- 개인키/인증서 (키 내용은 출력하지 않고 지문만), SSH/dropbear 호스트 키
- 설정 파일/스크립트의 하드코딩 자격증명 (값은 마스킹)
- 영구 쓰기 가능 마운트 (fstab, mount 명령, 설정의 persistent_paths)
- cctv-hunt-patterns.yaml: credential_patterns, text 범위 string_heuristics, interesting_paths, web_server_binaries

결과는 '후보'다. 확정은 REA/동적 확인(소유 기기, 격리 랩)으로 한다.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from .common import Ctl, clip, mask_secret, severity_key
from .elfinfo import describe_elf_header
from .fswalk import Entry, is_text, load_manifest, read_in_root, resolve_in_root, walk_tree
from .hashes import crack_entries, identify_hash
from .patterns import VENDOR_FAMILY, PatternSet, finding_category, glob_to_regex

LOGIN_SHELLS = ("/bin/sh", "/bin/ash", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/hush", "/usr/bin/bash", "/usr/bin/sh")
GENERIC_WEB = ["boa", "goahead", "webs", "lighttpd", "thttpd", "mini_httpd", "uhttpd", "httpd", "nginx", "mongoose", "civetweb", "appweb", "shttpd", "alphapd", "hydra", "jhttpd"]

STARTUP_GLOBS = [
    "etc/inittab", "etc/init.d/**", "etc/rc.d/**", "etc/rc[0-9S].d/*", "etc/rcS", "etc/rc", "etc/rc.local", "etc/rc.sysinit",
    "etc/rc.common", "etc/profile", "etc/profile.d/*", "etc/inetd.conf", "etc/xinetd.conf", "etc/xinetd.d/*",
    "etc/systemd/system/**", "lib/systemd/system/*.service", "usr/lib/systemd/system/*.service", "etc/service/*/run",
    "etc/sv/*/run", "etc/runit/**", "etc/init/*.conf", "usr/etc/rc*", "usr/etc/init.d/*", "etc_ro/rc*", "etc_ro/inittab",
    "etc_ro/init.d/*", "etc/boot.sh", "**/start*.sh", "**/rcS*", "etc/config/*.sh", "**/autorun*.sh",
]
_STARTUP_RX = [glob_to_regex(g) for g in STARTUP_GLOBS]

SERVICE_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("telnetd", re.compile(r"(?:^|[\s;&|(/])u?telnetd(?=$|[\s;&|)])"), "telnet 서버"),
    ("dropbear", re.compile(r"(?:^|[\s;&|(/])dropbear(?=$|[\s;&|)])"), "SSH 서버(dropbear)"),
    ("sshd", re.compile(r"(?:^|[\s;&|(/])sshd(?=$|[\s;&|)])"), "SSH 서버(OpenSSH)"),
    ("ftpd", re.compile(r"(?:^|[\s;&|(/])(?:vsftpd|bftpd|pure-ftpd|proftpd|ftpd)(?=$|[\s;&|)])"), "FTP 서버"),
    ("tftpd", re.compile(r"(?:^|[\s;&|(/])u?tftpd(?=$|[\s;&|)])"), "TFTP 서버"),
    ("remserial", re.compile(r"(?:^|[\s;&|(/])remserial(?=$|[\s;&|)])"), "UART→TCP 브리지(remserial)"),
    ("snmpd", re.compile(r"(?:^|[\s;&|(/])snmpd(?=$|[\s;&|)])"), "SNMP 에이전트"),
    ("upnpd", re.compile(r"(?:^|[\s;&|(/])(?:mini)?upnpd(?=$|[\s;&|)])"), "UPnP"),
    ("netcat-listener", re.compile(r"(?:^|[\s;&|(/])(?:nc|netcat|busybox\s+nc)\s+[^\n]*-[a-zA-Z]*l"), "netcat 리스너"),
    ("socat", re.compile(r"(?:^|[\s;&|(/])socat\s"), "socat"),
    ("tcpsvd", re.compile(r"(?:^|[\s;&|(/])tcpsvd\s"), "tcpsvd 슈퍼서버"),
    ("rtspd", re.compile(r"(?:^|[\s;&|(/])\w*rtsp\w*(?=$|[\s;&|)])", re.I), "RTSP 서버"),
]

EXTRA_CHECKS: list[tuple[str, re.Pattern[str], str, str, str, str]] = [
    # (id, regex, category, severity, title, rationale)
    ("builtin-dropbear-blank-password", re.compile(r"dropbear\b[^\n]*\s-[a-zA-Z]*B"), "insecure-default", "high",
     "dropbear 가 빈 비밀번호 로그인 허용(-B)으로 실행됨", "dropbear -B: Allow blank password logins."),
    ("builtin-netcat-shell", re.compile(r"\b(?:nc|netcat)\b[^\n]*\s-[a-zA-Z]*[el]\b[^\n]*(?:/bin/(?:sh|ash|bash)|-e\s)"), "backdoor", "critical",
     "netcat 으로 셸을 네트워크에 노출 (리스너 + -e 셸)", "nc -l ... -e /bin/sh 형태는 인증 없는 원격 셸이다."),
    ("builtin-socat-exec-shell", re.compile(r"\bsocat\b[^\n]*exec:[^\n]*(?:sh|bash)"), "backdoor", "critical",
     "socat 으로 셸을 노출", "socat ... EXEC:/bin/sh 형태는 원격 셸이다."),
    ("builtin-tcpsvd-shell", re.compile(r"\btcpsvd\b[^\n]*/bin/(?:sh|ash|bash|login)\b"), "backdoor", "high",
     "tcpsvd 로 셸/로그인을 네트워크에 노출", "tcpsvd 가 셸이나 login 을 직접 실행한다."),
    ("builtin-agetty-autologin", re.compile(r"\b(?:a|min)?getty\b[^\n]*--autologin\s+\S+"), "debug-interface", "high",
     "getty 자동 로그인", "getty --autologin 은 콘솔에서 비밀번호 없이 로그인시킨다."),
    ("builtin-login-f-root", re.compile(r"\blogin\s+-f\s+root\b"), "debug-interface", "high",
     "login -f root (인증 생략 로그인)", "login -f 는 인증을 건너뛴다."),
    ("builtin-remserial", re.compile(r"\bremserial\b[^\n]*-p\s*\d+"), "debug-interface", "high",
     "remserial 로 UART 콘솔을 TCP 포트에 브리지", "Kojenov(CVE-2020-24218 관련 장비): remserial -p 5150 ... /dev/ttyAMA1 로 시리얼을 네트워크에 노출."),
    ("builtin-chpasswd-literal", re.compile(r"echo\s+[\"']?[\w.-]+:[^\s\"'|]+[\"']?\s*\|\s*(?:/usr/s?bin/)?chpasswd"), "hardcoded-credential", "high",
     "시작 스크립트가 고정 비밀번호를 chpasswd 로 설정", "모든 기기에 같은 비밀번호가 설정된다."),
]

CRED_RX: list[tuple[str, re.Pattern[str]]] = [
    ("builtin-config-password", re.compile(r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,32}?(?:pass(?:word|wd)?|pwd|secret|psk|passphrase|rootpw))\b[\"']?\s*[=:]\s*(?P<q>[\"']?)(?P<val>[^\s\"'<>{};,&|]{3,64})(?P=q)")),
    ("builtin-xml-password", re.compile(r"(?i)<(?P<key>pass(?:word)?|pwd|psk|passphrase)>(?P<val>[^<\s]{1,64})</")),
    ("builtin-url-credential", re.compile(r"\b(?:ftp|http|https|rtsp|tftp|smb|mysql|postgres|mqtt)://(?P<key>[^/\s:@'\"]{1,64}):(?P<val>[^/\s@'\"]{1,64})@")),
]
_NON_VALUES = {"true", "false", "yes", "no", "on", "off", "none", "null", "nil", "required", "optional", "sufficient", "requisite", "include", "enable", "enabled", "disable", "disabled", "string", "char", "int", "text", "type", "hidden", "input", "value"}
CRED_EXT = {".conf", ".cfg", ".ini", ".xml", ".json", ".sh", ".txt", ".env", ".properties", ".yaml", ".yml", ".lua", ".dat", ".db", ".config", ".rc", ""}
CRED_DIR_PREFIXES = ("/etc/", "/usr/etc/", "/mnt/", "/home/", "/root/", "/var/", "/opt/", "/app", "/config", "/data", "/system/", "/program/", "/box/", "/usr/local/", "/usr/share/", "/www/", "/web/", "/usr/www/")

PEM_RX = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")
BANNERS = [
    ("App-webs/", "hikvision"), ("Hikvision-Webs", "hikvision"), ("DNVRS-Webs", "hikvision"), ("uc-httpd 1.0.0", "xiongmai"),
    ("H264DVR rtspd 1.0", "xiongmai"), ("Welcome to HiLinux.", "hisilicon_video_encoder"), ("GoAhead-Webs", "generic"), ("mini_httpd/", "generic"),
]
PATH_HINTS = [("/mnt/mtd/Config", "dahua/xiongmai"), ("/program/bin/maintain", "uniview"), ("/system/www", "wificam"), ("/usr/bin/sonia", "dahua"), ("/box/box.ini", "hisilicon_video_encoder")]
_ABS_PATH_RX = re.compile(r"(?<![\w.\-/$])(/(?:[\w.+\-]+/)*[\w.+\-]+)")
_MOUNT_RX = re.compile(r"\bmount\b[^\n;|&]*?-t\s+(?P<fs>jffs2|ubifs|yaffs2?|ext[234]|vfat|ntfs|f2fs)\b[^\n;|&]*?\s(?P<mp>/[\w./+-]*)\s*(?:$|[;&|])", re.M)
PERSISTENT_FS = {"jffs2", "ubifs", "yaffs", "yaffs2", "ext2", "ext3", "ext4", "vfat", "ntfs", "f2fs", "exfat"}


def _auth_hunt_families() -> frozenset[str]:
    """auth-hunt.schema.json 의 vendor_family 어휘 (스키마를 못 읽으면 같은 값의 내장 목록)."""
    try:
        from pweh import schemas

        return frozenset(schemas.load("auth-hunt")["properties"]["vendor_family"]["enum"])
    except Exception:  # pragma: no cover - 스키마 파일은 패키지에 포함된다
        return frozenset({"hikvision-like", "dahua-like", "xiongmai-like", "hisilicon-oem", "ingenic-oem", "generic", "unknown"})


_AUTH_HUNT_FAMILIES = _auth_hunt_families()


def _blank_comments(text: str) -> str:
    """주석 줄을 같은 길이의 공백으로 (줄 번호/오프셋 보존)."""
    out = []
    for line in text.split("\n"):
        s = line.lstrip()
        out.append(" " * len(line) if s.startswith("#") else line)
    return "\n".join(out)


def _binary_content(data: bytes) -> bool:
    """ELF 이거나 NUL 이 있거나 텍스트로 보이지 않는 내용인지 (passwd/shadow 같은 줄 단위 텍스트 DB 판별용)."""
    return data.startswith(b"\x7fELF") or b"\x00" in data[:65536] or not is_text(data[:4096])


def _match_pos(m: re.Match[str]) -> int:
    """정규식이 앞 구분자(개행/공백/;&|)까지 잡은 경우 실제 키워드 시작 위치."""
    g = m.group(0)
    k = len(g) - len(g.lstrip(" \t\r\n;&|(/"))
    return m.start() + (k if k < len(g) else 0)


def _line_of(text: str, pos: int) -> tuple[int, str]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end < 0:
        end = len(text)
    return text.count("\n", 0, pos) + 1, text[start:end]


class Auditor:
    def __init__(
        self,
        root: Path,
        ctl: Ctl,
        patterns: PatternSet,
        *,
        persistent_paths: list[str],
        profile: dict[str, Any] | None,
        max_file_size: int,
        crack: bool,
        crack_seconds: float,
        words: list[str],
        max_entries: int,
    ) -> None:
        self.root = root
        self.ctl = ctl
        self.patterns = patterns
        self.persistent_paths = [p.rstrip("/") for p in persistent_paths if p.startswith("/")]
        self.profile = profile or {}
        self.max_file_size = max_file_size
        self.crack = crack
        self.crack_seconds = crack_seconds
        self.words = words
        self.max_entries = max_entries
        self.manifest = load_manifest(root)
        self.items: list[dict[str, Any]] = []
        self._item_keys: set[tuple[Any, ...]] = set()
        self.limitations: list[str] = []
        self.entries: list[Entry] = []
        self.by_rel: dict[str, Entry] = {}

    # -- 공통 ---------------------------------------------------------------
    def add(self, hid: str, category: str, severity: str, title: str, *, file: str | None = None, line: int | None = None,
            excerpt: str | None = None, rationale: str | None = None, references: list[str] | None = None, extra: dict[str, Any] | None = None) -> None:
        key = (hid, file, line, excerpt if line is None else None)
        if key in self._item_keys:
            return
        self._item_keys.add(key)
        item: dict[str, Any] = {"id": hid, "category": finding_category(category), "severity": severity, "title": title}
        if category != item["category"]:
            item["heuristic_category"] = category
        if file:
            item["file"] = file
        if line is not None:
            item["line"] = line
        if excerpt is not None:
            item["excerpt"] = clip(excerpt, 240)
        if rationale:
            item["rationale"] = rationale
        if references:
            item["references"] = references
        if extra:
            item.update(extra)
        self.items.append(item)

    def covered(self, ids: tuple[str, ...], file: str | None, line: int | None) -> bool:
        """같은 파일/줄에 대해 YAML credential_patterns 가 이미 같은 내용을 보고했는지."""
        return any(it["id"] in ids and it.get("file") == file and it.get("line") == line for it in self.items)

    def mode_of(self, e: Entry) -> tuple[int, int | None, int | None, str]:
        """(모드, uid, gid, 출처) — 매니페스트 우선."""
        if self.manifest is not None:
            m = self.manifest.get(e.rel)
            if m is not None:
                try:
                    return int(m["mode"], 8), m.get("uid"), m.get("gid"), "manifest"
                except (KeyError, ValueError, TypeError):
                    pass
        return stat.S_IMODE(e.st.st_mode), None, None, "disk"

    def read(self, rel: str, limit: int | None = None) -> tuple[bytes | None, str | None]:
        return read_in_root(self.root, rel, limit or self.max_file_size)

    def match_globs(self, rx_list: list[re.Pattern[str]], rel: str) -> bool:
        r = rel.lstrip("/")
        return any(rx.match(r) for rx in rx_list)

    # -- 실행 ---------------------------------------------------------------
    def run(self) -> dict[str, Any]:
        t0 = time.monotonic()
        counts: dict[str, int] = {}
        for e in walk_tree(self.root, self.ctl, max_entries=self.max_entries):
            self.entries.append(e)
            self.by_rel[e.rel] = e
            counts[e.kind] = counts.get(e.kind, 0) + 1
        if len(self.entries) >= self.max_entries:
            self.limitations.append(f"항목이 {self.max_entries}개를 넘어 이후는 검사하지 않았습니다.")
        if self.manifest is None:
            self.limitations.append(
                "squashfs 매니페스트가 없어 디스크의 모드/소유자를 사용합니다. 비root 로 추출된 트리는 setuid 비트와 소유자 정보가 원본과 다를 수 있습니다 "
                "(fw_extract_squashfs 로 추출하면 매니페스트가 함께 생성됩니다)."
            )
        self.ctl.progress(1, 8, "플랫폼 정보")
        platform = self.platform_info()
        self.ctl.progress(2, 8, "계정")
        accounts, hashes = self.audit_accounts()
        self.ctl.progress(3, 8, "부팅 스크립트")
        startup = self.audit_startup()
        self.ctl.progress(4, 8, "웹")
        web = self.audit_web()
        self.ctl.progress(5, 8, "파일 내용(키/자격증명)")
        content = self.content_pass(hashes)
        self.ctl.progress(6, 8, "권한")
        perms = self.audit_permissions(startup["startup_files"])
        self.ctl.progress(7, 8, "해시 대조")
        crack_results = self.crack_hashes(hashes, accounts) if self.crack else []
        interesting = self.interesting_paths()
        vendor = self.vendor_guess(web, content)
        rootfs_summary = {
            "path": None,
            "fs_type": None,
            "arch": platform.get("arch"),
            "endianness": platform.get("endianness"),
            "init_scripts": startup["startup_files"][:60],
            "services": sorted({s["service"] for s in startup["services"]}),
            "web_servers": [w["path"] for w in web["servers"]][:30],
        }
        boi: list[dict[str, Any]] = []
        for w in web["servers"]:
            boi.append({"path": w["path"], "reason": f"웹/메인 앱 바이너리 ({w.get('vendor', 'generic')})"})
        for c in web["cgi"][:40]:
            boi.append({"path": c["path"], "reason": "CGI 프로그램"})
        for s in perms["setuid"][:20]:
            boi.append({"path": s["path"], "reason": f"setuid ({s['mode']})"})
        for s in startup["services"]:
            if s.get("binary") and s["service"] in ("telnetd", "dropbear", "remserial") and len(boi) < 120:
                boi.append({"path": s["binary"], "reason": f"부팅 시 실행되는 서비스 ({s['service']})"})
        seen = set()
        boi = [b for b in boi if not (b["path"] in seen or seen.add(b["path"]))]  # type: ignore[func-returns-value]
        self.items.sort(key=lambda it: (severity_key(it["severity"]), it["category"], it.get("file") or "", it.get("line") or 0))
        sev: dict[str, int] = {}
        cat: dict[str, int] = {}
        for it in self.items:
            sev[it["severity"]] = sev.get(it["severity"], 0) + 1
            cat[it["category"]] = cat.get(it["category"], 0) + 1
        return {
            "summary": {
                "entries": counts,
                "items_by_severity": sev,
                "items_by_category": cat,
                "accounts": len(accounts),
                "cracked_or_empty": sum(1 for r in crack_results if r.get("status") in ("cracked", "empty")),
                "services": rootfs_summary["services"],
                "web_servers": len(web["servers"]),
                "cgi_programs": len(web["cgi"]),
                "setuid": len(perms["setuid"]),
                "private_keys": len(content["private_keys"]),
                "manifest_used": self.manifest is not None,
                "vendor_family": vendor.get("family"),
            },
            "rootfs": rootfs_summary,
            "platform": platform,
            "accounts": accounts,
            "hash_checks": crack_results,
            "items": self.items,
            "services": startup["services"],
            "inittab": startup["inittab"],
            "startup_files": startup["startup_files"],
            "mounts": startup["mounts"],
            "web": web,
            "setuid": perms["setuid"],
            "setgid": perms["setgid"],
            "world_writable_startup": perms["world_writable_startup"],
            "private_keys": content["private_keys"],
            "certificates": content["certificates"],
            "interesting_paths": interesting,
            "vendor": vendor,
            "binaries_of_interest": boi,
            "limitations": self.limitations,
            "elapsed_seconds": round(time.monotonic() - t0, 3),
        }

    # -- 플랫폼 ---------------------------------------------------------------
    def platform_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {}
        for cand in ("/bin/busybox", "/bin/sh", "/sbin/init", "/usr/bin/busybox", "/bin/ls"):
            data, final = self.read(cand, 64)
            if data:
                h = describe_elf_header(data)
                if h:
                    info.update({"arch": h["machine"], "endianness": h["endianness"], "elf_class": h["class"], "arch_flags": h["flags"].get("summary"), "arch_source": final})
                    break
        if "arch" not in info:
            for e in self.entries:
                if e.kind == "file" and e.rel.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")) and e.st.st_size > 64:
                    data, _ = self.read(e.rel, 64)
                    h = describe_elf_header(data or b"")
                    if h:
                        info.update({"arch": h["machine"], "endianness": h["endianness"], "elf_class": h["class"], "arch_flags": h["flags"].get("summary"), "arch_source": e.rel})
                        break
        data, _ = self.read("/bin/busybox", 8 << 20)
        if data:
            m = re.search(rb"BusyBox v\d+\.\d+(?:\.\d+)?[^\x00\n]{0,60}", data)
            if m:
                info["busybox"] = m.group(0).decode("latin-1").strip()
        rel_files = {}
        for cand in ("/etc/os-release", "/etc/openwrt_release", "/etc/version", "/etc/issue", "/etc/banner", "/etc/sw_version", "/etc/VERSION", "/etc/hostname"):
            d, _ = self.read(cand, 4096)
            if d and is_text(d[:512]):
                rel_files[cand] = clip(d.decode("utf-8", "replace").strip(), 300)
        if rel_files:
            info["release_files"] = rel_files
        libc = set()
        mods = []
        for e in self.entries:
            n = e.name
            if n.startswith("ld-uClibc") or n.startswith("libuClibc"):
                libc.add("uClibc")
            elif n.startswith("ld-musl"):
                libc.add("musl")
            elif n.startswith("ld-linux") or n == "libc.so.6":
                libc.add("glibc")
            if n.endswith(".ko") and len(mods) < 80:
                mods.append(e.rel)
        info["libc"] = sorted(libc)
        info["kernel_modules"] = mods
        return info

    # -- 계정 -----------------------------------------------------------------
    def audit_accounts(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        accounts: dict[str, dict[str, Any]] = {}
        hashes: list[dict[str, Any]] = []
        cred_files = []
        names = {"passwd", "shadow", "passwd-", "shadow-", "master.passwd", "htpasswd", ".htpasswd", "passwd.bak", "shadow.bak"}
        for e in self.entries:
            if e.name in names and e.kind in ("file", "symlink"):
                # /bin/passwd, /usr/bin/passwd, /usr/sbin/passwd 등은 계정 DB 가 아니라 passwd 명령(대개 BusyBox 애플릿 링크)이다.
                # 읽으면 실행 파일 바이트가 ':' 로 잘려 가짜 계정('0' 등)이 생기고, 대상이 없는 애플릿 링크가 '이미지 밖을 가리키는 계정 DB' 로 보고된다.
                parent_name = e.rel.rsplit("/", 1)[0].rsplit("/", 1)[-1]
                if parent_name in ("bin", "sbin"):
                    continue
                cred_files.append(e)
        for e in cred_files:
            self.ctl.check()
            if e.kind == "symlink":
                try:
                    target = os.readlink(e.path)
                except OSError:
                    target = "?"
                final = resolve_in_root(self.root, e.rel)
                tgt = target if target.startswith("/") else None
                writable = tgt and any(tgt == p or tgt.startswith(p + "/") for p in self.persistent_paths + ["/tmp", "/var", "/mnt"])
                if final is None or (final and not self.by_rel.get(final)):
                    self.add(
                        "builtin-credential-db-symlink", "info-leak" if writable else "other", "medium" if writable else "info",
                        f"{e.rel} 가 이미지 밖(실행 시 생성/쓰기 가능 위치)을 가리키는 심볼릭 링크 (-> {target})",
                        file=e.rel,
                        rationale="실제 계정 DB 가 설정 파티션(jffs2 등)이나 tmpfs 에 있다. 설정 파티션을 fw_carve 로 분리해 같은 검사를 하거나, UART 셸에서 해당 경로를 확인한다.",
                        extra={"link_target": target},
                    )
                    continue
            data, final = self.read(e.rel, 1 << 20)
            if data is None:
                continue
            if _binary_content(data):
                continue  # 이름만 같은 실행 파일/바이너리 (계정 DB 는 텍스트다)
            text = data.decode("latin-1")
            is_shadow = "shadow" in e.name
            is_htpasswd = "htpasswd" in e.name
            for ln, line in enumerate(text.split("\n"), 1):
                if not line or line.startswith("#") or ":" not in line:
                    continue
                f = line.split(":")
                user = f[0].strip()
                if not user or not re.match(r"^[A-Za-z0-9_.$@-]{1,64}$", user):
                    continue
                pw = f[1] if len(f) > 1 else ""
                acc = accounts.setdefault(user, {"user": user, "files": []})
                acc["files"].append(f"{e.rel}:{ln}")
                if not is_shadow and not is_htpasswd and "passwd_line" not in acc:
                    acc["passwd_line"] = (e.rel, ln)
                if not is_shadow and not is_htpasswd and len(f) >= 7:
                    try:
                        acc["uid"] = int(f[2])
                        acc["gid"] = int(f[3])
                    except ValueError:
                        pass
                    acc["home"] = f[5]
                    acc["shell"] = f[6].strip()
                if pw in ("x", "*") and not is_htpasswd:
                    continue
                info = identify_hash(pw)
                acc.setdefault("hashes", []).append({"file": e.rel, "line": ln, "algorithm": info["algorithm"], "weak": info.get("weak"), "locked": info.get("locked")})
                if info["algorithm"] not in ("locked",):
                    hashes.append({"user": user, "hash": pw, "file": e.rel, "line": ln, "source": e.rel, "excerpt": line})
        # YAML credential_patterns (파일 glob + 줄 정규식)
        for cp in self.patterns.credential_patterns:
            if cp.rx is None or cp.candidate_passwords:
                continue
            for e in self.entries:
                if e.kind not in ("file", "symlink") or not self.match_globs(cp.file_rx, e.rel):
                    continue
                data, final = self.read(e.rel, 1 << 20)
                if not data:
                    continue
                text = data.decode("latin-1")
                for m in cp.rx.finditer(text):
                    ln, line = _line_of(text, m.start())
                    excerpt = line
                    hv = m.groupdict().get("hash") if m.groupdict() else None
                    if hv and len(hv) > 6:
                        excerpt = line.replace(hv, hv[:6] + "…")
                    self.add(cp.id, cp.category, cp.severity, f"{cp.id}: {e.rel}:{ln}", file=e.rel, line=ln, excerpt=excerpt, rationale=cp.rationale, references=cp.references)
        # 내장 계정 점검 (YAML 이 없을 때도 동작)
        for user, acc in accounts.items():
            shell = acc.get("shell") or ""
            login_shell = any(shell.endswith(s.rsplit("/", 1)[-1]) for s in LOGIN_SHELLS) if shell else False
            acc["login_shell"] = login_shell
            for hinfo in acc.get("hashes", []):
                if hinfo["algorithm"] == "empty":
                    sev = "critical" if acc.get("uid") == 0 else "high"
                    if self.covered(("passwd-empty-password",), hinfo["file"], hinfo["line"]):
                        for it in self.items:
                            if it["id"] == "passwd-empty-password" and it.get("file") == hinfo["file"] and it.get("line") == hinfo["line"] and severity_key(sev) < severity_key(it["severity"]):
                                it["severity"] = sev
                                it["title"] += " (uid 0 계정)"
                        continue
                    self.add("builtin-empty-password", "insecure-default", sev, f"계정 '{user}' 의 비밀번호가 비어 있음", file=hinfo["file"], line=hinfo["line"],
                             rationale="빈 비밀번호 필드 → telnet/UART/login 에서 비밀번호 없이 로그인 가능 (로그인 셸·서비스 노출 여부 확인).")
                elif hinfo["algorithm"] in ("des", "md5crypt", "apr1", "md5-hex", "sha1-hex", "sun-md5", "bsdi-des"):
                    if self.covered(("passwd-des-crypt", "passwd-md5-crypt"), hinfo["file"], hinfo["line"]):
                        continue
                    self.add("builtin-weak-hash", "weak-crypto", "medium", f"계정 '{user}' 의 비밀번호 해시가 약한 알고리즘({hinfo['algorithm']})", file=hinfo["file"], line=hinfo["line"],
                             rationale="DES crypt 는 앞 8자만 쓰고 MD5 계열은 빠르게 대입 가능하다. 펌웨어에 고정된 해시는 모든 기기 공통 비밀번호일 수 있다.")
            if acc.get("uid") == 0 and user != "root":
                pf, pl = acc.get("passwd_line") or (None, None)
                if not self.covered(("passwd-extra-uid0",), pf, pl):
                    self.add("builtin-extra-uid0", "backdoor", "high", f"root 외의 uid 0 계정 '{user}'", file=pf, line=pl,
                             rationale="추가 uid 0 계정은 숨은 관리자/백도어 계정일 수 있다.")
        return sorted(accounts.values(), key=lambda a: (a.get("uid", 99999), a["user"])), hashes

    def crack_hashes(self, hashes: list[dict[str, Any]], accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        uniq: dict[tuple[str | None, str], dict[str, Any]] = {}
        for h in hashes:
            uniq.setdefault((h["user"], h["hash"]), h)
        entries = [{"user": u, "hash": hh, "source": v["file"], "file": v["file"], "line": v.get("line")} for (u, hh), v in uniq.items()]
        if not entries:
            return []
        deadline = time.monotonic() + self.crack_seconds
        results = crack_entries(entries, self.words, deadline=deadline, known_hashes=self.patterns.known_hashes)
        uid_of = {a["user"]: a.get("uid") for a in accounts}
        for r in results:
            if r.get("known_hash"):
                kh = r["known_hash"]
                if not self.covered((kh.get("id", "known-hash"),), r.get("file"), r.get("line")):
                    self.add(kh.get("id", "known-hash"), "hardcoded-credential", kh.get("severity_hint", "critical"),
                             f"공개된 하드코딩 해시와 일치: 계정 '{r['user']}' ({r['file']})", file=r.get("file"), line=r.get("line"), rationale=kh.get("rationale"), references=kh.get("references"))
            if r["status"] == "cracked":
                sev = "critical" if (uid_of.get(r["user"]) == 0 or r["user"] in ("root", "admin")) else "high"
                self.add("builtin-default-password", "hardcoded-credential", sev,
                         f"계정 '{r['user']}' 의 비밀번호가 공개 기본 비밀번호 사전과 일치 ({mask_secret(r.get('password'))})", file=r.get("file"), line=r.get("line"),
                         rationale="공개된 IoT 기본 비밀번호 목록(src/pweh/data/default-passwords.txt)과 오프라인 대조 결과. 모든 동일 펌웨어 기기에 같은 비밀번호가 있을 가능성이 높다.",
                         extra={"algorithm": r["algorithm"]})
            if r["status"] == "partial":
                self.limitations.append("해시 대조가 시간 예산 안에 끝나지 않았습니다 (crack_seconds 증가 또는 fw_crack_hashes 사용).")
        for r in results:
            if "password" in r:
                r["password_masked"] = mask_secret(r["password"])
        return results

    # -- 부팅 -----------------------------------------------------------------
    def audit_startup(self) -> dict[str, Any]:
        startup: list[str] = []
        for e in self.entries:
            if e.kind in ("file", "symlink") and self.match_globs(_STARTUP_RX, e.rel):
                startup.append(e.rel)
        services: list[dict[str, Any]] = []
        inittab: list[dict[str, Any]] = []
        mounts: list[dict[str, Any]] = []
        queue = list(dict.fromkeys(startup))
        seen = set(queue)
        text_heur = [h for h in self.patterns.string_heuristics if h.rx is not None and h.scope in ("text", "any")]
        idx = 0
        writable_prefixes = list(self.persistent_paths)
        for cp in (self.profile.get("firmware") or {}).get("config_paths") or []:
            if isinstance(cp, str) and cp.startswith("/"):
                writable_prefixes.append(cp.rstrip("/"))
        # fstab
        data, _ = self.read("/etc/fstab", 1 << 16)
        if data:
            for ln, line in enumerate(data.decode("latin-1").split("\n"), 1):
                f = line.split()
                if len(f) >= 3 and not f[0].startswith("#"):
                    fs = f[2]
                    opts = f[3] if len(f) > 3 else "defaults"
                    if fs in PERSISTENT_FS and "ro" not in opts.split(","):
                        mounts.append({"source": "fstab", "file": "/etc/fstab", "line": ln, "device": f[0], "mount_point": f[1], "fs": fs, "options": opts})
                        writable_prefixes.append(f[1].rstrip("/"))
        while idx < len(queue) and idx < 400:
            rel = queue[idx]
            idx += 1
            self.ctl.check()
            data, final = self.read(rel, 1 << 20)
            if data is None or not is_text(data[:4096]):
                continue
            text = data.decode("latin-1")
            active = _blank_comments(text)
            name = rel.rsplit("/", 1)[-1]
            # inittab
            if name == "inittab":
                for ln, line in enumerate(text.split("\n"), 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    f = s.split(":", 3)
                    if len(f) == 4:
                        inittab.append({"line": ln, "id": f[0], "runlevels": f[1], "action": f[2], "process": f[3]})
            # YAML text/any 휴리스틱
            for h in text_heur:
                if not h.prefilter(active, lambda: active.lower()):
                    continue
                for m in h.rx.finditer(active):  # type: ignore[union-attr]
                    ln, line = _line_of(text, _match_pos(m))
                    self.add(h.id, h.category, h.severity, f"{h.id}: {rel}:{ln}", file=rel, line=ln, excerpt=line.strip(), rationale=h.rationale, references=h.references)
                    break
            for hid, rx, category, sev, title, rationale in EXTRA_CHECKS:
                for m in rx.finditer(active):
                    ln, line = _line_of(text, _match_pos(m))
                    excerpt = line.strip()
                    if hid == "builtin-chpasswd-literal":
                        excerpt = re.sub(r"(:)([^\s\"'|]+)", lambda mm: mm.group(1) + (mask_secret(mm.group(2)) or ""), excerpt, count=1)
                    self.add(hid, category, sev, f"{title} ({rel}:{ln})", file=rel, line=ln, excerpt=excerpt, rationale=rationale)
            # 서비스
            for svc, rx, label in SERVICE_RULES:
                for m in rx.finditer(active):
                    ln, line = _line_of(text, _match_pos(m))
                    binm = re.search(r"(/[\w./+-]*" + re.escape(svc.split("-")[0]) + r"[\w.+-]*)", line)
                    services.append({"service": svc, "label": label, "file": rel, "line": ln, "command": clip(line.strip(), 200), "binary": binm.group(1) if binm else None})
                    break
            # mount 명령
            for m in _MOUNT_RX.finditer(active):
                ln, line = _line_of(text, m.start())
                mo = re.search(r"\s-o\s+(\S+)", line)
                if mo and "ro" in mo.group(1).split(","):
                    continue
                mounts.append({"source": "script", "file": rel, "line": ln, "mount_point": m.group("mp"), "fs": m.group("fs"), "command": clip(line.strip(), 200)})
                writable_prefixes.append(m.group("mp").rstrip("/"))
            # 참조 스크립트 / 쓰기 가능한 저장소 실행
            for m in _ABS_PATH_RX.finditer(active):
                p = m.group(1)
                if p.startswith(("/dev/", "/proc/", "/sys/")) or len(p) < 3:
                    continue
                ln, line = _line_of(text, m.start())
                in_writable = any(p == w or p.startswith(w + "/") for w in writable_prefixes if w)
                exec_ctx = re.search(r"(?:^|[;&|]|\bthen\b|\bdo\b|\bexec\b|\bsh\b|\bash\b|\bbash\b|^\s*\.|\bsource\b)\s*" + re.escape(p), line) is not None
                if in_writable and exec_ctx and (p.endswith((".sh", ".bin")) or "/" in p):
                    self.add("builtin-exec-from-writable-storage", "insecure-default", "medium",
                             f"부팅 스크립트가 쓰기 가능한 영구 저장소의 파일을 실행: {p} ({rel}:{ln})", file=rel, line=ln, excerpt=line.strip(),
                             rationale="설정 파티션(jffs2 등)은 런타임에 쓰기 가능하다. 여기에 있는 스크립트/바이너리를 부팅 때 실행하면 지속성(persistence)·무결성 우회 경로가 된다.",
                             extra={"target": p, "present_in_image": resolve_in_root(self.root, p) in self.by_rel})
                if len(queue) < 400:
                    final_p = resolve_in_root(self.root, p)
                    ent = self.by_rel.get(final_p) if final_p else None
                    if ent and ent.kind == "file" and final_p not in seen and (final_p.endswith(".sh") or "init.d" in final_p or "/rc" in final_p or ent.st.st_size < 65536):
                        head, _ = self.read(final_p, 64)
                        if head and (head.startswith(b"#!") or final_p.endswith(".sh")):
                            seen.add(final_p)
                            queue.append(final_p)
        # world-writable 시작 스크립트 / 마운트 정리
        uniq_mounts = []
        mseen = set()
        for mt in mounts:
            k = (mt["mount_point"], mt["fs"])
            if k not in mseen:
                mseen.add(k)
                uniq_mounts.append(mt)
        for p in self.persistent_paths:
            if not any(mt["mount_point"].rstrip("/") == p for mt in uniq_mounts) and resolve_in_root(self.root, p) in self.by_rel:
                uniq_mounts.append({"source": "config.safety.persistent_paths", "mount_point": p, "fs": None, "present_in_image": True})
        return {"startup_files": queue, "services": services, "inittab": inittab, "mounts": uniq_mounts}

    # -- 웹 -------------------------------------------------------------------
    def audit_web(self) -> dict[str, Any]:
        name_vendor = self.patterns.web_binary_vendor()
        # 일반 웹 서버 이름은 어떤 벤더 목록에 함께 있어도 벤더 근거가 아니다 (YAML 에서 lighttpd 는 foscam 목록이 generic 보다 먼저 나와
        # 모든 lighttpd 가 foscam +3 표가 되었다)
        for n in list(self.patterns.web_server_binaries.get("generic") or []) + GENERIC_WEB:
            name_vendor[n] = "generic"
        for n in (self.profile.get("firmware") or {}).get("web_servers") or []:
            name_vendor.setdefault(str(n), "profile")
        servers: list[dict[str, Any]] = []
        configs: list[dict[str, Any]] = []
        cgi: list[dict[str, Any]] = []
        roots: dict[str, int] = {}
        for e in self.entries:
            n = e.name
            if e.kind == "file" and n in name_vendor:
                head, _ = self.read(e.rel, 64)
                h = describe_elf_header(head or b"")
                if h is not None or (head or b"").startswith(b"#!"):
                    servers.append({"path": e.rel, "name": n, "vendor": name_vendor[n], "elf": h["summary"] if h else None, "size": e.st.st_size})
            low = n.lower()
            if e.kind == "file" and (low in ("boa.conf", "lighttpd.conf", "httpd.conf", "thttpd.conf", "nginx.conf", "uhttpd", "goahead.conf", "route.txt", "auth.txt", "umconfig.txt", "mini_httpd.conf") or (low.endswith(".conf") and "httpd" in low)):
                configs.append(self.parse_web_config(e))
            parts = e.rel.split("/")
            if e.kind == "file" and ("cgi-bin" in parts or low.endswith((".cgi", ".fcgi"))):
                head, _ = self.read(e.rel, 64)
                h = describe_elf_header(head or b"")
                cgi.append({"path": e.rel, "elf": h["summary"] if h else None, "script": bool(head and head.startswith(b"#!")), "size": e.st.st_size})
            if e.kind == "dir" and n in ("www", "web", "webs", "html", "htdocs", "wwwroot", "webroot", "web_root"):
                roots[e.rel] = 0
        for r in list(roots):
            roots[r] = sum(1 for e in self.entries if e.kind == "file" and e.rel.startswith(r + "/"))
        return {"servers": servers, "configs": configs, "cgi": cgi[:500], "web_roots": [{"path": k, "files": v} for k, v in sorted(roots.items())]}

    def parse_web_config(self, e: Entry) -> dict[str, Any]:
        data, _ = self.read(e.rel, 1 << 18)
        out: dict[str, Any] = {"path": e.rel}
        if not data:
            return out
        text = data.decode("latin-1")
        low = e.name.lower()
        keys = {}
        for rx_key, label in ((r"(?im)^\s*DocumentRoot\s+(\S+)", "document_root"), (r"(?im)^\s*ScriptAlias\s+(\S+\s+\S+)", "script_alias"),
                              (r"(?im)server\.document-root\s*=\s*\"([^\"]+)\"", "document_root"), (r"(?im)^\s*(?:dir|cgipat)\s*=\s*(\S+)", "thttpd"),
                              (r"(?im)^\s*root\s+([^;]+);", "document_root"), (r"(?im)^\s*Port\s+(\d+)", "port"), (r"(?im)server\.port\s*=\s*(\d+)", "port"),
                              (r"(?im)^\s*option\s+home\s+'?([^'\s]+)", "document_root"), (r"(?im)^\s*User\s+(\S+)", "user")):
            for m in re.finditer(rx_key, text):
                keys.setdefault(label, []).append(m.group(1).strip())
        out.update({k: v[:5] for k, v in keys.items()})
        if low == "httpd.conf":
            # BusyBox httpd.conf: '/path:user:pass' 기본 인증 줄 (pass 는 평문 또는 crypt 해시)
            for ln, line in enumerate(text.split("\n"), 1):
                m = re.match(r"^(/[^:\s]*):([^:\s]+):(\S+)\s*$", line.strip())
                if m:
                    val = m.group(3)
                    self.add("builtin-busybox-httpd-auth", "hardcoded-credential", "high", f"BusyBox httpd 기본 인증 자격증명 ({e.rel}:{ln})", file=e.rel, line=ln,
                             excerpt=f"{m.group(1)}:{m.group(2)}:{mask_secret(val)}", rationale="httpd.conf 의 '/경로:사용자:비밀번호' 는 고정 자격증명이다 (비밀번호가 crypt 해시면 fw_crack_hashes 로 확인).")
        return out

    # -- 파일 내용 1회 순회 ----------------------------------------------------
    def content_pass(self, hashes: list[dict[str, Any]]) -> dict[str, Any]:
        private_keys: list[dict[str, Any]] = []
        certs: dict[str, int] = {}
        seen_inodes: set[tuple[int, int]] = set()
        n = 0
        for e in self.entries:
            if e.kind != "file":
                continue
            ino = (e.st.st_dev, e.st.st_ino)
            if ino in seen_inodes:
                continue
            seen_inodes.add(ino)
            n += 1
            if (n & 0xFF) == 0 and self.ctl.expired():
                self.limitations.append("시간 예산 초과로 파일 내용 검사(키/자격증명)를 일부만 수행했습니다.")
                break
            name = e.name
            low = name.lower()
            # 이름 기반 SSH/dropbear 호스트 키
            if (low.startswith("dropbear_") and low.endswith("_host_key")) or (low.startswith("ssh_host_") and low.endswith("_key")):
                self.add("builtin-embedded-host-key", "weak-crypto", "high", f"펌웨어에 SSH 호스트 개인키 내장: {e.rel}", file=e.rel,
                         rationale="모든 기기가 같은 호스트 키를 공유하면 중간자 공격/위장이 가능하다 (최초 부팅 시 생성해야 함).")
                private_keys.append({"path": e.rel, "type": "ssh-host-key", "encrypted": None})
            size = e.st.st_size
            if size == 0 or size > self.max_file_size:
                continue
            data, _ = self.read(e.rel, self.max_file_size)
            if not data:
                continue
            # PEM
            if b"-----BEGIN " in data:
                for m in PEM_RX.finditer(data):
                    label = m.group(1).decode("ascii")
                    end_marker = b"-----END " + m.group(1) + b"-----"
                    end = data.find(end_marker, m.end(), m.end() + 65536)
                    block = data[m.start() : end + len(end_marker)] if end >= 0 else data[m.start() : m.start() + 4096]
                    fp = hashlib.sha256(block).hexdigest()[:16]
                    if "PRIVATE KEY" in label:
                        enc = "ENCRYPTED" in label or b"Proc-Type: 4,ENCRYPTED" in block
                        private_keys.append({"path": e.rel, "type": label, "offset": m.start(), "encrypted": enc, "sha256_16": fp})
                        self.add("gen-private-key-pem" if any(h.id == "gen-private-key-pem" for h in self.patterns.string_heuristics) else "builtin-private-key", "crypto", "medium" if enc else "high",
                                 f"펌웨어에 개인키 내장 ({label}{', 암호화됨' if enc else ''}): {e.rel}", file=e.rel,
                                 rationale="펌웨어에 들어 있는 개인키는 모든 기기에 공통일 가능성이 높다 (TLS/푸시/클라우드 위장).",
                                 extra={"offset": m.start(), "fingerprint": fp})
                    elif "CERTIFICATE" in label:
                        certs[e.rel] = certs.get(e.rel, 0) + 1
                    if len(private_keys) > 200:
                        break
            # 텍스트 설정/스크립트의 자격증명
            ext = "." + low.rsplit(".", 1)[1] if "." in low else ""
            if size <= (1 << 20) and (ext in CRED_EXT) and e.rel.startswith(CRED_DIR_PREFIXES) and is_text(data[:4096]):
                text = data.decode("latin-1")
                active = _blank_comments(text) if ext in (".sh", ".conf", "", ".cfg", ".ini", ".rc") else text
                hits = 0
                for cid, rx in CRED_RX:
                    for m in rx.finditer(active):
                        val = m.group("val")
                        if val.lower() in _NON_VALUES or val.startswith(("$", "%", "`", "@", "{")) or set(val) <= {"*", "x", "X", "#"}:
                            continue
                        ln, line = _line_of(text, m.start())
                        excerpt = line.strip().replace(val, mask_secret(val) or "", 1)
                        sev = "medium"
                        self.add(cid, "hardcoded-credential", sev, f"설정/스크립트의 하드코딩 자격증명 후보 ({e.rel}:{ln})", file=e.rel, line=ln, excerpt=excerpt,
                                 rationale="평문 비밀번호/PSK/URL 자격증명이 펌웨어에 고정되어 있으면 모든 기기 공통이다 (값은 마스킹; 파일과 줄 번호로 확인).",
                                 extra={"key": m.group("key")})
                        if re.match(r"^\$(?:1|5|6|apr1)\$|^[./0-9A-Za-z]{13}$", val):
                            hashes.append({"user": m.group("key"), "hash": val, "file": e.rel, "line": ln, "source": e.rel})
                        hits += 1
                        if hits >= 20:
                            break
        cert_list = [{"path": k, "certificates": v} for k, v in sorted(certs.items())][:200]
        return {"private_keys": private_keys, "certificates": cert_list}

    # -- 권한 -----------------------------------------------------------------
    def audit_permissions(self, startup_files: list[str]) -> dict[str, Any]:
        setuid: list[dict[str, Any]] = []
        setgid: list[dict[str, Any]] = []
        ww: list[dict[str, Any]] = []
        startup_set = set(startup_files)
        for e in self.entries:
            if e.kind != "file":
                continue
            mode, uid, gid, src = self.mode_of(e)
            if mode & 0o4000:
                setuid.append({"path": e.rel, "mode": oct(mode), "uid": uid, "source": src})
            if mode & 0o2000:
                setgid.append({"path": e.rel, "mode": oct(mode), "gid": gid, "source": src})
            if e.rel in startup_set and mode & 0o002:
                ww.append({"path": e.rel, "mode": oct(mode), "source": src})
                self.add("builtin-world-writable-startup", "insecure-default", "high", f"world-writable 시작 스크립트: {e.rel} ({oct(mode)})", file=e.rel,
                         rationale="누구나 수정할 수 있는 시작 스크립트는 다음 부팅 때 root 권한으로 실행된다.")
        for s in setuid:
            name = s["path"].rsplit("/", 1)[-1]
            root_owned = s["uid"] in (0, None)
            if name == "busybox" and root_owned:
                self.add("builtin-setuid-busybox", "insecure-default", "medium", f"busybox 가 setuid ({s['mode']})", file=s["path"],
                         rationale="setuid busybox 는 (CONFIG_FEATURE_SUID 설정에 따라) 비권한 사용자의 권한 상승 경로가 될 수 있다.", extra={"mode_source": s["source"]})
            else:
                self.add("builtin-setuid", "other", "low" if root_owned else "info", f"setuid 바이너리: {s['path']} ({s['mode']})", file=s["path"], extra={"mode_source": s["source"], "uid": s["uid"]})
        if self.manifest is None and not setuid:
            self.limitations.append("setuid 0개: 매니페스트 없이 비root 추출 트리를 검사하면 setuid 비트가 사라져 있을 수 있습니다.")
        return {"setuid": setuid, "setgid": setgid, "world_writable_startup": ww}

    # -- 기타 -----------------------------------------------------------------
    def interesting_paths(self) -> dict[str, Any]:
        out: dict[str, list[str]] = {}
        total = 0
        for g, rx in self.patterns.interesting_rx:
            hits = []
            for e in self.entries:
                if rx.match(e.rel.lstrip("/")):
                    hits.append(e.rel)
                    if len(hits) >= 30:
                        break
            if hits:
                out[g] = hits
                total += len(hits)
            if total > 600:
                break
        return out

    def vendor_guess(self, web: dict[str, Any], content: dict[str, Any]) -> dict[str, Any]:
        votes: dict[str, int] = {}
        evidence: list[str] = []
        for s in web["servers"]:
            v = s.get("vendor")
            if v and v not in ("generic", "profile"):
                votes[v] = votes.get(v, 0) + 3
                evidence.append(f"바이너리 이름 {s['path']} → {v}")
        for s in web["servers"][:12]:
            data, _ = self.read(s["path"], 32 << 20)
            if not data:
                continue
            for banner, v in BANNERS:
                if banner.encode() in data:
                    evidence.append(f"배너 '{banner}' in {s['path']}")
                    if v != "generic":
                        votes[v] = votes.get(v, 0) + 2
        for p, v in PATH_HINTS:
            if resolve_in_root(self.root, p) in self.by_rel:
                evidence.append(f"경로 지표 {p} → {v}")
                for vv in v.split("/"):
                    votes[vv] = votes.get(vv, 0) + 1
        best = max(votes.items(), key=lambda kv: kv[1])[0] if votes else None
        prof_family = (self.profile.get("hunt") or {}).get("vendor_family")
        # family 결정 순서 (family_source 로 근거를 밝힌다). votes 와 vendor 는 파일 근거만 담는다.
        # 1) 파일 근거(바이너리 이름 +3, 배너 +2, 경로 +1) → evidence
        # 2) 파일 근거가 없으면 케이스 프로필의 hunt.vendor_family(구체적인 값일 때) → profile
        #    (cctv-auth-bypass-hunt 의 'votes 가 비어 있으면 프로필 값을 쓴다' 규칙과 같다)
        # 3) 일반 웹 서버(boa/goahead/lighttpd/httpd 등)만 있으면 → generic (벤더 특정 근거 없음, 'unknown' 이 아님)
        # 4) 웹 서버도 근거도 없으면 → unknown
        if not best:
            for s in web["servers"][:8]:
                evidence.append(f"일반 웹 서버 {s['path']} ({s.get('vendor')}) — 벤더 특정 근거 아님")
        if best:
            family, source = VENDOR_FAMILY.get(best, "generic"), "evidence"
        elif isinstance(prof_family, str) and prof_family in _AUTH_HUNT_FAMILIES and prof_family not in ("generic", "unknown"):
            family, source = prof_family, "profile"
            evidence.append(f"파일 근거(바이너리 이름·배너·경로 지표) 없음 → 케이스 프로필의 hunt.vendor_family '{prof_family}' 사용")
        elif web["servers"]:
            family, source = "generic", "generic-web-server"
        else:
            family, source = "unknown", "none"
        return {"family": family, "family_source": source, "vendor": best, "votes": votes, "evidence": evidence[:40], "profile_vendor_family": prof_family}
