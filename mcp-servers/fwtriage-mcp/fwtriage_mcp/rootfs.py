"""추출된 rootfs 감사 (fw_rootfs_audit).

점검 항목 (각 항목: 파일 경로, 줄/발췌, category(finding 스키마 어휘), severity 힌트, 근거):
- 계정: passwd/shadow — 빈 비밀번호, 해시 알고리즘(DES/MD5 약함), uid 0 추가 계정, 공개된 하드코딩 해시,
  내장 기본 비밀번호 사전과 일치(오프라인), passwd/shadow 가 쓰기 가능한 저장소로의 링크인지
- 부팅: inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트 — telnetd(+ -l /bin/sh), dropbear -B, nc -e 셸,
  getty 자동 로그인/콘솔 셸, remserial(UART 브리지), 쓰기 가능한 영구 저장소의 스크립트 실행, world-writable 시작 스크립트.
  핫플러그 처리기(mdev.conf 의 @/$/* 명령, udev 규칙의 RUN+=, /etc/hotplug*, 텍스트인 /sbin/hotplug)도 시작 스크립트처럼 따라간다
- 웹: 웹 서버/메인 앱 바이너리, 설정(boa/lighttpd/BusyBox httpd/thttpd/uhttpd/nginx), CGI, 웹 루트
- setuid/setgid (fw_extract_squashfs 매니페스트가 있으면 원본 모드/소유자 기준)
- 개인키/인증서 (키 내용은 출력하지 않고 지문만), SSH/dropbear 호스트 키
- 설정 파일/스크립트의 하드코딩 자격증명 (값은 마스킹)
- 영구 쓰기 가능 마운트 (fstab, mount 명령 — jffs2/ubifs/ext*/vfat/msdos/fat/exfat/ntfs(3)/f2fs/auto/sdcardfs 와 '-t' 없는
  /dev/mmcblk* 마운트, -o ro 는 제외 — 설정의 persistent_paths)
- cctv-hunt-patterns.yaml: credential_patterns, text 범위 string_heuristics, interesting_paths, web_server_binaries

결과는 '후보'다. 확정은 REA/동적 확인(소유 기기, 격리 랩)으로 한다.
"""

from __future__ import annotations

import bisect
import hashlib
import os
import re
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pweh.safety.redact import CRED_RX
from pweh.safety.redact import NON_VALUES as _NON_VALUES
from pweh.safety.redact import QUOTED_CRED_RX as _QUOTED_CRED_RX

from .common import Ctl, clip, mask_secret, severity_key
from .elfinfo import describe_elf_header
from .fswalk import Entry, is_text, load_manifest, read_in_root, resolve_in_root, walk_tree
from .hashes import crack_entries, identify_hash
from .patterns import VENDOR_FAMILY, PatternSet, finding_category, glob_to_regex, required_literals

LOGIN_SHELLS = ("/bin/sh", "/bin/ash", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/hush", "/usr/bin/bash", "/usr/bin/sh")
GENERIC_WEB = ["boa", "goahead", "webs", "lighttpd", "thttpd", "mini_httpd", "uhttpd", "httpd", "nginx", "mongoose", "civetweb", "appweb", "shttpd", "alphapd", "hydra", "jhttpd"]

STARTUP_GLOBS = [
    "etc/inittab", "etc/init.d/**", "etc/rc.d/**", "etc/rc[0-9S].d/*", "etc/rcS", "etc/rc", "etc/rc.local", "etc/rc.sysinit",
    "etc/rc.common", "etc/profile", "etc/profile.d/*", "etc/inetd.conf", "etc/xinetd.conf", "etc/xinetd.d/*",
    "etc/systemd/system/**", "lib/systemd/system/*.service", "usr/lib/systemd/system/*.service", "etc/service/*/run",
    "etc/sv/*/run", "etc/runit/**", "etc/init/*.conf", "usr/etc/rc*", "usr/etc/init.d/*", "etc_ro/rc*", "etc_ro/inittab",
    "etc_ro/init.d/*", "etc/boot.sh", "**/start*.sh", "**/rcS*", "etc/config/*.sh", "**/autorun*.sh",
    # 핫플러그: 장치(SD 카드 등)가 들어오고 나갈 때 root 로 실행되는 처리기. 바이너리(/sbin/hotplug 가 ELF 인 경우)는 아래 루프의 텍스트 검사로 건너뛴다
    "etc/mdev.conf", "etc/udev/rules.d/*", "lib/udev/rules.d/*", "usr/lib/udev/rules.d/*",
    "etc/hotplug/**", "etc/hotplug.d/**", "sbin/hotplug", "usr/sbin/hotplug",
]
_STARTUP_RX = [glob_to_regex(g) for g in STARTUP_GLOBS]
HOTPLUG_GLOBS = ["etc/mdev.conf", "etc/udev/rules.d/*", "lib/udev/rules.d/*", "usr/lib/udev/rules.d/*", "etc/hotplug/**", "etc/hotplug.d/**", "sbin/hotplug", "usr/sbin/hotplug"]
HOTPLUG_RX = [glob_to_regex(g) for g in HOTPLUG_GLOBS]
#: mdev 명령이 상대 이름이면 찾아볼 디렉터리 (mdev 는 system() 으로 실행하므로 PATH 와 흔한 벤더 위치)
MDEV_CMD_DIRS = ("/lib/mdev", "/etc/mdev", "/sbin", "/usr/sbin", "/bin", "/usr/bin")
#: udev RUN/PROGRAM 이 상대 이름이면 udev 가 찾는 디렉터리
UDEV_CMD_DIRS = ("/lib/udev", "/usr/lib/udev")
_SHELLS = ("sh", "ash", "bash", "dash", "hush", "ksh", "busybox")

class _Chain:
    """'키워드 … 옵션 … 셸' 처럼 한 논리 줄에 차례로 나오는 조각을 앞 조각이 끝난 자리부터 하나씩 찾는 규칙.

    '키워드[^\\n]*옵션[^\\n]*셸' 꼴 정규식을 한 줄 범위에 적용한 것과 같은 '있는지' 판정이다 (조각마다 가장 이른 일치의 끝이
    가장 앞이라 가장 이른 일치로 이어 가도 결과가 같다). 조각마다 줄을 한 번만 훑으므로 키워드가 수없이 되풀이된 긴 줄에서도 선형 시간이고,
    줄을 자르거나 규칙을 건너뛸 필요가 없다. search(text, pos, endpos) 는 한 줄 범위 [pos, endpos) 만 본다 — audit_startup 은 이어쓰기('\\'·
    줄 끝 |·||·&&)로 이어진 줄을 한 논리 줄로 넘기므로 'nc -p 4444 \\' + '-l -e /bin/sh' 같은 여러 줄 명령도 한 범위다 (logical_text)."""

    def __init__(self, *parts: str, flags: int = 0, literals: list[str] | None = None) -> None:
        self.parts = [re.compile(x, flags | re.M) for x in parts]  # re.M: 줄 범위 [pos, endpos) 의 처음에서도 ^ 가 맞게
        self.pattern = " … ".join(parts)
        # 줄 후보를 고르는 필수 리터럴(OR). sre 파서가 못 뽑는 짧은 낱말(nc 등)은 직접 준다
        self.literals = (literals, False) if literals else required_literals(("(?i)" if flags & re.I else "") + parts[0])

    def search(self, text: str, pos: int = 0, endpos: int | None = None) -> re.Match[str] | None:
        end = len(text) if endpos is None else endpos
        first = None
        for rx in self.parts:
            m = rx.search(text, pos, end)
            if m is None:
                return None
            if first is None:
                first = m
            pos = m.end()
        return first


class _WordRule:
    """구분자(줄 처음·공백·;&|(/) 바로 뒤에서 시작해 끝 구분자(줄 끝·공백·;&|)) 바로 앞에서 끝나는 낱말(\\w+)에 needle 이 들어 있는지.

    예전 '(?:^|[\\s;&|(/])\\w*needle\\w*(?=$|[\\s;&|)])' 와 같은 판정이다. 그 정규식은 needle 이 되풀이된 긴 낱말에서 되돌아가기가
    제곱으로 늘어 낱말을 한 번만 뽑고 포함 여부를 문자열로 본다 (길이 상한 없이 선형)."""

    _TOK = re.compile(r"(?:^|(?<=[\s;&|(/]))\w+(?=$|[\s;&|)])", re.M)

    def __init__(self, needle: str) -> None:
        self.needle = needle.lower()
        self.pattern = f"word containing {needle!r}"
        self.literals = ([self.needle], True)

    def search(self, text: str, pos: int = 0, endpos: int | None = None) -> re.Match[str] | None:
        for m in self._TOK.finditer(text, pos, len(text) if endpos is None else endpos):
            if self.needle in m.group(0).lower():
                return m
        return None



# ---------------------------------------------------------------------------
# YAML 패턴의 최상위 무제한 간격을 선형으로 판정 (기본 감사의 줄 단위 평가)
# ---------------------------------------------------------------------------

_GLOBAL_FLAGS_RX = re.compile(r"\(\?[aiLmsux]+\)")
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a", "0": "\0"}


#: 상한이 이 값 이상인 같은 줄 간격('[^\n…]{m,N}')도 무제한 간격으로 본다. YAML 의 큰 상한(예: {0,1024}?)은 원래 정규식을 쓰는
#: fw_strings_hunt 의 선형 시간을 위한 것이라, 줄 단위로 선형 판정하는 기본 감사는 HEAD 의 무제한 패턴처럼 길이 제한 없이 본다.
LINE_GAP_UNBOUND_MIN = 256
_BOUNDED_GAP_RX = re.compile(r"\{(\d{1,5}),(\d{1,6})\}")


def _gap_quant(pattern: str, k: int) -> tuple[int, int] | None:
    """pattern[k:] 이 무제한 반복('*'·'+')이거나 상한이 LINE_GAP_UNBOUND_MIN 이상인 '{m,N}' 이면 (최소 길이, 끝 위치). 게으른 '?' 허용.
    소유 반복('*+'·'{m,N}+')과 상한이 작은 유한 반복은 간격이 아니다."""
    if k >= len(pattern):
        return None
    if pattern[k] in "*+":
        gmin = 1 if pattern[k] == "+" else 0
        k += 1
    else:
        m = _BOUNDED_GAP_RX.match(pattern, k)
        if m is None or int(m.group(2)) < LINE_GAP_UNBOUND_MIN or int(m.group(1)) > int(m.group(2)):
            return None
        gmin = int(m.group(1))
        k = m.end()
    if k < len(pattern) and pattern[k] == "+":
        return None
    if k < len(pattern) and pattern[k] == "?":
        k += 1
    return gmin, k


def _class_chars(body: str) -> str | None:
    """부정 문자 클래스 '[^body]' 의 금지 문자들 (단순 문자·한 글자 이스케이프만, 범위·\\s 같은 클래스 이스케이프는 None)."""
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            if i + 1 >= len(body):
                return None
            e = body[i + 1]
            if e in _SIMPLE_ESCAPES:
                out.append(_SIMPLE_ESCAPES[e])
            elif e == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
                out.append(chr(int(body[i + 2:i + 4], 16)))
                i += 2
            elif e.isalnum():
                return None
            else:
                out.append(e)
            i += 2
            continue
        if c == "-" and 0 < i < len(body) - 1:
            return None  # 범위
        out.append(c)
        i += 1
    return "".join(out)


def _split_unbounded_gaps(pattern: str) -> tuple[list[str], list[tuple[str, int]]] | None:
    """패턴을 최상위의 무제한 줄 간격([^\\n…]* / [^\\n…]+ / .* / .+ / 상한 256 이상의 {m,N}, 게으른 꼴 포함)에서 조각으로 나눈다.

    반환: (조각들, 간격마다 (금지 문자, 최소 길이)). 간격이 없거나, 최상위 '|'·역참조·조건 그룹·복잡한 클래스가 있으면 None
    (그 패턴은 원래 정규식으로 평가한다). 앞뒤의 간격은 존재 판정에 영향이 없어 버린다."""
    n = len(pattern)
    i = 0
    while True:
        m = _GLOBAL_FLAGS_RX.match(pattern, i)
        if not m:
            break
        i = m.end()
    depth = 0
    cur = i
    parts: list[str] = []
    gaps: list[tuple[str, int]] = []
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 < n and (pattern[i + 1] in "123456789" or pattern[i + 1] == "g"):
                return None
            i += 2
            continue
        if c == "[":
            j = i + 1
            neg = j < n and pattern[j] == "^"
            if neg:
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            if j >= n:
                return None
            q = _gap_quant(pattern, j + 1) if (neg and depth == 0) else None
            forb = _class_chars(pattern[i + 2:j]) if q is not None else None
            if q is not None and forb is not None and "\n" in forb:
                # 줄 안에서 끝없이 늘어나는 간격('[^\\n…]*') 만 나눈다. '[^"]+' 처럼 다음 구분자에서 멈추는 클래스는 그대로 둔다
                parts.append(pattern[cur:i])
                gaps.append((forb.replace("\n", ""), q[0]))
                cur = i = q[1]
                continue
            i = j + 1
            continue
        if c == "(":
            if pattern.startswith("(?P=", i) or pattern.startswith("(?(", i):
                return None
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            return None
        elif c == "." and depth == 0:
            q = _gap_quant(pattern, i + 1)
            if q is not None:
                parts.append(pattern[cur:i])
                gaps.append(("", q[0]))
                cur = i = q[1]
                continue
        i += 1
    parts.append(pattern[cur:])
    if not gaps:
        return None
    if parts[0] == "":
        parts.pop(0)
        gaps.pop(0)
    if parts and parts[-1] == "":
        parts.pop()
        gaps.pop()
    if not parts or any(x == "" for x in parts) or len(gaps) != len(parts) - 1:
        return None
    if any(f for f, _ in gaps) and len(gaps) > 1:
        return None  # 금지 문자가 있는 간격은 조각이 둘일 때만 (아래 _GapChain 의 정확성 근거)
    return parts, gaps


class _GapChain:
    """YAML 패턴 'A[^\\n]*B[^\\n]*C' 의 줄 단위 판정을 조각 검색의 연쇄로 (선형 시간, 길이 상한 없음).

    정규식 엔진은 키워드 A 가 줄에 k 번 나오면 각 A 에서 줄 끝까지 다시 훑는다 (k×줄 길이). 간격이 금지 문자 없는 '[^\\n]*' 이면
    가장 이른 A 의 끝 뒤에서 가장 이른 B 를 찾는 것으로 존재 판정이 같다 (뒤의 A 는 B 를 찾을 범위가 더 좁다).
    금지 문자가 있는 간격('[^\\n%]*')은 조각이 둘일 때만: 금지 문자 구간마다 A·B 를 한 번씩 보고 B 검색 결과는 재사용한다."""

    def __init__(self, parts: list[re.Pattern[str]], gaps: list[tuple[str, int]], pattern: str) -> None:
        self.parts = parts
        self.gaps = gaps
        self.pattern = pattern

    def search(self, text: str, pos: int = 0, endpos: int | None = None) -> re.Match[str] | None:
        end = len(text) if endpos is None else endpos
        forb = self.gaps[0][0] if len(self.gaps) == 1 else ""
        if not forb:
            first = None
            lo = pos
            for k, rx in enumerate(self.parts):
                m = rx.search(text, lo, end)
                if m is None:
                    return None
                if first is None:
                    first = m
                lo = m.end() + (self.gaps[k][1] if k < len(self.gaps) else 0)
            return first
        p0, p1 = self.parts
        gmin = self.gaps[0][1]
        start = pos
        skip_until = -1
        q_lo, q_at = -1, -1  # 캐시: q_lo 이상에서 가장 이른 B 의 시작 (없으면 -2)
        f_cache: dict[str, tuple[int, int]] = {}
        while start <= end:
            m0 = p0.search(text, start, end)
            if m0 is None:
                return None
            e0 = m0.end()
            if e0 <= skip_until:
                start = m0.start() + 1
                continue
            lo = e0 + gmin
            if not (q_lo != -1 and q_lo <= lo and (q_at == -2 or q_at >= lo)):
                m1 = p1.search(text, lo, end)
                q_lo, q_at = lo, (m1.start() if m1 else -2)
            if q_at == -2:
                return None
            f = end
            for ch in forb:
                c_lo, c_at = f_cache.get(ch, (-1, -1))
                if not (c_lo != -1 and c_lo <= e0 and (c_at == end or c_at >= e0)):
                    c_at = text.find(ch, e0, end)
                    c_at = end if c_at < 0 else c_at
                    f_cache[ch] = (e0, c_at)
                f = min(f, c_at)
            if q_at <= f:
                return m0
            skip_until = f  # 이 금지 문자 앞에서 끝나는 A 는 모두 같은 결과
            start = m0.start() + 1
        return None


_YAML_MATCHERS: dict[tuple[str, str], Any] = {}


def yaml_line_matcher(h: Any) -> Any:
    """YAML text/any 휴리스틱의 줄 단위 판정기: 최상위 무제한 간격(상한 256 이상의 같은 줄 간격 포함 — 길이 제한 없이 본다)이 있으면
    _GapChain, 아니면 원래 정규식 (둘 다 search(text, pos, endpos))."""
    key = (h.id, h.pattern)
    hit = _YAML_MATCHERS.get(key)
    if hit is not None:
        return hit
    matcher: Any = h.rx
    split = _split_unbounded_gaps(h.pattern) if h.rx is not None else None
    if split is not None:
        parts_txt, gaps = split
        flags = h.rx.flags
        try:
            parts = [re.compile(x, flags) for x in parts_txt]
        except re.error:
            parts = []
        if parts:
            if flags & re.I:
                gaps = [("".join(sorted(set(f.lower() + f.upper()))), g) for f, g in gaps]
            matcher = _GapChain(parts, gaps, h.pattern)
    if len(_YAML_MATCHERS) < 4096:
        _YAML_MATCHERS[key] = matcher
    return matcher

SERVICE_RULES: list[tuple[str, Any, str]] = [
    ("telnetd", re.compile(r"(?:^|[\s;&|(/])u?telnetd(?=$|[\s;&|)])", re.M), "telnet 서버"),
    ("dropbear", re.compile(r"(?:^|[\s;&|(/])dropbear(?=$|[\s;&|)])", re.M), "SSH 서버(dropbear)"),
    ("sshd", re.compile(r"(?:^|[\s;&|(/])sshd(?=$|[\s;&|)])", re.M), "SSH 서버(OpenSSH)"),
    ("ftpd", re.compile(r"(?:^|[\s;&|(/])(?:vsftpd|bftpd|pure-ftpd|proftpd|ftpd)(?=$|[\s;&|)])", re.M), "FTP 서버"),
    ("tftpd", re.compile(r"(?:^|[\s;&|(/])u?tftpd(?=$|[\s;&|)])", re.M), "TFTP 서버"),
    ("remserial", re.compile(r"(?:^|[\s;&|(/])remserial(?=$|[\s;&|)])", re.M), "UART→TCP 브리지(remserial)"),
    ("snmpd", re.compile(r"(?:^|[\s;&|(/])snmpd(?=$|[\s;&|)])", re.M), "SNMP 에이전트"),
    ("upnpd", re.compile(r"(?:^|[\s;&|(/])(?:mini)?upnpd(?=$|[\s;&|)])", re.M), "UPnP"),
    ("netcat-listener", _Chain(r"(?:^|[\s;&|(/])(?:nc|netcat|busybox\s+nc)\s+", r"-[a-zA-Z]*l", literals=["nc", "netcat"]), "netcat 리스너"),
    ("socat", re.compile(r"(?:^|[\s;&|(/])socat\s", re.M), "socat"),
    ("tcpsvd", re.compile(r"(?:^|[\s;&|(/])tcpsvd\s", re.M), "tcpsvd 슈퍼서버"),
    ("rtspd", _WordRule("rtsp"), "RTSP 서버"),
]

EXTRA_CHECKS: list[tuple[str, Any, str, str, str, str]] = [
    # (id, 규칙(정규식 또는 _Chain — 둘 다 search(줄)), category, severity, title, rationale)
    ("builtin-dropbear-blank-password", _Chain(r"dropbear\b", r"\s-[a-zA-Z]*B"), "insecure-default", "high",
     "dropbear 가 빈 비밀번호 로그인 허용(-B)으로 실행됨", "dropbear -B: Allow blank password logins."),
    ("builtin-netcat-shell", _Chain(r"\b(?:nc|netcat)\b", r"\s-[a-zA-Z]*[el]\b", r"(?:/bin/(?:sh|ash|bash)|-e\s)", literals=["nc", "netcat"]), "backdoor", "critical",
     "netcat 으로 셸을 네트워크에 노출 (리스너 + -e 셸)", "nc -l ... -e /bin/sh 형태는 인증 없는 원격 셸이다."),
    ("builtin-socat-exec-shell", _Chain(r"\bsocat\b", r"(?i:exec:)", r"(?:sh|bash)"), "backdoor", "critical",
     "socat 으로 셸을 노출", "socat ... EXEC:/bin/sh 형태는 원격 셸이다."),
    ("builtin-tcpsvd-shell", _Chain(r"\btcpsvd\b", r"/bin/(?:sh|ash|bash|login)\b"), "backdoor", "high",
     "tcpsvd 로 셸/로그인을 네트워크에 노출", "tcpsvd 가 셸이나 login 을 직접 실행한다."),
    ("builtin-agetty-autologin", _Chain(r"\b(?:a|min)?getty\b", r"--autologin\s+\S+"), "debug-interface", "high",
     "getty 자동 로그인", "getty --autologin 은 콘솔에서 비밀번호 없이 로그인시킨다."),
    ("builtin-login-f-root", re.compile(r"\blogin\s+-f\s+root\b", re.M), "debug-interface", "high",
     "login -f root (인증 생략 로그인)", "login -f 는 인증을 건너뛴다."),
    ("builtin-remserial", _Chain(r"\bremserial\b", r"-p\s*\d+"), "debug-interface", "high",
     "remserial 로 UART 콘솔을 TCP 포트에 브리지", "Kojenov(CVE-2020-24218 관련 장비): remserial -p 5150 ... /dev/ttyAMA1 로 시리얼을 네트워크에 노출."),
    ("builtin-chpasswd-literal", re.compile(r"echo\s+[\"']?[\w.-]+:[^\s\"'|]+[\"']?\s*\|\s*(?:/usr/s?bin/)?chpasswd", re.M), "hardcoded-credential", "high",
     "시작 스크립트가 고정 비밀번호를 chpasswd 로 설정", "모든 기기에 같은 비밀번호가 설정된다."),
]



def _rule_literals(rule: Any) -> tuple[list[str] | None, bool]:
    """규칙이 맞으려면 줄에 반드시 있어야 하는 리터럴(OR 집합, 대소문자 무시 여부). 없으면 (None, False) — 모든 줄을 본다."""
    lits = getattr(rule, "literals", None)
    if lits is not None:
        return lits  # type: ignore[no-any-return]
    return required_literals(("(?i)" if rule.flags & re.I else "") + rule.pattern)


_NL_RX = re.compile("\n")


class _LineIndex:
    """한 파일 텍스트에서 '리터럴(OR)이 하나라도 있는 줄'만 앞에서부터 차례로 낸다 (str.find 는 C 수준, 줄마다 한 번).

    규칙은 그 줄 범위 [줄 시작, 줄 끝) 에만 적용하므로 줄 의미(YAML notes: text 범위 = 텍스트 파일의 각 줄)를 지키면서
    줄을 복사하거나 자르지 않는다. 줄 번호는 처음 필요할 때 만든 줄 시작 목록에서 이분 탐색한다."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._low: str | None = None
        self._starts: list[int] | None = None

    def low(self) -> str:
        if self._low is None:
            self._low = self.text.lower()  # latin-1 로 읽은 문자는 소문자로 바꿔도 길이가 같다 (오프셋 보존)
        return self._low

    def line_no(self, pos: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in _NL_RX.finditer(self.text)]
        return bisect.bisect_right(self._starts, pos)

    def bounds(self, pos: int) -> tuple[int, int]:
        ls = self.text.rfind("\n", 0, pos) + 1
        le = self.text.find("\n", pos)
        return ls, (len(self.text) if le < 0 else le)

    def span(self, pos: int) -> tuple[int, int]:
        """bounds 와 같은 [줄 시작, 줄 끝) 이지만 줄 시작 목록에서 이분 탐색한다 — 긴 한 줄에 일치가 많아도 일치마다 줄을 훑지 않는다."""
        i = self.line_no(pos)
        starts = self._starts
        assert starts is not None
        return starts[i - 1], (starts[i] - 1 if i < len(starts) else len(self.text))

    def candidates(self, lits: list[str] | None, ic: bool = False) -> Iterator[tuple[int, int]]:
        text = self.text
        n = len(text)
        lits = [x for x in (lits or []) if x and "\n" not in x]  # 빈 리터럴·개행 리터럴은 후보를 고르는 데 못 쓴다
        if not lits:
            # 리터럴 제약이 없으면(없음·빈 목록·모두 걸러짐) 모든 줄을 본다 — 규칙을 조용히 건너뛰지 않는다
            ls = 0
            while ls <= n:
                le = text.find("\n", ls)
                if le < 0:
                    le = n
                yield ls, le
                ls = le + 1
            return
        hay = self.low() if ic else text
        if ic:
            lits = [x.lower() for x in lits]
        nxt = [hay.find(x) for x in lits]
        while True:
            q = -1
            for x in nxt:
                if x >= 0 and (q < 0 or x < q):
                    q = x
            if q < 0:
                return
            ls = text.rfind("\n", 0, q) + 1
            le = text.find("\n", q)
            if le < 0:
                le = n
            yield ls, le
            nextpos = le + 1
            for i, x in enumerate(nxt):
                if 0 <= x < nextpos:
                    nxt[i] = hay.find(lits[i], nextpos)


_EXEC_CTX_WORDS = ("then", "do", "exec", "sh", "ash", "bash", "source")

#: 실행 문맥을 그대로 넘겨주는 래퍼(이름은 낱말의 basename 으로 비교 — '/usr/bin/nohup' 도)와, 래퍼와 프로그램 사이에 올 수 있는
#: 인자 없는 옵션. 'NAME=값' 은 명령 처음(셸 대입)과 env 뒤에만 온다. 인자를 받는 실행기(nice -n N·ionice·taskset·chrt·timeout 시간·
#: chroot 디렉터리)는 보지 않는다 — 인자와 실행 파일을 가르려면 실행기마다 옵션 문법이 필요하다
_EXEC_WRAPPERS: dict[str, frozenset[str]] = {
    "nohup": frozenset({"--"}),
    "setsid": frozenset({"-c", "-f", "-w", "--ctty", "--fork", "--wait", "--"}),
    "env": frozenset({"-", "-i", "-0", "-v", "--ignore-environment", "--null", "--debug", "--"}),
    "command": frozenset({"-p", "--"}),  # 'command -v/-V 경로' 는 경로를 찾기만 한다
    "time": frozenset({"-p", "-v", "--portability", "--verbose", "--"}),
}
#: 셸 대입 낱말 'NAME=값': 값은 따옴표 밖 공백·명령 치환·리다이렉션·연산자 없이, 따옴표는 짝이 맞게 (따옴표 안 공백은 된다)
_ASSIGN_WORD_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=(?:[^\s'\"\\`()<>|;&]|\\.|'[^']*'|\"(?:[^\"\\]|\\.)*\")*")
_QUOTES_BALANCED_RX = re.compile(r"(?:[^'\"\\]|\\.|'[^']*'|\"(?:[^\"\\]|\\.)*\")*")
#: 경로 앞에서 건너는 투명 낱말 수와 낱말 하나(따옴표로 넓힌 것 포함)의 길이 상한 — 적대적인 긴 줄('A=1 A=1 …', 'nohup nohup …',
#: 아주 긴 낱말)에서도 경로마다 비용이 묶인다
_EXEC_CTX_HOPS = 16
_EXEC_CTX_TOKEN_MAX = 1024
#: start-stop-daemon 의 실행 파일 옵션: -x/--exec, -a/--startas, 인자 없는 옵션과 묶인 '-Sbx' 꼴. '--exec=경로'·'--startas=경로' 는 붙은 꼴
_SSD_NAME = "start-stop-daemon"
_SSD_OPT_RX = re.compile(r"-[SbqmovC]*[xa]|--exec|--startas")
_SSD_GLUED = ("--exec=", "--startas=")
#: 멈춤·상태·시험 동작(-K/--stop, -T/--status, -t/--test, 묶인 꼴 포함) — 이때 -x 경로는 실행되지 않는다.
#: 띄어 쓴 '--exec 경로' 는 예전(HEAD)처럼 exec 낱말 규칙(_exec_boundary)으로 먼저 실행 위치가 되므로 '--stop --exec 경로' 도 실행으로 본다.
#: 묶인 꼴은 앞보기로 K/T/t 가 있는지만 본 뒤 낱말을 한 번 훑는다 ('[A-Za-z]*[KTt][A-Za-z]*' 는 '-ttt…t1' 에서 낱말 길이의 제곱)
_SSD_STOP_RX = re.compile(r"(?<!\S)(?:--stop|--status|--test|-(?=[A-Za-z]*[KTt])[A-Za-z]+)(?!\S)")
#: 같은 명령의 -x/--exec — 있으면 -a/--startas 경로는 BusyBox 에서 argv[0] 일 뿐 실행 파일이 아니다
_SSD_EXEC_RX = re.compile(r"(?<!\S)(?:-[SbqmovC]*x|--exec)(?:=|(?!\S))")
#: 한 명령의 끝: 줄바꿈·; & |, 또는 '--' (그 뒤는 데몬 인자)
_SSD_CMD_END_RX = re.compile(r"[;&|\n]|(?<!\S)--(?!\S)")
#: start-stop-daemon 을 찾는 범위 (옵션 앞·경로 뒤로 각각, 같은 줄 안)
_SSD_WINDOW = 2048


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _exec_boundary(text: str, j: int) -> bool:
    """j(앞 공백을 건너뛴 자리) 바로 앞이 명령 시작인지: 줄 처음·;&|·then/do/exec/sh/ash/bash/source 낱말, 또는 source 의 '.'
    (예전 '(?:^|[;&|]|\\bthen\\b|…|^\\s*\\.|\\bsource\\b)\\s*경로' 판정을 이 자리에서)."""
    if j == 0 or text[j - 1] == "\n":
        return True
    c = text[j - 1]
    if c in ";&|":
        return True
    if c == ".":
        # '. 파일' 은 앞이 줄 처음·; & | ( ·then/do/else 일 때 source 다 ('[ -f x ] && . x', 'foo; . /usr/lib/x')
        k = j - 1
        while k > 0 and text[k - 1] != "\n" and text[k - 1].isspace():
            k -= 1
        if k == 0 or text[k - 1] == "\n" or text[k - 1] in ";&|(":
            return True
        for kw in ("then", "do", "else"):
            if text.endswith(kw, 0, k) and (k - len(kw) == 0 or not _is_word_char(text[k - len(kw) - 1])):
                return True
        return False
    for kw in _EXEC_CTX_WORDS:
        if text.endswith(kw, 0, j):
            b = j - len(kw)
            if b == 0 or not _is_word_char(text[b - 1]):
                return True
    return False


def _word_start(text: str, j: int) -> int:
    """text[j-1] 에서 끝나는 낱말(공백으로 나눔, 같은 줄 안)의 시작. 낱말이 _EXEC_CTX_TOKEN_MAX 자보다 길면 -1."""
    lo = j - _EXEC_CTX_TOKEN_MAX
    k = j
    while k > 0 and not text[k - 1].isspace():
        if k <= lo:
            return -1
        k -= 1
    return k


def _quoted_assign_start(text: str, j: int, k: int) -> int:
    """[k, j) 낱말의 따옴표 짝이 맞지 않으면 따옴표 안 공백에서 잘린 'NAME="a b"' 일 수 있다 — 같은 줄의 앞 낱말까지 넓혀
    (4번까지, 길이 _EXEC_CTX_TOKEN_MAX 안) 짝이 맞는 대입 낱말이 되면 그 시작, 아니면 -1."""
    lo = j - _EXEC_CTX_TOKEN_MAX
    for _ in range(4):
        i = k
        while i > 0 and text[i - 1] != "\n" and text[i - 1].isspace():
            if i <= lo:
                return -1
            i -= 1
        if i == 0 or text[i - 1] == "\n":
            return -1
        while i > 0 and not text[i - 1].isspace():
            if i <= lo:
                return -1
            i -= 1
        k = i
        if _QUOTES_BALANCED_RX.fullmatch(text, k, j):
            return k if _ASSIGN_WORD_RX.fullmatch(text, k, j) else -1
    return -1


def _ssd_exec_target(text: str, pos: int, opt_start: int, opt: str, memo: dict[int, bool] | None, shell: bool = True) -> bool:
    """opt_start 의 옵션 opt(-x·--exec·-a·--startas·'-Sbx' 꼴, 붙은 '--exec=' 은 '--exec')가 명령 자리의 start-stop-daemon 에
    딸린 실행 파일 인자인지 — 같은 줄에서 옵션 앞 _SSD_WINDOW 자 안의 마지막 start-stop-daemon 이고 사이에 ; & | -- 가 없어야 한다.
    같은 명령(경로 뒤 _SSD_WINDOW 자 안, ; & | -- 까지)에 -K/--stop·-T/--status·-t/--test 가 있으면 경로를 실행하지 않는다.
    -a/--startas 는 같은 명령에 -x/--exec 가 없을 때만 (BusyBox 는 -x 를 실행하고 -a 는 argv[0], 없으면 -a 를 실행).
    찾기·확인은 범위가 묶인 C 수준 검색이라 경로마다 비용이 일정하다."""
    lo = max(0, opt_start - _SSD_WINDOW)
    nl = text.rfind("\n", lo, opt_start)
    if nl >= 0:
        lo = nl + 1
    s = text.rfind(_SSD_NAME, lo, opt_start)
    if s < 0:
        return False
    se = s + len(_SSD_NAME)
    if not text[se].isspace():
        return False
    ts = _word_start(text, se)
    if ts < 0 or (ts != s and text[s - 1] != "/"):  # 'start-stop-daemon' 또는 '/sbin/start-stop-daemon' 낱말
        return False
    if _SSD_CMD_END_RX.search(text, se, opt_start):
        return False  # 다른 명령의 옵션
    end = min(len(text), pos + _SSD_WINDOW)
    m = _SSD_CMD_END_RX.search(text, pos, end)
    if m is not None:
        end = m.start()
    if _SSD_STOP_RX.search(text, se, end):
        return False
    if (opt == "--startas" or (not opt.startswith("--") and opt.endswith("a"))) and _SSD_EXEC_RX.search(text, se, end):
        return False
    return _exec_ctx_before(text, ts, memo, ssd=False, shell=shell)


def _exec_ctx_before(text: str, pos: int, memo: dict[int, bool] | None = None, *, ssd: bool = True, shell: bool = True) -> bool:
    """text[pos] 에서 시작하는 절대 경로가 실행 위치인지. 바로 앞(공백 건너뜀)이 명령 시작(_exec_boundary)이면 실행 위치다.
    아니면 바로 앞 낱말(공백으로 나눔, 같은 논리 줄)이 투명한 앞말일 때 그 낱말 시작이 실행 위치인지로 판정하며 거슬러 올라간다:
    셸 대입 'NAME=값'('LD_LIBRARY_PATH=/x \\' 다음 줄의 경로, 'FOO="a b" 경로'), 래퍼 nohup·setsid·env·command·time(basename 비교)과
    그 인자 없는 옵션('env -i A=1 경로', 'setsid -f 경로'). 'command -v 경로'·'echo nohup 경로'·'echo FOO=1 경로'·'nohup FOO=1 경로' 는
    실행 위치가 아니다. 이어진 줄 처음(물리 줄 처음)은 따로 실행 위치로 치지 않는다 ('cp \\'·'chmod +x \\'·'[ -f \\' 다음 줄의 경로는 인자).
    start-stop-daemon … -x|--exec|-a|--startas 경로와 '--exec=경로' 도 실행 위치다 (_ssd_exec_target).
    shell=False(셸 문법이 아닌 파일 — shell_syntax)면 대입·래퍼를 건너지 않는다: systemd 유닛의 'ExecStart=/usr/bin/app 경로' 는 'NAME=값'
    대입이 아니라 프로그램과 인자다.

    건너는 낱말은 _EXEC_CTX_HOPS 개, 낱말 하나는 _EXEC_CTX_TOKEN_MAX 자까지만 보고, 경로 꼴 래퍼('/usr/bin/nohup' 이 이어진 줄)는
    memo(같은 파일에서 앞서 판정한 경로 위치 → 결과)로 끊으므로 경로마다 비용이 묶인다. 줄을 복사하지 않고 공백을 덧대어 숨길 수도 없다."""
    j = pos
    if ssd and j > 0 and text[j - 1] == "=":
        for g in _SSD_GLUED:
            if text.endswith(g, 0, j) and (j - len(g) == 0 or text[j - len(g) - 1].isspace()):
                return _ssd_exec_target(text, pos, j - len(g), g[:-1], memo, shell)
    opts: list[str] = []  # 가장 가까운 래퍼(또는 경로)와 그 왼쪽 사이의 옵션들 (거꾸로 본 순서)
    assign = False  # 같은 구간에 대입 낱말이 있었는지
    hops = 0
    while True:
        e = j
        while j > 0 and text[j - 1] != "\n" and text[j - 1].isspace():
            j -= 1
        if _exec_boundary(text, j):
            return not opts  # 명령 처음: 앞말은 대입뿐이어야 한다 (래퍼 없는 옵션은 다른 명령의 인자)
        if j == e or hops >= _EXEC_CTX_HOPS:
            return False  # 앞 글자에 붙은 경로(따로 떨어진 낱말이 아님), 또는 건너기 상한
        k = _word_start(text, j)
        if k < 0:
            return False
        tok = text[k:j]
        if hops == 0 and ssd and _SSD_OPT_RX.fullmatch(tok):
            return _ssd_exec_target(text, pos, k, tok, memo, shell)
        if not shell:
            return False
        hops += 1
        if _ASSIGN_WORD_RX.fullmatch(tok):
            if opts:
                return False  # 'env A=1 -i 경로' 의 -i 는 프로그램 이름이다
            assign = True
        elif ("'" in tok or '"' in tok) and not _QUOTES_BALANCED_RX.fullmatch(tok):
            # 따옴표 짝이 안 맞는 낱말은 따옴표 안 공백에서 잘린 조각('OPTS="-a -b"' 의 '-b"') — 넓혀서 대입 낱말이 될 때만 투명하다
            if opts:
                return False
            k = _quoted_assign_start(text, j, k)
            if k < 0:
                return False
            assign = True
            j = k
            continue
        elif tok[0] == "-":
            opts.append(tok)
        else:
            name = tok.rsplit("/", 1)[-1]
            allowed = _EXEC_WRAPPERS.get(name)
            if allowed is None:
                return False
            if (assign and name != "env") or any(o not in allowed for o in opts):
                return False
            opts = []
            assign = False
            if memo is not None and k in memo:
                return memo[k]  # 이 래퍼 낱말은 앞서 판정한 경로('/usr/bin/nohup') — 그 결과가 곧 이 자리의 답이다
        j = k


#: 같은 파일의 같은 규칙 항목은 이만큼까지만 적고 나머지는 수만 센다 (summary.items_suppressed·limitations).
#: 예전에는 'login -f root' 줄 7만 개짜리 1 MB 스크립트와 그 심볼릭 링크들이 항목 수백만 개(GiB 단위 메모리·결과 파일)를 만들었다
ITEM_CAP_PER_RULE_FILE = 20

_CONT_BS_RX = re.compile(r"(?<!\\)((?:\\\\)*)\\\n")
#: 셸 파일에서 이어쓰기 후보인 줄: 줄 끝이 '\\'·'|'·'||'·'&&'(뒤에 공백만)이거나 연산자 바로 뒤에 주석('a | # 설명')이 오는 줄.
#: 후보마다 줄 끝 주석·here-document 를 확인한다
_CONT_END_RX = re.compile(r"(?:\\|\||&&)[ \t\r]*\n|(?:\||&&)[ \t]+#")
#: here-document 연산자와 구분자 낱말: 따옴표 밖 공백·;&|<>() 까지 한 셸 낱말 ('<<END-OF-BANNER'·'<<!'·'<<E"O"F'·'<<\\EOF'·"<<'EOF'").
#: 구분자는 따옴표·역슬래시를 벗긴 글자다 (_heredoc_word)
_HEREDOC_OP_RX = re.compile(r"<<(-?)[ \t]*((?:[^\s;&|<>()'\"\\]|\\.|'[^'\n]*'|\"(?:[^\"\\\n]|\\.)*\")+)")
#: 끝 구분자로 볼 줄의 길이 상한 (줄 색인에 넣는 줄)
_HEREDOC_TERM_MAX = 256

#: 셸 문법이 아닌 시작·설정 파일 — 줄 끝 '\\' 로만 줄을 잇는다 (BusyBox parse_config 의 inittab·inetd.conf·mdev.conf, udev 규칙,
#: systemd 유닛·설정, crontab). 이 파일들의 줄 끝 '|'·'&&' 는 다음 줄과 상관없다 ('::sysinit:/etc/init.d/rcS ||' 다음 줄의
#: '::respawn:-/bin/sh' 는 따로 실행되는 항목이다)
_NON_SHELL_NAMES = frozenset({"inittab", "inetd.conf", "xinetd.conf", "mdev.conf", "crontab"})
_NON_SHELL_DIRS = ("/xinetd.d/", "/crontabs/", "/cron.d/")
#: /systemd/ 아래에서 셸이 아닌 것은 INI 문법의 유닛·설정 파일(이 접미사)뿐이다 — 셰뱅 없는 도우미 스크립트('ExecStart=/bin/sh
#: /etc/systemd/system/camera-init')는 셸로 읽는다
_SYSTEMD_INI_SUFFIXES = (".service", ".socket", ".device", ".mount", ".automount", ".swap", ".target", ".path", ".timer", ".slice", ".scope",
                         ".conf", ".network", ".netdev", ".link", ".preset", ".nspawn", ".dnssd")


def shell_syntax(rel: str, head: str = "") -> bool:
    """rel 파일을 셸 문법으로 읽는지 (줄 끝 |·||·&& 이어쓰기, 명령 앞 대입·래퍼 건너뛰기를 적용할지). head 는 내용 앞부분
    ('#!' 로 시작하면 셸 스크립트)."""
    p = "/" + rel.lstrip("/")
    name = p.rsplit("/", 1)[-1]
    if head.startswith("#!") or name.endswith(".sh"):
        return True
    if name in _NON_SHELL_NAMES or (name.endswith(".rules") and "/udev/" in p):
        return False
    if "/systemd/" in p and name.endswith(_SYSTEMD_INI_SUFFIXES):
        return False
    return not any(d in p for d in _NON_SHELL_DIRS)


def _heredoc_word(w: str) -> str:
    """here-document 구분자 낱말의 따옴표·역슬래시를 벗긴다 ('E"O"F' → 'EOF', '\\EOF' → 'EOF'). _HEREDOC_OP_RX 가 짝을 맞춘 낱말만 받는다."""
    if "'" not in w and '"' not in w and "\\" not in w:
        return w
    out: list[str] = []
    i = 0
    n = len(w)
    while i < n:
        c = w[i]
        if c == "\\" and i + 1 < n:
            out.append(w[i + 1])
            i += 2
        elif c == "'":
            j = w.find("'", i + 1)
            if j < 0:
                j = n
            out.append(w[i + 1:j])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and w[j] != '"':
                if w[j] == "\\" and j + 1 < n and w[j + 1] in '"\\$`':
                    j += 1
                out.append(w[j])
                j += 1
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _heredoc_delims(line: str) -> list[tuple[str, bool]]:
    """셸 한 줄의 here-document 구분자들 [(구분자, '<<-' 인지)]. 따옴표 안·주석('#' 앞이 줄 처음·공백·;&|() — 셸의 낱말 시작)·'<<<'·
    $((…)) 안의 '<<' 는 아니다."""
    out: list[tuple[str, bool]] = []
    q = ""
    depth = 0
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if q:
            if c == q:
                q = ""
            elif c == "\\" and q == '"':
                i += 1
        elif c in "\"'":
            q = c
        elif c == "\\":
            i += 1
        elif c == "#" and (i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|()"):
            break
        elif c == "(" and line.startswith("((", i):
            depth += 1
            i += 1
        elif c == ")" and depth and line.startswith("))", i):
            depth -= 1
            i += 1
        elif c == "<" and not depth and line.startswith("<<", i):
            if line.startswith("<<<", i):
                i += 3
                continue
            m = _HEREDOC_OP_RX.match(line, i)
            if m is None:
                i += 2
                continue
            d = _heredoc_word(m.group(2))
            if d:
                out.append((d, bool(m.group(1))))
            i = m.end()
            continue
        i += 1
    return out


def _term_index(text: str) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    """끝 구분자 찾기용 줄 색인: (줄 그대로 → 그 줄 다음 위치들, 앞 탭을 뗀 줄('<<-') → 다음 위치들). _HEREDOC_TERM_MAX 자 이하의 줄만."""
    exact: dict[str, list[int]] = {}
    tabbed: dict[str, list[int]] = {}
    pos = 0
    for ln in text.split("\n"):
        nxt = pos + len(ln) + 1
        if len(ln) <= _HEREDOC_TERM_MAX + 1:
            key = ln[:-1] if ln.endswith("\r") else ln
            exact.setdefault(key, []).append(nxt)
            if key.startswith("\t"):
                tabbed.setdefault(key.lstrip("\t"), []).append(nxt)
        pos = nxt
    return exact, tabbed


def _heredoc_bodies(text: str) -> list[tuple[int, int]]:
    """here-document 본문 범위 [(시작 줄의 줄바꿈 위치, 끝 구분자 줄 다음 위치)] — 이 안에서는 줄을 잇지 않는다
    ('cat > /etc/inittab <<EOF' 처럼 셸 파일이 다른 문법의 파일 내용을 쓴다).

    끝 구분자 줄이 없으면 본문으로 보지 않는다: 셸은 파일 끝까지 본문으로 읽지만, 실제 스크립트에서는 대개 잘못 읽은 시작
    (여러 줄 문자열 안의 '<<낱말' 등)이라 뒤의 이어쓰기를 모두 끄면 그 뒤 명령을 놓친다 (예전 HEAD 처럼 잇는다).
    끝 구분자는 줄 색인(_term_index — here-document 가 있을 때 한 번 만듦)에서 찾으므로 시작이 많아도 선형이다."""
    out: list[tuple[int, int]] = []
    n = len(text)
    pos = 0
    index: tuple[dict[str, list[int]], dict[str, list[int]]] | None = None
    while True:
        i = text.find("<<", pos)
        if i < 0:
            return out
        ls = text.rfind("\n", 0, i) + 1
        le = text.find("\n", i)
        if le < 0:
            return out
        delims = _heredoc_delims(text[ls:le])
        if not delims:
            pos = le + 1
            continue
        if index is None:
            index = _term_index(text)
        b = le + 1
        for d, tabs in delims:
            nxt = -1
            for k, lst in enumerate(index):
                if k == 1 and not tabs:
                    break
                hit = lst.get(d)
                if hit:
                    j = bisect.bisect_right(hit, b)  # 줄 다음 위치 > b ⇔ 그 줄이 b 이후에 시작
                    if j < len(hit) and (nxt < 0 or hit[j] < nxt):
                        nxt = hit[j]
            if nxt < 0:
                break
            b = nxt
        else:
            end = min(b, n)
            out.append((le, end))
            pos = end
            continue
        pos = le + 1  # 끝 구분자 없음: 본문으로 보지 않는다


def _join_points(text: str, shell: bool) -> tuple[list[int], list[tuple[int, int]]]:
    """논리 줄로 이을 때 공백으로 바꿀 위치들(오름차순)과, 이은 쪽에서 지울 줄 끝 주석 범위들.

    - 줄 끝 '\\'(바로 앞의 '\\' 가 짝수 개): 그 '\\' 와 줄바꿈. 셸 파일에서 줄 끝 주석 안의 '\\' 는 잇지 않는다 (주석은 줄바꿈까지다).
    - 셸 파일만: 주석을 뗀 줄이 '|'·'||'·'&&' 로 끝나면 그 줄바꿈과, 뒤따르는 빈 줄·주석 줄의 줄바꿈 (POSIX linebreak — 셸도 한 명령으로 읽는다).
      그 줄의 끝 주석('a &&  # 설명')은 지울 범위로 돌려준다 — 남기면 이어 붙인 다음 줄이 주석 안으로 들어간다.
      줄 끝 주석 안의 연산자('echo x  # 1단계 ||')와 '\\|'·'\\&&'(글자 '|'·'&' — '\\&&' 는 글자 '&' 와 백그라운드 '&')는 잇지 않는다.
    - 셸 파일의 here-document 본문(시작 줄 포함)은 잇지 않는다.
    후보 줄 끝만 보고 줄마다 한 번씩만 훑으므로 선형이다."""
    blanks: list[tuple[int, int]] = []
    if not shell:
        if "\\\n" not in text:
            return [], blanks
        pts: list[int] = []
        for m in _CONT_BS_RX.finditer(text):
            pts.append(m.end() - 2)
            pts.append(m.end() - 1)
        return pts, blanks
    if "\\" not in text and "|" not in text and "&&" not in text:
        return [], blanks
    bodies = _heredoc_bodies(text) if "<<" in text else []
    bi = 0
    pts = []
    last = 0
    n = len(text)
    for m in _CONT_END_RX.finditer(text):
        if text[m.end() - 1] == "\n":
            nl = m.end() - 1
        else:
            if m.start() < last:
                continue  # 이미 본 줄 (줄마다 한 번만 줄 끝을 찾는다)
            nl = text.find("\n", m.end())
            if nl < 0:
                break
        if nl < last:
            continue
        last = nl + 1
        while bi < len(bodies) and bodies[bi][1] <= nl:
            bi += 1
        if bi < len(bodies) and bodies[bi][0] <= nl:
            continue
        ls = text.rfind("\n", 0, nl) + 1
        line = text[ls:nl]
        core = strip_sh_comment(line) if "#" in line else line
        commented = len(core) != len(line)
        if text[nl - 1] == "\\":
            if commented:
                continue
            k = nl - 1
            while k >= ls and text[k] == "\\":
                k -= 1
            if (nl - 1 - k) % 2 == 1:
                pts.append(nl - 1)
                pts.append(nl)
            continue
        c = core.rstrip(" \t\r")
        if not c.endswith(("|", "&&")):
            continue
        op = 1 if c[-1] == "|" else 2
        k = len(c) - op - 1
        while k >= 0 and c[k] == "\\":
            k -= 1
        if (len(c) - op - 1 - k) % 2 == 1:
            continue  # '\|' 는 글자 '|', '\&&' 는 글자 '&' 와 백그라운드 '&' 다
        if commented:
            blanks.append((ls + len(core), nl))
        pts.append(nl)
        j = nl + 1
        while j < n:
            e = text.find("\n", j)
            if e < 0:
                break
            s = text[j:e].strip(" \t\r")
            if s and not s.startswith("#"):
                break
            if s:
                blanks.append((j, e))  # 사이의 주석 줄 (주석 줄을 이미 지운 active 에서는 공백 그대로)
            pts.append(e)
            j = e + 1
        last = j
    return pts, blanks


def _apply_points(text: str, pts: list[int]) -> str:
    parts: list[str] = []
    prev = 0
    for p in pts:
        parts.append(text[prev:p])
        prev = p + 1
    parts.append(text[prev:])
    return " ".join(parts)


def _blank_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """오름차순 범위들을 같은 길이의 공백으로 (오프셋 보존)."""
    if not spans:
        return text
    parts: list[str] = []
    prev = 0
    for a, b in spans:
        parts.append(text[prev:a])
        parts.append(" " * (b - a))
        prev = b
    parts.append(text[prev:])
    return "".join(parts)


def logical_pair(active: str, text: str, *, shell: bool = True) -> tuple[str, str]:
    """주석 줄을 지운 본문(active)과 원문(text)을 같은 자리에서 이어 논리 줄로 만든다 (이을 자리는 active 에서 한 번 정하므로
    두 결과의 줄 경계가 같다 — 발췌는 text 쪽을 쓴다). shell=False 면 줄 끝 '\\' 만 잇는다 (shell_syntax 참고).
    연산자 뒤 주석으로 이은 줄('a &&  # 설명')의 그 주석은 active 쪽에서만 지운다 (text 쪽 발췌에는 남는다).

    길이·오프셋이 그대로라 원문 위치로 줄 번호(논리 줄의 첫 물리 줄)를 셀 수 있다. 이을 자리가 없으면 입력을 그대로 돌려준다."""
    pts, blanks = _join_points(active, shell)
    if not pts:
        return active, text
    return _apply_points(_blank_spans(active, blanks), pts), _apply_points(text, pts)


def logical_text(text: str, *, shell: bool = True) -> str:
    """text 하나를 논리 줄로 (logical_pair 의 active 쪽과 같은 규칙): 줄 끝 '\\', 셸 파일이면 줄 끝 '|'·'||'·'&&'(뒤따르는 빈 줄·주석 줄 포함,
    그 줄 끝 주석은 지움)."""
    pts, blanks = _join_points(text, shell)
    return _apply_points(_blank_spans(text, blanks), pts) if pts else text


_SHELL_RUNNERS = {"sh", "ash", "bash", "dash", "hush", "ksh", ".", "source"}


def _shell_run_before(text: str, pos: int) -> bool:
    """text[pos] 의 경로가 'sh 경로'·'. 경로'·'source 경로' 처럼 셸이 읽어 실행하는 파일인지 (셸 옵션 '-x' 등 3개까지 건너뜀, 같은 줄 안)."""
    j = pos
    for _ in range(4):
        while j > 0 and text[j - 1] != "\n" and text[j - 1].isspace():
            j -= 1
        k = j
        while k > 0 and j - k < 64 and not text[k - 1].isspace():
            k -= 1
        w = text[k:j]
        if not w:
            return False
        if w.startswith("-") and len(w) > 1:
            j = k
            continue
        return w.rsplit("/", 1)[-1] in _SHELL_RUNNERS
    return False


#: 시작 스크립트 큐 상한: 참조된 스크립트는 400개까지(예전과 같음), 실행 문맥(sh /x, ; /x, then /x …)으로 참조된 스크립트와
#: 핫플러그 처리기는 2000개까지 따라간다. 상한에 걸려 따라가지 못한 실행 참조는 '[시작 스크립트 검사 미완료]' 로 알린다
STARTUP_QUEUE_MAX = 400
STARTUP_QUEUE_EXEC_MAX = 2000
#: 시작 스크립트 한 개를 읽는 크기 상한 (넘으면 앞부분만 검사하고 '[시작 스크립트 검사 미완료]' 로 알린다)
STARTUP_FILE_MAX = 1 << 20
#: 시작 스크립트 전체에서 같은 규칙 항목은 이만큼까지만 적고 나머지는 수만 센다 (summary.items_suppressed, limitations 에 규칙과 수).
#: (규칙, 파일) 상한(ITEM_CAP_PER_RULE_FILE)만으로는 같은 내용의 시작 스크립트 2000개(큐 상한)가 파일마다 ~250개, 모두 49만 개
#: (1.9 GiB, 결과 파일 200 MiB)를 만들었다. 규칙마다 따로 세므로 한 규칙의 홍수가 다른 규칙의 항목을 밀어내지 않고, 전체는
#: 시작 스크립트 규칙 수(YAML text/any 휴리스틱 68 + 내장 9) × 500 ≈ 3.9만 개로 묶인다
STARTUP_ITEM_CAP_PER_RULE = 500
#: execve·mount 가 받는 경로 길이 상한 (Linux PATH_MAX). 더 긴 경로는 ENAMETOOLONG 으로 실행·마운트될 수 없다
PATH_MAX = 4096

# 자격증명 정규식 CRED_RX(비밀번호·PSK·URL 자격증명)·_QUOTED_CRED_RX(따옴표로 감싼 값)와 값이 아닌 낱말 _NON_VALUES 는
# 코어 pweh.safety.redact 에서 가져온다(파일 위 import — 에뮬레이터 콘솔 마스킹과 같은 정의, 결정 D2).


def mask_credentials(text: str) -> str:
    """줄 안의 자격증명 모양 값(CRED_RX: 비밀번호·PSK·URL 자격증명, 따옴표로 감싼 값 전체)을 mask_secret 으로 가린다.

    일치한 '위치'를 가린다 — 같은 값이 앞에 또 있어도(username=admin,password=admin) 비밀번호 자리를 가린다. 값이 경로·변수·자리표시면 그대로 둔다."""
    spans: list[tuple[int, int]] = []
    for rx in [_QUOTED_CRED_RX] + [r for _cid, r in CRED_RX]:
        for m in rx.finditer(text):
            val = m.group("val")
            if not val or val.lower() in _NON_VALUES or val.startswith(("$", "%", "`", "@", "{", "/")) or set(val) <= {"*", "x", "X", "#"}:
                continue
            spans.append(m.span("val"))
    if not spans:
        return text
    out: list[str] = []
    last = 0
    for a, b in sorted(spans):
        if a < last:  # 겹치는 일치(따옴표 규칙과 CRED_RX)는 앞의 것만
            continue
        out.append(text[last:a])
        out.append(mask_secret(text[a:b]) or "")
        last = b
    out.append(text[last:])
    return "".join(out)


CRED_EXT = {".conf", ".cfg", ".ini", ".xml", ".json", ".sh", ".txt", ".env", ".properties", ".yaml", ".yml", ".lua", ".dat", ".db", ".config", ".rc", ""}
CRED_DIR_PREFIXES = ("/etc/", "/usr/etc/", "/mnt/", "/home/", "/root/", "/var/", "/opt/", "/app", "/config", "/data", "/system/", "/program/", "/box/", "/usr/local/", "/usr/share/", "/www/", "/web/", "/usr/www/")

PEM_RX = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")
#: PEM 머리줄 바로 뒤의 본문: 줄바꿈(실제 CR/LF 또는 문자열 안의 '\n' 이스케이프), 선택적인 머리글 줄(Proc-Type·DEK-Info), base64 32자 이상.
#: mbedTLS 같은 라이브러리의 머리줄 상수는 본문 없이 NUL·END 상수가 이어지므로 개인키·인증서로 세지 않는다(cctv 팩 gen-private-key-pem 과 같은 기준).
_PEM_NL = rb"(?:\r?\n|(?:\\r)?\\n)"
PEM_BODY_RX = re.compile(_PEM_NL + rb"(?:[A-Za-z][A-Za-z-]*: [^\r\n\\]*" + _PEM_NL + rb")*" + _PEM_NL + rb"?[A-Za-z0-9+/]{32}")
BANNERS = [
    ("App-webs/", "hikvision"), ("Hikvision-Webs", "hikvision"), ("DNVRS-Webs", "hikvision"), ("uc-httpd 1.0.0", "xiongmai"),
    ("H264DVR rtspd 1.0", "xiongmai"), ("Welcome to HiLinux.", "hisilicon_video_encoder"), ("GoAhead-Webs", "generic"), ("mini_httpd/", "generic"),
]
PATH_HINTS = [("/mnt/mtd/Config", "dahua/xiongmai"), ("/program/bin/maintain", "uniview"), ("/system/www", "wificam"), ("/usr/bin/sonia", "dahua"), ("/box/box.ini", "hisilicon_video_encoder")]
_ABS_PATH_RX = re.compile(r"(?<![\w.\-/$])(/(?:[\w.+\-]+/)*[\w.+\-]+)")
#: 쓰기 가능한 영구·이동식 파일 시스템 (mount -t / fstab). auto 는 커널이 고르므로 SD·USB 의 vfat/exfat 일 수 있다
MOUNT_FS_ALT = r"jffs2|ubifs|yaffs2?|ext[234]|vfat|msdos|fat|exfat|ntfs3?|f2fs|auto|sdcardfs"
PERSISTENT_FS = {"jffs2", "ubifs", "yaffs", "yaffs2", "ext2", "ext3", "ext4", "vfat", "msdos", "fat", "ntfs", "ntfs3", "f2fs", "exfat", "auto", "sdcardfs"}
#: 읽기 전용 파일 시스템: /dev/mmcblk* 위에 있어도 쓰기 가능한 영구 저장소로 보지 않는다
READ_ONLY_FS = {"squashfs", "cramfs", "erofs", "romfs", "iso9660", "udf"}
_SEG_SPLIT_RX = re.compile(r"[;&|]")
_TOKEN_SPAN_RX = re.compile(r"\S+")
_MOUNT_WORD_RX = re.compile(r"\bmount\b")
_MOUNT_MP_RX = re.compile(r"/[\w./+${}-]*")
_REDIR_TOKEN_RX = re.compile(r"^[0-9]?>")
_FS_NAME_RX = re.compile(r"\w+")


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[1:-1]
    return tok


def strip_sh_comment(line: str) -> str:
    """셸 줄 끝의 주석('#' 앞이 줄 처음이나 공백이고 따옴표 밖) 을 떼어 낸다 (한 번 훑기)."""
    if "#" not in line:
        return line
    q = ""
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if q:
            if c == q:
                q = ""
            elif c == "\\" and q == '"':
                i += 1
        elif c in "\"'":
            q = c
        elif c == "\\":
            i += 1
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


def iter_mount_commands(line: str) -> list[dict[str, Any]]:
    """한 줄의 쓰기 가능 mount 명령들 — 토큰을 한 번 훑는다 (정규식 되돌아가기 없음, 긴 줄도 자르거나 건너뛰지 않음).

    판정 (예전 mount 정규식과 같은 뜻을 넓힌 것): ;&| 로 나눈 명령 조각에서 'mount' 낱말 뒤에 쓰기 가능한 -t <fs>/-t<fs>
    (PERSISTENT_FS, fs 이름은 앞의 낱말 부분) 나 '-t' 없는 /dev/mmcblk* 장치가 있고, 조각 끝(또는 2>/dev/null 같은 리다이렉션)
    바로 앞 토큰이 그 뒤에 오는 절대 경로면 그것이 마운트 지점이다 ($MDEV 같은 변수 허용, 따옴표 벗김).
    -o ro… / -oro / -r / --read-only 는 건너뛰고, /dev/mmcblk 장치인데 같은 명령의 -t 가 쓰기 가능 fs 가 아니면(squashfs 등) 건너뛴다.
    반환: [{fs, device, mount_point, start}] (start = 줄 안의 mount 낱말 위치)."""
    out: list[dict[str, Any]] = []
    line = strip_sh_comment(line)  # 'mount … /mnt/mtd  # 주석' 의 주석 낱말을 마운트 지점으로 보지 않는다
    a = 0
    bounds = [m.start() for m in _SEG_SPLIT_RX.finditer(line)] + [len(line)]
    for b in bounds:
        seg_start, a = a, b + 1
        seg = line[seg_start:b]
        if "mount" not in seg:
            continue
        toks = [(seg_start + m.start(), m.group(0)) for m in _TOKEN_SPAN_RX.finditer(seg)]
        st: dict[str, Any] = {}

        def reset() -> None:
            st.clear()
            st.update(mount=None, fs=None, dev=None, alt_idx=None, ro=False, other_fs=False, pending_t=False, pending_o=False)

        def finish(last_idx: int) -> None:
            # last_idx = 마운트 지점 후보 토큰 (리다이렉션·조각 끝 바로 앞)
            if st["mount"] is None or st["alt_idx"] is None or last_idx <= st["alt_idx"] or st["ro"]:
                return
            mp = _unquote(toks[last_idx][1])
            if not _MOUNT_MP_RX.fullmatch(mp):
                return
            if st["fs"] is None and st["other_fs"]:
                return  # /dev/mmcblk 이지만 -t 가 squashfs 같은 쓰기 불가 fs
            out.append({"fs": st["fs"], "device": st["dev"], "mount_point": mp, "start": st["mount"]})

        reset()
        for idx, (pos, t) in enumerate(toks):
            if st["mount"] is None:
                if _MOUNT_WORD_RX.search(t):
                    st["mount"] = pos
                continue
            if _REDIR_TOKEN_RX.match(t):
                finish(idx - 1)
                reset()
                continue
            if st["pending_t"] or (t.startswith("-t") and not t.startswith("--") and len(t) > 2):
                val = _unquote(t if st["pending_t"] else t[2:])
                st["pending_t"] = False
                fm = _FS_NAME_RX.match(val)
                fs = fm.group(0) if fm else ""
                if fs in PERSISTENT_FS:
                    if st["fs"] is None:
                        st["fs"] = fs
                        if st["alt_idx"] is None:
                            st["alt_idx"] = idx
                else:
                    st["other_fs"] = True
                continue
            if st["pending_o"] or (t.startswith("-o") and len(t) > 2):
                opts = _unquote(t if st["pending_o"] else t[2:]).split(",")
                st["pending_o"] = False
                if "ro" in opts:
                    st["ro"] = True
                continue
            if t == "-t":
                st["pending_t"] = True
            elif t == "-o":
                st["pending_o"] = True
            elif t in ("-r", "--read-only"):
                st["ro"] = True
            elif _unquote(t).startswith("/dev/mmcblk") and st["dev"] is None:
                st["dev"] = _unquote(t)
                if st["alt_idx"] is None:
                    st["alt_idx"] = idx
        finish(len(toks) - 1)
    return out


# ---------------------------------------------------------------------------
# 핫플러그 설정 해석 (mdev.conf / udev 규칙) — 시작 스크립트 큐와 sdsurface 가 함께 쓴다
# ---------------------------------------------------------------------------

_MDEV_REST_RX = re.compile(r"^(?:(?P<move>[=>]\S*|!)\s*)?(?:(?P<act>[@$*])\s*(?P<cmd>.*))?$")
_MDEV_ACTIONS = {"@": "add", "$": "remove", "*": "both"}
_UDEV_PAIR_RX = re.compile(r"(?P<key>[A-Za-z_]{1,64}(?:\{[^}\"\n]{0,64}\})?)\s{0,8}(?P<op>==|!=|\+=|-=|:=|=)\s{0,8}\"(?P<val>[^\"\n]{0,4096})\"")
#: udev 규칙 한 개(이어쓰기 포함)를 해석할 때의 상한
UDEV_MAX_CONTINUATION = 64
UDEV_MAX_RULE_CHARS = 16384


def parse_mdev_conf(text: str) -> list[dict[str, Any]]:
    """BusyBox mdev.conf 규칙: '[-][ENV=re;]<장치 정규식> uid:gid 권한 [=경로|>경로|!] [@|$|*명령]'.

    반환: [{line, matcher, device_regex, env, action(add/remove/both/None), command}]. 형식이 맞지 않는 줄은 건너뛴다."""
    out: list[dict[str, Any]] = []
    for ln, raw in enumerate(text.split("\n"), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split(None, 3)
        if len(f) < 3 or ":" not in f[1] or not re.fullmatch(r"[0-7]{3,4}", f[2]):
            continue
        rest = f[3].strip() if len(f) > 3 else ""
        m = _MDEV_REST_RX.match(rest)
        act = cmd = None
        if m and m.group("act"):
            act = _MDEV_ACTIONS[m.group("act")]
            cmd = (m.group("cmd") or "").strip() or None
        matcher = f[0].lstrip("-")
        parts = matcher.split(";")
        out.append({"line": ln, "matcher": f[0], "device_regex": parts[-1], "env": parts[:-1], "action": act, "command": cmd, "text": s})
    return out


def parse_udev_rules(text: str) -> list[dict[str, Any]]:
    """udev 규칙(줄 이어쓰기 '\\' 처리): 일치 키(KERNEL/SUBSYSTEM/ACTION/ENV{..}...)와 실행 키(RUN/PROGRAM/IMPORT{program}).

    반환: [{line, match{키: 값}, run[명령], run_kinds[RUN/PROGRAM/IMPORT — run 과 같은 순서], text}] — 실행 키나 일치 키가 하나도 없는 줄은 건너뛴다."""
    out: list[dict[str, Any]] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        start = i
        parts = [lines[i]]
        while parts[-1].endswith("\\") and i + 1 < len(lines) and len(parts) < UDEV_MAX_CONTINUATION:
            parts[-1] = parts[-1][:-1]
            i += 1
            parts.append(lines[i])
        i += 1
        t = " ".join(parts).strip()[:UDEV_MAX_RULE_CHARS]
        if not t or t.startswith("#"):
            continue
        match: dict[str, str] = {}
        run: list[str] = []
        run_kinds: list[str] = []
        for m in _UDEV_PAIR_RX.finditer(t):
            key, op, val = m.group("key"), m.group("op"), m.group("val")
            ku = key.upper()
            if ku.startswith(("RUN", "PROGRAM")) or ku == "IMPORT{PROGRAM}":
                if op in ("=", "+=", ":=", "=="):
                    run.append(val)
                    run_kinds.append("RUN" if ku.startswith("RUN") else ("PROGRAM" if ku.startswith("PROGRAM") else "IMPORT"))
            elif op in ("==", "!="):
                match[key] = ("!" if op == "!=" else "") + val
        if match or run:
            out.append({"line": start + 1, "match": match, "run": run, "run_kinds": run_kinds, "text": t})
    return out


def command_program(cmd: str) -> str | None:
    """명령 문자열의 실제 프로그램 (첫 토큰, 'sh /x.sh' 면 스크립트). 따옴표·인자는 버린다."""
    toks = [t.strip("'\"") for t in cmd.split()]
    toks = [t for t in toks if t]
    i = 0
    while i < len(toks) and "=" in toks[i] and not toks[i].startswith("/"):
        i += 1  # VAR=값 접두
    if i < len(toks) and toks[i].rsplit("/", 1)[-1] in _SHELLS:
        i += 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 1
        if i < len(toks) and toks[i] in ("sh", "ash"):
            i += 1  # busybox sh x
    return toks[i] if i < len(toks) else None


def resolve_program(root: Path, prog: str | None, search_dirs: tuple[str, ...]) -> str | None:
    """명령 프로그램을 rootfs 안의 경로로 (절대 경로는 그대로, 상대 이름은 search_dirs 에서). 심볼릭 링크는 rootfs 안에서만."""
    if not prog or prog.startswith("$") or "%" in prog:
        return None
    if prog.startswith("/"):
        return resolve_in_root(root, prog)
    if "/" in prog:
        return None
    for d in search_dirs:
        r = resolve_in_root(root, f"{d}/{prog}")
        if r is not None:
            return r
    return None


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
        self._item_counts: dict[tuple[str, str], int] = {}  # (규칙, 파일) → 본 항목 수 (상한을 넘어 버린 것 포함)
        self.items_suppressed = 0
        self.limitations: list[str] = []
        self.entries: list[Entry] = []
        self.by_rel: dict[str, Entry] = {}
        self.entry_counts: dict[str, int] = {}
        self.walk_truncated = False
        self._walked = False
        #: 시작 스크립트 검사를 끝까지 했는지 (시간 예산·큐 상한·크기 상한에 걸리면 False, limitations 에 '[시작 스크립트 검사 미완료]')
        self.startup_scan_complete = True

    # -- 공통 ---------------------------------------------------------------
    def add(self, hid: str, category: str, severity: str, title: str, *, file: str | None = None, line: int | None = None,
            excerpt: str | None = None, rationale: str | None = None, references: list[str] | None = None, extra: dict[str, Any] | None = None) -> bool:
        """항목을 적는다. 적었으면 True (같은 항목이 이미 있거나 (규칙, 파일) 상한에 걸려 세기만 했으면 False)."""
        key = (hid, file, line, excerpt if line is None else None)
        if key in self._item_keys:
            return False
        if file is not None:
            ck = (hid, file)
            n = self._item_counts.get(ck, 0)
            self._item_counts[ck] = n + 1
            if n >= ITEM_CAP_PER_RULE_FILE:
                self.items_suppressed += 1  # 같은 파일의 같은 규칙은 상한까지만 적는다 (키도 기억하지 않아 메모리가 묶인다)
                return False
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
        return True

    def over_cap(self, hid: str, file: str) -> bool:
        """(규칙, 파일) 항목이 이미 상한만큼 있으면 True 이고 버린 항목으로 센다 — 발췌·마스킹을 만들기 전에 부른다."""
        ck = (hid, file)
        n = self._item_counts.get(ck, 0)
        if n < ITEM_CAP_PER_RULE_FILE:
            return False
        self._item_counts[ck] = n + 1
        self.items_suppressed += 1
        return True

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
    def walk(self) -> dict[str, int]:
        """트리를 한 번 순회해 entries/by_rel 을 채운다 (심볼릭 링크는 따라가지 않음). 두 번째 호출부터는 그대로 돌려준다.

        run() 과 sdsurface(fw_sd_surface: 순회 + 시작 스크립트 + 웹만, 계정·해시 대조 없음)가 함께 쓴다."""
        if self._walked:
            return self.entry_counts
        counts: dict[str, int] = {}
        for e in walk_tree(self.root, self.ctl, max_entries=self.max_entries):
            self.entries.append(e)
            self.by_rel[e.rel] = e
            counts[e.kind] = counts.get(e.kind, 0) + 1
        if len(self.entries) >= self.max_entries:
            self.walk_truncated = True
            self.limitations.append(f"항목이 {self.max_entries}개를 넘어 이후는 검사하지 않았습니다.")
        if self.manifest is None:
            self.limitations.append(
                "squashfs 매니페스트가 없어 디스크의 모드/소유자를 사용합니다. 비root 로 추출된 트리는 setuid 비트와 소유자 정보가 원본과 다를 수 있습니다 "
                "(fw_extract_squashfs 로 추출하면 매니페스트가 함께 생성됩니다)."
            )
        self.entry_counts = counts
        self._walked = True
        return counts

    def run(self) -> dict[str, Any]:
        t0 = time.monotonic()
        counts = self.walk()
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
        # (규칙, 파일) 상한으로 센 수만 (시작 스크립트 전체 규칙 상한으로 센 수는 audit_startup 이 따로 적는다; summary.items_suppressed 는 둘의 합)
        per_file = [(n - ITEM_CAP_PER_RULE_FILE, hid, f) for (hid, f), n in self._item_counts.items() if n > ITEM_CAP_PER_RULE_FILE]
        if per_file:
            over = sorted(per_file, reverse=True)[:5]
            self.limitations.append(f"항목 상한(같은 파일의 같은 규칙은 {ITEM_CAP_PER_RULE_FILE}개)에 걸려 {sum(x[0] for x in per_file)}개 항목은 적지 않고 수만 셌습니다: "
                                    + ", ".join(f"{hid} {f} +{n}" for n, hid, f in over))
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
                "startup_scan_complete": self.startup_scan_complete,
                "items_suppressed": self.items_suppressed,
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
        # 쓰기 가능 접두: 문자열 집합(중복 확인)과 '성분 사슬 해시 → 접두 문자열' (in_writable 이 경로를 앞에서부터 한 번만 훑게).
        # 사슬 해시는 '/' 로 나눈 성분마다 hash((앞 성분까지의 해시, 성분)) — 접두마다 잘라 해시하던 깊이 D 경로의 D² 비용이 없고,
        # 접두 하나에 해시 하나만 더 두므로 (성분마다 사전을 두는 트라이와 달리) 깊은 마운트 지점이 메모리를 불리지 않는다
        writable: set[str] = set()
        wkeys: dict[int, list[str]] = {}
        wdepth = [0]  # 접두의 최대 성분 수 (경로는 이만큼까지만 본다)

        def add_writable(w: str) -> None:
            w = w.rstrip("/")
            # PATH_MAX 보다 긴 마운트 지점은 mount 가 받지 못하고, 그 아래 경로도 execve 로 실행될 수 없다 — 쓰기 가능 접두로 두지 않는다
            if not w or len(w) > PATH_MAX or w in writable:
                return
            writable.add(w)
            h = 0
            comps = w.split("/")
            for c in comps:
                h = hash((h, c))
            wkeys.setdefault(h, []).append(w)
            wdepth[0] = max(wdepth[0], len(comps))

        def in_writable(pth: str) -> bool:
            """pth 가 쓰기 가능 접두와 같거나 그 아래('/' 경계)인지. 성분마다 사슬 해시를 이어 계산하고 해시가 같은 접두만 문자열로
            확인하므로 경로 길이에 선형이다 (접두의 최대 성분 수까지만 본다).
            execve 는 PATH_MAX(4096)보다 긴 경로를 실행하지 못하므로(ENAMETOOLONG) 그런 경로는 실행 파일로 보지 않고 건너뛴다."""
            n = len(pth)
            if n > PATH_MAX:
                return False
            h = 0
            i = 0
            for _ in range(wdepth[0]):
                k = pth.find("/", i)
                end = n if k < 0 else k
                h = hash((h, pth[i:end]))
                for w in wkeys.get(h, ()):
                    if len(w) == end and pth.startswith(w):
                        return True
                if k < 0:
                    break
                i = k + 1
            return False

        for w in self.persistent_paths:
            add_writable(w)
        for cp in (self.profile.get("firmware") or {}).get("config_paths") or []:
            if isinstance(cp, str) and cp.startswith("/"):
                add_writable(cp)
        # fstab (쓰기 가능한 fs, 또는 fs 와 상관없이 /dev/mmcblk* 장치 — SD·eMMC)
        data, _ = self.read("/etc/fstab", 1 << 16)
        if data:
            for ln, line in enumerate(data.decode("latin-1").split("\n"), 1):
                f = line.split()
                if len(f) >= 3 and not f[0].startswith("#"):
                    fs = f[2]
                    opts = f[3] if len(f) > 3 else "defaults"
                    mmc = f[0].startswith("/dev/mmcblk") and f[1].startswith("/") and fs not in READ_ONLY_FS
                    if (fs in PERSISTENT_FS or mmc) and "ro" not in opts.split(","):
                        mounts.append({"source": "fstab", "file": "/etc/fstab", "line": ln, "device": f[0], "mount_point": f[1], "fs": fs, "options": opts})
                        add_writable(f[1])

        script_cache: dict[tuple[str, bool], str | None] = {}
        resolve_cache: dict[str, str | None] = {}
        overflow_exec: set[str] = set()
        overflow_ref: set[str] = set()
        truncated_files: list[str] = []
        timed_out_startup = False
        processed: set[str] = set()  # 읽은 최종 파일 (같은 파일을 가리키는 심볼릭 링크는 한 번만 읽는다)
        processed_ino: set[tuple[int, int]] = set()  # 읽은 파일의 (st_dev, st_ino) — 하드 링크도 한 번만 (content_pass 와 같은 기준)
        mount_keys = {(mt["mount_point"], mt["fs"]) for mt in mounts}
        rule_total: dict[str, int] = {}  # 규칙 → 시작 스크립트 전체에서 적은 항목 수
        rule_over: dict[str, int] = {}  # 규칙 → 시작 스크립트 전체 상한(STARTUP_ITEM_CAP_PER_RULE)에 걸려 세기만 한 항목 수

        def capped(hid: str, file: str) -> bool:
            """(규칙, 파일) 상한 또는 시작 스크립트 전체의 규칙 상한에 걸리면 True (버린 항목으로 센다) — 발췌를 만들기 전에 부른다."""
            if self.over_cap(hid, file):
                return True
            if rule_total.get(hid, 0) < STARTUP_ITEM_CAP_PER_RULE:
                return False
            rule_over[hid] = rule_over.get(hid, 0) + 1
            self.items_suppressed += 1
            return True

        def record(hid: str, category: str, severity: str, title: str, **kw: Any) -> None:
            if self.add(hid, category, severity, title, **kw):
                rule_total[hid] = rule_total.get(hid, 0) + 1

        def resolved(pth: str) -> str | None:
            if pth in resolve_cache:
                return resolve_cache[pth]
            r = resolve_in_root(self.root, pth)
            if len(resolve_cache) < 100000:
                resolve_cache[pth] = r
            return r

        def script_target(pth: str, textual: bool = False) -> str | None:
            """참조 경로가 따라갈 스크립트면 rootfs 안 최종 경로 (rootfs 안에서만 링크 해석, 셰뱅이 있거나 .sh 인 일반 파일).
            textual: 핫플러그 처리기·'sh 경로'·'. 경로' 처럼 셸이 읽는 파일 — 셰뱅이 없어도 텍스트 파일이면 따라간다. 경로별로 한 번만 확인."""
            key = (pth, textual)
            if key in script_cache:
                return script_cache[key]
            res = None
            final_p = resolved(pth)
            ent = self.by_rel.get(final_p) if final_p else None
            if ent and final_p and ent.kind == "file":
                if final_p.endswith(".sh") or "init.d" in final_p or "/rc" in final_p or ent.st.st_size < 65536:
                    head, _ = self.read(final_p, 64)
                    if head and (head.startswith(b"#!") or final_p.endswith(".sh")):
                        res = final_p
                if res is None and textual and 0 < ent.st.st_size <= STARTUP_FILE_MAX:
                    head, _ = self.read(final_p, 4096)
                    if head and not head.startswith(b"\x7fELF") and is_text(head):
                        res = final_p
            if len(script_cache) < 100000:
                script_cache[key] = res
            return res

        def enqueue(pth: str | None, exec_ctx: bool = False, textual: bool = False) -> None:
            """참조된 스크립트를 큐에 넣는다. 일반 참조는 STARTUP_QUEUE_MAX, 실행 문맥 참조·핫플러그 처리기는 STARTUP_QUEUE_EXEC_MAX 까지.
            상한에 걸려 넣지 못한 스크립트는 세어 두었다가 limitations 에 적는다 (조용히 버리지 않는다)."""
            if not pth:
                return
            final_p = script_target(pth, textual)
            if not final_p or final_p in seen:
                return
            if len(queue) < STARTUP_QUEUE_MAX or (exec_ctx and len(queue) < STARTUP_QUEUE_EXEC_MAX):
                seen.add(final_p)
                queue.append(final_p)
                overflow_exec.discard(final_p)
                overflow_ref.discard(final_p)
            elif exec_ctx:
                if len(overflow_exec) < 10000:
                    overflow_exec.add(final_p)
            elif len(overflow_ref) < 10000:
                overflow_ref.add(final_p)

        rule_lits = {hid: _rule_literals(rule) for hid, rule, *_ in EXTRA_CHECKS}
        svc_lits = {svc: _rule_literals(rule) for svc, rule, _ in SERVICE_RULES}
        while idx < len(queue) and idx < STARTUP_QUEUE_EXEC_MAX:
            if self.ctl.expired():
                timed_out_startup = True
                break
            rel = queue[idx]
            idx += 1
            final0 = resolved(rel)
            if final0 is not None:
                if final0 in processed:
                    continue  # 같은 파일을 가리키는 다른 이름(심볼릭 링크) — 이미 검사했다
                processed.add(final0)
                ent0 = self.by_rel.get(final0)
                if ent0 is not None and ent0.kind == "file" and ent0.st.st_ino:
                    ino = (ent0.st.st_dev, ent0.st.st_ino)
                    if ino in processed_ino:
                        continue  # 이미 검사한 파일의 하드 링크
                    processed_ino.add(ino)
            data, final = self.read(rel, STARTUP_FILE_MAX)
            if data is None or not is_text(data[:4096]):
                continue
            ent_f = self.by_rel.get(final) if final else None
            if len(data) >= STARTUP_FILE_MAX and ent_f is not None and ent_f.st.st_size > STARTUP_FILE_MAX:
                truncated_files.append(rel)
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
            # 규칙은 논리 줄(이어쓰기 '\\', 셸 파일이면 줄 끝 |·||·&& 로 이어진 줄)에 적용한다. 길이가 같아 위치·줄 번호(첫 물리 줄)는 원문 그대로.
            # inittab·inetd.conf·udev 규칙·systemd 유닛 같은 셸이 아닌 파일은 줄 끝 '\\' 로만 잇고 경로 앞의 대입·래퍼를 건너지 않는다.
            # ltext 는 발췌용 원문 (같은 자리에서 이음)
            sh_syntax = shell_syntax(rel, text[:2])
            logical, ltext = logical_pair(active, text, shell=sh_syntax)
            lines = _LineIndex(logical)
            phys = _LineIndex(active)

            def excerpt_at(ls: int, le: int) -> str:
                # 발췌는 240자로 잘리므로 앞 2048자만 마스킹한다 (긴 줄 전체를 복사·마스킹하지 않음)
                return mask_credentials(ltext[ls:min(le, ls + 2048)].replace("\n", " ").strip())

            # 1차: 규칙마다 그 규칙의 필수 리터럴이 있는 논리 줄에만 적용한다 (줄을 자르거나 규칙을 건너뛰지 않는다).
            # 내장 규칙은 _Chain/_WordRule(선형), YAML 패턴은 줄 단위 판정기(최상위 무제한 간격은 _GapChain), mount 는 토큰 순회.
            # YAML text/any 휴리스틱: 파일마다 첫 일치 한 줄 (예전과 같음)
            for h in text_heur:
                if self.ctl.expired():
                    timed_out_startup = True
                    break
                if not h.prefilter(logical, lines.low):
                    continue
                matcher = yaml_line_matcher(h)
                for ls, le in lines.candidates(h.literals, h.ignorecase):
                    if matcher.search(logical, ls, le):
                        ln = phys.line_no(ls)
                        if not capped(h.id, rel):
                            record(h.id, h.category, h.severity, f"{h.id}: {rel}:{ln}", file=rel, line=ln, excerpt=excerpt_at(ls, le), rationale=h.rationale,
                                   references=h.references)
                        break
            if timed_out_startup:
                break
            # 내장 규칙: 맞는 논리 줄마다 (같은 파일의 같은 규칙은 ITEM_CAP_PER_RULE_FILE 개, 시작 스크립트 전체의 같은 규칙은
            # STARTUP_ITEM_CAP_PER_RULE 개까지 적고 나머지는 센다)
            for hid, rule, category, sev, title, rationale in EXTRA_CHECKS:
                lits, ic = rule_lits[hid]
                for ls, le in lines.candidates(lits, ic):
                    if rule.search(logical, ls, le):
                        ln = phys.line_no(ls)
                        if (hid, rel, ln, None) in self._item_keys or capped(hid, rel):
                            continue
                        excerpt = ltext[ls:min(le, ls + 2048)].replace("\n", " ").strip()
                        if hid == "builtin-chpasswd-literal":
                            excerpt = re.sub(r"(:)([^\s\"'|]+)", lambda mm: mm.group(1) + (mask_secret(mm.group(2)) or ""), excerpt, count=1)
                        record(hid, category, sev, f"{title} ({rel}:{ln})", file=rel, line=ln, excerpt=excerpt, rationale=rationale)
            # 서비스: 규칙마다 파일의 첫 논리 줄 (예전과 같음)
            for svc, rule, label in SERVICE_RULES:
                lits, ic = svc_lits[svc]
                for ls, le in lines.candidates(lits, ic):
                    sm = rule.search(logical, ls, le)
                    if sm:
                        ln = phys.line_no(ls)
                        # 실행 파일 경로는 규칙이 맞은 자리 둘레에서만 찾는다 (줄 앞 덧대기와 상관없이, '////' 홍수에서도 비용이 묶인다)
                        seg = logical[max(ls, sm.start() - 300):min(le, sm.end() + 80)]
                        binm = re.search(r"(/[\w./+-]{0,256}" + re.escape(svc.split("-")[0]) + r"[\w.+-]{0,64})", seg)
                        services.append({"service": svc, "label": label, "file": rel, "line": ln, "command": clip(excerpt_at(ls, le), 200), "binary": binm.group(1) if binm else None})
                        break
            # mount 명령 (-o ro·-r·--read-only 와 읽기 전용 fs 는 쓰기 저장소가 아니다). 같은 (마운트 지점, fs) 는 처음 것만
            for ls, le in lines.candidates(["mount"]):
                for mc in iter_mount_commands(logical[ls:le]):
                    add_writable(mc["mount_point"])
                    mk = (mc["mount_point"], mc["fs"])
                    if mk in mount_keys:
                        continue
                    mount_keys.add(mk)
                    mt: dict[str, Any] = {"source": "script", "file": rel, "line": phys.line_no(ls), "mount_point": mc["mount_point"], "fs": mc["fs"],
                                          "command": clip(excerpt_at(ls, le), 200)}
                    if mc["device"]:
                        mt["device"] = mc["device"]
                    mounts.append(mt)
            # 2차: 참조 스크립트 / 쓰기 가능한 저장소 실행 (같은 파일의 mount 를 다 본 뒤). 파일 전체의 경로 일치를 흘려 보며
            # 일치마다 줄을 복사하지 않고, 일치 수 상한도 없다 (경로별 확인은 캐시, 시간 예산은 1024 일치마다)
            wcache: dict[str, bool] = {}
            ctx_memo: dict[int, bool] = {}  # 경로 위치 → 실행 문맥 (경로 꼴 래퍼 '/usr/bin/nohup …' 사슬을 _exec_ctx_before 가 끊는 데 쓴다)
            for k, m in enumerate(_ABS_PATH_RX.finditer(logical)):
                if (k & 0x3FF) == 0x3FF and self.ctl.expired():
                    timed_out_startup = True
                    break
                p = m.group(1)
                if len(p) < 3 or p.startswith(("/dev/", "/proc/", "/sys/")):
                    continue
                exec_ctx = _exec_ctx_before(logical, m.start(), ctx_memo, shell=sh_syntax)
                if len(ctx_memo) >= 1024:
                    ctx_memo.clear()  # 거슬러 보는 범위는 경로마다 낱말 몇 개뿐이라 최근 것만 있으면 된다
                ctx_memo[m.start()] = exec_ctx
                if exec_ctx:
                    w_ok = wcache.get(p)
                    if w_ok is None:
                        w_ok = in_writable(p)
                        if len(wcache) < 100000:
                            wcache[p] = w_ok
                    if w_ok:
                        ls, le = lines.span(m.start())
                        ln = phys.line_no(ls)
                        hid = "builtin-exec-from-writable-storage"
                        if (hid, rel, ln, None) not in self._item_keys and not capped(hid, rel):
                            record(hid, "insecure-default", "medium",
                                   f"부팅 스크립트가 쓰기 가능한 영구 저장소의 파일을 실행: {p} ({rel}:{ln})", file=rel, line=ln, excerpt=excerpt_at(ls, le),
                                   rationale="설정 파티션(jffs2 등)은 런타임에 쓰기 가능하다. 여기에 있는 스크립트/바이너리를 부팅 때 실행하면 지속성(persistence)·무결성 우회 경로가 된다.",
                                   extra={"target": p, "present_in_image": resolved(p) in self.by_rel})
                enqueue(p, exec_ctx, textual=exec_ctx and _shell_run_before(logical, m.start()))
            if timed_out_startup:
                break
            # 핫플러그 처리기 따라가기: mdev.conf 의 @/$/* 명령('$' 는 위 경로 정규식이 놓친다), udev 의 RUN+=/PROGRAM/IMPORT{program}
            # (상대 이름은 udev 규칙대로 /lib/udev, /usr/lib/udev 에서 찾는다). 처리기는 실행되므로 실행 문맥 참조로 세고, 셰뱅이 없어도
            # 텍스트면 따라간다 (mdev 는 system(), udev 는 sh -c 로 부르므로 ENOEXEC 대체로 셸이 읽는다)
            if name == "mdev.conf":
                for rule in parse_mdev_conf(active):
                    if rule["command"]:
                        enqueue(resolve_program(self.root, command_program(rule["command"]), MDEV_CMD_DIRS), True, textual=True)
            elif "/udev/" in rel and name.endswith(".rules"):
                for rule in parse_udev_rules(active):
                    for cmd in rule["run"]:
                        enqueue(resolve_program(self.root, command_program(cmd), UDEV_CMD_DIRS), True, textual=True)
        unprocessed = len(queue) - idx
        self.startup_scan_complete = not (timed_out_startup or unprocessed > 0 or overflow_exec or truncated_files)
        if timed_out_startup:
            self.limitations.append(f"[시작 스크립트 검사 미완료] 시간 예산 초과로 시작 스크립트 {len(queue)}개 중 {idx}개까지만 검사했습니다 — "
                                    "부팅·핫플러그 항목(telnetd·nc 셸 등)이 더 있을 수 있습니다 (max_seconds 를 늘려 다시 실행).")
        elif unprocessed > 0:
            self.limitations.append(f"[시작 스크립트 검사 미완료] 시작 스크립트 큐 상한({STARTUP_QUEUE_EXEC_MAX})에 걸려 {unprocessed}개를 검사하지 못했습니다: "
                                    + ", ".join(queue[idx:idx + 5]))
        if overflow_exec:
            self.limitations.append(f"[시작 스크립트 검사 미완료] 시작 스크립트 큐 상한({STARTUP_QUEUE_EXEC_MAX})에 걸려 실행 문맥으로 참조된 스크립트 "
                                    f"{len(overflow_exec)}개를 따라가지 못했습니다: " + ", ".join(sorted(overflow_exec)[:5]))
        if truncated_files:
            self.limitations.append(f"[시작 스크립트 검사 미완료] {STARTUP_FILE_MAX >> 20} MiB 를 넘는 시작 스크립트 {len(truncated_files)}개는 앞 {STARTUP_FILE_MAX >> 20} MiB 만 검사했습니다: "
                                    + ", ".join(truncated_files[:5]))
        if overflow_ref:
            self.limitations.append(f"시작 스크립트 큐 상한({STARTUP_QUEUE_MAX})에 걸려 실행 문맥이 아닌 곳에서 참조된 스크립트 {len(overflow_ref)}개는 따라가지 않았습니다: "
                                    + ", ".join(sorted(overflow_ref)[:5]))
        if rule_over:
            # 검사는 끝까지 했다 (startup_scan_complete 와 상관없음) — 적지 않은 항목의 규칙과 수만 알린다
            top = sorted(rule_over.items(), key=lambda x: (-x[1], x[0]))
            self.limitations.append(f"항목 상한(시작 스크립트 전체에서 같은 규칙은 {STARTUP_ITEM_CAP_PER_RULE}개)에 걸려 {sum(rule_over.values())}개 항목은 "
                                    "적지 않고 수만 셌습니다: " + ", ".join(f"{hid} +{n}" for hid, n in top[:10])
                                    + (f" 외 {len(top) - 10}개 규칙" if len(top) > 10 else ""))
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
                    if not PEM_BODY_RX.match(data, m.end()):
                        continue  # 본문 없는 머리줄(라이브러리 상수 등) — 키·인증서가 아니다
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
