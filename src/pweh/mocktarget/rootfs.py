"""합성 카메라 루트 파일시스템 트리.

펌웨어 빌더(``firmware.py``, squashfs 생성)와 리눅스 셸 흉내(``linux.py``, cat/ls)가 같은 트리를 쓴다.
트리에는 분석 파이프라인 테스트용으로 **의도적으로 심은 합성 취약점**이 들어 있다 (``PLANTED_ISSUES``).
모든 문자열/토큰/비밀번호는 합성 값이며 실제 벤더 문자열이 아니다.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from .profiles import SYNTHETIC_MARKER

# 합성 비밀값 (실제 벤더 값 아님)
BACKDOOR_TOKEN = "PWEH-SYNTHETIC-BACKDOOR-TOKEN-7f3a9c"
ADMIN_USER = "admin"
ADMIN_PASS = "pweh-synth-admin-0000"
SELFTEST_BASIC = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()

S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFCHR = 0o020000
S_IFBLK = 0o060000


@dataclass
class Node:
    """트리 항목. kind: dir|file|symlink|chr|blk."""

    kind: str
    mode: int
    data: bytes = b""
    target: str = ""
    major: int = 0
    minor: int = 0
    uid: int = 0
    gid: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        if self.kind == "file":
            return len(self.data)
        if self.kind == "symlink":
            return len(self.target)
        return 0


# ---------------------------------------------------------------------------
# md5crypt ($1$) — 순수 파이썬 구현 (crypt 모듈 의존 없음)
# ---------------------------------------------------------------------------
_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def md5crypt(password: str, salt: str, magic: str = "$1$") -> str:
    """FreeBSD/glibc 호환 MD5-crypt."""
    pw = password.encode("utf-8")
    salt_b = salt.encode("ascii")[:8]
    mg = magic.encode("ascii")
    ctx = hashlib.md5(pw + mg + salt_b)
    final = hashlib.md5(pw + salt_b + pw).digest()
    pl = len(pw)
    while pl > 0:
        ctx.update(final[: min(16, pl)])
        pl -= 16
    i = len(pw)
    while i:
        ctx.update(b"\0" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if i & 1 else final)
        if i % 3:
            c.update(salt_b)
        if i % 7:
            c.update(pw)
        c.update(final if i & 1 else pw)
        final = c.digest()

    def to64(v: int, n: int) -> str:
        out = []
        for _ in range(n):
            out.append(_ITOA64[v & 0x3F])
            v >>= 6
        return "".join(out)

    f = final
    res = (to64((f[0] << 16) | (f[6] << 8) | f[12], 4) + to64((f[1] << 16) | (f[7] << 8) | f[13], 4)
           + to64((f[2] << 16) | (f[8] << 8) | f[14], 4) + to64((f[3] << 16) | (f[9] << 8) | f[15], 4)
           + to64((f[4] << 16) | (f[10] << 8) | f[5], 4) + to64(f[11], 2))
    return f"{magic}{salt_b.decode()}${res}"


# ---------------------------------------------------------------------------
# BusyBox 애플릿 설치 위치 (busybox --install 레이아웃 근사)
# ---------------------------------------------------------------------------
_SBIN = {"init", "ifconfig", "reboot", "poweroff", "halt", "insmod", "rmmod", "lsmod", "mdev", "klogd", "syslogd",
         "route", "getty", "hwclock", "sysctl", "udhcpc", "watchdog", "pivot_root", "fdisk", "mknod", "ip",
         "flash_eraseall", "flash_lock", "flash_unlock", "flashcp", "devmem", "losetup", "modprobe", "logread"}
_USR_BIN = {"[", "[[", "basename", "clear", "cmp", "cut", "dirname", "du", "env", "expr", "find", "free", "fuser",
            "head", "hexdump", "hd", "id", "killall", "md5sum", "mktemp", "nc", "nslookup", "passwd", "printf", "seq",
            "sort", "tail", "tee", "test", "tftp", "time", "top", "tr", "uptime", "wc", "wget", "which", "xargs", "yes",
            "telnet", "uniq", "less", "strings", "base64"}
_USR_SBIN = {"telnetd", "addgroup", "adduser", "delgroup", "deluser", "chroot", "httpd_bb"}
_NO_LINK = {"linuxrc"}


def applet_dir(name: str) -> str:
    if name in _SBIN:
        return "/sbin"
    if name in _USR_BIN:
        return "/usr/bin"
    if name in _USR_SBIN:
        return "/usr/sbin"
    return "/bin"


def _rel(from_dir: str, target: str) -> str:
    depth = len([p for p in from_dir.split("/") if p])
    return "../" * depth + target.lstrip("/") if depth else target.lstrip("/")


# ---------------------------------------------------------------------------
# 계획된(심어진) 합성 취약점 — ground truth
# ---------------------------------------------------------------------------
def planted_issues(profile: Mapping[str, Any], *, httpd_kind: str = "elf") -> list[dict[str, Any]]:
    """매니페스트에 기록할 ground truth. httpd_kind: elf(zig 빌드) | script(대체 셸 CGI)."""
    pw = profile["linux"]["login"].get("password") or ""
    web = profile.get("firmware", {}).get("web_server", "/usr/sbin/httpd")
    if httpd_kind == "elf":
        a = {"file": web, "function": "check_auth", "pattern": f'strcmp(req->token, "{BACKDOOR_TOKEN}") == 0 → 인증 성공'}
        b = {"file": web, "function": "is_static_resource",
             "pattern": 'strncmp(path, "/static/", 8) / strstr(path, ".css"|".js"|".png"|".jpg") → 인증 생략 (정규화 전 원문 부분 문자열 비교)'}
        c = {"file": web, "function": "handle_ping_cgi",
             "pattern": 'snprintf(cmd, ..., "ping -c 1 %s > /tmp/ping.log 2>&1", host); system(cmd) — host 는 요청 파라미터'}
        d = {"file": web, "function": "check_credentials",
             "pattern": f'strcmp(user, "{ADMIN_USER}") == 0 && strcmp(pass, "{ADMIN_PASS}") == 0; 내장 "Authorization: Basic {SELFTEST_BASIC}"'}
    else:
        a = {"file": "/var/www/cgi-bin/login.cgi", "function": None, "pattern": f'[ "$token" = "{BACKDOOR_TOKEN}" ] → 인증 성공'}
        b = {"file": "/var/www/cgi-bin/auth.sh", "function": None, "pattern": 'case "$REQUEST_URI" in /static/*|*.css*|*.js*|*.png*) exit 0 — 인증 생략'}
        c = {"file": "/var/www/cgi-bin/ping.cgi", "function": None, "pattern": 'sh -c "ping -c 1 $host" — host 는 QUERY_STRING 파라미터'}
        d = {"file": "/var/www/cgi-bin/login.cgi", "function": None, "pattern": f'[ "$user" = "{ADMIN_USER}" ] && [ "$pass" = "{ADMIN_PASS}" ]'}
    return [
        {"id": "PWEH-PLANT-01", "category": "backdoor", "title": "웹 서버 인증 검사 안의 하드코딩된 백도어 토큰 비교",
         "severity": "critical", "token": BACKDOOR_TOKEN, **a},
        {"id": "PWEH-PLANT-02", "category": "auth-bypass", "title": "정적 파일 접두어/접미어 경로에 대한 인증 생략 (URI 부분 문자열 매칭)",
         "severity": "high", **b},
        {"id": "PWEH-PLANT-03", "category": "command-injection", "title": "CGI 요청 파라미터가 system() 으로 전달되는 명령 주입",
         "severity": "critical", **c},
        {"id": "PWEH-PLANT-04", "category": "hardcoded-credential", "title": "하드코딩된 관리자 계정/비밀번호",
         "severity": "high", "username": ADMIN_USER, "password": ADMIN_PASS, **d},
        {"id": "PWEH-PLANT-05", "category": "debug-interface", "title": "부팅 시 telnetd 무조건 실행",
         "severity": "medium", "file": "/etc/init.d/rcS", "function": None, "pattern": "/usr/sbin/telnetd &"},
        {"id": "PWEH-PLANT-06", "category": "hardcoded-credential", "title": "약한 MD5-crypt root 비밀번호 해시 (기본 비밀번호)",
         "severity": "high", "file": "/etc/shadow", "function": None, "pattern": "root:$1$...",
         "username": profile["linux"]["login"].get("username", "root"), "password": pw,
         "hash": root_hash(profile)},
    ]


def root_salt(profile: Mapping[str, Any]) -> str:
    return hashlib.sha256(("pweh-salt:" + profile["name"]).encode()).hexdigest()[:8].replace("0", "Q")


def root_hash(profile: Mapping[str, Any]) -> str:
    pw = profile["linux"]["login"].get("password") or ""
    if not pw:
        return ""
    return md5crypt(pw, root_salt(profile))


# ---------------------------------------------------------------------------
# 파일 내용
# ---------------------------------------------------------------------------
def _passwd(profile: Mapping[str, Any]) -> str:
    user = profile["linux"]["login"].get("username", "root")
    lines = [f"{user}:x:0:0:{user}:/root:/bin/sh" if user == "root" else "root:x:0:0:root:/root:/bin/sh"]
    if user != "root":
        lines.append(f"{user}:x:1000:1000:{user}:/home/{user}:/bin/sh")
    lines += ["daemon:x:1:1:daemon:/usr/sbin:/bin/false", "bin:x:2:2:bin:/bin:/bin/false",
              "nobody:x:65534:65534:nobody:/nonexistent:/bin/false"]
    return "\n".join(lines) + "\n"


def _shadow(profile: Mapping[str, Any]) -> str:
    user = profile["linux"]["login"].get("username", "root")
    h = root_hash(profile)
    lines = [f"{user}:{h}:18000:0:99999:7:::"]
    if user != "root":
        lines.insert(0, "root:*:18000:0:99999:7:::")
    lines += ["daemon:*:18000:0:99999:7:::", "bin:*:18000:0:99999:7:::", "nobody:*:18000:0:99999:7:::"]
    return "\n".join(lines) + "\n"


def _rcs(profile: Mapping[str, Any]) -> str:
    lx = profile["linux"]
    iface = (lx.get("interfaces") or {}).get("eth0") or {}
    app_mount = profile.get("firmware", {}).get("app_mount", "/app")
    return f"""#!/bin/sh
# /etc/init.d/rcS — {SYNTHETIC_MARKER}
# pweh.mocktarget 합성 카메라 부팅 스크립트 (분석 파이프라인 테스트용)

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mkdir -p /tmp/run /tmp/log
mount -t squashfs /dev/mtdblock4 {app_mount}
hostname -F /etc/hostname

ifconfig lo 127.0.0.1 up
ifconfig eth0 {iface.get('inet', '192.168.1.10')} netmask {iface.get('mask', '255.255.255.0')} up

syslogd
klogd

# PWEH-PLANT-05: telnetd 를 항상 기동 (디버그 인터페이스 상시 개방)
echo "Starting telnetd..."
/usr/sbin/telnetd &

echo "ipcam: starting synthetic httpd on port 80"
/usr/sbin/httpd -p 80 -h /var/www &
"""


def _inittab() -> str:
    return f"""# /etc/inittab — {SYNTHETIC_MARKER}
::sysinit:/etc/init.d/rcS
::askfirst:/bin/login
::restart:/sbin/init
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
"""


def _profile_sh() -> str:
    return """# /etc/profile
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PS1='# '
export TERM=vt100
umask 022
"""


def _fallback_cgis(profile: Mapping[str, Any]) -> dict[str, str]:
    """zig 가 없을 때 쓰는 셸 스크립트 CGI (같은 취약점 클래스를 셸로 표현)."""
    return {
        "/var/www/cgi-bin/auth.sh": f"""#!/bin/sh
# {SYNTHETIC_MARKER}
# PWEH-PLANT-02: 정적 리소스로 보이는 경로는 인증을 건너뛴다 (URI 원문 부분 문자열 매칭)
case "$REQUEST_URI" in
  /static/*|*.css*|*.js*|*.png*) exit 0 ;;
esac
. /var/www/cgi-bin/login.cgi
""",
        "/var/www/cgi-bin/login.cgi": f"""#!/bin/sh
# {SYNTHETIC_MARKER}
token=$(echo "$QUERY_STRING" | sed -n 's/.*token=\\([^&]*\\).*/\\1/p')
user=$(echo "$QUERY_STRING" | sed -n 's/.*user=\\([^&]*\\).*/\\1/p')
pass=$(echo "$QUERY_STRING" | sed -n 's/.*pass=\\([^&]*\\).*/\\1/p')
# PWEH-PLANT-01: 하드코딩된 백도어 토큰
if [ "$token" = "{BACKDOOR_TOKEN}" ]; then echo "Status: 200"; exit 0; fi
# PWEH-PLANT-04: 하드코딩된 관리자 계정
if [ "$user" = "{ADMIN_USER}" ] && [ "$pass" = "{ADMIN_PASS}" ]; then echo "Status: 200"; exit 0; fi
echo "Status: 401"
exit 1
""",
        "/var/www/cgi-bin/ping.cgi": f"""#!/bin/sh
# {SYNTHETIC_MARKER}
echo "Content-Type: text/plain"
echo
host=$(echo "$QUERY_STRING" | sed -n 's/.*host=\\([^&]*\\).*/\\1/p')
# PWEH-PLANT-03: 요청 파라미터가 그대로 셸로 전달됨 (명령 주입)
sh -c "ping -c 1 $host"
""",
    }


def _placeholder_elf(profile: Mapping[str, Any], name: str) -> bytes:
    """빌드된 바이너리가 없을 때 셸 화면용 자리표시자 (ELF 헤더 + 표식). 펌웨어 이미지에는 넣지 않는다."""
    is_arm = profile["arch"] == "arm"
    machine = 40 if is_arm else 8
    hdr = bytearray(52)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 1  # ELFCLASS32
    hdr[5] = 1  # little endian
    hdr[6] = 1
    hdr[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    hdr[18:20] = machine.to_bytes(2, "little")
    hdr[20:24] = (1).to_bytes(4, "little")
    return bytes(hdr) + f"\0{name}\0{SYNTHETIC_MARKER}\0".encode()


def build_tree(profile: Mapping[str, Any], *, binaries: Mapping[str, bytes] | None = None,
               httpd_kind: str | None = None) -> dict[str, Node]:
    """프로필로부터 루트 파일시스템 트리를 만든다.

    binaries: {"/bin/busybox": ELF, "/usr/sbin/httpd": ELF} — 없으면 자리표시자(셸 표시용) 사용.
    httpd_kind: "elf" | "script" | None(binaries 에 httpd 가 있으면 elf, 없으면 script).
    """
    binaries = dict(binaries or {})
    lx = profile["linux"]
    web = profile.get("firmware", {}).get("web_server", "/usr/sbin/httpd")
    if httpd_kind is None:
        httpd_kind = "elf" if web in binaries else "script"
    tree: dict[str, Node] = {}

    def d(path: str, mode: int = 0o755) -> None:
        parts = [p for p in path.split("/") if p]
        cur = ""
        for p in parts:
            cur += "/" + p
            if cur not in tree:
                tree[cur] = Node("dir", S_IFDIR | 0o755)
        if path == "/":
            tree["/"] = Node("dir", S_IFDIR | 0o755)
        else:
            tree[path].mode = S_IFDIR | mode

    def f(path: str, content: str | bytes, mode: int = 0o644) -> None:
        d(path.rsplit("/", 1)[0] or "/")
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        tree[path] = Node("file", S_IFREG | mode, data=data)

    def ln(path: str, target: str) -> None:
        d(path.rsplit("/", 1)[0] or "/")
        tree[path] = Node("symlink", S_IFLNK | 0o777, target=target)

    def dev(path: str, kind: str, major: int, minor: int, mode: int = 0o600) -> None:
        d(path.rsplit("/", 1)[0] or "/")
        tree[path] = Node(kind, (S_IFCHR if kind == "chr" else S_IFBLK) | mode, major=major, minor=minor)

    d("/")
    for p in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/etc/init.d", "/proc", "/sys", "/dev", "/tmp",
              "/root", "/mnt", "/mnt/mtd", "/mnt/sd", "/var", "/var/www/cgi-bin", "/var/www/static",
              profile.get("firmware", {}).get("app_mount", "/app"), "/home"):
        d(p)
    tree["/tmp"].mode = S_IFDIR | 0o1777
    tree["/root"].mode = S_IFDIR | 0o700

    busybox = binaries.get("/bin/busybox") or _placeholder_elf(profile, "busybox")
    f("/bin/busybox", busybox, 0o755)
    tree["/bin/busybox"].meta["placeholder"] = "/bin/busybox" not in binaries
    for applet in lx.get("applets") or []:
        if applet in _NO_LINK:
            continue
        ad = applet_dir(applet)
        path = f"{ad}/{applet}"
        if path in tree:
            continue
        ln(path, _rel(ad, "bin/busybox") if ad != "/bin" else "busybox")
    ln("/linuxrc", "bin/busybox")
    ln("/var/run", "../tmp/run")
    ln("/var/log", "../tmp/log")
    ln("/etc/resolv.conf", "../tmp/resolv.conf")

    # mtd-utils / u-boot-tools (카메라 업그레이드 스크립트가 흔히 가지고 있음)
    for tool in ("flash_erase", "mtd_debug", "fw_printenv", "fw_setenv"):
        data = binaries.get(f"/usr/sbin/{tool}") or _placeholder_elf(profile, tool)
        f(f"/usr/sbin/{tool}", data, 0o755)
        tree[f"/usr/sbin/{tool}"].meta["placeholder"] = f"/usr/sbin/{tool}" not in binaries

    # 웹 서버
    if httpd_kind == "elf" and web in binaries:
        f(web, binaries[web], 0o755)
    elif httpd_kind == "elf":
        f(web, _placeholder_elf(profile, "httpd"), 0o755)
        tree[web].meta["placeholder"] = True
    else:
        f(web, f"#!/bin/sh\n# {SYNTHETIC_MARKER}\n# zig 미설치 대체: BusyBox httpd + 셸 CGI\nexec /usr/sbin/httpd_bb -f -p 80 -h /var/www \"$@\"\n", 0o755)
        for path, content in _fallback_cgis(profile).items():
            f(path, content, 0o755)

    f("/var/www/index.html", f"""<!DOCTYPE html>
<html><head><title>IP Camera</title><link rel="stylesheet" href="/static/style.css"></head>
<body><!-- {SYNTHETIC_MARKER} --><h1>Synthetic IP Camera</h1>
<form action="/cgi-bin/login.cgi" method="get">user <input name="user"> pass <input name="pass" type="password">
<input type="submit" value="login"></form></body></html>
""")
    f("/var/www/static/style.css", "body { font-family: sans-serif; }\n")
    f("/var/www/static/app.js", f"/* {SYNTHETIC_MARKER} */\nfunction ping(h) {{ location = '/cgi-bin/ping.cgi?host=' + h; }}\n")
    f("/var/www/cgi-bin/status.cgi", f"#!/bin/sh\n# {SYNTHETIC_MARKER}\necho \"Content-Type: text/plain\"\necho\ncat /proc/uptime\n", 0o755)

    f("/etc/passwd", _passwd(profile))
    f("/etc/shadow", _shadow(profile), 0o600)
    f("/etc/group", "root:x:0:\ndaemon:x:1:\nbin:x:2:\nnogroup:x:65534:\n")
    f("/etc/inittab", _inittab())
    f("/etc/init.d/rcS", _rcs(profile), 0o755)
    f("/etc/profile", _profile_sh())
    hostname = lx.get("hostname") or "(none)"
    f("/etc/hostname", ("ipcam" if hostname == "(none)" else hostname) + "\n")
    f("/etc/hosts", "127.0.0.1\tlocalhost\n")
    f("/etc/fstab", "proc\t/proc\tproc\tdefaults\t0\t0\ntmpfs\t/tmp\ttmpfs\tdefaults\t0\t0\nsysfs\t/sys\tsysfs\tdefaults\t0\t0\n")
    f("/etc/securetty", "console\nttyS0\nttyS1\nttyAMA0\n")
    f("/etc/shells", "/bin/sh\n/bin/ash\n")
    f("/etc/issue", lx.get("issue") or "")
    f("/etc/pweh-synthetic.txt", f"{SYNTHETIC_MARKER}\nprofile={profile['name']}\n"
      "이 파일시스템은 pweh.mocktarget 이 만든 합성 테스트 펌웨어입니다. 실제 벤더 펌웨어가 아닙니다.\n")
    f("/etc/version", f"{profile['name']} synthetic build {profile.get('firmware', {}).get('build_date', '')}\n")

    dev("/dev/console", "chr", 5, 1)
    dev("/dev/null", "chr", 1, 3, 0o666)
    return dict(sorted(tree.items()))


def app_tree(profile: Mapping[str, Any]) -> dict[str, Node]:
    """app 파티션(두 번째 squashfs)의 내용: 설정 파일 + 표식."""
    tree: dict[str, Node] = {"/": Node("dir", S_IFDIR | 0o755)}

    def f(path: str, content: str, mode: int = 0o644) -> None:
        parent = path.rsplit("/", 1)[0] or "/"
        cur = ""
        for p in [x for x in parent.split("/") if x]:
            cur += "/" + p
            tree.setdefault(cur, Node("dir", S_IFDIR | 0o755))
        tree[path] = Node("file", S_IFREG | mode, data=content.encode())

    f("/config/network.conf", "dhcp=0\nipaddr=192.168.1.10\nnetmask=255.255.255.0\ngateway=192.168.1.1\n")
    f("/config/onvif.conf", "enable=1\nport=80\n")
    f("/config/rtsp.conf", "enable=1\nport=554\n")
    f("/README.txt", f"{SYNTHETIC_MARKER}\napp partition for profile {profile['name']}\n")
    return dict(sorted(tree.items()))


__all__ = ["ADMIN_PASS", "ADMIN_USER", "BACKDOOR_TOKEN", "Node", "app_tree", "applet_dir", "build_tree",
           "md5crypt", "planted_issues", "root_hash"]
