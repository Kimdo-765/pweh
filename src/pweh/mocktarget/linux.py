"""리눅스 커널 부팅 로그 + BusyBox init/login/ash 흉내.

형식 근거 (~/pweh-refs/src/busybox-1.24.1, ~/pweh-refs/linux/v3.10, v4.9):
- init/init.c askfirst: ``"\\nPlease press Enter to activate this console. "``
- loginutils/login.c: ``"<hostname> login: "``, ``"Password: "``, 실패 시 3초 뒤 ``"Login incorrect"``, 3회 실패 시 종료,
  프롬프트 직전 tcflush(TCIFLUSH) 로 미리 보낸 입력은 버려진다.
- shell/ash.c: 찾을 수 없는 명령 ``"-sh: X: not found"`` (arg0 이 로그인 셸 "-sh")
- libbb/lineedit.c: Ctrl-C 는 줄을 버리고 새 줄(``goto_new_line``)만 출력, Ctrl-D(빈 줄) 은 EOF
- util-linux/hexdump.c + libbb/dump.c (``hexdump -C``), coreutils/uudecode.c (base64 76자 줄),
  coreutils/md5_sha1_sum.c (``"%s  %s\\n"``), coreutils/dd.c (통계는 stderr: records in/out + 세 번째 줄)
- drivers/mtd/mtdcore.c ``/proc/mtd``, drivers/mtd/mtdpart.c ``Creating %d MTD partitions on "%s":`` /
  ``0x%012llx-0x%012llx : "%s"``, init/do_mounts.c ``VFS: Mounted root (%s filesystem)%s on device %u:%u.``
"""

from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import re
import time
from typing import TYPE_CHECKING, Any, Callable

from ..formats import build_uboot_env, parse_mtdparts, parse_uboot_env
from . import rootfs
from .device import RX_DROP, RX_TTY, ResetEvent
from .fmt import busybox_base64, hexdump_canonical, make_human_readable_str, smart_ulltoa5
from .rootfs import Node, S_IFBLK, S_IFCHR, S_IFDIR, S_IFLNK, S_IFREG

if TYPE_CHECKING:  # pragma: no cover
    from .device import MockDevice
    from .uboot import BootKernel

PIPE_BUF_CAPACITY = 65536  # 리눅스 파이프 버퍼 (dd 통계가 출력 중간에 끼어드는 위치 계산용)


class _SigInt(Exception):
    """Ctrl-C (SIGINT)."""


class _ShellExit(Exception):
    def __init__(self, code: int = 0) -> None:
        super().__init__(code)
        self.code = code


class FsError(Exception):
    def __init__(self, errno_name: str, path: str = "") -> None:
        super().__init__(errno_name)
        self.errno_name = errno_name
        self.path = path

    @property
    def text(self) -> str:
        return {
            "ENOENT": "No such file or directory",
            "EROFS": "Read-only file system",
            "EISDIR": "Is a directory",
            "ENOTDIR": "Not a directory",
            "EACCES": "Permission denied",
            "EINVAL": "Invalid argument",
            "ELOOP": "Too many symbolic links encountered",
            "EEXIST": "File exists",
            "ENOTEMPTY": "Directory not empty",
            "EBUSY": "Device or resource busy",
        }.get(self.errno_name, self.errno_name)


# ---------------------------------------------------------------------------
# 가상 파일시스템
# ---------------------------------------------------------------------------
class VFS:
    """rootfs(squashfs, 읽기 전용) + app 마운트 + /tmp(tmpfs) + /proc + /dev."""

    def __init__(self, linux: "Linux") -> None:
        self.lx = linux
        prof = linux.prof
        man = linux.dev.firmware_manifest or {}
        sizes = {f["path"]: f.get("size") for f in (man.get("rootfs") or {}).get("files", []) if isinstance(f, dict)}
        self.root = rootfs.build_tree(prof, httpd_kind=(man.get("httpd") or {}).get("kind"))
        for path, node in self.root.items():
            if node.kind == "file" and node.meta.get("placeholder") and sizes.get(path):
                node.meta["size"] = sizes[path]
        self.app_mount = prof.get("firmware", {}).get("app_mount", "/app")
        self.app = rootfs.app_tree(prof)
        self.tmp: dict[str, Node] = {
            "/tmp": Node("dir", S_IFDIR | 0o1777),
            "/tmp/run": Node("dir", S_IFDIR | 0o755),
            "/tmp/log": Node("dir", S_IFDIR | 0o755),
            "/tmp/resolv.conf": Node("file", S_IFREG | 0o644, data=b"nameserver 192.168.1.1\n"),
            "/tmp/run/telnetd.pid": Node("file", S_IFREG | 0o644, data=b"528\n"),
        }

    # -- 경로 ----------------------------------------------------------
    @staticmethod
    def norm(path: str, cwd: str = "/") -> str:
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        out: list[str] = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if out:
                    out.pop()
                continue
            out.append(part)
        return "/" + "/".join(out)

    def _raw_node(self, path: str) -> Node | None:
        if path == "/proc" or path.startswith("/proc/"):
            return self._proc_node(path)
        if path == "/dev" or path.startswith("/dev/"):
            return self._dev_node(path)
        if path == "/tmp" or path.startswith("/tmp/"):
            return self.tmp.get(path)
        if path == self.app_mount or path.startswith(self.app_mount + "/"):
            sub = path[len(self.app_mount):] or "/"
            return self.app.get(sub)
        return self.root.get(path)

    def resolve(self, path: str, cwd: str = "/", *, follow: bool = True) -> tuple[str, Node | None]:
        """경로를 정규화하고 심볼릭 링크를 따라간다. (최종 경로, 노드 또는 None)."""
        p = self.norm(path, cwd)
        for _ in range(16):
            parts = [x for x in p.split("/") if x]
            cur = ""
            restart = False
            for i, part in enumerate(parts):
                nxt = cur + "/" + part
                node = self._raw_node(nxt)
                if node is None:
                    return p, None
                last = i == len(parts) - 1
                if node.kind == "symlink" and (follow or not last):
                    base = cur or "/"
                    target = node.target
                    rest = "/".join(parts[i + 1:])
                    newp = self.norm(target, base)
                    p = self.norm(rest, newp) if rest else newp
                    restart = True
                    break
                if not last and node.kind != "dir":
                    raise FsError("ENOTDIR", nxt)
                cur = nxt
            if not restart:
                return p, self._raw_node(p) if p != "/" else self.root.get("/")
        raise FsError("ELOOP", path)

    def listdir(self, path: str) -> list[str]:
        if path == "/proc":
            pids = [str(p[0]) for p in self.lx.processes()]
            return sorted(set(self._proc_files()) | set(pids), key=lambda s: (not s.isdigit(), int(s) if s.isdigit() else 0, s))
        if path == "/dev":
            return sorted(self._dev_entries())
        if path == "/tmp" or path.startswith("/tmp/"):
            src: dict[str, Node] = self.tmp
            base = path
        elif path == self.app_mount or path.startswith(self.app_mount + "/"):
            src = self.app
            base = path[len(self.app_mount):] or "/"
        else:
            src = self.root
            base = path
        prefix = base.rstrip("/") + "/"
        names = set()
        for p in src:
            if p.startswith(prefix) and p != base:
                rest = p[len(prefix):]
                if rest and "/" not in rest:
                    names.add(rest)
        if path == "/":
            names.update({"proc", "dev", "tmp"})
        return sorted(names)

    def read(self, path: str, cwd: str = "/") -> bytes:
        real, node = self.resolve(path, cwd)
        if node is None:
            raise FsError("ENOENT", path)
        if node.kind == "dir":
            raise FsError("EISDIR", path)
        if real.startswith("/proc/"):
            return self._proc_read(real)
        if node.kind in ("chr", "blk"):
            return self.lx.device_read(real, None)
        return node.data

    def writable(self, path: str) -> bool:
        return path == "/tmp" or path.startswith("/tmp/")

    def write(self, path: str, data: bytes, cwd: str = "/", *, append: bool = False) -> None:
        real, node = self.resolve(path, cwd)
        if real.startswith("/dev/"):
            self.lx.device_write(real, data)
            return
        if real.startswith("/proc/") or real.startswith("/sys/"):
            raise FsError("EACCES" if real.startswith("/proc/") else "EROFS", path)
        if not self.writable(real):
            raise FsError("EROFS", path)
        parent = posixpath.dirname(real)
        pnode = self._raw_node(parent)
        if pnode is None or pnode.kind != "dir":
            raise FsError("ENOENT", path)
        if node is not None and node.kind == "dir":
            raise FsError("EISDIR", path)
        if node is None or not append:
            self.tmp[real] = Node("file", S_IFREG | 0o644, data=bytes(data))
        else:
            node.data = node.data + bytes(data)

    def mkdir(self, path: str, cwd: str = "/") -> None:
        real = self.norm(path, cwd)
        if self._raw_node(real) is not None:
            raise FsError("EEXIST", path)
        if not self.writable(real):
            raise FsError("EROFS", path)
        self.tmp[real] = Node("dir", S_IFDIR | 0o755)

    def remove(self, path: str, cwd: str = "/") -> None:
        real, node = self.resolve(path, cwd, follow=False)
        if node is None:
            raise FsError("ENOENT", path)
        if not self.writable(real):
            raise FsError("EROFS", path)
        if node.kind == "dir" and self.listdir(real):
            raise FsError("ENOTEMPTY", path)
        self.tmp.pop(real, None)

    # -- /proc ---------------------------------------------------------
    @staticmethod
    def _proc_files() -> list[str]:
        return ["cmdline", "cpuinfo", "devices", "filesystems", "loadavg", "meminfo", "mounts", "mtd",
                "partitions", "self", "stat", "uptime", "version"]

    def _proc_node(self, path: str) -> Node | None:
        if path == "/proc":
            return Node("dir", S_IFDIR | 0o555)
        name = path[len("/proc/"):]
        if name == "self":
            return Node("symlink", S_IFLNK | 0o777, target=str(self.lx.shell_pid))
        if name in self._proc_files():
            return Node("file", S_IFREG | 0o444)
        first = name.split("/", 1)[0]
        if first.isdigit() and int(first) in {p[0] for p in self.lx.processes()}:
            if "/" not in name:
                return Node("dir", S_IFDIR | 0o555)
            if name.split("/", 1)[1] in ("cmdline", "status", "comm"):
                return Node("file", S_IFREG | 0o444)
        return None

    def _proc_read(self, path: str) -> bytes:
        return self.lx.proc_file(path[len("/proc/"):]).encode("utf-8")

    # -- /dev ----------------------------------------------------------
    def _dev_entries(self) -> dict[str, tuple[str, int, int, int]]:
        ents: dict[str, tuple[str, int, int, int]] = {
            "console": ("chr", 5, 1, 0o600), "null": ("chr", 1, 3, 0o666), "zero": ("chr", 1, 5, 0o666),
            "random": ("chr", 1, 8, 0o666), "urandom": ("chr", 1, 9, 0o666), "mem": ("chr", 1, 1, 0o640),
            "watchdog": ("chr", 10, 130, 0o600), "tty": ("chr", 5, 0, 0o666),
        }
        console = self.lx.console_dev
        if console.startswith("ttyAMA"):
            ents["ttyAMA0"] = ("chr", 204, 64, 0o600)
            ents["ttyAMA1"] = ("chr", 204, 65, 0o600)
        else:
            ents["ttyS0"] = ("chr", 4, 64, 0o600)
            ents["ttyS1"] = ("chr", 4, 65, 0o600)
        for i, _p in enumerate(self.lx.parts):
            ents[f"mtd{i}"] = ("chr", 90, 2 * i, 0o600)
            ents[f"mtd{i}ro"] = ("chr", 90, 2 * i + 1, 0o400)
            ents[f"mtdblock{i}"] = ("blk", 31, i, 0o600)
        return ents

    def _dev_node(self, path: str) -> Node | None:
        if path == "/dev":
            return Node("dir", S_IFDIR | 0o755)
        name = path[len("/dev/"):]
        ent = self._dev_entries().get(name)
        if ent is None:
            return None
        kind, major, minor, mode = ent
        return Node(kind, (S_IFCHR if kind == "chr" else S_IFBLK) | mode, major=major, minor=minor)


# ---------------------------------------------------------------------------
# 리눅스 본체
# ---------------------------------------------------------------------------
class Linux:
    def __init__(self, dev: "MockDevice", kernel: "BootKernel") -> None:
        self.dev = dev
        self.prof = dev.profile
        self.kn: dict[str, Any] = dev.profile["kernel"]
        self.lx: dict[str, Any] = dev.profile["linux"]
        self.kernel = kernel
        self.cmdline = kernel.bootargs
        self.parts = self._parse_parts(self.cmdline)
        self.console_dev = self._console_from_cmdline()
        self.boot_time = time.monotonic()
        self.env: dict[str, str] = {"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/root", "SHELL": "/bin/sh",
                                    "USER": "root", "LOGNAME": "root", "TERM": "vt100", "PS1": self.lx.get("shell_prompt", "# ")}
        self.cwd = "/"
        self.status = 0
        self.history: list[str] = []
        self.kmsg: list[str] = []
        self.vfs = VFS(self)
        self.shell_pid = 600
        self.next_pid = 610
        self.logged_in_user = "root"

    # ------------------------------------------------------------------
    def out(self, text: str | bytes) -> None:
        self.dev.write(text)

    def t(self, key: str, default: float) -> float:
        return float((self.prof["uboot"].get("timings") or {}).get(key, default))

    def _parse_parts(self, cmdline: str) -> list[dict[str, Any]]:
        size = self.dev.flash.size
        try:
            m = re.search(r"mtdparts=(\S+)", cmdline)
            if m:
                return [p for p in parse_mtdparts(m.group(0), total_size=size) if p["size"]]
        except Exception:
            pass
        return [{"device": self.prof["flash"]["mtd_id"], "name": self.prof["flash"]["mtd_id"], "offset": 0, "size": size, "ro": False}]

    def _console_from_cmdline(self) -> str:
        m = re.search(r"console=(tty[A-Za-z]+\d+)", self.cmdline)
        return m.group(1) if m else "ttyS0"

    def uptime(self) -> float:
        return (time.monotonic() - self.boot_time) / max(self.dev.time_scale, 1e-3) + 4.2

    # ------------------------------------------------------------------
    # 부팅
    # ------------------------------------------------------------------
    def run(self) -> None:
        dev = self.dev
        dev.set_rx_mode(RX_DROP)
        dev.set_state("kernel-boot")
        if self.kn.get("zimage_banner"):
            self.out("Uncompressing Linux... done, booting the kernel.\n")
            dev.sleep(0.15)
        delay = self.t("kernel_line", 0.01)
        for line in self.render_boot_log():
            self.kmsg.append(line)
            self.out(line + "\n")
            if delay:
                dev.sleep(delay)
        banner = self.lx.get("busybox_banner", "BusyBox")
        self.out(f"init started: {banner}\n")
        dev.sleep(self.t("userspace", 0.5) / 2)
        for line in (self.lx.get("rcs_output") or "").splitlines():
            self.out(line + "\n")
            dev.sleep(0.02)
        dev.sleep(self.t("userspace", 0.5) / 2)
        dev.set_rx_mode(RX_TTY, flush=True)
        while True:
            try:
                if self.lx.get("askfirst", True):
                    self._askfirst()
                user = self._login()
                if user is None:
                    continue
                self._shell(user)
            except _SigInt:
                # login 이 SIGINT 로 죽으면 init 이 다시 askfirst 를 띄운다
                self.out("\n")
                continue

    def render_boot_log(self) -> list[str]:
        mtd_lines = [f'{len(self.parts)} cmdlinepart partitions found on MTD device {self.parts[0]["device"]}',
                     f'Creating {len(self.parts)} MTD partitions on "{self.parts[0]["device"]}":']
        for p in self.parts:
            mtd_lines.append(f'0x{p["offset"]:012x}-0x{p["offset"] + p["size"]:012x} : "{p["name"]}"')
        rootdev = self._root_device()
        repl = {
            "{version_line}": self.kn.get("version_line", f"Linux version {self.kn['version']}"),
            "{cmdline}": self.cmdline,
            "{mtd_partitions}": "\n".join(mtd_lines),
            "{rootdev}": rootdev,
        }
        text = self.kn.get("boot_log") or "{version_line}\nKernel command line: {cmdline}\n{mtd_partitions}\n"
        for k, v in repl.items():
            text = text.replace(k, v)
        return text.rstrip("\n").split("\n")

    def _root_device(self) -> str:
        m = re.search(r"root=/dev/mtdblock(\d+)", self.cmdline)
        minor = int(m.group(1)) if m else 3
        return f"{self.kn.get('rootdev_major', 31)}:{minor}"

    # ------------------------------------------------------------------
    # 콘솔 입력 (tty)
    # ------------------------------------------------------------------
    def _getc(self) -> int:
        while True:
            c = self.dev.getc(reading=True)
            if c is not None:
                return c

    def read_tty_line(self, *, echo: bool = True) -> str | None:
        """정규(canonical) 모드 한 줄: 에코, Backspace/Ctrl-U 편집, Ctrl-C=SIGINT, 빈 줄 Ctrl-D=EOF(None)."""
        buf: list[str] = []
        while True:
            c = self._getc()
            if c in (0x0D, 0x0A):
                self.out("\n")
                return "".join(buf)
            if c == 0x03:
                self.out("^C" if echo else "")
                raise _SigInt()
            if c == 0x04:
                if not buf:
                    return None
                continue
            if c in (0x7F, 0x08):
                if buf:
                    buf.pop()
                    if echo:
                        self.out("\b \b")
                continue
            if c == 0x15:
                if echo:
                    self.out("\b \b" * len(buf))
                buf.clear()
                continue
            if c < 0x20 and c != 0x09:
                if echo:
                    self.out("^" + chr(c + 0x40))
                buf.append(chr(c))
                continue
            buf.append(chr(c))
            if echo:
                self.out(chr(c))

    def _askfirst(self) -> None:
        self.dev.set_state("linux-login")
        self.out("\nPlease press Enter to activate this console. ")
        while True:
            c = self._getc()
            if c in (0x0D, 0x0A):
                self.out("\n")
                return
            if 0x20 <= c < 0x7F:
                self.out(chr(c))

    def _login(self) -> str | None:
        """BusyBox login. 성공하면 사용자 이름, 3회 실패/EOF 면 None (→ init 이 askfirst 를 다시 띄움)."""
        self.dev.set_state("linux-login")
        lg = self.lx.get("login") or {}
        user_ok = lg.get("username", "root")
        pw_ok = lg.get("password") or ""
        hostname = self.lx.get("hostname") or "(none)"
        self.out("\r\n")
        issue = self.lx.get("issue") or ""
        if issue:
            self.out(issue if issue.endswith("\n") else issue + "\n")
        count = 0
        while True:
            self.dev.flush_input()  # tcflush(0, TCIFLUSH): 미리 보낸 입력은 버려진다
            username = None
            for _ in range(10):
                self.out(f"{hostname} login: ")
                line = self.read_tty_line(echo=True)
                if line is None:
                    return None
                line = line.strip()
                if line:
                    username = line.split()[0]
                    break
            if username is None:
                return None
            self.dev.record({"type": "command", "context": "login", "line": "<username>", "username": username})
            if username == user_ok and not pw_ok:
                ok = True
            else:
                self.dev.flush_input()  # bb_ask(): tcflush(TCIFLUSH) — 프롬프트 전에 보낸 비밀번호는 버려진다
                self.out("Password: ")
                pw = self.read_tty_line(echo=False)
                if pw is None:
                    return None
                self.dev.record({"type": "command", "context": "password", "line": "<masked>"})
                ok = username == user_ok and pw == pw_ok
            if ok:
                motd = lg.get("motd") or ""
                if motd:
                    self.out(motd if motd.endswith("\n") else motd + "\n")
                self.dev.record({"type": "login", "user": username, "ok": True})
                return username
            self.dev.record({"type": "login", "user": username, "ok": False})
            self.dev.sleep(3.0)
            self.out("Login incorrect\n")
            count += 1
            if count >= 3:
                return None

    # ------------------------------------------------------------------
    # ash
    # ------------------------------------------------------------------
    def _shell(self, user: str) -> None:
        self.dev.set_state("linux-shell")
        self.logged_in_user = user
        self.shell_pid = self.next_pid
        self.next_pid += 3
        self.cwd = "/root" if user == "root" else f"/home/{user}"
        if self.vfs.resolve(self.cwd)[1] is None:
            self.cwd = "/"
        while True:
            prompt = self._prompt()
            try:
                line = self._lineedit(prompt)
            except _SigInt:
                continue
            if line is None:
                return  # EOF → 로그인 셸 종료
            if line.strip():
                self.history.append(line)
                if len(self.history) > 255:
                    del self.history[0]
            self.dev.record({"type": "command", "context": "linux-shell", "line": line})
            try:
                self.run_line(line)
            except _ShellExit:
                return

    def _prompt(self) -> str:
        ps1 = self.env.get("PS1", "# ")
        return ps1.replace("\\w", self.cwd).replace("\\u", self.logged_in_user).replace("\\h", self.lx.get("hostname") or "(none)")

    def _lineedit(self, prompt: str) -> str | None:
        """libbb/lineedit.c 흉내 (raw 모드, 자체 에코)."""
        self.out(prompt)
        buf: list[str] = []
        cur = 0
        hist = len(self.history)
        esc: list[str] = []
        while True:
            c = self._getc()
            ch = chr(c)
            if esc:
                esc.append(ch)
                if len(esc) == 2 and ch in "[O":
                    continue
                seq = "".join(esc)
                esc = []
                if seq.endswith("A") or seq.endswith("B"):
                    if seq.endswith("A") and hist > 0:
                        hist -= 1
                    elif seq.endswith("B") and hist < len(self.history):
                        hist += 1
                    else:
                        self.out("\a")
                        continue
                    newl = self.history[hist] if hist < len(self.history) else ""
                    self.out("\b" * cur + " " * len(buf) + "\b" * len(buf) + newl)
                    buf = list(newl)
                    cur = len(buf)
                elif seq.endswith("D") and cur > 0:
                    self.out("\b")
                    cur -= 1
                elif seq.endswith("C") and cur < len(buf):
                    self.out(buf[cur])
                    cur += 1
                continue
            if c in (0x0D, 0x0A):
                self.out("\n")
                return "".join(buf)
            if c == 0x1B:
                esc = ["\x1b"]
                continue
            if c == 0x03:
                self.out("\n")  # goto_new_line, 입력 폐기
                raise _SigInt()
            if c == 0x04:
                if not buf:
                    return None
                if cur < len(buf):
                    del buf[cur]
                    rest = "".join(buf[cur:])
                    self.out(rest + " " + "\b" * (len(rest) + 1))
                continue
            if c in (0x7F, 0x08):
                if cur > 0:
                    cur -= 1
                    del buf[cur]
                    rest = "".join(buf[cur:])
                    self.out("\b" + rest + " " + "\b" * (len(rest) + 1))
                continue
            if c == 0x15:
                self.out("\b" * cur + " " * len(buf) + "\b" * len(buf))
                buf.clear()
                cur = 0
                continue
            if c == 0x01:
                self.out("\b" * cur)
                cur = 0
                continue
            if c == 0x05:
                self.out("".join(buf[cur:]))
                cur = len(buf)
                continue
            if c == 0x09:
                self.out("\a")
                continue
            if c < 0x20:
                continue
            buf.insert(cur, ch)
            rest = "".join(buf[cur:])
            self.out(rest + "\b" * (len(rest) - 1))
            cur += 1

    # ------------------------------------------------------------------
    # 명령 실행
    # ------------------------------------------------------------------
    def run_line(self, line: str) -> int:
        try:
            pipelines = parse_shell(line)
        except ShellSyntaxError as exc:
            self.out(f"-sh: syntax error: {exc}\n")
            self.status = 2
            return 2
        rc = self.status
        for op, pipeline in pipelines:
            if op == "&&" and rc != 0:
                continue
            if op == "||" and rc == 0:
                continue
            try:
                rc = self._run_pipeline(pipeline)
            except _SigInt:
                self.out("^C\n")
                rc = 130
            self.status = rc
        return rc

    def _expand_word(self, word: dict[str, Any]) -> str:
        return "".join(self._expand_var(t) if k == "var" else t for k, t in word["parts"])

    def _expand_var(self, name: str) -> str:
        if name == "?":
            return str(self.status)
        if name == "$":
            return str(self.shell_pid)
        if name == "0":
            return "-sh"
        return self.env.get(name, "")

    def _glob(self, word: str) -> list[str]:
        if not any(ch in word for ch in "*?["):
            return [word]
        absolute = word.startswith("/")
        base = "/" if absolute else self.cwd
        parts = [p for p in word.split("/") if p]
        results = [("/" if absolute else "", base)]
        for part in parts:
            nxt = []
            for shown, real in results:
                if any(ch in part for ch in "*?["):
                    try:
                        names = self.vfs.listdir(real)
                    except FsError:
                        names = []
                    for nm in names:
                        if nm.startswith(".") and not part.startswith("."):
                            continue
                        if fnmatch.fnmatchcase(nm, part):
                            nxt.append((shown.rstrip("/") + "/" + nm if shown else nm, posixpath.join(real, nm)))
                else:
                    nxt.append((shown.rstrip("/") + "/" + part if shown else part, posixpath.join(real, part)))
            results = nxt
        found = sorted(s for s, _r in results if self.vfs.resolve(_r)[1] is not None)
        return found or [word]

    def _run_pipeline(self, pipeline: list[dict[str, Any]]) -> int:
        """파이프라인 실행. 각 단계는 (stdout, stderr, rc).

        stderr 는 실제 타이밍을 흉내 내어 최종 출력 사이에 끼워 넣는다: 앞 단계가 쓴 양이 파이프 버퍼(64KiB)
        이하이면 다음 단계가 출력하기 전에 끝나므로 맨 앞, 더 많으면 다음 단계가 (전체-64KiB) 만큼 소비했을 때.
        예) ``dd if=/dev/mtd1 bs=64k count=4 | hexdump -C`` 의 records in/out 은 출력 4분의 3 지점에 나타난다.
        """
        data: bytes | None = None  # None: 첫 단계 stdin 은 tty
        inserts: list[tuple[float, bytes]] = []  # (최종 출력에서의 위치 비율, stderr) — 1.0 이상은 끝
        final_out = b""
        rc = 0
        n = len(pipeline)
        for idx, cmd in enumerate(pipeline):
            argv: list[str] = []
            for w in cmd["words"]:
                text = self._expand_word(w)
                if text == "" and w["parts"] and all(k == "var" for k, _ in w["parts"]):
                    continue  # 따옴표 없는 빈 변수 확장은 단어를 만들지 않는다
                argv.extend(self._glob(text) if w.get("glob") else [text])
            redirs = []
            for r in cmd.get("redirs", []):
                r2 = dict(r)
                if "target_word" in r2:
                    r2["target"] = self._expand_word(r2.pop("target_word"))
                redirs.append(r2)
            out, err, rc = self._run_simple(argv, redirs, data, last=(idx == n - 1))
            if err:
                if idx == n - 1:
                    name = posixpath.basename(argv[0]) if argv else ""
                    frac = 2.0 if name == "dd" else -1.0
                elif len(out) <= PIPE_BUF_CAPACITY:
                    frac = -1.0
                else:
                    frac = (len(out) - PIPE_BUF_CAPACITY) / len(out)
                inserts.append((frac, err))
            data = out
            final_out = out
        if not inserts:
            self._emit(final_out)
            return rc
        parts = final_out.splitlines(keepends=True)
        buf = bytearray()
        placed = [False] * len(inserts)
        for i, part in enumerate(parts):
            for k, (frac, err) in enumerate(inserts):
                if not placed[k] and frac < 1.0 and (frac < 0 or i >= int(round(frac * len(parts)))):
                    buf += err
                    placed[k] = True
            buf += part
        for k, (_frac, err) in enumerate(inserts):
            if not placed[k]:
                buf += err
        self._emit(bytes(buf))
        return rc

    def _emit(self, data: bytes) -> None:
        if not data:
            return
        step = 65536
        for i in range(0, len(data), step):
            if self.dev.ctrlc():
                raise _SigInt()
            self.out(data[i : i + step])

    def _run_simple(self, argv: list[str], redirs: list[dict[str, Any]], stdin: bytes | None, *, last: bool) -> tuple[bytes, bytes, int]:
        # 리다이렉션 해석
        out_target = None
        err_target = None
        err_to_out = False
        in_file = None
        for r in redirs:
            if r["op"] in (">", ">>") and r["fd"] == 1:
                out_target = (r["target"], r["op"] == ">>")
            elif r["op"] in (">", ">>") and r["fd"] == 2:
                err_target = (r["target"], r["op"] == ">>")
            elif r["op"] == ">&" and r["fd"] == 2 and r["target"] == "1":
                err_to_out = True
            elif r["op"] == "<":
                in_file = r["target"]
        assigns = {}
        while argv and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0]):
            k, v = argv[0].split("=", 1)
            assigns[k] = v
            argv = argv[1:]
        if not argv:
            self.env.update(assigns)
            return b"", b"", 0
        if in_file is not None:
            try:
                stdin = self.vfs.read(in_file, self.cwd)
            except FsError as exc:
                return b"", f"-sh: can't open '{in_file}': {exc.text}\n".encode(), 1
        self._check_destructive(argv, redirs)
        out, err, rc = self.execute(argv, stdin)
        if err_to_out:
            out, err = out + err, b""
        if out_target is not None:
            path, append = out_target
            if path != "/dev/null":
                try:
                    self.vfs.write(path, out, self.cwd, append=append)
                except FsError as exc:
                    err += f"-sh: can't create {path}: {exc.text}\n".encode()
                    rc = 1
            out = b""
        if err_target is not None:
            path, append = err_target
            if path != "/dev/null":
                try:
                    self.vfs.write(path, err, self.cwd, append=append)
                    err = b""
                except FsError as exc:
                    err = f"-sh: can't create {path}: {exc.text}\n".encode()
                    rc = 1
            else:
                err = b""
        return out, err, rc

    # -- 파괴적 작업 감지 (안전 게이트 검증용 기록) -------------------------
    _DESTRUCTIVE_CMDS = {"flash_erase", "flash_eraseall", "flashcp", "nandwrite", "nandtest", "fw_setenv", "passwd",
                         "chpasswd", "adduser", "deluser", "addgroup", "delgroup", "mkfs", "mke2fs", "mkfs.jffs2",
                         "mkfs.ubifs", "ubiformat", "ubimkvol", "ubirmvol", "ubiupdatevol", "sysupgrade", "i2cset",
                         "flash_lock", "flash_unlock", "fdisk", "eraseall", "wipefs", "shred"}

    def _check_destructive(self, argv: list[str], redirs: list[dict[str, Any]]) -> None:
        name = posixpath.basename(argv[0])
        if name == "busybox" and len(argv) > 1:
            argv = argv[1:]
            name = argv[0]
        persistent = [p.rstrip("/") for p in ("/mnt/mtd", "/mnt/flash", "/mnt/config", "/mnt/custom", "/config",
                                               "/data", "/etc/config", "/home", "/opt", "/usr/local", "/var/lib",
                                               "/appfs", "/mnt/sd")]

        def is_persistent(p: str) -> bool:
            q = VFS.norm(p, self.cwd)
            return any(q == b or q.startswith(b + "/") for b in persistent)

        def is_flashdev(p: str) -> bool:
            q = VFS.norm(p, self.cwd)
            return bool(re.match(r"/dev/(mtd|mtdblock)\d+", q))

        reason = None
        if name in self._DESTRUCTIVE_CMDS or name.startswith("mkfs"):
            reason = name
        elif name == "dd" and any(a.startswith("of=") and (is_flashdev(a[3:]) or is_persistent(a[3:])) for a in argv[1:]):
            reason = "dd of=flash"
        elif name in ("mtd", "mtd_debug") and len(argv) > 1 and argv[1] in ("write", "erase", "unlock", "jffs2write"):
            reason = f"{name} {argv[1]}"
        elif name in ("devmem", "devmem2", "himm") and len([a for a in argv[1:] if not a.startswith("-")]) >= (3 if name != "himm" else 2):
            reason = f"{name} write"
        elif name in ("rm", "mv", "cp", "touch", "mkdir", "tee", "chmod", "chown", "ln", "truncate"):
            paths = [a for a in argv[1:] if not a.startswith("-")]
            if name in ("chmod", "chown") and paths:
                paths = paths[1:]
            if name in ("cp", "mv", "ln") and len(paths) >= 2:
                paths = paths[-1:]
            if any(is_persistent(p) or is_flashdev(p) for p in paths):
                reason = f"{name} persistent"
            elif name in ("rm", "mv") and any(VFS.norm(p, self.cwd).startswith(("/etc", "/bin", "/sbin", "/usr", "/lib")) for p in paths):
                reason = f"{name} system path"
        for r in redirs:
            if r["op"] in (">", ">>") and r["fd"] in (1, 2) and (is_flashdev(r["target"]) or is_persistent(r["target"])):
                reason = reason or f"redirect > {r['target']}"
        if reason:
            # 셸 쪽은 실행 직전에 기록한다 (명령이 실패해도 "기기에 도달한 파괴적 시도"로 남긴다)
            self.dev.record_destructive("shell", reason=reason, argv=list(argv), cmd=" ".join(argv),
                                        redirs=[f"{r['fd']}{r['op']}{r['target']}" for r in redirs])

    # -- 디스패치 ------------------------------------------------------
    def _applet_available(self, name: str) -> bool:
        return name in set(self.lx.get("applets") or [])

    def execute(self, argv: list[str], stdin: bytes | None) -> tuple[bytes, bytes, int]:
        name = argv[0]
        builtin = _BUILTINS.get(name)
        if builtin is not None:
            return builtin(self, argv, stdin)
        if "/" in name:
            real, node = self.vfs.resolve(name, self.cwd)
            if node is None:
                return b"", f"-sh: {name}: not found\n".encode(), 127
            if node.kind == "dir":
                return b"", f"-sh: {name}: Permission denied\n".encode(), 126
            base = posixpath.basename(real)
            if base == "busybox":
                base = posixpath.basename(name)
            if base == "busybox":
                return self._busybox(argv, stdin)
            return self._dispatch(base, argv, stdin)
        # PATH 탐색
        for d in self.env.get("PATH", "/bin:/sbin:/usr/bin:/usr/sbin").split(":"):
            real, node = self.vfs.resolve(posixpath.join(d or "/", name), "/")
            if node is not None and node.kind == "file":
                base = posixpath.basename(real)
                if base == "busybox" and name != "busybox":
                    base = name
                if base == "busybox":
                    return self._busybox(argv, stdin)
                return self._dispatch(base, argv, stdin)
        return b"", f"-sh: {name}: not found\n".encode(), 127

    def _busybox(self, argv: list[str], stdin: bytes | None) -> tuple[bytes, bytes, int]:
        if len(argv) == 1:
            return self._busybox_help().encode(), b"", 0
        if argv[1] in ("--list", "--list-full"):
            names = sorted(self.lx.get("applets") or [])
            return ("\n".join(names) + "\n").encode(), b"", 0
        sub = argv[1]
        if not self._applet_available(sub):
            return b"", f"{sub}: applet not found\n".encode(), 127
        return self._dispatch(sub, argv[1:], stdin)

    def _busybox_help(self) -> str:
        banner = self.lx.get("busybox_banner", "BusyBox")
        head = (f"{banner} multi-call binary.\n"
                "BusyBox is copyrighted by many authors between 1998-2015.\n"
                "Licensed under GPLv2. See source distribution for detailed\n"
                "copyright notices.\n\n"
                "Usage: busybox [function [arguments]...]\n"
                "   or: busybox --list[-full]\n"
                "   or: busybox --install [-s] [DIR]\n"
                "   or: function [arguments]...\n\n"
                "\tBusyBox is a multi-call binary that combines many common Unix\n"
                "\tutilities into a single executable.  Most people will create a\n"
                "\tlink to busybox for each function they wish to use and BusyBox\n"
                "\twill act like whatever it was invoked as.\n\n"
                "Currently defined functions:\n")
        out = [head]
        col = 0
        width = 80 - 1
        for a in sorted(self.lx.get("applets") or [], key=lambda s: s.encode()):
            len2 = len(a) + 2
            if col >= width - len2:
                out.append(",\n")
                col = 0
            if col == 0:
                col = 6
                out.append("\t")
            else:
                out.append(", ")
            out.append(a)
            col += len2
        out.append("\n\n")
        return "".join(out)

    def _dispatch(self, name: str, argv: list[str], stdin: bytes | None) -> tuple[bytes, bytes, int]:
        fn = _APPLETS.get(name)
        if fn is None:
            return b"", f"{name}: (pweh simulator: applet not emulated)\n".encode(), 1
        return fn(self, argv, stdin)

    # -- 장치 I/O -------------------------------------------------------
    def part_for_dev(self, path: str) -> dict[str, Any] | None:
        m = re.fullmatch(r"/dev/(?:mtd|mtdblock)(\d+)(ro)?", path)
        if not m:
            return None
        i = int(m.group(1))
        return self.parts[i] if i < len(self.parts) else None

    def device_read(self, path: str, length: int | None, offset: int = 0) -> bytes:
        part = self.part_for_dev(path)
        if part is not None:
            size = part["size"]
            if offset >= size:
                return b""
            n = size - offset if length is None else min(length, size - offset)
            return self.dev.flash.read(part["offset"] + offset, n)
        if path == "/dev/null":
            return b""
        if path == "/dev/zero":
            return bytes(length if length is not None else 1 << 20)
        if path in ("/dev/urandom", "/dev/random"):
            n = length if length is not None else 1 << 20
            seed = hashlib.sha256(f"urandom:{time.monotonic_ns()}".encode()).digest()
            out = bytearray()
            ctr = 0
            while len(out) < n:
                out += hashlib.sha256(seed + ctr.to_bytes(8, "little")).digest()
                ctr += 1
            return bytes(out[:n])
        raise FsError("EACCES", path)

    def device_write(self, path: str, data: bytes, offset: int = 0) -> None:
        part = self.part_for_dev(path)
        if part is not None:
            if path.endswith("ro"):
                raise FsError("EACCES", path)
            if offset + len(data) > part["size"]:
                raise FsError("EINVAL", path)
            if "mtdblock" in path:
                # mtdblock: 블록 단위 read-modify-erase-write
                fl = self.dev.flash
                start = part["offset"] + offset
                es = fl.erase_size
                b0 = start - start % es
                b1 = start + len(data)
                b1 = b1 + (es - b1 % es) % es
                buf = bytearray(fl.read(b0, b1 - b0))
                buf[start - b0 : start - b0 + len(data)] = data
                fl.erase(b0, b1 - b0)
                fl.program(b0, bytes(buf))
            else:
                self.dev.flash.program(part["offset"] + offset, data)
            return
        if path in ("/dev/null", "/dev/console", "/dev/tty"):
            if path != "/dev/null":
                self.out(data)
            return
        raise FsError("EACCES", path)

    # -- /proc 내용 ----------------------------------------------------
    def processes(self) -> list[tuple[int, str, int, str, str]]:
        procs = [tuple(p) for p in (self.lx.get("processes") or [])]
        procs.append((self.shell_pid, self.logged_in_user, 1612, "S", "-sh"))
        return procs  # type: ignore[return-value]

    def proc_file(self, name: str) -> str:
        if name == "mtd":
            lines = ["dev:    size   erasesize  name"]
            es = self.prof["flash"]["erase_size"]
            for i, p in enumerate(self.parts):
                lines.append(f'mtd{i}: {p["size"]:08x} {es:08x} "{p["name"]}"')
            return "\n".join(lines) + "\n"
        if name == "cpuinfo":
            text = self.kn.get("cpuinfo") or ""
            return text if text.endswith("\n") else text + "\n"
        if name == "cmdline":
            return self.cmdline + "\n"
        if name == "version":
            return self.kn.get("version_line", f"Linux version {self.kn['version']}") + "\n"
        if name == "meminfo":
            mi = self.kn.get("meminfo") or {}
            keys = ["MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapCached", "Active", "Inactive",
                    "SwapTotal", "SwapFree", "Dirty", "Writeback", "AnonPages", "Mapped", "Shmem", "Slab",
                    "KernelStack", "PageTables", "VmallocTotal", "VmallocUsed"]
            defaults = {"SwapCached": 0, "Active": 6100, "Inactive": 3400, "SwapTotal": 0, "SwapFree": 0, "Dirty": 0,
                        "Writeback": 0, "AnonPages": 2156, "Mapped": 2316, "Shmem": 52, "Slab": 3912,
                        "KernelStack": 344, "PageTables": 132, "VmallocTotal": 991232, "VmallocUsed": 0}
            out = []
            for k in keys:
                if k in mi or k in defaults:
                    v = int(mi.get(k, defaults.get(k, 0)))
                    out.append(f"{k + ':':<16}{v:8d} kB")
            return "\n".join(out) + "\n"
        if name == "mounts":
            return "".join(f"{m[0]} {m[1]} {m[2]} {m[3]} 0 0\n" for m in (self.lx.get("mounts") or []))
        if name == "partitions":
            lines = ["major minor  #blocks  name", ""]
            for i, p in enumerate(self.parts):
                lines.append(f"  31 {i:8d} {p['size'] // 1024:10d} mtdblock{i}")
            return "\n".join(lines) + "\n"
        if name == "uptime":
            up = self.uptime()
            return f"{up:.2f} {up * 0.93:.2f}\n"
        if name == "loadavg":
            return f"0.00 0.01 0.00 1/{len(self.processes())} {self.next_pid}\n"
        if name == "filesystems":
            return "nodev\tsysfs\nnodev\trootfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tdevtmpfs\n\tsquashfs\n\tjffs2\n"
        if name == "devices":
            return "Character devices:\n  1 mem\n  4 /dev/vc/0\n  5 /dev/tty\n  5 /dev/console\n 90 mtd\n\nBlock devices:\n 31 mtdblock\n"
        if name == "stat":
            return "cpu  120 0 340 51234 12 0 8 0 0 0\n"
        m = re.fullmatch(r"(\d+)/(cmdline|status|comm)", name)
        if m:
            pid = int(m.group(1))
            for p in self.processes():
                if p[0] == pid:
                    if m.group(2) == "cmdline":
                        return "\0".join(p[4].split()) + "\0"
                    if m.group(2) == "comm":
                        return p[4].split()[0].strip("[]-").rsplit("/", 1)[-1] + "\n"
                    return f"Name:\t{p[4].split()[0].strip('[]-').rsplit('/', 1)[-1]}\nState:\t{p[3][0]}\nPid:\t{pid}\n"
        return ""


# ---------------------------------------------------------------------------
# 셸 구문 분석 (ash 부분 집합)
# ---------------------------------------------------------------------------
class ShellSyntaxError(Exception):
    pass


def parse_shell(line: str, expand: Callable[[str], str] | None = None) -> list[tuple[str, list[dict[str, Any]]]]:
    """``a | b && c; d > f 2>&1`` → [(op, [cmd, ...]), ...]. op 는 앞 파이프라인과의 연결(';','&&','||')."""
    tokens: list[tuple[str, Any]] = []
    i = 0
    n = len(line)
    word: list[tuple[str, str]] = []  # [(kind, text)] kind: lit|var — 변수는 실행 직전에 확장한다 ($? 등)
    in_word = False
    glob = False

    def flush() -> None:
        nonlocal word, in_word, glob
        if in_word:
            merged: list[tuple[str, str]] = []
            for k, t in word:
                if k == "lit" and merged and merged[-1][0] == "lit":
                    merged[-1] = ("lit", merged[-1][1] + t)
                else:
                    merged.append((k, t))
            tokens.append(("word", {"parts": merged, "glob": glob,
                                    "text": "".join(t for k, t in merged if k == "lit")}))
        word = []
        in_word = False
        glob = False

    def read_var(j: int) -> tuple[tuple[str, str], int]:
        if j + 1 < n and line[j + 1] == "{":
            k = line.find("}", j + 2)
            if k < 0:
                raise ShellSyntaxError("bad substitution")
            return ("var", line[j + 2 : k]), k + 1
        if j + 1 < n and line[j + 1] in "?$0":
            return ("var", line[j + 1]), j + 2
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(line, j + 1)
        if m:
            return ("var", m.group(0)), m.end()
        return ("lit", "$"), j + 1

    while i < n:
        c = line[i]
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "#" and not in_word:
            break
        if c in ";|&<>":
            # fd 번호 접두 (2>, 1>&2)
            fd = None
            if c in "<>" and in_word and all(k == "lit" for k, _ in word) and "".join(t for _, t in word).isdigit() and not glob:
                fd = int("".join(t for _, t in word))
                word = []
                in_word = False
            else:
                flush()
            if line.startswith("&&", i):
                tokens.append(("op", "&&"))
                i += 2
                continue
            if line.startswith("||", i):
                tokens.append(("op", "||"))
                i += 2
                continue
            if c in ";|":
                tokens.append(("op", c))
                i += 1
                continue
            if c == "&" and not line.startswith("&>", i):
                tokens.append(("op", ";"))  # 백그라운드는 순차 실행으로 단순화
                i += 1
                continue
            if line.startswith("&>", i):
                tokens.append(("redir", {"fd": 1, "op": ">", "both": True}))
                i += 2
                continue
            if line.startswith(">>", i):
                tokens.append(("redir", {"fd": 1 if fd is None else fd, "op": ">>"}))
                i += 2
                continue
            if line.startswith(">&", i):
                m = re.match(r">&(\d)", line[i:])
                if m:
                    tokens.append(("redir", {"fd": 1 if fd is None else fd, "op": ">&", "target": m.group(1)}))
                    i += len(m.group(0))
                    continue
            if c == ">":
                tokens.append(("redir", {"fd": 1 if fd is None else fd, "op": ">"}))
                i += 1
                continue
            if c == "<":
                tokens.append(("redir", {"fd": 0 if fd is None else fd, "op": "<"}))
                i += 1
                continue
        if c == "\\":
            if i + 1 < n:
                word.append(("lit", line[i + 1]))
                in_word = True
                i += 2
                continue
            i += 1
            continue
        if c == "'":
            k = line.find("'", i + 1)
            if k < 0:
                raise ShellSyntaxError("unterminated quoted string")
            word.append(("lit", line[i + 1 : k]))
            in_word = True
            i = k + 1
            continue
        if c == '"':
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise ShellSyntaxError("unterminated quoted string")
                ch = line[j]
                if ch == '"':
                    j += 1
                    break
                if ch == "\\" and j + 1 < n and line[j + 1] in '"\\$`':
                    buf.append(line[j + 1])
                    j += 2
                    continue
                if ch == "$":
                    seg, j = read_var(j)
                    if buf:
                        word.append(("lit", "".join(buf)))
                        buf = []
                    word.append(seg)
                    continue
                buf.append(ch)
                j += 1
            word.append(("lit", "".join(buf)))
            in_word = True
            i = j
            continue
        if c == "$":
            seg, i = read_var(i)
            word.append(seg)
            in_word = True
            continue
        if c in "*?[":
            glob = True
        word.append(("lit", c))
        in_word = True
        i += 1
    flush()

    result: list[tuple[str, list[dict[str, Any]]]] = []
    op = ";"
    pipeline: list[dict[str, Any]] = []
    cmd: dict[str, Any] = {"words": [], "redirs": []}
    pending_redir: dict[str, Any] | None = None
    for kind, val in tokens:
        if pending_redir is not None:
            if kind != "word":
                raise ShellSyntaxError("unexpected redirection")
            pending_redir["target_word"] = val
            pending_redir["target"] = val["text"]
            cmd["redirs"].append(pending_redir)
            if pending_redir.pop("both", False):
                cmd["redirs"].append({"fd": 2, "op": ">&", "target": "1"})
            pending_redir = None
            continue
        if kind == "word":
            cmd["words"].append(val)
        elif kind == "redir":
            if val["op"] == ">&":
                cmd["redirs"].append(val)
            else:
                pending_redir = dict(val)
        elif kind == "op":
            if val == "|":
                if not cmd["words"]:
                    raise ShellSyntaxError("unexpected \"|\"")
                pipeline.append(cmd)
                cmd = {"words": [], "redirs": []}
            else:
                if cmd["words"] or cmd["redirs"]:
                    pipeline.append(cmd)
                elif pipeline:
                    raise ShellSyntaxError(f"unexpected \"{val}\"")
                if pipeline:
                    result.append((op, pipeline))
                elif val in ("&&", "||"):
                    raise ShellSyntaxError(f"unexpected \"{val}\"")
                pipeline = []
                cmd = {"words": [], "redirs": []}
                op = val
    if pending_redir is not None:
        raise ShellSyntaxError("unexpected newline")
    if cmd["words"] or cmd["redirs"]:
        pipeline.append(cmd)
    elif pipeline:
        raise ShellSyntaxError("unexpected end of file")
    if pipeline:
        result.append((op, pipeline))
    return result


# ---------------------------------------------------------------------------
# 내장 명령 / 애플릿
# ---------------------------------------------------------------------------
Result = tuple[bytes, bytes, int]


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _read_inputs(lx: Linux, files: list[str], stdin: bytes | None, applet: str) -> tuple[list[tuple[str, bytes]], bytes, int]:
    """파일 목록 또는 stdin. 반환: [(이름, 데이터)], stderr, rc."""
    err = b""
    rc = 0
    out: list[tuple[str, bytes]] = []
    if not files:
        files = ["-"]
    for f in files:
        if f == "-":
            out.append(("-", stdin if stdin is not None else lx_read_tty_eof(lx)))
            continue
        try:
            out.append((f, lx.vfs.read(f, lx.cwd)))
        except FsError as exc:
            if exc.errno_name == "EISDIR":
                err += _b(f"{applet}: read error: Is a directory\n")
            else:
                err += _b(f"{applet}: can't open '{f}': {exc.text}\n")
            rc = 1
    return out, err, rc


def lx_read_tty_eof(lx: Linux) -> bytes:
    """stdin 이 콘솔이면 Ctrl-D 까지 줄 단위로 읽는다 (에코 포함)."""
    data = []
    while True:
        line = lx.read_tty_line(echo=True)
        if line is None:
            break
        data.append(line + "\n")
    return "".join(data).encode()


def b_echo(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    args = argv[1:]
    newline = True
    escapes = False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        if "n" in args[0]:
            newline = False
        if "e" in args[0]:
            escapes = True
        args = args[1:]
    text = " ".join(args)
    if escapes:
        text = text.encode("latin-1", "replace").decode("unicode_escape", "replace")
    return _b(text + ("\n" if newline else "")), b"", 0


def b_cd(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    target = argv[1] if len(argv) > 1 else lx.env.get("HOME", "/")
    try:
        real, node = lx.vfs.resolve(target, lx.cwd)
    except FsError as exc:
        return b"", _b(f"-sh: cd: can't cd to {target}: {exc.text}\n"), 1
    if node is None:
        return b"", _b(f"-sh: cd: can't cd to {target}: No such file or directory\n"), 1
    if node.kind != "dir":
        return b"", _b(f"-sh: cd: can't cd to {target}: Not a directory\n"), 1
    del real
    lx.cwd = VFS.norm(target, lx.cwd)  # ash 의 논리적 cd (심볼릭 링크 경로 유지)
    return b"", b"", 0


def b_pwd(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b(lx.cwd + "\n"), b"", 0


def b_exit(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    code = int(argv[1]) if len(argv) > 1 and argv[1].lstrip("-").isdigit() else lx.status
    raise _ShellExit(code)


def b_export(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    for a in argv[1:]:
        if "=" in a:
            k, v = a.split("=", 1)
            lx.env[k] = v
    if len(argv) == 1:
        return _b("".join(f"export {k}='{v}'\n" for k, v in sorted(lx.env.items()))), b"", 0
    return b"", b"", 0


def b_unset(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    for a in argv[1:]:
        lx.env.pop(a, None)
    return b"", b"", 0


def b_true(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return b"", b"", 0


def b_false(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return b"", b"", 1


def b_test(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    a = argv[1:]
    if argv[0] == "[":
        if not a or a[-1] != "]":
            return b"", b"-sh: [: missing ]\n", 2
        a = a[:-1]
    neg = False
    if a and a[0] == "!":
        neg, a = True, a[1:]
    res = False
    if len(a) == 1:
        res = a[0] != ""
    elif len(a) == 2:
        op, x = a
        if op in ("-e", "-f", "-d", "-L", "-c", "-b", "-r", "-w", "-x", "-s"):
            try:
                real, node = lx.vfs.resolve(x, lx.cwd, follow=op != "-L")
            except FsError:
                node = None
            res = {"-e": node is not None, "-f": node is not None and node.kind == "file",
                   "-d": node is not None and node.kind == "dir", "-L": node is not None and node.kind == "symlink",
                   "-c": node is not None and node.kind == "chr", "-b": node is not None and node.kind == "blk",
                   "-r": node is not None, "-w": node is not None and lx.vfs.writable(real),
                   "-x": node is not None and bool(node.mode & 0o111),
                   "-s": node is not None and node.size > 0}[op]
        elif op == "-n":
            res = x != ""
        elif op == "-z":
            res = x == ""
    elif len(a) == 3:
        x, op, y = a
        try:
            if op == "=" or op == "==":
                res = x == y
            elif op == "!=":
                res = x != y
            elif op in ("-eq", "-ne", "-lt", "-gt", "-le", "-ge"):
                xi, yi = int(x), int(y)
                res = {"-eq": xi == yi, "-ne": xi != yi, "-lt": xi < yi, "-gt": xi > yi, "-le": xi <= yi, "-ge": xi >= yi}[op]
        except ValueError:
            return b"", _b(f"-sh: {argv[0]}: {x if not x.lstrip('-').isdigit() else y}: bad number\n"), 2
    if neg:
        res = not res
    return b"", b"", 0 if res else 1


def b_type(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    out = []
    rc = 0
    args = argv[1:]
    if argv[0] == "command":
        if not args or args[0] != "-v":
            return lx.execute(args, stdin) if args else (b"", b"", 0)
        args = args[1:]
    for a in args:
        if a in _BUILTINS:
            out.append(f"{a} is a shell builtin" if argv[0] == "type" else a)
            continue
        path = _which(lx, a)
        if path:
            out.append(f"{a} is {path}" if argv[0] == "type" else path)
        else:
            if argv[0] == "type":
                out.append(f"{a}: not found")
            rc = 1
    return _b("".join(x + "\n" for x in out)), b"", rc


def _which(lx: Linux, name: str) -> str | None:
    if "/" in name:
        return name if lx.vfs.resolve(name, lx.cwd)[1] is not None else None
    for d in lx.env.get("PATH", "").split(":"):
        p = posixpath.join(d or "/", name)
        try:
            node = lx.vfs.resolve(p, "/")[1]
        except FsError:
            node = None
        if node is not None and node.kind == "file":
            return p
    return None


def b_history(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b("".join(f"{i:5d} {h}\n" for i, h in enumerate(lx.history))), b"", 0


def b_sh(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    args = argv[1:]
    if args and args[0] == "-c" and len(args) > 1:
        script = args[1]
    elif args and not args[0].startswith("-"):
        try:
            script = lx.vfs.read(args[0], lx.cwd).decode("utf-8", "replace")
        except FsError as exc:
            return b"", _b(f"sh: can't open '{args[0]}': {exc.text}\n"), 2
    else:
        return b"", b"", 0
    rc = 0
    # 하위 셸 출력은 곧바로 콘솔로 (단순화)
    for ln in script.splitlines():
        if ln.strip() and not ln.strip().startswith("#"):
            rc = lx.run_line(ln)
    return b"", b"", rc


_BUILTINS: dict[str, Callable[[Linux, list[str], bytes | None], Result]] = {
    "echo": b_echo, "cd": b_cd, "pwd": b_pwd, "exit": b_exit, "logout": b_exit, "export": b_export,
    "unset": b_unset, "true": b_true, "false": b_false, "test": b_test, "[": b_test, "[[": b_test,
    "type": b_type, "command": b_type, "history": b_history, ":": b_true,
}


# -- 애플릿 ---------------------------------------------------------------

def a_cat(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    files = [a for a in argv[1:] if not (a.startswith("-") and a != "-")]
    data, err, rc = _read_inputs(lx, files, stdin, "cat")
    return b"".join(d for _, d in data), err, rc


def a_ls(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    opts = set()
    paths = []
    for a in argv[1:]:
        if a.startswith("-") and len(a) > 1:
            opts.update(a[1:])
        else:
            paths.append(a)
    if not paths:
        paths = ["."]
    long = "l" in opts
    show_all = "a" in opts or "A" in opts
    one = "1" in opts
    err = b""
    rc = 0
    out: list[str] = []
    files: list[tuple[str, str, Node]] = []
    dirs: list[tuple[str, str]] = []
    for p in paths:
        try:
            real, node = lx.vfs.resolve(p, lx.cwd, follow=not long)
            if node is not None and node.kind == "symlink" and not long:
                real, node = lx.vfs.resolve(p, lx.cwd)
            if long and node is not None and node.kind == "symlink" and p.endswith("/"):
                real, node = lx.vfs.resolve(p, lx.cwd)
        except FsError as exc:
            err += _b(f"ls: {p}: {exc.text}\n")
            rc = 1
            continue
        if node is None:
            err += _b(f"ls: {p}: No such file or directory\n")
            rc = 1
            continue
        if node.kind == "dir" and "d" not in opts:
            dirs.append((p, real))
        else:
            files.append((p, real, node))

    def entry_line(name: str, real: str, node: Node) -> str:
        if not long:
            return name
        mode = _mode_string(node)
        size = node.meta.get("size", node.size)
        if node.kind in ("chr", "blk"):
            sz = f"{node.major:4d}, {node.minor:4d}"
        else:
            sz = f"{size:9d}"
        nlink = 2 if node.kind == "dir" else 1
        date = "Jan  1 00:00" if real.startswith(("/proc", "/dev", "/tmp")) else _fw_date(lx)
        tail = f" -> {node.target}" if node.kind == "symlink" else ""
        return f"{mode} {nlink:4d} {'root':<8} {'root':<8} {sz} {date} {name}{tail}"

    names_out: list[str] = []
    for p, real, node in files:
        names_out.append(entry_line(p, real, node))
    if names_out:
        out.extend(names_out if (long or one) else _columns(names_out))
    for i, (p, real) in enumerate(dirs):
        if len(paths) > 1:
            if out:
                out.append("")
            out.append(f"{p}:")
        try:
            names = lx.vfs.listdir(real)
        except FsError as exc:
            err += _b(f"ls: {p}: {exc.text}\n")
            continue
        if show_all:
            names = [".", ".."] + names
        else:
            names = [n for n in names if not n.startswith(".")]
        entries = []
        if long:
            entries.append(f"total {len(names)}")
        for nm in names:
            if nm in (".", ".."):
                node = Node("dir", S_IFDIR | 0o755)
                entries.append(entry_line(nm, real, node) if long else nm)
                continue
            child = posixpath.join(real, nm)
            try:
                _r, cnode = lx.vfs.resolve(child, "/", follow=False)
            except FsError:
                cnode = None
            if cnode is None:
                continue
            entries.append(entry_line(nm, child, cnode) if long else nm)
        if long or one:
            out.extend(entries)
        else:
            out.extend(_columns(entries))
    return _b("".join(x + "\n" for x in out)), err, rc


def _fw_date(lx: Linux) -> str:
    bd = lx.prof.get("firmware", {}).get("build_date", "2020-01-01 00:00:00")
    try:
        y, mo, d = bd.split()[0].split("-")
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        return f"{months[int(mo) - 1]} {int(d):2d}  {y}"
    except Exception:
        return "Jan  1  2020"


def _columns(names: list[str], width: int = 80) -> list[str]:
    """BusyBox ls showfiles(): 열 우선 배치, 열 폭 = 최장 이름 + 1."""
    if not names:
        return []
    column_width = max(len(n) for n in names) + 1
    ncols = max(1, width // column_width)
    nrows = (len(names) + ncols - 1) // ncols
    if ncols <= 1:
        return list(names)
    lines = []
    for row in range(nrows):
        line = ""
        column = 0
        nexttab = 0
        for nc in range(ncols):
            i = nc * nrows + row
            if i < len(names):
                if column > 0:
                    pad = nexttab - column
                    line += " " * pad
                    column += pad
                nexttab = column + column_width
                line += names[i]
                column += len(names[i])
        lines.append(line)
    return lines


def _mode_string(node: Node) -> str:
    t = {"dir": "d", "file": "-", "symlink": "l", "chr": "c", "blk": "b"}[node.kind]
    m = node.mode
    s = ""
    for shift in (6, 3, 0):
        s += "r" if m & (4 << shift) else "-"
        s += "w" if m & (2 << shift) else "-"
        s += "x" if m & (1 << shift) else "-"
    if m & 0o1000:
        s = s[:-1] + ("t" if s[-1] == "x" else "T")
    return t + s


def a_ps(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    lines = ["  PID USER       VSZ STAT COMMAND"]
    procs = list(lx.processes())
    pid = lx.next_pid
    lx.next_pid += 1
    procs.append((pid, lx.logged_in_user, 1600, "R", " ".join(argv)))
    for p in procs:
        state = (p[3] + "   ")[:3]
        line = f"{p[0]:5d} {p[1][:8]:<8} {smart_ulltoa5(int(p[2]))} {state}  {p[4]}"
        lines.append(line[:80])
    return _b("\n".join(lines) + "\n"), b"", 0


def a_mount(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) == 1:
        return _b("".join(f"{m[0]} on {m[1]} type {m[2]} ({m[3]})\n" for m in (lx.lx.get("mounts") or []))), b"", 0
    lx.dev.record({"type": "linux_modify", "argv": argv})
    return b"", b"", 0


def a_umount(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) < 2:
        return b"", b"", 1
    return b"", _b(f"umount: can't unmount {argv[-1]}: Device or resource busy\n"), 1


def a_id(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    u = lx.logged_in_user
    uid = 0 if u == "root" else 1000
    if "-u" in argv:
        return _b(f"{uid}\n"), b"", 0
    if "-un" in argv or ("-u" in argv and "-n" in argv):
        return _b(f"{u}\n"), b"", 0
    return _b(f"uid={uid}({u}) gid={uid}({u}) groups={uid}({u})\n"), b"", 0


def a_whoami(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b(lx.logged_in_user + "\n"), b"", 0


def a_uname(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    opts = set("".join(a[1:] for a in argv[1:] if a.startswith("-")))
    host = lx.lx.get("hostname") or "(none)"
    fields = {"s": "Linux", "n": host, "r": lx.kn.get("version", ""), "v": lx.kn.get("build", "#1"),
              "m": lx.kn.get("machine", "armv7l"), "o": "GNU/Linux"}
    if not opts:
        opts = {"s"}
    if "a" in opts:
        order = ["s", "n", "r", "v", "m", "o"]
    else:
        order = [k for k in ["s", "n", "r", "v", "m", "o"] if k in opts]
    return _b(" ".join(fields[k] for k in order) + "\n"), b"", 0


def a_hostname(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) > 1 and not argv[1].startswith("-"):
        lx.lx = dict(lx.lx)
        lx.lx["hostname"] = argv[1]
        return b"", b"", 0
    return _b((lx.lx.get("hostname") or "(none)") + "\n"), b"", 0


def a_ifconfig(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    positional = [a for a in argv[1:] if not a.startswith("-")]
    ifaces = dict(lx.lx.get("interfaces") or {})
    if len(positional) > 1:
        lx.dev.record({"type": "linux_modify", "argv": argv})
        return b"", b"", 0
    out = []
    names = list(ifaces) + ["lo"]
    if positional:
        if positional[0] not in names:
            return b"", _b(f"ifconfig: {positional[0]}: error fetching interface information: Device not found\n"), 1
        names = [positional[0]]
    for name in names:
        if name == "lo":
            out.append("lo        Link encap:Local Loopback  \n"
                       "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
                       "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
                       "          RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n"
                       "          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n"
                       "          collisions:0 txqueuelen:1 \n"
                       "          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n\n")
            continue
        i = ifaces[name]
        out.append(f"{name:<9} Link encap:Ethernet  HWaddr {i.get('hwaddr', '00:00:00:00:00:00').upper()}  \n"
                   f"          inet addr:{i.get('inet')}  Bcast:{i.get('bcast')}  Mask:{i.get('mask')}\n"
                   f"          {i.get('flags', 'UP BROADCAST MULTICAST')}  MTU:{i.get('mtu', 1500)}  Metric:1\n"
                   "          RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n"
                   "          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n"
                   f"          collisions:0 txqueuelen:{i.get('txqueuelen', 1000)} \n"
                   "          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n\n")
    return _b("".join(out)), b"", 0


def a_netstat(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    opts = set("".join(a[1:] for a in argv[1:] if a.startswith("-")))
    want_tcp = "t" in opts or not ({"t", "u"} & opts)
    want_udp = "u" in opts or not ({"t", "u"} & opts)
    listening = "l" in opts or "a" in opts
    if "a" in opts:
        title = "(servers and established)"
    elif "l" in opts:
        title = "(only servers)"
    else:
        title = "(w/o servers)"
    lines = [f"Active Internet connections {title}",
             f"Proto Recv-Q Send-Q {'Local Address':<23} {'Foreign Address':<23} State       "]
    if listening:
        for proto, addr in lx.lx.get("listening") or []:
            if (proto == "tcp" and want_tcp) or (proto == "udp" and want_udp):
                state = "LISTEN" if proto == "tcp" else ""
                lines.append(f"{proto}   {0:6d} {0:6d} {addr:<23} {'0.0.0.0:*':<23} {state:<12}")
    return _b("\n".join(lines) + "\n"), b"", 0


def a_dmesg(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b("".join(line + "\n" for line in lx.kmsg)), b"", 0


def a_md5sum(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    files = [a for a in argv[1:] if not (a.startswith("-") and a != "-")]
    data, err, rc = _read_inputs(lx, files, stdin, "md5sum")
    out = "".join(f"{hashlib.md5(d).hexdigest()}  {name}\n" for name, d in data)
    return _b(out), err, rc


def a_hexdump(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    canonical = argv[0] == "hd"
    squeeze = True
    length = None
    skip = 0
    files = []
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-C":
            canonical = True
        elif a == "-v":
            squeeze = False
        elif a in ("-n", "-s") and i + 1 < len(args):
            val = _parse_dd_num(args[i + 1])
            if val is None:
                return b"", _b(f"hexdump: invalid number '{args[i + 1]}'\n"), 1
            if a == "-n":
                length = val
            else:
                skip = val
            i += 1
        elif a.startswith("-") and len(a) > 1:
            for ch in a[1:]:
                if ch == "C":
                    canonical = True
                elif ch == "v":
                    squeeze = False
        else:
            files.append(a)
        i += 1
    data_list, err, rc = _read_inputs(lx, files, stdin, "hexdump")
    data = b"".join(d for _, d in data_list)
    data = data[skip:]
    if length is not None:
        data = data[:length]
    if canonical:
        return _b(hexdump_canonical(data, start=skip, squeeze=squeeze)), err, rc
    return _b(_hexdump_default(data, skip, squeeze)), err, rc


def _hexdump_default(data: bytes, start: int, squeeze: bool) -> str:
    """BusyBox hexdump 기본 형식: "%07.7_Ax\\n" + "%07.7_ax " 8/2 "%04x " "\\n"."""
    lines = []
    prev = None
    starred = False
    n = len(data)
    pos = 0
    while pos < n:
        block = data[pos : pos + 16]
        if squeeze and prev is not None and block == prev and len(block) == 16:
            if not starred:
                lines.append("*")
                starred = True
            pos += 16
            continue
        starred = False
        words = []
        for j in range(0, 16, 2):
            if j < len(block):
                w = block[j : j + 2] + (b"\0" if len(block[j : j + 2]) == 1 else b"")
                words.append(f"{int.from_bytes(w, 'little'):04x}")
        lines.append(f"{start + pos:07x} " + " ".join(words))
        prev = block
        pos += 16
    if n:
        lines.append(f"{start + n:07x}")
    return "".join(x + "\n" for x in lines)


def a_base64(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    decode = "-d" in argv[1:]
    files = [a for a in argv[1:] if not a.startswith("-")]
    if len(files) > 1:
        return b"", b"base64: too many arguments\n", 1
    data_list, err, rc = _read_inputs(lx, files, stdin, "base64")
    if rc:
        return b"", err, rc
    data = data_list[0][1] if data_list else b""
    if decode:
        import base64 as b64

        try:
            return b64.b64decode(re.sub(rb"[^A-Za-z0-9+/=]", b"", data)), b"", 0
        except Exception:
            return b"", b"base64: invalid input\n", 1
    return _b(busybox_base64(data)), b"", 0


def _parse_dd_num(text: str) -> int | None:
    """BusyBox dd 접미사: c=1 w=2 b=512 kD/kB=1000 k/K=1024 MD/MB M G ..."""
    m = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)(c|w|b|kD|kB|k|K|MD|MB|M|GD|GB|G)?", text)
    if not m:
        return None
    base = int(m.group(1), 0) if m.group(1).startswith("0x") else int(m.group(1))
    mult = {None: 1, "c": 1, "w": 2, "b": 512, "kD": 1000, "kB": 1000, "k": 1024, "K": 1024, "MD": 10**6,
            "MB": 10**6, "M": 1 << 20, "GD": 10**9, "GB": 10**9, "G": 1 << 30}[m.group(2)]
    return base * mult


def a_dd(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    ops: dict[str, str] = {}
    for a in argv[1:]:
        if "=" not in a:
            return b"", _b(f"dd: invalid option -- '{a}'\nBusyBox v1 multi-call binary.\n"), 1
        k, v = a.split("=", 1)
        ops[k] = v
    bs = None
    ibs = obs = 512
    for key in ("bs", "ibs", "obs", "count", "skip", "seek"):
        if key in ops and _parse_dd_num(ops[key]) is None:
            return b"", _b(f"dd: invalid number '{ops[key]}'\n"), 1
    if "bs" in ops:
        bs = _parse_dd_num(ops["bs"])
        ibs = obs = bs  # type: ignore[assignment]
    else:
        if "ibs" in ops:
            ibs = _parse_dd_num(ops["ibs"])  # type: ignore[assignment]
        if "obs" in ops:
            obs = _parse_dd_num(ops["obs"])  # type: ignore[assignment]
    if not ibs or not obs:
        return b"", b"dd: invalid number '0'\n", 1
    count = _parse_dd_num(ops["count"]) if "count" in ops else None
    skip = _parse_dd_num(ops.get("skip", "0")) or 0
    seek = _parse_dd_num(ops.get("seek", "0")) or 0
    src = ops.get("if")
    dst = ops.get("of")
    # 입력
    if src is None:
        data_src = stdin if stdin is not None else lx_read_tty_eof(lx)
        reader = _BytesReader(data_src)
    else:
        try:
            real, node = lx.vfs.resolve(src, lx.cwd)
        except FsError as exc:
            return b"", _b(f"dd: can't open '{src}': {exc.text}\n"), 1
        if node is None:
            return b"", _b(f"dd: can't open '{src}': No such file or directory\n"), 1
        if node.kind == "dir":
            return b"", _b("dd: read error: Is a directory\n"), 1
        if node.kind in ("chr", "blk"):
            reader = _DevReader(lx, real)
        else:
            reader = _BytesReader(lx.vfs.read(real, "/"))
    reader.skip(skip * ibs)
    chunks = []
    in_full = in_part = 0
    total = 0
    while count is None or in_full + in_part < count:
        if lx.dev.ctrlc():
            raise _SigInt()
        buf = reader.read(ibs)
        if not buf:
            break
        if len(buf) == ibs:
            in_full += 1
        else:
            in_part += 1
        chunks.append(buf)
        total += len(buf)
        if count is None and total > (64 << 20):
            break
    data = b"".join(chunks)
    out_full, out_part = divmod(total, obs)
    out_part = 1 if out_part else 0
    if bs is not None:
        out_full, out_part = in_full, in_part
    out = b""
    if dst is None:
        out = data
    else:
        try:
            real, node = lx.vfs.resolve(dst, lx.cwd)
            if real.startswith("/dev/"):
                lx.device_write(real, data, seek * obs)
            else:
                lx.vfs.write(dst, data, lx.cwd)
        except FsError as exc:
            return b"", _b(f"dd: can't open '{dst}': {exc.text}\n"), 1
    status = ops.get("status")
    err = b""
    if status != "none":
        err = _b(f"{in_full}+{in_part} records in\n{out_full}+{out_part} records out\n")
        if lx.lx.get("dd_third_status_line", True) and status != "noxfer":
            secs = total / 2_500_000 + 0.000041
            rate = int(total / secs) if secs > 0 else 0
            err += _b(f"{total} bytes ({make_human_readable_str(total)}B) copied, {secs:f} seconds, "
                      f"{make_human_readable_str(rate)}B/s\n")
    lx.dev.sleep(total / 2_500_000)
    return out, err, 0


class _BytesReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def skip(self, n: int) -> None:
        self.pos += n

    def read(self, n: int) -> bytes:
        out = self.data[self.pos : self.pos + n]
        self.pos += len(out)
        return out


class _DevReader:
    def __init__(self, lx: Linux, path: str) -> None:
        self.lx = lx
        self.path = path
        self.pos = 0

    def skip(self, n: int) -> None:
        self.pos += n

    def read(self, n: int) -> bytes:
        out = self.lx.device_read(self.path, n, self.pos)
        self.pos += len(out)
        return out


def a_head(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    nlines = 10
    nbytes = None
    files = []
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "-c") and i + 1 < len(args):
            v = _parse_dd_num(args[i + 1])
            if v is None:
                return b"", _b(f"head: invalid number '{args[i + 1]}'\n"), 1
            if a == "-n":
                nlines = v
            else:
                nbytes = v
            i += 2
            continue
        if re.fullmatch(r"-\d+", a):
            nlines = int(a[1:])
        elif a.startswith("-n") and a[2:].isdigit():
            nlines = int(a[2:])
        elif a.startswith("-c") and a[2:].isdigit():
            nbytes = int(a[2:])
        else:
            files.append(a)
        i += 1
    if files and len(files) == 1 and nbytes is not None:
        try:
            real, node = lx.vfs.resolve(files[0], lx.cwd)
            if node is not None and node.kind in ("chr", "blk"):
                return lx.device_read(real, nbytes), b"", 0
        except FsError:
            pass
    data_list, err, rc = _read_inputs(lx, files, stdin, "head")
    out = b""
    for _name, d in data_list:
        if nbytes is not None:
            out += d[:nbytes]
        else:
            out += b"".join(line for line in d.splitlines(keepends=True)[:nlines])
    return out, err, rc


def a_tail(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    nlines = 10
    files = []
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args):
            nlines = int(args[i + 1]) if args[i + 1].isdigit() else 10
            i += 2
            continue
        if re.fullmatch(r"-\d+", a):
            nlines = int(a[1:])
        else:
            files.append(a)
        i += 1
    data_list, err, rc = _read_inputs(lx, files, stdin, "tail")
    out = b""
    for _name, d in data_list:
        lines = d.splitlines(keepends=True)
        out += b"".join(lines[-nlines:] if nlines else [])
    return out, err, rc


def a_wc(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    opts = set("".join(a[1:] for a in argv[1:] if a.startswith("-") and a != "-"))
    files = [a for a in argv[1:] if not (a.startswith("-") and a != "-")]
    data_list, err, rc = _read_inputs(lx, files, stdin, "wc")
    out = []
    for name, d in data_list:
        vals = []
        if not opts or "l" in opts:
            vals.append(d.count(b"\n"))
        if not opts or "w" in opts:
            vals.append(len(d.split()))
        if not opts or "c" in opts:
            vals.append(len(d))
        text = " ".join(f"{v:7d}" for v in vals) if len(vals) > 1 else f"{vals[0]}"
        out.append(text + ("" if name == "-" else f" {name}"))
    return _b("".join(x + "\n" for x in out)), err, rc


def a_grep(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    opts = set()
    args = []
    for a in argv[1:]:
        if a.startswith("-") and len(a) > 1 and not args:
            opts.update(a[1:])
        else:
            args.append(a)
    if not args:
        return b"", b"BusyBox grep: missing pattern\n", 2
    pattern, files = args[0], args[1:]
    flags = re.I if "i" in opts else 0
    try:
        rx = re.compile(pattern if ("E" in opts or "e" in opts) else pattern.replace("\\|", "|"), flags)
    except re.error:
        rx = re.compile(re.escape(pattern), flags)
    data_list, err, rc = _read_inputs(lx, files, stdin, "grep")
    out = []
    count = 0
    for name, d in data_list:
        for no, line in enumerate(d.decode("utf-8", "replace").splitlines(), 1):
            hit = bool(rx.search(line))
            if "v" in opts:
                hit = not hit
            if hit:
                count += 1
                if "c" in opts or "q" in opts or "l" in opts:
                    continue
                prefix = f"{name}:" if len(files) > 1 else ""
                if "n" in opts:
                    prefix += f"{no}:"
                out.append(prefix + line)
    if "c" in opts:
        out = [str(count)]
    return _b("".join(x + "\n" for x in out)) if "q" not in opts else b"", err, (0 if count else 1) if not rc else 2


def a_free(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    mi = lx.kn.get("meminfo") or {}
    total = int(mi.get("MemTotal", 40000))
    free = int(mi.get("MemFree", 20000))
    buffers = int(mi.get("Buffers", 0))
    used = total - free
    out = (f"             total       used       free     shared    buffers     cached\n"
           f"Mem:      {total:8d}   {used:8d}   {free:8d}   {52:8d}   {buffers:8d}   {int(mi.get('Cached', 0)):8d}\n"
           f"-/+ buffers/cache:   {used - buffers - int(mi.get('Cached', 0)):8d}   {free + buffers + int(mi.get('Cached', 0)):8d}\n"
           f"Swap:     {0:8d}   {0:8d}   {0:8d}\n")
    return _b(out), b"", 0


def a_df(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    lines = ["Filesystem           1K-blocks      Used Available Use% Mounted on"]
    for m in lx.lx.get("mounts") or []:
        if m[2] in ("proc", "sysfs"):
            continue
        if m[2] == "squashfs":
            idx = 3 if m[0] == "/dev/root" else int(re.sub(r"\D", "", m[0]) or 0)
            total = (lx.parts[idx]["size"] // 1024) if idx < len(lx.parts) else 4096
            lines.append(f"{m[0]:<20} {total:9d} {total:9d} {0:9d} 100% {m[1]}")
        else:
            lines.append(f"{m[0]:<20} {17344:9d} {8:9d} {17336:9d}   0% {m[1]}")
    return _b("\n".join(lines) + "\n"), b"", 0


def a_uptime(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    up = int(lx.uptime())
    h, rem = divmod(up, 3600)
    mnt, s = divmod(rem, 60)
    if h:
        upstr = f"{h}:{mnt:02d}"
    else:
        upstr = f"{mnt} min"
    return _b(f" {h:02d}:{mnt:02d}:{s:02d} up {upstr},  load average: 0.00, 0.01, 0.00\n"), b"", 0


def a_date(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if any(a == "-s" for a in argv[1:]):
        lx.dev.record({"type": "linux_modify", "argv": argv})
    up = int(lx.uptime())
    h, rem = divmod(up, 3600)
    m, s = divmod(rem, 60)
    return _b(f"Thu Jan  1 {h:02d}:{m:02d}:{s:02d} UTC 1970\n"), b"", 0


def a_sleep(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    try:
        secs = float(argv[1]) if len(argv) > 1 else 0.0
    except ValueError:
        return b"", _b(f"sleep: invalid number '{argv[1]}'\n"), 1
    if lx.dev.sleep(secs, ctrlc_poll=True):
        raise _SigInt()
    return b"", b"", 0


def a_sync(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return b"", b"", 0


def a_which(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    out = []
    rc = 0
    for a in argv[1:]:
        p = _which(lx, a)
        if p:
            out.append(p)
        else:
            rc = 1
    return _b("".join(x + "\n" for x in out)), b"", rc


def a_kill(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    lx.dev.record({"type": "linux_modify", "argv": argv})
    return b"", b"", 0


def a_reboot(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    lx.out("The system is going down NOW!\nSent SIGTERM to all processes\nSent SIGKILL to all processes\nRequesting system reboot\n")
    lx.dev.sleep(0.3)
    lx.out("Restarting system.\n")
    lx.dev.sleep(0.1)
    raise ResetEvent("linux reboot")


def a_poweroff(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    lx.out("The system is going down NOW!\nSent SIGTERM to all processes\nSent SIGKILL to all processes\nRequesting system poweroff\n")
    lx.dev.sleep(0.3)
    lx.out("Power down.\n")
    lx.dev.record({"type": "linux_poweroff"})
    lx.dev.hang()
    return b"", b"", 0


def a_service_busy(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    name = posixpath.basename(argv[0])
    return b"", _b(f"{name}: bind: Address already in use\n"), 1


def a_mkdir(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    err = b""
    rc = 0
    for p in [a for a in argv[1:] if not a.startswith("-")]:
        try:
            lx.vfs.mkdir(p, lx.cwd)
        except FsError as exc:
            if exc.errno_name == "EEXIST" and "-p" in argv:
                continue
            err += _b(f"mkdir: can't create directory '{p}': {exc.text}\n")
            rc = 1
    return b"", err, rc


def a_touch(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    err = b""
    rc = 0
    for p in [a for a in argv[1:] if not a.startswith("-")]:
        try:
            real, node = lx.vfs.resolve(p, lx.cwd)
            if node is None:
                lx.vfs.write(p, b"", lx.cwd)
            elif not lx.vfs.writable(real):
                raise FsError("EROFS", p)
        except FsError as exc:
            err += _b(f"touch: {p}: {exc.text}\n")
            rc = 1
    return b"", err, rc


def a_rm(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    err = b""
    rc = 0
    force = any(a.startswith("-") and "f" in a for a in argv[1:])
    for p in [a for a in argv[1:] if not a.startswith("-")]:
        try:
            lx.vfs.remove(p, lx.cwd)
        except FsError as exc:
            if force and exc.errno_name == "ENOENT":
                continue
            err += _b(f"rm: can't remove '{p}': {exc.text}\n")
            rc = 1
    return b"", err, rc


def a_cp(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    paths = [a for a in argv[1:] if not a.startswith("-")]
    if len(paths) < 2:
        return b"", b"cp: missing destination file operand\n", 1
    *srcs, dst = paths
    err = b""
    rc = 0
    for s in srcs:
        try:
            data = lx.vfs.read(s, lx.cwd)
        except FsError as exc:
            err += _b(f"cp: can't stat '{s}': {exc.text}\n")
            rc = 1
            continue
        target = dst
        try:
            real, node = lx.vfs.resolve(dst, lx.cwd)
            if node is not None and node.kind == "dir":
                target = posixpath.join(dst, posixpath.basename(s))
            if real.startswith("/dev/"):
                lx.device_write(real, data)
            else:
                lx.vfs.write(target, data, lx.cwd)
        except FsError as exc:
            err += _b(f"cp: can't create '{target}': {exc.text}\n")
            rc = 1
    return b"", err, rc


def a_mv(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    paths = [a for a in argv[1:] if not a.startswith("-")]
    if len(paths) < 2:
        return b"", b"mv: missing destination file operand\n", 1
    out, err, rc = a_cp(lx, ["cp", *paths], stdin)
    if rc == 0:
        for s in paths[:-1]:
            try:
                lx.vfs.remove(s, lx.cwd)
            except FsError as exc:
                return b"", _b(f"mv: can't remove '{s}': {exc.text}\n"), 1
    return out, err.replace(b"cp:", b"mv:"), rc


def a_chmod(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    paths = [a for a in argv[1:] if not a.startswith("-")][1:]
    err = b""
    rc = 0
    for p in paths:
        try:
            real, node = lx.vfs.resolve(p, lx.cwd)
            if node is None:
                raise FsError("ENOENT", p)
            if not lx.vfs.writable(real):
                raise FsError("EROFS", p)
        except FsError as exc:
            err += _b(f"chmod: {p}: {exc.text}\n")
            rc = 1
    return b"", err, rc


def a_tee(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    data = stdin if stdin is not None else lx_read_tty_eof(lx)
    append = "-a" in argv
    err = b""
    rc = 0
    for p in [a for a in argv[1:] if not a.startswith("-")]:
        try:
            lx.vfs.write(p, data, lx.cwd, append=append)
        except FsError as exc:
            err += _b(f"tee: {p}: {exc.text}\n")
            rc = 1
    return data, err, rc


def a_env(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) > 1:
        return lx.execute(argv[1:], stdin)
    return _b("".join(f"{k}={v}\n" for k, v in lx.env.items())), b"", 0


def a_top(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    mi = lx.kn.get("meminfo") or {}
    total = int(mi.get("MemTotal", 40000))
    free = int(mi.get("MemFree", 20000))
    head = (f"Mem: {total - free}K used, {free}K free, 52K shrd, 0K buff, {int(mi.get('Cached', 0))}K cached\n"
            "CPU:   0% usr   1% sys   0% nic  98% idle   0% io   0% irq   0% sirq\n"
            "Load average: 0.00 0.01 0.00 1/40 600\n"
            "  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n")
    rows = "".join(f"{p[0]:5d} {1:5d} {p[1]:<8} {p[3]:<4} {int(p[2]):5d}   4%   0% {p[4]}\n" for p in lx.processes())
    return _b(head + rows), b"", 0


def a_flash_eraseall(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    devs = [a for a in argv[1:] if not a.startswith("-")]
    if not devs:
        return b"", b"BusyBox: flash_eraseall [-jNq] MTD_DEVICE\n", 1
    real = VFS.norm(devs[0], lx.cwd)
    part = lx.part_for_dev(real)
    if part is None:
        return b"", _b(f"flash_eraseall: can't open '{devs[0]}': No such file or directory\n"), 1
    es = lx.prof["flash"]["erase_size"]
    out = []
    for pos in range(0, part["size"], es):
        out.append(f"\rErasing {es // 1024} Kibyte @ {pos:x} - {pos * 100 // part['size']:2d}% complete.")
    lx.dev.flash.erase(part["offset"], part["size"])
    lx.dev.sleep(0.02 * (part["size"] // es))
    out.append(f"\rErasing {es // 1024} Kibyte @ {part['size']:x} - 100% complete.\n")
    return _b("".join(out)), b"", 0


def a_flash_erase(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    """mtd-utils flash_erase MTD_DEVICE START BLOCKS (BLOCKS=0 이면 끝까지)."""
    pos = [a for a in argv[1:] if not a.startswith("-")]
    if len(pos) < 3:
        return b"", b"Usage: flash_erase [options] MTD_device start_offset block_count\n", 1
    real = VFS.norm(pos[0], lx.cwd)
    part = lx.part_for_dev(real)
    if part is None:
        return b"", _b(f"flash_erase: error!: {pos[0]}\n            error 2 (No such file or directory)\n"), 1
    es = lx.prof["flash"]["erase_size"]
    start = int(pos[1], 0)
    blocks = int(pos[2], 0)
    if blocks == 0:
        blocks = (part["size"] - start) // es
    out = []
    for b in range(blocks):
        off = start + b * es
        if off + es > part["size"]:
            break
        lx.dev.flash.erase(part["offset"] + off, es)
        out.append(f"\rErasing {es // 1024} Kibyte @ {off:x} -- {(b + 1) * 100 // blocks:2d} % complete ")
    lx.dev.sleep(0.02 * blocks)
    return _b("".join(out) + "\n"), b"", 0


def a_flashcp(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    pos = [a for a in argv[1:] if not a.startswith("-")]
    if len(pos) < 2:
        return b"", b"BusyBox: flashcp [-v] FILE MTD_DEVICE\n", 1
    try:
        data = lx.vfs.read(pos[0], lx.cwd)
    except FsError as exc:
        return b"", _b(f"flashcp: can't open '{pos[0]}': {exc.text}\n"), 1
    real = VFS.norm(pos[1], lx.cwd)
    part = lx.part_for_dev(real)
    if part is None or len(data) > part["size"]:
        return b"", _b(f"flashcp: {pos[1]}: error\n"), 1
    es = lx.prof["flash"]["erase_size"]
    erase_len = (len(data) + es - 1) // es * es
    lx.dev.flash.erase(part["offset"], erase_len)
    lx.dev.flash.program(part["offset"], data)
    return b"", b"", 0


def a_mtd_debug(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) < 3:
        return b"", b"usage: mtd_debug info <device>\n       mtd_debug read <device> <offset> <len> <dest-filename>\n", 1
    op, devp = argv[1], VFS.norm(argv[2], lx.cwd)
    part = lx.part_for_dev(devp)
    if part is None:
        return b"", _b("open(): No such file or directory\n"), 1
    if op == "info":
        return _b(f"mtd.type = MTD_NORFLASH\nmtd.flags = MTD_CAP_NORFLASH\nmtd.size = {part['size']} ({part['size'] // 1024}K)\n"
                  f"mtd.erasesize = {lx.prof['flash']['erase_size']} ({lx.prof['flash']['erase_size'] // 1024}K)\n"
                  f"mtd.writesize = 1 \nmtd.oobsize = 0 \nregions = 0\n\n"), b"", 0
    if op == "read" and len(argv) >= 6:
        off, n = int(argv[3], 0), int(argv[4], 0)
        data = lx.device_read(devp, n, off)
        try:
            lx.vfs.write(argv[5], data, lx.cwd)
        except FsError as exc:
            return b"", _b(f"{argv[5]}: {exc.text}\n"), 1
        return _b(f"Copied {len(data)} bytes from address 0x{off:08x} in flash to {argv[5]}\n"), b"", 0
    if op == "erase" and len(argv) >= 5:
        off, n = int(argv[3], 0), int(argv[4], 0)
        lx.dev.flash.erase(part["offset"] + off, n)
        return _b(f"Erased {n} bytes from address 0x{off:08x} in flash\n"), b"", 0
    if op == "write" and len(argv) >= 6:
        off, n = int(argv[3], 0), int(argv[4], 0)
        try:
            data = lx.vfs.read(argv[5], lx.cwd)[:n]
        except FsError as exc:
            return b"", _b(f"{argv[5]}: {exc.text}\n"), 1
        lx.device_write(devp, data, off)
        return _b(f"Copied {len(data)} bytes from {argv[5]} to address 0x{off:08x} in flash\n"), b"", 0
    return b"", b"mtd_debug: unknown command\n", 1


def _env_location(lx: Linux) -> tuple[int, int]:
    ub = lx.prof["uboot"]
    return int(ub["env_offset"]), int(ub["env_size"])


def a_fw_printenv(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    off, size = _env_location(lx)
    res = parse_uboot_env(lx.dev.flash.read(off, size))
    if not res:
        return b"", b"Warning: Bad CRC, using default environment\n", 0
    env = res["env"]
    names = argv[1:]
    if names:
        out = []
        rc = 0
        for n in names:
            if n in env:
                out.append(f"{n}={env[n]}")
            else:
                return _b("".join(x + "\n" for x in out)), _b(f"## Error: \"{n}\" not defined\n"), 1
        return _b("".join(x + "\n" for x in out)), b"", rc
    return _b("".join(f"{k}={v}\n" for k, v in env.items())), b"", 0


def a_fw_setenv(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    if len(argv) < 2:
        return b"", b"Usage: fw_setenv [OPTIONS]... [VARIABLE]...\n", 1
    off, size = _env_location(lx)
    res = parse_uboot_env(lx.dev.flash.read(off, size))
    env = dict(res["env"]) if res else dict(lx.prof["uboot"].get("default_env") or {})
    name = argv[1]
    if len(argv) > 2:
        env[name] = " ".join(argv[2:])
    else:
        env.pop(name, None)
    block = build_uboot_env(env, size=size, redundant=bool(lx.prof["uboot"].get("env_redundant")))
    es = lx.prof["flash"]["erase_size"]
    lx.dev.flash.erase(off, max(es, size))
    lx.dev.flash.program(off, block)
    return b"", b"", 0


def a_passwd(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return b"", b"passwd: (pweh simulator: interactive password change not emulated)\n", 1


def a_devmem(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    pos = [a for a in argv[1:] if not a.startswith("-")]
    if not pos:
        return b"", b"BusyBox: devmem ADDRESS [WIDTH [VALUE]]\n", 1
    addr = int(pos[0], 0)
    width = int(pos[1]) if len(pos) > 1 else 32
    if len(pos) >= 3:
        lx.dev.ram.write_uint(addr, max(1, width // 8), int(pos[2], 0))
        return b"", b"", 0
    val = lx.dev.ram.read_uint(addr, max(1, width // 8))
    return _b(f"0x{val:0{max(1, width // 4)}X}\n"), b"", 0


def a_free_text(name: str) -> Callable[[Linux, list[str], bytes | None], Result]:
    def fn(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
        return b"", _b(f"{name}: (pweh simulator: applet not emulated)\n"), 1
    return fn


def a_seq(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    nums = [int(a) for a in argv[1:] if re.fullmatch(r"-?\d+", a)]
    if len(nums) == 1:
        rng = range(1, nums[0] + 1)
    elif len(nums) == 2:
        rng = range(nums[0], nums[1] + 1)
    elif len(nums) == 3:
        rng = range(nums[0], nums[2] + 1, nums[1] or 1)
    else:
        return b"", b"seq: missing operand\n", 1
    return _b("".join(f"{i}\n" for i in rng)), b"", 0


def a_lsmod(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b("Module                  Size  Used by    Tainted: P  \n"), b"", 0


def a_logread(lx: Linux, argv: list[str], stdin: bytes | None) -> Result:
    return _b("Jan  1 00:00:05 ipcam syslog.info syslogd started: " + lx.lx.get("busybox_banner", "BusyBox") + "\n"), b"", 0


_APPLETS: dict[str, Callable[[Linux, list[str], bytes | None], Result]] = {
    "cat": a_cat, "ls": a_ls, "ps": a_ps, "mount": a_mount, "umount": a_umount, "id": a_id, "whoami": a_whoami,
    "uname": a_uname, "hostname": a_hostname, "ifconfig": a_ifconfig, "netstat": a_netstat, "dmesg": a_dmesg,
    "md5sum": a_md5sum, "hexdump": a_hexdump, "hd": a_hexdump, "base64": a_base64, "dd": a_dd, "head": a_head,
    "tail": a_tail, "wc": a_wc, "grep": a_grep, "egrep": a_grep, "fgrep": a_grep, "free": a_free, "df": a_df,
    "uptime": a_uptime, "date": a_date, "sleep": a_sleep, "usleep": a_sync, "sync": a_sync, "which": a_which,
    "kill": a_kill, "killall": a_kill, "reboot": a_reboot, "poweroff": a_poweroff, "halt": a_poweroff,
    "telnetd": a_service_busy, "httpd": a_service_busy, "mkdir": a_mkdir, "touch": a_touch, "rm": a_rm,
    "cp": a_cp, "mv": a_mv, "chmod": a_chmod, "chown": a_chmod, "tee": a_tee, "env": a_env, "printenv": a_env,
    "top": a_top, "flash_eraseall": a_flash_eraseall, "flash_erase": a_flash_erase, "flashcp": a_flashcp,
    "mtd_debug": a_mtd_debug, "fw_printenv": a_fw_printenv, "fw_setenv": a_fw_setenv, "passwd": a_passwd,
    "devmem": a_devmem, "seq": a_seq, "lsmod": a_lsmod, "logread": a_logread, "sh": b_sh, "ash": b_sh,
    "echo": b_echo, "test": b_test, "[": b_test, "[[": b_test, "true": b_true, "false": b_false, "pwd": b_pwd,
}


__all__ = ["Linux", "VFS", "parse_shell"]
