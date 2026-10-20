"""fwtriage 논리 줄(rootfs.logical_pair·logical_text·shell_syntax) 회귀 테스트.

셸은 줄 끝 '|'·'||'·'&&' 뒤의 빈 줄·주석 줄까지 한 명령으로 읽고(POSIX linebreak), 줄 끝 주석 안의 연산자·'\\' 로는 줄을 잇지 않는다.
inittab·inetd.conf·udev 규칙·systemd 유닛 같은 셸이 아닌 파일은 줄 끝 '\\' 로만 잇고, 셸 파일의 here-document 본문은 잇지 않는다.
기본 감사(audit_startup)는 HEAD 가 내던 항목을 그대로 내야 하고, SD 점검(fw_sd_surface)도 같은 줄 규칙을 쓴다.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from fwtriage.builders import build_flash
from fwtriage.sd_builders import write_tree

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp.common import Ctl  # noqa: E402
from fwtriage_mcp.patterns import load_patterns  # noqa: E402
from fwtriage_mcp.rootfs import Auditor, _blank_comments, logical_pair, logical_text, shell_syntax  # noqa: E402
from fwtriage_mcp.sdsurface import SdSurface  # noqa: E402
from fwtriage_mcp.uboot import env_scan  # noqa: E402


def _audit(root: Path, persistent: list[str] | None = None) -> Auditor:
    aud = Auditor(root, Ctl(max_seconds=120), load_patterns(), persistent_paths=persistent or [], profile={}, max_file_size=16 << 20,
                  crack=False, crack_seconds=1, words=[], max_entries=20000)
    aud.walk()
    return aud


def _items(root: Path, persistent: list[str] | None = None) -> tuple[Auditor, dict]:
    aud = _audit(root, persistent)
    out = aud.audit_startup()
    return aud, out


def _ids(aud: Auditor) -> set[str]:
    return {i["id"] for i in aud.items}


def _surface(root: Path, image: bytes | None = None) -> dict[str, dict]:
    ctl = Ctl(max_seconds=120)
    sd = SdSurface(ctl, load_patterns())
    aud = _audit(root)
    sd.scan_rootfs(aud, aud.audit_startup(), aud.audit_web())
    if image is not None:
        sd.scan_image(image, len(image), "dumps/flash.bin", env_scan(image, len(image), ctl, include_default=True))
    res = sd.result(rootfs_given=True, image_given=image is not None)
    return {c["id"]: c for c in res["checks"]}


# ---------------------------------------------------------------------------
# logical_text / logical_pair 단위
# ---------------------------------------------------------------------------

JOIN_CASES = [
    # (입력, 이어진 결과의 줄바꿈 수) — 줄 끝 연산자 뒤의 빈 줄·주석 줄은 같은 명령
    ("a |\n\nb\n", 1),
    ("a &&\n   \n\t\nb\n", 1),
    ("a ||\n  # 설명\nb\n", 1),
    ("a |\n\n  # 설명\n\nb\n", 1),
    ("a |\r\n\r\nb\n", 1),
    ("a | # 설명\nb\n", 1),  # 주석 앞이 연산자면 잇는다
    ("x &&\n  y ||\n z |\n w\n", 1),
    # 잇지 않는 것
    ("echo x  # 1단계 ||\nmount -t jffs2 /dev/mtdblock5 /mnt/data\n", 2),  # 주석 안의 연산자
    ("echo x  # 1단계 &&\nb\n", 2),
    ("echo x  # 붙임 |\nb\n", 2),
    ("echo x # 주석 \\\nb\n", 2),  # 주석 안의 '\\'
    ("# 전체 주석 ||\nb\n", 2),
    ("echo a\\|\nb\n", 2),  # '\|' 는 글자
    ("x &\ny;\nz\n", 3),
    ("a \\\\\nb\n", 2),  # 짝수 개 '\\'
    ("a \\\r\nb\n", 2),  # '\\' + CR LF 는 이어쓰기가 아니다
]


@pytest.mark.parametrize("text, newlines", JOIN_CASES)
def test_logical_text_joins(text, newlines):
    out = logical_text(text)
    assert len(out) == len(text) and out.count("\n") == newlines, repr(out)


def test_backslash_continuation_and_lengths():
    assert logical_text("a \\\\\\\nb\n") == "a \\\\  b\n"
    assert logical_text("nc -p 1 \\\n  -l -e /bin/sh\n").count("\n") == 1


def test_non_shell_files_join_only_backslash():
    t = "::sysinit:/etc/init.d/rcS ||\n::respawn:-/bin/sh\n"
    assert logical_text(t, shell=False) == t
    assert logical_text("a &&\nb\n", shell=False).count("\n") == 2
    assert logical_text("x \\\ny\n", shell=False) == "x   y\n"


HEREDOC_CASES = [
    # (입력, 이어진 결과의 줄바꿈 수)
    ("cat > /etc/inittab <<EOF\n::sysinit:/etc/init.d/rcS ||\n::respawn:-/bin/sh\nEOF\necho a |\nb\n", 5),
    ("cat <<'EOF' > /etc/inetd.conf\nftp stream tcp nowait root /usr/sbin/ftpd ftpd |\ntelnet stream tcp nowait root /usr/sbin/telnetd telnetd\nEOF\n", 4),
    ("cat <<-\"END\"\n\ta ||\n\tb\n\tEND\nx |\ny\n", 5),
    ("cat <<EOF\na |\nb\n", 2),  # 끝 구분자 없음 → 본문으로 보지 않는다 (잘못 읽은 시작이 뒤의 이어쓰기를 모두 끄지 않게 — HEAD 처럼 잇는다)
    # 구분자는 한 셸 낱말 전체 (따옴표·역슬래시를 벗김): '-'·'!'·섞인 따옴표·'\\'·'<<-' 와 탭
    ("cat > /etc/motd <<END-OF-BANNER\nhi |\nEND-OF-BANNER\necho 'root:pw' |\n  chpasswd\n", 4),
    ("cat > /etc/inittab <<!\n::sysinit:/etc/init.d/rcS ||\n::respawn:-/bin/sh\n!\n", 4),
    ("cat <<E\"O\"F\na |\nb\nEOF\nx |\ny\n", 5),
    ("cat <<\\END-X\na |\nb\nEND-X\nx |\ny\n", 5),
    ("cat <<-END-X\n\ta |\n\tb\n\tEND-X\nx |\ny\n", 5),
    ("cat <<EOF.\na |\nEOF.\nx |\ny\n", 4),
    ("cat <<END\na |\nEND-OF-BANNER\nx |\ny\n", 3),  # 'END' 줄이 없음 → 끝 구분자 없음 → 본문 아님 (모두 잇는다)
    ("fi;# <<EOF marks\na |\nb\n", 2),  # ';' 뒤의 '#' 도 주석 시작
    ("echo \"Usage: $0 [start|stop]\n    <<start>> run\"\necho x |\nwc\n", 3),  # 여러 줄 문자열 속 '<<낱말' (끝 구분자 없음)
    ("echo $((1 << n)) |\ncat\n", 1),  # 산술 시프트는 here-document 가 아니다
    ("cat <<< word |\nwc\n", 1),  # here-string
    ("echo \"<<EOF\" |\nwc\n", 1),  # 따옴표 안
    ("echo x # <<EOF\na |\nb\n", 2),  # 주석 안
]


@pytest.mark.parametrize("text, newlines", HEREDOC_CASES)
def test_heredoc_bodies_are_not_joined(text, newlines):
    out = logical_text(text)
    assert len(out) == len(text) and out.count("\n") == newlines, repr(out)


def test_logical_pair_uses_the_same_join_points():
    text = "#!/bin/sh\necho 'root:pw' |\n  # 비밀번호\n\n  chpasswd\n# 끝 ||\nnext\n"
    active = _blank_comments(text)
    la, lt = logical_pair(active, text)
    assert len(la) == len(lt) == len(text)
    assert [i for i, c in enumerate(la) if c == "\n"] == [i for i, c in enumerate(lt) if c == "\n"]
    assert la.count("\n") == 4
    same_a, same_t = logical_pair("a\nb\n", "a\nb\n")
    assert same_a == "a\nb\n" and same_t == "a\nb\n"


@pytest.mark.parametrize("rel, head, expect", [
    ("etc/init.d/rcS", "", True),
    ("etc/inittab", "", False),
    ("etc_ro/inittab", "", False),
    ("etc/inetd.conf", "", False),
    ("etc/xinetd.d/telnet", "", False),
    ("etc/mdev.conf", "", False),
    ("etc/udev/rules.d/99-sd.rules", "", False),
    ("lib/systemd/system/app.service", "", False),
    ("etc/systemd/system/app.service.d/override.conf", "", False),
    ("etc/systemd/system/start.sh", "", True),
    ("etc/crontabs/root", "", False),
    ("/mnt/mtd/app/run", "", True),
    ("usr/lib/systemd/scripts/net", "#!", True),
    # /systemd/ 아래는 INI 문법의 유닛·설정 접미사만 셸이 아니다 (셰뱅 없는 도우미 스크립트는 셸)
    ("etc/systemd/system/camera-init", "", True),
    ("lib/systemd/system/app.socket", "", False),
    ("etc/systemd/network/10-eth0.network", "", False),
    ("etc/systemd/system.conf", "", False),
    ("etc/systemd/system/multi-user.target.wants/app.service", "", False),
])
def test_shell_syntax(rel, head, expect):
    assert shell_syntax(rel, head) is expect


def test_join_cost_is_linear():
    """줄 끝 주석·연산자·빈 줄·here-document 시작이 빽빽한 입력도 선형 (줄마다 한 번만 훑는다)."""
    shapes = [
        "echo x  # c ||\n",
        "a |\n\n# c\n",
        "cat <<E\nx |\nE\n",
        "echo \"q # \" | # c |\n",
        "a \\\n",
    ]
    for unit in shapes:
        small = unit * 4000
        big = unit * 32000
        t0 = time.perf_counter()
        logical_text(small)
        t1 = time.perf_counter()
        logical_text(big)
        t2 = time.perf_counter()
        assert t2 - t1 < max(0.5, 20 * (t1 - t0)), (unit, t1 - t0, t2 - t1)


def test_long_line_with_comment_and_operator():
    line = "echo " + "\"a#b\" " * 100000 + "# c ||\nnext\n"
    t0 = time.perf_counter()
    out = logical_text(line)
    assert out.count("\n") == 2 and time.perf_counter() - t0 < 5.0


# ---------------------------------------------------------------------------
# 기본 감사: HEAD 가 내던 항목 (5차 검증 #1·#2·#3)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gap", ["\n", "  # 비밀번호 설정\n", "\r\n", "\n  # c\n\n"])
def test_chpasswd_after_pipe_and_blank_or_comment_lines(tmp_path, gap):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\necho 'root:Adm1n2024' |\n" + gap + "  chpasswd\n"})
    aud, _ = _items(root)
    hits = [i for i in aud.items if i["id"] == "builtin-chpasswd-literal"]
    assert hits and hits[0]["line"] == 2 and "Adm1n2024" not in hits[0]["excerpt"], aud.items


INITTAB_CASES = [
    "::sysinit:/etc/init.d/rcS   # rc ||\n::respawn:-/bin/sh\n",
    "::shutdown:/bin/umount -a -r ||\n::respawn:-/bin/sh\n",
    "::sysinit:/etc/init.d/rcS &&\n::respawn:-/bin/sh\n",
    "::sysinit:/etc/init.d/rcS\t&&\r\n::respawn:-/bin/sh\r\n",
]


@pytest.mark.parametrize("body", INITTAB_CASES)
def test_inittab_entries_are_not_joined_by_operators(tmp_path, body):
    root = write_tree(tmp_path / "r", {"etc/inittab": body, "etc/init.d/rcS": "#!/bin/sh\n"})
    aud, out = _items(root)
    assert "gen-inittab-console-shell" in _ids(aud), aud.items
    assert any(e["process"].strip() == "-/bin/sh" for e in out["inittab"]), out["inittab"]


def test_inittab_backslash_still_joins(tmp_path):
    """BusyBox parse_config 는 줄 끝 '\\' 로 줄을 잇는다 → 다음 줄은 앞 항목의 일부라 콘솔 셸 항목이 아니다 (HEAD 의 거짓 양성)."""
    root = write_tree(tmp_path / "r", {"etc/inittab": "::sysinit:/etc/init.d/rcS \\\n::respawn:-/bin/sh\n", "etc/init.d/rcS": "#!/bin/sh\n"})
    aud, _ = _items(root)
    assert "gen-inittab-console-shell" not in _ids(aud)


def test_inetd_entry_after_commented_operator(tmp_path):
    body = "ftp stream tcp nowait root /usr/sbin/ftpd ftpd   # ftp |\ntelnet stream tcp nowait root /usr/sbin/telnetd telnetd\n"
    root = write_tree(tmp_path / "r", {"etc/inetd.conf": body})
    aud, _ = _items(root)
    assert "gen-inetd-telnet" in _ids(aud), aud.items


def test_inittab_written_by_heredoc_in_rcs(tmp_path):
    rcs = "#!/bin/sh\ncat > /etc/inittab <<EOF\n::sysinit:/etc/init.d/rcS ||\n::respawn:-/bin/sh\nEOF\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    aud, _ = _items(root)
    assert "gen-inittab-console-shell" in _ids(aud), aud.items


@pytest.mark.parametrize("comment", ["# 1단계 ||", "# mtd 읽기 &&", "# 붙이기 |", "# 이어서 \\"])
def test_commented_operator_does_not_swallow_the_next_mount(tmp_path, comment):
    rcs = f"#!/bin/sh\necho 'mounting user data'   {comment}\nmount -t jffs2 /dev/mtdblock5 /mnt/data\n/mnt/data/start.sh &\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    aud, out = _items(root)
    assert any(m["mount_point"] == "/mnt/data" for m in out["mounts"]), out["mounts"]
    hits = [i for i in aud.items if i["id"] == "builtin-exec-from-writable-storage"]
    assert hits and hits[0]["line"] == 4, aud.items


def test_systemd_unit_lines_are_not_joined_by_operators(tmp_path):
    unit = "[Service]\nExecStartPre=/bin/true ||\nExecStart=/usr/sbin/telnetd -F -l /bin/sh\n"
    root = write_tree(tmp_path / "r", {"etc/systemd/system/telnet.service": unit})
    aud, _ = _items(root)
    assert "gen-telnetd-login-shell" in _ids(aud), aud.items


# ---------------------------------------------------------------------------
# SD 점검도 같은 줄 규칙
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gap", ["\n", "  # 플래그가 있으면\n"])
def test_sd_trigger_after_andand_and_blank_line(tmp_path, gap):
    rcs = "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\n[ -f /mnt/sd/telnet.flag ] &&\n" + gap + "  telnetd -l /bin/sh &\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    assert _surface(root)["SD-01"]["status"] == "found"


@pytest.mark.parametrize("gap", ["\n", "# 펌웨어 쓰기\n"])
def test_sd_flash_write_after_pipe_and_blank_line(tmp_path, gap):
    rcs = "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\ncat /mnt/sd/fw.bin |\n" + gap + "dd of=/dev/mtdblock2\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    img, _ = build_flash(None)
    assert _surface(root, img)["SD-02"]["status"] == "found"


def test_sd_inittab_entry_after_operator_line(tmp_path):
    inittab = "::sysinit:/etc/init.d/rcS   # rc ||\n::once:/bin/sh -c '/mnt/sd/autorun.sh'\n"
    rcs = "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\n"
    root = write_tree(tmp_path / "r", {"etc/inittab": inittab, "etc/init.d/rcS": rcs})
    assert _surface(root)["SD-01"]["status"] == "found"


# ---------------------------------------------------------------------------
# 6차 검증: 연산자 뒤 줄 끝 주석으로 이은 줄(#1·#4·#13), here-document 구분자(#5·#14), '\\&&'(#8)
# ---------------------------------------------------------------------------

def test_operator_comment_is_blanked_only_on_the_active_side():
    text = "#!/bin/sh\n[ -b /dev/mtdblock5 ] &&   # data partition\nmount -t jffs2 /dev/mtdblock5 /mnt/data\n"
    la, lt = logical_pair(_blank_comments(text), text)
    assert len(la) == len(lt) == len(text) and la.count("\n") == lt.count("\n") == 2
    assert "data partition" not in la and la.split("\n")[1].rstrip().endswith("mount -t jffs2 /dev/mtdblock5 /mnt/data")
    assert "# data partition" in lt  # 발췌용 원문에는 남는다
    # 사이의 주석 줄도 지운다 (주석 줄을 지우지 않은 텍스트에서도)
    assert logical_text("a | # c\n# d\nb\n") == "a |" + " " * 9 + "b\n"


OP_COMMENT_MOUNT = [
    "[ -b /dev/mtdblock5 ] && # data partition\nmount -t jffs2 /dev/mtdblock5 /mnt/data\n",
    "mountpoint -q /mnt/data || # not mounted yet\n    mount -t jffs2 /dev/mtdblock5 /mnt/data\n",
    "cat /proc/mounts |      # data partition mounted?\ngrep -q /mnt/data ||\nmount -t jffs2 /dev/mtdblock5 /mnt/data\n",
]


@pytest.mark.parametrize("head", OP_COMMENT_MOUNT)
def test_mount_after_operator_and_trailing_comment(tmp_path, head):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + head + "/mnt/data/start.sh &\n"})
    aud, out = _items(root)
    assert any(m["mount_point"] == "/mnt/data" for m in out["mounts"]), out["mounts"]
    assert "builtin-exec-from-writable-storage" in _ids(aud), aud.items


def test_exec_after_operator_and_trailing_comment(tmp_path):
    rcs = ("#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd\n[ -x /mnt/mtd/app/run.sh ] && # vendor app\n    /mnt/mtd/app/run.sh &\n"
           "dmesg | # log sink\n/mnt/mtd/app/logsink -f &\n")
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    aud, _ = _items(root)
    got = sorted((i["line"], i["target"]) for i in aud.items if i["id"] == "builtin-exec-from-writable-storage")
    assert got == [(3, "/mnt/mtd/app/run.sh"), (5, "/mnt/mtd/app/logsink")], aud.items


def test_chpasswd_after_pipe_with_trailing_comment(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\necho 'root:Adm1n2024' | # set pw\nchpasswd\n"})
    aud, _ = _items(root)
    assert "builtin-chpasswd-literal" in _ids(aud), aud.items


@pytest.mark.parametrize("rcs", [
    "mount -t vfat /dev/mmcblk0p1 /mnt/sd &&   # card ok\n    /mnt/sd/debugd &\n",
    "mount -a\n[ -x /mnt/sd/autorun.sh ] && # run card hook\n    /mnt/sd/autorun.sh &\n",
    "[ -b /dev/mmcblk0p1 ] &&   # card inserted\nmount -t vfat /dev/mmcblk0p1 /mnt/extsd\n/mnt/extsd/autorun.sh &\n",
])
def test_sd_exec_after_operator_and_trailing_comment(tmp_path, rcs):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + rcs, "etc/fstab": "/dev/mmcblk0p1 /mnt/sd vfat defaults 0 0\n"})
    sd1 = _surface(root)["SD-01"]
    assert sd1["status"] == "found" and "direct-exec" in {e["rule"] for e in sd1["evidence"]}, sd1


def test_sd_trigger_and_flash_after_operator_comment(tmp_path):
    rcs = ("#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\n[ -f /mnt/sd/telnet.flag ] &&   # factory\ntelnetd -l /bin/sh &\n"
           "cat /mnt/sd/fw.bin |   # write image\ndd of=/dev/mtdblock2\n")
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    img, _ = build_flash(None)
    c = _surface(root, img)
    assert c["SD-01"]["status"] == "found" and c["SD-02"]["status"] == "found", (c["SD-01"], c["SD-02"])


@pytest.mark.parametrize("before", [
    "cat > /etc/motd <<END-OF-BANNER\nWelcome to IPC\nEND-OF-BANNER\n",
    "cat > /etc/hosts <<EOF.\n127.0.0.1 localhost\nEOF.\n",
    "cat > /etc/hosts <<\\END-OF-HOSTS\n127.0.0.1 localhost\nEND-OF-HOSTS\n",
    "cat > /etc/motd <<-END-X\n\tWelcome\n\tEND-X\n",
    "echo \"Usage: $0 [start|stop]\n    <<start>> run the app\"\n",
    "fi;# <<EOF marks\n",
    "sed -i 's/<<HOST>>/cam/' /etc/hosts\n",
])
def test_chpasswd_after_heredoc_word_delimiters_and_misreads(tmp_path, before):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + before + "echo 'root:Adm1n2024' |\n  chpasswd\n"})
    aud, _ = _items(root)
    assert "builtin-chpasswd-literal" in _ids(aud), aud.items


def test_inittab_heredoc_with_bang_delimiter_is_not_joined(tmp_path):
    rcs = "#!/bin/sh\ncat > /etc/inittab <<!\n::sysinit:/etc/init.d/rcS ||\n::respawn:-/bin/sh\n!\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    aud, _ = _items(root)
    assert "gen-inittab-console-shell" in _ids(aud), aud.items


def test_sd_trigger_and_flash_after_dash_delimiter_heredoc(tmp_path):
    rcs = ("#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\ncat > /etc/motd <<END-OF-BANNER\nWelcome\nEND-OF-BANNER\n"
           "[ -f /mnt/sd/telnet.flag ] &&\ntelnetd -l /bin/sh &\ncat /mnt/sd/fw.bin |\ndd of=/dev/mtdblock2\n")
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": rcs})
    img, _ = build_flash(None)
    c = _surface(root, img)
    assert c["SD-01"]["status"] == "found" and c["SD-02"]["status"] == "found", (c["SD-01"], c["SD-02"])


def test_escaped_ampersand_before_background_does_not_continue(tmp_path):
    assert logical_text("tcpsvd -vE 0 23 \\&&\n/bin/login &\n").count("\n") == 2
    assert logical_text("a \\\\&&\nb\n").count("\n") == 1  # '\\\\' 는 글자 '\\' — 뒤의 '&&' 는 연산자
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\ntelnetd -p 2323 \\&&\n-l /bin/sh\ntcpsvd -vE 0 23 \\&&\n/bin/login &\n"})
    aud, _ = _items(root)
    assert not _ids(aud) & {"gen-telnetd-login-shell", "builtin-tcpsvd-shell"}, aud.items


def test_heredoc_scan_is_linear_with_many_unterminated_starts():
    """끝 구분자 없는 시작이 많아도(구분자마다 다름) 끝 구분자는 줄 색인에서 찾으므로 선형이다."""
    for unit in ("cat <<X{i}\na |\nb\n", "cat <<'E {i}'\nx\nE {i}\ny |\nz\n"):
        small = "".join(unit.format(i=i) for i in range(2000))
        big = "".join(unit.format(i=i) for i in range(16000))
        t0 = time.perf_counter()
        logical_text(small)
        t1 = time.perf_counter()
        logical_text(big)
        t2 = time.perf_counter()
        assert t2 - t1 < max(0.5, 20 * (t1 - t0)), (unit, t1 - t0, t2 - t1)
