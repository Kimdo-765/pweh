"""기본 fw_rootfs_audit 시작 스크립트 감사(audit_startup) — 5차 리뷰 #4·#6·#12·#15 회귀 테스트.

- #4·#6 이어쓰기 줄 다음의 실행 위치: 셸 대입('LD_LIBRARY_PATH=/x \\')·래퍼(nohup·setsid·env·command·time, basename 비교)와 그 인자 없는
  옵션 뒤의 경로는 실행 위치이고(한 줄 꼴도), HEAD 가 물리 줄 처음이라 잘못 낸 꼴(cp \\·mount … \\·echo > \\·chmod +x \\·ln -sf \\·[ -f \\,
  --config \\ 인자)은 실행 위치가 아니다. start-stop-daemon -x/--exec/-a/--startas 경로(멈춤·상태 명령 제외). 건너기는 낱말 16개까지.
- #12 항목 양: 하드 링크는 한 번만 읽고, 시작 스크립트 전체에서 같은 규칙 항목은 STARTUP_ITEM_CAP_PER_RULE 개까지 (나머지는 센다).
- #15 쓰기 가능 접두 판정은 경로 길이에 선형, PATH_MAX(4096)보다 긴 경로·마운트 지점은 실행·마운트될 수 없어 건너뛴다.
- 적대적 1 MiB 줄(대입·래퍼 반복, 아주 긴 낱말, 따옴표 홍수, start-stop-daemon 옵션 홍수, 긴 줄의 일치 홍수)에서도 선형.
시간 단언은 넉넉한 절대 상한(옛 코드는 같은 입력에서 수십 초)만 둔다 — 바쁜 기계에서도 흔들리지 않게.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import tracemalloc
from pathlib import Path

import pytest
from mcp import Client

from fwtriage.sd_builders import write_tree
from mcp_helpers import call

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import rootfs  # noqa: E402
from fwtriage_mcp.common import Ctl  # noqa: E402
from fwtriage_mcp.patterns import load_patterns  # noqa: E402
from fwtriage_mcp.rootfs import (  # noqa: E402
    ITEM_CAP_PER_RULE_FILE,
    PATH_MAX,
    STARTUP_ITEM_CAP_PER_RULE,
    Auditor,
    _exec_ctx_before,
)

#: 넉넉한 시간 상한(초) — 옛 코드는 같은 입력에서 20~80초
SLOW = 5.0
EXEC = "builtin-exec-from-writable-storage"
MOUNTS = ("mount -t jffs2 /dev/mtdblock3 /mnt/mtd\n"
          "mount -t vfat /dev/mmcblk0p1 /mnt/sd\n"
          "mount -t jffs2 /dev/mtdblock5 /mnt/flash\n")


def _audit(root: Path, *, persistent: list[str] | None = None, profile: dict | None = None, ctl: Ctl | None = None) -> Auditor:
    aud = Auditor(root, ctl or Ctl(max_seconds=120), load_patterns(), persistent_paths=persistent or [], profile=profile or {},
                  max_file_size=16 << 20, crack=False, crack_seconds=1, words=[], max_entries=20000)
    aud.walk()
    return aud


def _exec_items(tmp_path: Path, body: str, **kw) -> list[tuple[int, str]]:
    """rcS = 셰뱅 + 마운트 3줄 + body → audit_startup 의 builtin-exec-from-writable-storage [(줄, 대상)] (body 의 줄 번호는 5부터)."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNTS + body + "\n"})
    aud = _audit(root, **kw)
    aud.audit_startup()
    assert aud.startup_scan_complete
    return sorted((i["line"], i["target"]) for i in aud.items if i["id"] == EXEC)


def _timed(fn, *a, **kw):
    t0 = time.monotonic()
    out = fn(*a, **kw)
    return out, time.monotonic() - t0


# ---------------------------------------------------------------------------
# #4·#6: 이어쓰기 줄 다음의 실행 위치 (투명한 앞말)
# ---------------------------------------------------------------------------

EXEC_SHAPES = {
    # 이어쓰기 꼴 — HEAD 는 물리 줄 처음이라 냈고, 4차 이후 논리 줄로 이어 잃었던 항목 (줄 번호는 논리 줄의 첫 물리 줄)
    "env_prefix_cont": ("LD_LIBRARY_PATH=/mnt/mtd/app/lib \\\n    /mnt/mtd/app/ipcam -c /mnt/mtd/app/ipcam.conf &", (5, "/mnt/mtd/app/ipcam")),
    "two_env_prefix_cont": ("LD_LIBRARY_PATH=/mnt/mtd/lib:$LD_LIBRARY_PATH \\\nPATH=/mnt/mtd/bin:$PATH \\\n/mnt/mtd/bin/appd &", (5, "/mnt/mtd/bin/appd")),
    "ld_preload_col0_cont": ("LD_PRELOAD=/mnt/mtd/lib/libhook.so \\\n/mnt/mtd/app/ipcam &", (5, "/mnt/mtd/app/ipcam")),
    "nohup_cont": ("nohup \\\n    /mnt/mtd/app/watchdog.sh > /dev/null 2>&1 &", (5, "/mnt/mtd/app/watchdog.sh")),
    "setsid_cont": ("setsid \\\n    /mnt/mtd/app/ipcam &", (5, "/mnt/mtd/app/ipcam")),
    "env_cmd_cont": ("/usr/bin/env -i HOME=/root \\\n    /mnt/mtd/app/run.sh", (5, "/mnt/mtd/app/run.sh")),
    "sd_binary_cont": ("LD_LIBRARY_PATH=/mnt/sd/lib \\\n    /mnt/sd/bin/debugd &", (5, "/mnt/sd/bin/debugd")),
    # 실제 벤더 꼴 (리뷰 tree H S20flash)
    "vendor_flash_custom": ("LD_LIBRARY_PATH=/mnt/flash/custom/lib \\\n/mnt/flash/custom/init.sh &", (5, "/mnt/flash/custom/init.sh")),
    # 한 줄 꼴 (HEAD·4차 모두 놓치던 것)
    "env_prefix_single": ("LD_LIBRARY_PATH=/mnt/mtd/app/lib /mnt/mtd/app/ipcam &", (5, "/mnt/mtd/app/ipcam")),
    "nohup_single": ("nohup /mnt/mtd/app/watchdog.sh > /dev/null 2>&1 &", (5, "/mnt/mtd/app/watchdog.sh")),
    "usr_bin_nohup": ("/usr/bin/nohup /mnt/mtd/app/x &", (5, "/mnt/mtd/app/x")),
    "quoted_assign_with_space": ('OPTS="-a -b" LIB=\'/mnt/mtd/lib\' /mnt/mtd/app/x &', (5, "/mnt/mtd/app/x")),
    "env_assign": ("env LD_LIBRARY_PATH=/mnt/mtd/lib /mnt/mtd/app/x", (5, "/mnt/mtd/app/x")),
    "setsid_opt": ("setsid -f /mnt/mtd/app/x", (5, "/mnt/mtd/app/x")),
    "command_p": ("command -p /mnt/mtd/app/x", (5, "/mnt/mtd/app/x")),
    "time_p": ("time -p /mnt/mtd/app/x", (5, "/mnt/mtd/app/x")),
    "stacked_wrappers": ("FOO=1 nohup env -i A=1 setsid /mnt/mtd/app/x &", (5, "/mnt/mtd/app/x")),
    # start-stop-daemon 의 실행 파일 인자
    "ssd_x_cont": ("start-stop-daemon -S -b -m -p /var/run/appd.pid -x \\\n    /mnt/mtd/app/bin/appd -- -c /etc/app.conf", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_x_single": ("start-stop-daemon -S -b -x /mnt/mtd/app/bin/appd", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_exec_glued": ("start-stop-daemon --start --exec=/mnt/mtd/app/bin/appd", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_cluster_path_form": ("/sbin/start-stop-daemon -Sbx /mnt/mtd/app/bin/appd", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_startas_only": ("start-stop-daemon -S -a /mnt/mtd/app/bin/appd", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_after_nohup": ("nohup start-stop-daemon -S -x /mnt/mtd/app/bin/appd &", (5, "/mnt/mtd/app/bin/appd")),
    "ssd_daemon_args_after_dashdash": ("start-stop-daemon -S -x /mnt/mtd/app/bin/appd -- -K -t", (5, "/mnt/mtd/app/bin/appd")),
}


@pytest.mark.parametrize("name", sorted(EXEC_SHAPES))
def test_transparent_prefix_keeps_exec_from_writable(tmp_path, name):
    body, want = EXEC_SHAPES[name]
    assert _exec_items(tmp_path, body) == [want]


def test_if_block_env_prefix_and_test_arg(tmp_path):
    """'[ -x 경로 ]' 의 경로는 인자(start-stop-daemon 이 없으면 -x 는 실행 옵션이 아니다), 다음 줄의 대입 뒤 경로는 실행."""
    body = "if [ -x /mnt/mtd/custom/init.sh ]; then\n    LD_LIBRARY_PATH=/mnt/mtd/custom/lib \\\n    /mnt/mtd/custom/init.sh &\nfi"
    assert _exec_items(tmp_path, body) == [(6, "/mnt/mtd/custom/init.sh")]


NON_EXEC_SHAPES = {
    # HEAD 의 물리 줄 처음 오탐 6꼴 (이어진 줄 처음의 경로가 인자)
    "cp_arg": "cp \\\n    /mnt/mtd/app/ipcam.conf /tmp/ipcam.conf",
    "mount_point_arg": "mount -t jffs2 /dev/mtdblock4 \\\n    /mnt/data",
    "redirect_arg": "echo boot > \\\n    /mnt/mtd/boot.log",
    "chmod_arg": "chmod +x \\\n    /mnt/mtd/app/ipcam",
    "ln_arg": "ln -sf \\\n    /mnt/mtd/app/cfg /etc/cfg",
    "test_arg": "[ -f \\\n    /mnt/mtd/app/ipcam ] && echo ok",
    "config_arg": "/usr/bin/appd --config \\\n    /mnt/mtd/app.conf &",
    # 투명하지 않은 앞말
    "command_v": "command -v /mnt/mtd/app/x",
    "echo_nohup": "echo nohup /mnt/mtd/app/x",
    "echo_assign": "echo FOO=1 /mnt/mtd/app/x",
    "nohup_then_assign": "nohup FOO=1 /mnt/mtd/app/x",
    "env_assign_then_opt": "env A=1 -i /mnt/mtd/app/x",
    "cmd_subst_arg": "FOO=$(cat /mnt/mtd/app/x) /usr/bin/foo",
    "unbalanced_quote": 'echo "a FOO="x y" /mnt/mtd/app/x',
    # start-stop-daemon 멈춤·상태·시험, -x 가 있을 때의 -a(argv[0]), 다른 명령
    "ssd_stop": "start-stop-daemon -K -x /mnt/mtd/app/x",
    "ssd_stop_after": "start-stop-daemon -x /mnt/mtd/app/x -K",
    "ssd_status": "start-stop-daemon -T -x /mnt/mtd/app/x",
    "ssd_test": "start-stop-daemon -S -t -x /mnt/mtd/app/x",
    "ssd_stop_glued": "start-stop-daemon --stop --exec=/mnt/mtd/app/x",
    "ssd_startas_is_argv0": "start-stop-daemon -S -x /usr/bin/appd -a /mnt/mtd/app/name",
    "ssd_other_command": "start-stop-daemon -K -x /usr/bin/a; [ -x /mnt/mtd/app/x ]",
    "ssd_not_command": "echo start-stop-daemon -S -x /mnt/mtd/app/x",
    # 인자를 받는 실행기는 범위 밖 (문서의 한계)
    "nice_n": "nice -n 10 /mnt/mtd/app/x",
}


@pytest.mark.parametrize("name", sorted(NON_EXEC_SHAPES))
def test_argument_paths_are_not_exec(tmp_path, name):
    assert _exec_items(tmp_path, NON_EXEC_SHAPES[name]) == []


def test_exec_ctx_unit_rules():
    def ctx(s: str, path: str = "/mnt/mtd/x") -> bool:
        return _exec_ctx_before(s, s.rindex(path))

    # 예전 판정은 그대로 (명령 시작·키워드·source 의 '.')
    for s in ("/mnt/mtd/x", "a; /mnt/mtd/x", "a && /mnt/mtd/x", "then /mnt/mtd/x", "sh /mnt/mtd/x", "[ -f y ] && . /mnt/mtd/x",
              "find . -exec /mnt/mtd/x {} \\;", "a |/mnt/mtd/x"):
        assert ctx(s), s
    for s in ("echo /mnt/mtd/x", "A=/mnt/mtd/x", "cat /mnt/mtd/x", "echo . /mnt/mtd/x"):
        assert not ctx(s), s
    # 건너기 상한: 대입 16개는 되고 17개는 아니다 (경로마다 비용이 묶인다)
    assert ctx("A=1 " * 16 + "/mnt/mtd/x")
    assert not ctx("A=1 " * 17 + "/mnt/mtd/x")
    assert not ctx("A=" + "x" * 2000 + " /mnt/mtd/x")  # 낱말 길이 상한
    # 경로 꼴 래퍼 사슬('/usr/bin/nohup' 반복)은 앞서 판정한 경로 위치의 결과(memo)를 이어 쓴다 — 경로마다 낱말 하나만 거슬러 본다
    s = "/usr/bin/nohup " * 40 + "/mnt/mtd/x"
    memo: dict[int, bool] = {}
    for m in re.finditer(r"/usr/bin/nohup|/mnt/mtd/x", s):
        memo[m.start()] = _exec_ctx_before(s, m.start(), memo)
    assert memo[s.rindex("/mnt/mtd/x")] is True


def test_continuation_exec_item_through_mcp(tmp_path, workspace, auth):
    """실제 MCP fw_rootfs_audit: 환경 변수 접두 + 이어쓰기와 nohup 이어쓰기 둘 다 항목, HEAD 오탐 꼴(cp \\)은 항목 없음."""
    import asyncio

    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="시작 스크립트", authorization=auth, case_id="startupcase")
    write_tree(case.dir / "extract" / "rootfs-001", {
        "etc/fstab": "/dev/mtdblock3 /mnt/mtd jffs2 defaults 0 0\n",
        "etc/init.d/rcS": ("#!/bin/sh\nLD_LIBRARY_PATH=/mnt/mtd/app/lib \\\n    /mnt/mtd/app/ipcam &\nnohup \\\n/mnt/mtd/app/run.sh > /dev/null 2>&1 &\n"
                           "cp \\\n    /mnt/mtd/app/ipcam.conf /tmp/ipcam.conf\n"),
    })

    async def go() -> dict:
        from fwtriage_mcp.server import server

        async with Client(server) as c:
            return await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir="extract/rootfs-001", crack_defaults=False)

    r = asyncio.run(go())
    assert r["ok"] and r["summary"]["startup_scan_complete"]
    full = json.loads((case.dir / r["result_path"]).read_text(encoding="utf-8"))
    got = sorted((i["line"], i["target"]) for i in full["items"] if i["id"] == EXEC)
    assert got == [(2, "/mnt/mtd/app/ipcam"), (4, "/mnt/mtd/app/run.sh")]


# ---------------------------------------------------------------------------
# 적대적 긴 줄: 경로마다 비용이 묶여 전체 선형 (1 MiB 안팎)
# ---------------------------------------------------------------------------

PRE = "#!/bin/sh\n" + MOUNTS


def _rep(unit: str, size: int, head: str = "", tail: str = "") -> str:
    return PRE + head + unit * max(1, (size - len(head) - len(tail)) // len(unit)) + tail + "\n"


ADVERSARIAL = {
    "assign_chain": lambda n: _rep("A=1 ", n, tail="/mnt/mtd/p &"),
    "nohup16_groups": lambda n: _rep("nohup " * 16 + "/mnt/mtd/p ", n),
    "nohup_then_paths": lambda n: PRE + "nohup " * (n // 12) + "/mnt/mtd/p " * (n // 22) + "\n",
    "path_nohup_flood": lambda n: _rep("/usr/bin/nohup ", n, tail="/mnt/mtd/p"),
    "path_nohup_assign": lambda n: _rep("/usr/bin/nohup FOO=/mnt/mtd/x ", n),
    "long_tokens": lambda n: _rep("X" * 1000 + " /mnt/mtd/p ", n),
    "long_assign_tokens": lambda n: _rep("A=" + "x" * 1010 + " /mnt/mtd/p ", n),
    "assign_paths": lambda n: _rep("A=/mnt/mtd/p ", n),
    "quote_flood_double": lambda n: _rep('x" /mnt/mtd/p ', n),
    "quote_flood_single": lambda n: _rep("FOO='a /mnt/mtd/p ", n),
    "quoted_paths": lambda n: PRE + '"' + " /mnt/mtd/p" * (n // 11) + '" /mnt/mtd/q\n',
    "ssd_opt_flood": lambda n: _rep("-x /mnt/mtd/p ", n, head="start-stop-daemon -S "),
    "ssd_name_flood": lambda n: _rep("start-stop-daemon ", n, tail="-x /mnt/mtd/p"),
    "ssd_glued_flood": lambda n: _rep("--exec=/mnt/mtd/p ", n, head="start-stop-daemon -S "),
    "env_opt_flood": lambda n: _rep("-i ", n, head="env ", tail="/mnt/mtd/p"),
    "hits_on_one_line": lambda n: _rep(";/mnt/mtd/x", n),
    "whitespace_flood": lambda n: PRE + "nohup" + " " * n + "/mnt/mtd/p\n",
    "mixed_wrappers": lambda n: _rep("env -i A=1 setsid -f time -p command -p nohup /mnt/mtd/p ", n),
    # 6차 #9: 긴 묶음 옵션 낱말('-ttt…t1') 옆의 -x 경로마다 멈춤 동작 확인 — 낱말 길이의 제곱이던 정규식 (한 줄·이어쓰기 줄)
    "ssd_long_option_words": lambda n: _rep("start-stop-daemon -" + "t" * 2000 + "1 -x /mnt/mtd/p ", n),
    "ssd_long_option_words_bs": lambda n: _rep("start-stop-daemon -" + "t" * 2000 + "1 -x /mnt/mtd/p \\\n", n),
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_exec_context_walk_is_bounded_on_adversarial_lines(tmp_path, name):
    body = ADVERSARIAL[name](1000 << 10)
    assert len(body) <= rootfs.STARTUP_FILE_MAX
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": body})
    aud = _audit(root)
    _, dt = _timed(aud.audit_startup)
    assert dt < SLOW, (name, dt)
    assert aud.startup_scan_complete


# ---------------------------------------------------------------------------
# #12: 항목 양 — 하드 링크 한 번, 시작 스크립트 전체의 규칙 상한
# ---------------------------------------------------------------------------

BUILTIN_LINES = ["dropbear -B -p 22", "nc -l -p 4444 -e /bin/sh", "socat tcp-l:1 exec:sh", "tcpsvd 0 23 /bin/login", "getty --autologin root tty1",
                 "login -f root", "remserial -p 5150 /dev/ttyS0", "echo root:pass1 | chpasswd", "/mnt/mtd/run.sh"]


def test_hard_linked_startup_scripts_read_once(tmp_path):
    body = "#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd\n" + "\n".join(f"{b}  # {k}" for b in BUILTIN_LINES for k in range(3)) + "\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/S0000x": body})
    for i in range(1, 300):
        os.link(root / "etc/init.d/S0000x", root / f"etc/init.d/S{i:04d}x")
    aud = _audit(root)
    st, dt = _timed(aud.audit_startup)
    files = {i["file"] for i in aud.items if i.get("file", "").startswith("/etc/init.d/")}
    assert len(files) == 1, files  # 같은 inode 는 한 번만 읽는다 (항목은 처음 이름에)
    assert sum(1 for f in st["startup_files"] if f.startswith("/etc/init.d/")) == 300 and aud.startup_scan_complete
    assert sum(1 for i in aud.items if i["id"] == "builtin-login-f-root") == 3
    assert dt < SLOW


def test_startup_rule_cap_counts_excess_and_names_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(rootfs, "STARTUP_ITEM_CAP_PER_RULE", 30)
    body = "#!/bin/sh\n" + "login -f root\n" * 20 + "telnetd -l /bin/sh &\n"
    root = write_tree(tmp_path / "r", {f"etc/init.d/S{i:02d}copy": body for i in range(5)})  # 내용이 같은 서로 다른 파일 5개
    aud = _audit(root)
    res = aud.run()
    login = [i for i in res["items"] if i["id"] == "builtin-login-f-root"]
    assert len(login) == 30  # 파일마다 20개(상한과 같음)지만 시작 스크립트 전체에서 30개까지만
    assert res["summary"]["items_suppressed"] == 5 * 20 - 30
    lim = [x for x in res["limitations"] if "시작 스크립트 전체에서 같은 규칙은 30개" in x]
    assert len(lim) == 1 and "builtin-login-f-root +70" in lim[0], res["limitations"]
    assert not any(x.startswith("항목 상한(같은 파일의 같은 규칙") for x in res["limitations"])  # 파일마다 상한에는 걸리지 않았다
    assert res["summary"]["startup_scan_complete"]  # 검사는 끝까지 했다 (세기만 했을 뿐)
    # 다른 규칙은 밀려나지 않는다 (YAML 휴리스틱은 파일마다 첫 줄 하나)
    assert sum(1 for i in res["items"] if i["id"] == "gen-telnetd-login-shell") == 5


def test_startup_rule_cap_applies_to_yaml_heuristics(tmp_path, monkeypatch):
    monkeypatch.setattr(rootfs, "STARTUP_ITEM_CAP_PER_RULE", 3)
    root = write_tree(tmp_path / "r", {f"etc/init.d/S{i:02d}tel": "#!/bin/sh\ntelnetd -l /bin/sh &\n" for i in range(5)})
    res = _audit(root).run()
    assert sum(1 for i in res["items"] if i["id"] == "gen-telnetd-login-shell") == 3
    lim = [x for x in res["limitations"] if "시작 스크립트 전체에서 같은 규칙은 3개" in x]
    assert len(lim) == 1 and "gen-telnetd-login-shell +2" in lim[0]


def test_both_caps_are_reported_separately(tmp_path, monkeypatch):
    monkeypatch.setattr(rootfs, "STARTUP_ITEM_CAP_PER_RULE", 30)
    body = "#!/bin/sh\n" + "login -f root\n" * 25
    root = write_tree(tmp_path / "r", {f"etc/init.d/S{i:02d}copy": body for i in range(3)})
    res = _audit(root).run()
    # 첫 파일: 20개 적고 5개는 파일 상한. 둘째: 10개 적고(전체 30개) 15개는 전체 상한. 셋째: 25개 모두 전체 상한 (파일 상한을 먼저 본다)
    assert sum(1 for i in res["items"] if i["id"] == "builtin-login-f-root") == 30
    per_file = [x for x in res["limitations"] if x.startswith(f"항목 상한(같은 파일의 같은 규칙은 {ITEM_CAP_PER_RULE_FILE}개)")]
    glob = [x for x in res["limitations"] if "시작 스크립트 전체에서" in x]
    assert len(per_file) == 1 and len(glob) == 1
    n_file = int(per_file[0].split("걸려 ")[1].split("개")[0])
    n_glob = int(glob[0].split("걸려 ")[1].split("개")[0])
    assert (n_file, n_glob) == (5, 40)
    assert n_file + n_glob == res["summary"]["items_suppressed"] == 3 * 25 - 30


def test_many_copied_startup_scripts_bounded_items_and_memory(tmp_path):
    """리뷰 m1 축소판: 내용이 같은 시작 스크립트 600개(서로 다른 inode) — 예전에는 파일마다 ~180개(10만 개 이상)."""
    body = "#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd\n" + "\n".join(f"{b}  # {k}" for b in BUILTIN_LINES for k in range(20)) + "\n"
    root = write_tree(tmp_path / "r", {f"etc/init.d/S{i:04d}x": body for i in range(600)})
    aud = _audit(root)
    tracemalloc.start()
    try:
        res, dt = _timed(aud.run)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    by_rule: dict[str, int] = {}
    for it in res["items"]:
        if it.get("file", "").startswith("/etc/init.d/"):
            by_rule[it["id"]] = by_rule.get(it["id"], 0) + 1
    assert by_rule and max(by_rule.values()) <= STARTUP_ITEM_CAP_PER_RULE
    assert by_rule["builtin-login-f-root"] == STARTUP_ITEM_CAP_PER_RULE and by_rule[EXEC] == STARTUP_ITEM_CAP_PER_RULE
    assert res["summary"]["items_suppressed"] >= 600 * 20 - STARTUP_ITEM_CAP_PER_RULE
    assert any("시작 스크립트 전체에서 같은 규칙은" in x and "builtin-login-f-root" in x for x in res["limitations"])
    assert res["summary"]["startup_scan_complete"] and sum(1 for f in res["startup_files"] if f.startswith("/etc/init.d/")) == 600
    assert len(res["items"]) <= 9 * STARTUP_ITEM_CAP_PER_RULE + 50
    assert dt < 30 and peak < (48 << 20), (dt, peak)  # 상한 전에는 항목 10만 개 이상 (같은 입력에서 수백 MiB)


# ---------------------------------------------------------------------------
# #15: 쓰기 가능 접두 판정 (선형, PATH_MAX)
# ---------------------------------------------------------------------------


def test_writable_prefix_semantics(tmp_path):
    body = "\n".join(["/mnt/mtd/x", "/mnt/mtd", "/mnt/mtdx/y", "/mnt", "/opt/data/run.sh", "/cfg/a/b/c/d/e", "/cfg/a/b", "/var/w/sub/app"])
    root = write_tree(tmp_path / "r", {
        "etc/fstab": "/dev/mtdblock6 /var/w ubifs defaults 0 0\n/dev/mtdblock7 /var/ro jffs2 ro 0 0\n",
        "etc/init.d/rcS": "#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd/\n" + body + "\n/var/ro/app\n",
    })
    aud = _audit(root, persistent=["/opt/data/"], profile={"firmware": {"config_paths": ["/cfg/a/b/c"]}})
    aud.audit_startup()
    got = sorted(i["target"] for i in aud.items if i["id"] == EXEC)
    assert got == sorted(["/mnt/mtd/x", "/mnt/mtd", "/opt/data/run.sh", "/cfg/a/b/c/d/e", "/var/w/sub/app"])


def test_deep_writable_prefix_within_path_max_is_linear(tmp_path):
    """깊이 2000(4000자, PATH_MAX 안)의 마운트 지점 아래 서로 다른 실행 경로 수백 개 — 옛 판정은 경로마다 접두를 잘라 해시(D²)."""
    mp = "/a" * 2000
    lines = [f"{mp}/x{i}" for i in range(250)]
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": f"#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 {mp}\n" + "\n".join(lines) + f"\n{mp[:-2]}/b/c\n"})
    aud = _audit(root)
    _, dt = _timed(aud.audit_startup)
    targets = [i["target"] for i in aud.items if i["id"] == EXEC]
    assert len(targets) == ITEM_CAP_PER_RULE_FILE and all(t.startswith(mp + "/x") for t in targets)  # 형제 접두('/a'*1999 + '/b')는 아니다
    assert aud.items_suppressed == 250 - ITEM_CAP_PER_RULE_FILE
    assert dt < SLOW


@pytest.mark.parametrize("two_files", [False, True])
def test_paths_longer_than_path_max_are_skipped_quickly(tmp_path, two_files):
    """리뷰 i1/i2: 깊이 26만의 마운트 지점과 실행 위치의 깊은 경로 (옛 코드 19.5초·77.5초, max_seconds 무시). execve 는 PATH_MAX 보다 긴
    경로를 실행할 수 없으므로 건너뛰는 것이 맞다."""
    d = 260000
    mount = "mount -t vfat /dev/mmcblk0p1 " + "/a" * d + "\n"
    files = ({"etc/init.d/S00mount": "#!/bin/sh\n" + mount, "etc/init.d/S99exec": "#!/bin/sh\n" + "/a" * d + "/b\n"} if two_files
             else {"etc/init.d/rcS": "#!/bin/sh\n" + mount + "/b" * d + "\n"})
    root = write_tree(tmp_path / "r", files)
    aud = _audit(root, ctl=Ctl(max_seconds=1))
    _, dt = _timed(aud.audit_startup)
    assert dt < SLOW and aud.startup_scan_complete
    assert not [i for i in aud.items if i["id"] == EXEC]


def test_long_exec_path_under_normal_prefix_is_not_reported(tmp_path):
    """PATH_MAX(4096)보다 긴 경로는 쓰기 가능 접두 아래여도 실행될 수 없어 항목이 아니다 (문서화된 한계: 그보다 짧으면 항목)."""
    long_p = "/mnt/mtd/" + "d/" * (PATH_MAX // 2) + "app"
    ok_p = "/mnt/mtd/" + "d/" * 100 + "app"
    assert _exec_items(tmp_path, f"{long_p} &\n{ok_p} &") == [(6, ok_p)]


# ---------------------------------------------------------------------------
# 6차 검증 #17·#16: 셸 문법이 아닌 파일(systemd 유닛)은 대입·래퍼를 건너지 않는다, #9 멈춤 동작 정규식은 선형
# ---------------------------------------------------------------------------

def test_systemd_exec_arguments_are_not_exec_targets(tmp_path):
    files = {
        "etc/systemd/system/rkipc.service": ("[Unit]\nDescription=rkipc\n[Service]\nExecStartPre=-/bin/rm /userdata/rkipc.lock\n"
                                            "ExecStart=/oem/usr/bin/rkipc /userdata/rkipc.ini\nExecStopPost=/bin/umount /userdata\n"),
        "etc/systemd/system/hostapd.service": "[Service]\nExecStart=/usr/sbin/hostapd /userdata/cfg/hostapd.conf\n",
        # 셸 스크립트의 대입 접두는 그대로 실행 위치다
        "etc/init.d/S50app": "#!/bin/sh\nLD_LIBRARY_PATH=/userdata/lib /userdata/app/run.sh &\n",
    }
    root = write_tree(tmp_path / "r", files)
    aud = _audit(root, persistent=["/userdata"])
    aud.audit_startup()
    got = sorted((i["file"], i["target"]) for i in aud.items if i["id"] == EXEC)
    assert got == [("/etc/init.d/S50app", "/userdata/app/run.sh")], aud.items


def test_exec_ctx_respects_shell_flag():
    unit = "ExecStart=/usr/bin/recorder /mnt/sdcard/record\n"
    assert not _exec_ctx_before(unit, unit.index("/mnt/sdcard"), shell=False)
    sh = "LD_LIBRARY_PATH=/x /mnt/mtd/app &\n"
    assert _exec_ctx_before(sh, sh.index("/mnt/mtd"), shell=True) and not _exec_ctx_before(sh, sh.index("/mnt/mtd"), shell=False)
    ssd = "ExecStart=/sbin/start-stop-daemon -S -x /mnt/mtd/app\n"
    assert _exec_ctx_before(ssd, ssd.index("/mnt/mtd"), shell=False)  # 유닛도 start-stop-daemon 의 실행 파일은 실행이다


def test_shebangless_shell_helper_under_systemd_dir_joins(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/systemd/system/camera-init": "echo 'root:Adm1n2024' |\n  chpasswd\n"})
    aud = _audit(root)
    aud.audit_startup()
    assert "builtin-chpasswd-literal" in {i["id"] for i in aud.items}, aud.items


def test_ssd_stop_regex_is_linear_and_keeps_spans():
    for w in (500, 4000):
        t0 = time.perf_counter()
        rootfs._SSD_STOP_RX.search(" -" + "t" * w + "1")
        assert time.perf_counter() - t0 < 0.05, w
    for word, stop in [("-K", True), ("-Sbx", False), ("-tbx", True), ("--stop", True), ("--status", True), ("-T", True), ("-x", False),
                       ("-Kx1", False), ("-a", False), ("-oKx", True), ("--test", True), ("-" + "t" * 3000, True)]:
        assert bool(rootfs._SSD_STOP_RX.search(" " + word + " ")) is stop, word
