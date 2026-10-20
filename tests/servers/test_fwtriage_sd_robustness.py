"""fwtriage SD 표면(I3a) 적대적 리뷰 회귀 테스트 — 리뷰의 재현 스크립트(R1~R27)를 빠르고 경계가 있는 입력으로 옮겼다.

- 견고성: 펌웨어 정규식을 실행하지 않음(R2), U-Boot env run 펼침 상한(R1·R18), 파일 안 선형 처리(R3·R20), YAML 패턴 선형(R4 + 두 팩 전체 일반 검사),
  udev 해석 선형(R19), 기본 감사(audit_startup)의 긴 반복 줄
- 마스킹: 일치 위치 마스킹(R6), openssl 키·IV·따옴표 값(R7)
- 의미: 읽기 전용 fs(R8), verify(R9), 버튼 '읽기'만(R10), 디렉터리로 복사 뒤 플래시(R11), cd 뒤 상대 실행(R12), 히트 상한(R13), SD-09 단계(R14),
  eMMC 전용 기기(R15), 한 줄 시험의 범위(R17), fw_setenv 만 있는 스크립트(R21), fstrim 애플릿 문자열(R22), 순회 잘림(R23),
  따옴표 속 괄호·/mnt/tftpboot(R24), 결정적 순회(R25), eMMC vfat /boot(R27)
- 3차 검증(V1~V7): 기본 감사가 키워드 홍수·긴 덧대기 줄도 끝까지 보고(V2), 경로 일치를 흘려 보며 상한을 조용히 두지 않음(V3),
  mdev '$MODALIAS=.*'·일반 catch-all·'[hs]d…' 분류(V1·V1b), 큰따옴표 안 $( )·역따옴표·su -c·eval·case·find -exec(V4·V4b),
  가드 '|| exit/return'·'&& {' 여러 줄·줄 수 상한 없는 if 본문, 서브셸·인자 없는 cd·cp -r(V7)
시간 단언은 옛 코드가 수십~수백 초 걸리던 입력에 넉넉한 상한(수 초)을 둔다 (느린 기계에서도 흔들리지 않게).
"""

from __future__ import annotations

import json
import re
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

from fwtriage.builders import build_flash, build_min_elf
from fwtriage.sd_builders import write_tree

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import sdsurface  # noqa: E402
from fwtriage_mcp.common import Ctl  # noqa: E402
from fwtriage_mcp.hunt import hunt  # noqa: E402
from fwtriage_mcp.patterns import load_patterns  # noqa: E402
from fwtriage_mcp.rootfs import Auditor, mask_credentials, parse_udev_rules  # noqa: E402
from fwtriage_mcp.sdsurface import (  # noqa: E402
    _SERVICE_START_RX,
    SdSurface,
    _glob_match,
    _mask_excerpt,
    attach_sd_boot,
    classify_mdev_matcher,
    classify_udev_match,
    sd_boot_analysis,
)
from fwtriage_mcp.uboot import env_scan  # noqa: E402
from pweh.formats import build_uboot_env  # noqa: E402

#: 넉넉한 시간 상한(초) — 옛 코드는 같은 입력에서 10~160초
SLOW = 5.0


def _plain_flash() -> bytes:
    img, _ = build_flash(None)
    return img


def _audit(root: Path, ctl: Ctl | None = None, max_entries: int = 20000) -> Auditor:
    aud = Auditor(root, ctl or Ctl(max_seconds=120), load_patterns(), persistent_paths=[], profile={}, max_file_size=16 << 20,
                  crack=False, crack_seconds=1, words=[], max_entries=max_entries)
    aud.walk()
    return aud


def _surface(root: Path | None = None, image: bytes | None = None, ctl: Ctl | None = None, max_entries: int = 20000, **kw) -> dict:
    ctl = ctl or Ctl(max_seconds=120)
    sd = SdSurface(ctl, load_patterns(), **kw)
    if root is not None:
        aud = _audit(root, ctl, max_entries)
        sd.scan_rootfs(aud, aud.audit_startup(), aud.audit_web())
    if image is not None:
        sd.scan_image(image, len(image), "dumps/flash.bin", env_scan(image, len(image), ctl, include_default=True))
    return sd.result(rootfs_given=root is not None, image_given=image is not None)


def _checks(res: dict) -> dict[str, dict]:
    return {c["id"]: c for c in res["checks"]}


def _rules(c: dict) -> set[str]:
    return {e["rule"] for e in c["evidence"]}


def _timed(fn, *a, **kw):
    t0 = time.monotonic()
    out = fn(*a, **kw)
    return out, time.monotonic() - t0


# ---------------------------------------------------------------------------
# R2: 펌웨어 정규식을 실행하지 않는다
# ---------------------------------------------------------------------------

EVIL_MDEV = ["(?:.*){30}X", "a{4294967296}", "(" * 1200 + "m" + ")" * 1200, "(a|a)*" * 20 + "b"]


def test_mdev_device_regex_is_never_compiled_or_executed(tmp_path, monkeypatch):
    import re as _re

    real = _re._compile
    seen: list[str] = []

    def spy(pattern, flags):
        if isinstance(pattern, str) and pattern in EVIL_MDEV:
            seen.append(pattern)
            raise AssertionError(f"펌웨어 정규식을 컴파일함: {pattern[:40]}")
        return real(pattern, flags)

    monkeypatch.setattr(_re, "_compile", spy)
    out, dt = _timed(lambda: [classify_mdev_matcher(r, []) for r in EVIL_MDEV])
    assert dt < 1.0 and all(k in ("unclassifiable", "other") for k in out), out
    assert [SdSurface._mdev_matches_sd(r, []) for r in EVIL_MDEV] == [False] * len(EVIL_MDEV)
    # 끝까지: 분류 못 하는 규칙만 있으면 SD-04 는 unknown(처리기로 적음), 예외·멈춤 없음
    root = write_tree(tmp_path / "evil", {"etc/mdev.conf": f"{EVIL_MDEV[0]} 0:0 660 @/sbin/x.sh\n{EVIL_MDEV[1]} 0:0 660\n", "sbin/x.sh": "#!/bin/sh\necho x\n"})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=5))
    assert dt < SLOW and not seen
    c = _checks(res)["SD-04"]
    assert c["status"] == "unknown" and "분류하지 못했다" in c["unknown_reason"]
    assert any(h["match_kind"] == "unclassifiable" for h in res["hotplug_handlers"])
    # SD 규칙이 함께 있으면 found
    root2 = write_tree(tmp_path / "mix", {"etc/mdev.conf": f"{EVIL_MDEV[0]} 0:0 660\nmmcblk[0-9]p[0-9] 0:0 660 */etc/hotplug/sd.sh\n",
                                          "etc/hotplug/sd.sh": "#!/bin/sh\nmount -t vfat /dev/$MDEV /mnt/sd\n"})
    assert _checks(_surface(root2, ctl=Ctl(max_seconds=5)))["SD-04"]["status"] == "found" and not seen
    assert not hasattr(sdsurface, "fnmatch")  # udev glob 도 정규식으로 바꾸지 않는다


@pytest.mark.parametrize("regex, env, kind", [
    ("mmcblk[0-9]p[0-9]", [], "sd"), ("sd[a-z][0-9]*", [], "sd"), ("(sd|hd)[a-z]", [], "sd"), ("@179,0-255", [], "sd"), ("@31,0", [], "other"),
    ("$DEVNAME=mmcblk.*", [], "sd"), (".*", [], "catch-all"), (".*", ["SUBSYSTEM=block"], "catch-all"), ("null", [], "other"), ("tty.*", [], "other"),
    ("mtdblock[0-9]", [], "other"), ("x", ["SUBSYSTEM=block", "DEVNAME=mmcblk.*"], "sd"), ("a" * 200, [], "unclassifiable"), ("a\\1", [], "unclassifiable"),
])
def test_classify_mdev_matcher(regex, env, kind):
    assert classify_mdev_matcher(regex, env) == kind


def test_udev_glob_match_without_regex():
    assert _glob_match("mmcblk[0-9]p[0-9]", "mmcblk0p1") and _glob_match("sd*", "sda1") and _glob_match("mmc?", "mmc0")
    assert not _glob_match("ttyS*", "mmcblk0") and _glob_match("[!t]*", "sda") and not _glob_match("[!s]*", "sda")
    assert _glob_match("*" * 200, "x") is None  # 128자 상한 → 분류 불가
    assert classify_udev_match({"KERNEL": "mmcblk*"}) == "sd" and classify_udev_match({"KERNEL": "ttyUSB*"}) == "other"
    assert classify_udev_match({"KERNEL": "*" * 200}) == "unclassifiable" and classify_udev_match({"ENV{ID_BUS}": "usb"}) == "sd"


# ---------------------------------------------------------------------------
# R1·R18: U-Boot env run 펼침 상한
# ---------------------------------------------------------------------------


def test_env_run_expansion_is_bounded_in_memory_and_time():
    env = {"bootdelay": "1", "bootcmd": "run x", "x": "run " + "a " * 60000, "a": "Z" * 120000}
    tracemalloc.start()
    b, dt = _timed(sd_boot_analysis, env, storage="flash-crc")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert dt < SLOW and peak < (64 << 20), (dt, peak)  # 옛 코드: 3 GiB 한도에서 MemoryError
    assert b["expansion_truncated"] is True and any("펼침 예산" in n for n in b["notes"])
    # 끝나지 않는 'run run run … !' (옛 _ENV_RUN_RX: 80 KB 에서 37초)
    _, dt = _timed(sd_boot_analysis, {"bootdelay": "1", "bootcmd": "run " * 20000 + "!"}, storage="flash-crc")
    assert dt < SLOW
    # CRC 가 맞는 256 KiB env 를 fw_uboot_env 와 같은 경로(env_scan → attach_sd_boot)로
    blk = build_uboot_env(env, size=0x40000)
    img = b"\xff" * 0x10000 + blk + b"\xff" * 0x10000
    scan = env_scan(img, len(img), Ctl(max_seconds=60), include_default=False)
    _, dt = _timed(attach_sd_boot, scan)
    assert dt < SLOW and scan["envs"][0]["sd_boot"]["expansion_truncated"] is True


def test_env_run_expansion_still_in_place_for_mmc_first():
    b = sd_boot_analysis({"bootcmd": "if gpio input 3; then run sdboot; fi; sf probe 0; bootm", "sdboot": "fatload mmc 0 0x82000000 uImage"}, storage="flash-crc")
    assert b["mmc_first"] is True and b["expansion_truncated"] is False
    b = sd_boot_analysis({"bootcmd": "sf probe 0; sf read 0x82000000 0 0x100; run sdboot", "sdboot": "fatload mmc 0 0x82000000 uImage"}, storage="flash-crc")
    assert b["mmc_first"] is False


# ---------------------------------------------------------------------------
# R3·R20: 파일 안 처리 선형·시간 예산·줄 길이 상한
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", [
    "flashcp /mnt/sd/u.bin /dev/mtd2\n" * 4000,  # 옛 코드: SD-02 토큰마다 파일 전체 join (4000줄 11초)
    "openssl -in /mnt/sd/a " * 200 + "\n",  # 옛 _OPENSSL_IO_RX: 4.3 KiB 한 줄 160초
    "flashcp /mnt/sd/u.bin /dev/mtd2\n" + "gpg " * 20000 + "\n",  # 옛 _SIGNATURE_RX 다항 역추적
    "[ -f /mnt/sd/a ] && echo a\n" + "nc " * 40000 + "\n",  # 옛 _SERVICE_START_RX / 기본 감사의 nc 규칙 (13초)
])
def test_intra_file_work_is_bounded(tmp_path, body):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + body})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=2))
    assert dt < SLOW, dt
    assert _SERVICE_START_RX.search("nc " * 40000) is None


def test_overlong_line_makes_text_checks_unknown_not_not_found(tmp_path):
    root = write_tree(tmp_path / "long", {"etc/init.d/rcS": "#!/bin/sh\necho start\n" + "/mnt/sd" * 4000 + "\n"})
    res = _surface(root, _plain_flash())
    c = _checks(res)
    assert res["phases"]["rootfs_text"] == "truncated" and any("자를 넘는 줄" in x for x in res["limitations"])
    for cid in ("SD-01", "SD-05", "SD-06", "SD-09"):
        assert c[cid]["status"] == "unknown", (cid, c[cid])


def test_expired_budget_inside_per_line_loop(tmp_path):
    root = write_tree(tmp_path / "big", {"etc/init.d/rcS": "#!/bin/sh\n" + "sh /mnt/sd/x.sh\n" * 30000})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=1e-9))
    assert dt < SLOW and "not-found" not in {c["status"] for c in res["checks"]}


# ---------------------------------------------------------------------------
# R4: YAML 휴리스틱 선형 (두 팩 전체) + 기본 감사·fw_strings_hunt 경로
# ---------------------------------------------------------------------------

PATHOLOGICAL_SEEDS = ["/mnt/sd", "syslogd ", "a/", "nc ", "openssl -in ", "mount -t vfat ", "load mmc ", "telnetd ", "/mnt/sd/update", "core_pattern /mnt/sd",
                      "%s", "password=", "sh -c ", "-l /bin/sh "]
#: 예외 없음 — gen-telnetd-login-shell·gen-getty-autologin·gen-static-digest-nonce 도 간격을 {0,1024}? 로 묶었다
#: (옛 무제한: 'telnetd ' 200 KiB 에 14초, 'getty ' 64 KiB 에 약 2초, 'Digest ' 64 KiB 에 약 0.7초 — 크기의 제곱으로 늘었다).
#: 기본 감사는 최상위 무제한 간격('[^\n]*')과 상한 256 이상의 같은 줄 간격('{0,1024}?')을 _GapChain 으로 나눠 길이 제한 없이 평가한다 —
#: 그 판정기 자체의 선형성은 test_default_audit_yaml_evaluator_linear_on_own_literal_floods 가 휴리스틱마다 자기 리터럴 홍수로 잰다.
KNOWN_SLOW: set[tuple[str, str]] = set()


def _pattern_words(h) -> list[str]:
    """휴리스틱의 리터럴과 패턴 안의 단어(이스케이프·플래그 제외) — 그 패턴의 시작점이 될 수 있는 낱말들."""
    src = h.rx.pattern if h.rx is not None else h.rx_bytes.pattern.decode("latin-1")
    src = re.sub(r"\(\?[A-Za-z]+\)", " ", re.sub(r"\\[A-Za-z]", " ", src))
    return list(dict.fromkeys(list(h.literals or [])[:8] + re.findall(r"[A-Za-z][A-Za-z0-9_]+", src)))[:12]


def test_every_string_heuristic_in_both_packs_is_linear_on_pathological_inputs():
    """fw_strings_hunt 가 쓰는 원래 정규식(사전 필터 없이)을 고정 씨앗과, 휴리스틱마다 자기 단어를 되풀이한 64 KiB 입력으로 잰다."""
    size = 64 * 1024
    inputs = {s: (s * (size // len(s) + 1))[:size] for s in PATHOLOGICAL_SEEDS}
    slow = []
    for pack in ("cctv", "game"):
        for h in load_patterns(pack=pack).string_heuristics:
            own = {w + suf: None for w in _pattern_words(h) for suf in (" ", "\t", "", "a")}
            for seed in own:
                own[seed] = (seed * (size // len(seed) + 1))[:size]
            for seed, text in {**inputs, **own}.items():
                if (h.id, seed) in KNOWN_SLOW:
                    continue
                t0 = time.monotonic()
                if h.rx is not None:
                    for _ in h.rx.finditer(text):  # 사전 필터 없이 (최악)
                        pass
                else:
                    for _ in h.rx_bytes.finditer(text.encode("latin-1")):
                        pass
                dt = time.monotonic() - t0
                if dt > 0.5:
                    slow.append((h.id, seed, round(dt, 2)))
    assert slow == [], f"긴 입력에서 다항 시간 패턴: {slow}"


def test_default_audit_and_strings_hunt_not_slowed_by_sd_patterns(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\necho start\n" + "/mnt/sd" * 32000 + "\n"})  # 219 KiB 한 줄 (옛: 38초)
    aud = _audit(root, Ctl(max_seconds=2))
    _, dt = _timed(aud.audit_startup)
    assert dt < SLOW
    case = tmp_path / "case"
    f = case / "dumps" / "app.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x7fELF\x00\x00" + b"/mnt/sd" * 32000 + b"\x00")
    sel, _ = load_patterns().select(None)
    _, dt = _timed(hunt, f, False, case, Ctl(max_seconds=2), sel, max_hits=500, per_pattern_cap=50, max_file_size=64 << 20)
    assert dt < SLOW


#: (키워드 홍수 줄, 그 줄 끝에 붙인 진짜 명령, 기본 감사가 찾아야 할 항목 id, 서비스) — 옛 키워드 반복 건너뛰기·4096자 창이 숨기던 모양
FLOOD_CASES = [
    ("nc ", "nc -l -p 4444 -e /bin/sh", "builtin-netcat-shell", "netcat-listener"),
    ("netcat ", "netcat -l -p 4444 -e /bin/sh", "builtin-netcat-shell", "netcat-listener"),
    ("dropbear ", "; /usr/sbin/dropbear -B", "builtin-dropbear-blank-password", "dropbear"),
    ("telnetd ", "; telnetd -l /bin/sh", "gen-telnetd-login-shell", "telnetd"),
    ("getty ", "; getty -n -l /bin/sh 115200 ttyS0", "gen-getty-autologin", None),
    ("getty ", "; agetty --autologin root ttyS0", "builtin-agetty-autologin", None),
    ("mount -t vfat ", "; login -f root", "builtin-login-f-root", None),
    ("socat ", "; socat TCP-LISTEN:23,fork EXEC:/bin/sh", "builtin-socat-exec-shell", "socat"),
    ("remserial ", "; remserial -d -p 5150 /dev/ttyS1", "builtin-remserial", "remserial"),
    ("login ", "; login -f root", "builtin-login-f-root", None),
    ("rtsp", " /usr/bin/" + "rtsp" * 64 + "_server_daemon &", None, "rtspd"),
    ("Digest ", 'Digest realm="x" nonce="tick"', "gen-static-digest-nonce", None),
]


@pytest.mark.parametrize("seed, tail, item, svc", FLOOD_CASES)
def test_default_audit_startup_scans_whole_flood_lines(tmp_path, seed, tail, item, svc):
    """기본 fw_rootfs_audit·fw_sd_surface 가 함께 쓰는 audit_startup: 키워드가 수없이 되풀이되는 긴 줄도 빠르게 끝까지 본다.

    옛 코드는 키워드가 한 줄에 16번 넘게 나오거나 줄이 4096자를 넘으면 규칙을 건너뛰거나 앞부분만 봐서, 같은 줄 끝의 진짜 백도어를 놓쳤다."""
    line = seed * (120 * 1024 // len(seed) + 1)
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + line + "\n" + line + tail + "\n"})
    aud = _audit(root, Ctl(max_seconds=60))
    st, dt = _timed(aud.audit_startup)
    assert dt < SLOW, (seed, dt)
    assert aud.startup_scan_complete and not [x for x in aud.limitations if "미완료" in x]
    ids = {i["id"] for i in aud.items if i.get("line") == 3}
    if item:
        assert item in ids, (seed, ids)
    if svc:
        assert svc in {s["service"] for s in st["services"]}, seed


@pytest.mark.parametrize("pad", [4100, 70000])
def test_default_audit_startup_finds_command_after_long_padding(tmp_path, pad):
    """같은 줄 앞에 긴 덧대기(': aaaa…;')를 둬도 뒤의 telnetd -l /bin/sh 를 찾고 실행 파일 경로도 남긴다 (줄 앞 4096자만 보던 옛 창 제거)."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n: " + "a" * pad + " ; /usr/sbin/telnetd -l /bin/sh &\n"})
    aud = _audit(root)
    st = aud.audit_startup()
    assert {"gen-telnetd-launch", "gen-telnetd-login-shell"} <= {i["id"] for i in aud.items}
    assert [(s["service"], s["binary"]) for s in st["services"]] == [("telnetd", "/usr/sbin/telnetd")]


def test_default_audit_service_binary_lookup_bounded_on_slash_flood(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + "/" * 200000 + " telnetd &\n"})
    aud = _audit(root)
    st, dt = _timed(aud.audit_startup)
    assert dt < SLOW and [s["service"] for s in st["services"]] == ["telnetd"]


def test_default_audit_mount_with_trailing_comment_counts_as_writable(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\nmount -t jffs2 /dev/mtdblock4 /mnt/mtd # mount " + "mount " * 17 + "\nsh /mnt/mtd/start.sh &\n"})
    aud = _audit(root)
    st = aud.audit_startup()
    assert [m["mount_point"] for m in st["mounts"]] == ["/mnt/mtd"]
    assert [(i["id"], i["line"]) for i in aud.items if i["id"] == "builtin-exec-from-writable-storage"] == [("builtin-exec-from-writable-storage", 3)]


def test_default_audit_follows_script_after_many_absolute_paths(tmp_path):
    """옛 abs_hits[:20000] 상한은 앞에 경로 2만 개를 두면 뒤의 'sh /usr/bin/backdoor.sh' 를 조용히 버렸다 (그 스크립트를 감사하지 않음)."""
    paths = "\n".join(f"[ -d /opt/d{i} ] || true" for i in range(20001))
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + paths + "\nsh /usr/bin/backdoor.sh &\n",
                                       "usr/bin/backdoor.sh": "#!/bin/sh\n/usr/sbin/telnetd -l /bin/sh &\n"})
    aud = _audit(root)
    st, dt = _timed(aud.audit_startup)
    assert dt < SLOW
    assert "/usr/bin/backdoor.sh" in st["startup_files"]
    assert any(i["id"] == "gen-telnetd-login-shell" and i["file"] == "/usr/bin/backdoor.sh" for i in aud.items)
    assert aud.startup_scan_complete


def test_default_audit_path_pass_memory_is_streaming(tmp_path):
    """옛 코드는 경로 일치마다 4096자 줄 조각을 만들어 1 MiB 시작 스크립트에 1.45 GiB 를 썼다."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + ("/a " * 1366 + "xx\n") * 255})
    aud = _audit(root)
    tracemalloc.start()
    try:
        _, dt = _timed(aud.audit_startup)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert dt < SLOW and peak < 64 << 20, (dt, peak)


def test_startup_queue_cap_is_reported_not_silent(tmp_path, monkeypatch):
    """큐 상한에 걸려 실행 문맥 참조를 따라가지 못하면 '[시작 스크립트 검사 미완료]' 와 summary.startup_scan_complete=False."""
    from fwtriage_mcp import rootfs

    monkeypatch.setattr(rootfs, "STARTUP_QUEUE_MAX", 3)
    monkeypatch.setattr(rootfs, "STARTUP_QUEUE_EXEC_MAX", 5)
    files = {"etc/init.d/rcS": "#!/bin/sh\n" + "".join(f"cat /usr/lib/ref{i}.sh\n" for i in range(4)) + "".join(f"sh /usr/bin/s{i}.sh\n" for i in range(6))}
    for i in range(4):
        files[f"usr/lib/ref{i}.sh"] = "#!/bin/sh\necho ref\n"
    for i in range(6):
        files[f"usr/bin/s{i}.sh"] = "#!/bin/sh\necho s\n"
    root = write_tree(tmp_path / "r", files)
    aud = _audit(root)
    st = aud.audit_startup()
    assert len(st["startup_files"]) == 5 and not aud.startup_scan_complete
    lim = " ".join(aud.limitations)
    assert "[시작 스크립트 검사 미완료]" in lim and "실행 문맥으로 참조된 스크립트" in lim and "/usr/bin/s" in lim
    assert "실행 문맥이 아닌 곳에서 참조된 스크립트" in lim
    assert aud.run()["summary"]["startup_scan_complete"] is False


def test_oversized_startup_script_is_reported(tmp_path, monkeypatch):
    from fwtriage_mcp import rootfs

    monkeypatch.setattr(rootfs, "STARTUP_FILE_MAX", 4096)
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + "echo pad\n" * 1000 + "telnetd -l /bin/sh &\n"})
    aud = _audit(root)
    aud.audit_startup()
    assert not aud.startup_scan_complete and any("[시작 스크립트 검사 미완료]" in x and "/etc/init.d/rcS" in x for x in aud.limitations)


def test_expired_budget_marks_startup_incomplete_and_sd_surface_unknown(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\necho hi\n"})
    aud = _audit(root, Ctl(max_seconds=1e-9))
    st = aud.audit_startup()
    assert not aud.startup_scan_complete and any(x.startswith("[시작 스크립트 검사 미완료] 시간 예산") for x in aud.limitations)
    sd = SdSurface(Ctl(max_seconds=60), load_patterns())
    sd.scan_rootfs(aud, st, {"servers": [], "cgi": [], "config": []})
    res = sd.result(rootfs_given=True, image_given=False)
    assert res["phases"]["rootfs_text"] == "truncated"
    assert _checks(res)["SD-01"]["status"] == "unknown"


def _literal_flood_seeds(h) -> list[str]:
    seeds = []
    for lit in (h.literals or [])[:6]:
        for suf in (" ", "\t", "/", "=", "", "-", ":", "a"):
            seeds.append(lit + suf)
    return seeds


def test_default_audit_yaml_evaluator_linear_on_own_literal_floods():
    """기본 감사가 실제로 쓰는 판정기(yaml_line_matcher: 최상위 무제한 간격은 _GapChain)로 두 팩의 text/any 휴리스틱을
    각자의 리터럴을 되풀이한 120 KiB 줄에서 잰다 (일반 선형 시험의 고정 씨앗에 없는 'getty '·'Digest ' 같은 홍수 포함)."""
    from fwtriage_mcp.rootfs import yaml_line_matcher

    size = 120 * 1024
    slow = []
    for pack in ("cctv", "game"):
        for h in load_patterns(pack=pack).string_heuristics:
            if h.rx is None or h.scope not in ("text", "any"):
                continue
            m = yaml_line_matcher(h)
            for seed in _literal_flood_seeds(h):
                text = seed * (size // len(seed) + 1)
                t0 = time.monotonic()
                m.search(text, 0, len(text))
                dt = time.monotonic() - t0
                if dt > 0.5:
                    slow.append((pack, h.id, seed, round(dt, 2)))
    assert slow == [], slow


def test_gap_chain_agrees_with_regex_on_random_lines():
    """_GapChain 으로 바꾼 휴리스틱은 짧은 무작위 줄에서 원래 정규식과 같은 판정을 한다 (나눠 평가해도 뜻이 같다)."""
    import random
    from types import SimpleNamespace

    from fwtriage_mcp.rootfs import _GapChain, yaml_line_matcher

    # 기본 팩의 큰 상한 간격({0,1024}?)과, 옛 무제한 꼴(사용자 팩에 올 수 있는 모양) 모두 짧은 줄에서는 원래 정규식과 같은 판정이어야 한다
    legacy = [
        SimpleNamespace(id="legacy-getty", pattern=r"getty\b[^\n]*[ \t]-l[ \t]*/bin/(?:sh|ash|bash)\b", literals=["getty"], scope="text"),
        SimpleNamespace(id="legacy-digest", pattern=r'Digest\s+[^\n%]*nonce="[^"%]+"', literals=['nonce="'], scope="any"),
        SimpleNamespace(id="legacy-telnetd", pattern=r"telnetd\b[^\n]*[ \t]-l[ \t]*/bin/(?:sh|ash|bash)\b", literals=["telnetd"], scope="any"),
    ]
    for h in legacy:
        h.rx = re.compile(h.pattern)
    rnd = random.Random(7)
    checked = 0
    for h in [h for pack in ("cctv", "game") for h in load_patterns(pack=pack).string_heuristics] + legacy:
        if h.rx is None or h.scope not in ("text", "any"):
            continue
        m = yaml_line_matcher(h)
        if not isinstance(m, _GapChain):
            continue
        checked += 1
        words = sorted(set(re.findall(r"[A-Za-z0-9_./=\"%:-]{1,12}", h.pattern)) | set(h.literals or []))
        toks = words + [" ", "\t", "x", "-l", "/bin/sh", "%", '"', "nonce=\"", "Digest", "getty"]
        for _ in range(20000):
            line = "".join(rnd.choice(toks) for _ in range(rnd.randint(1, 12)))
            assert (h.rx.search(line) is not None) == (m.search(line, 0, len(line)) is not None), (h.id, line)
    assert checked >= 6  # 기본 팩의 {0,1024}? 셋(telnetd·getty·digest) + 옛 무제한 꼴 셋


#: (YAML id, 키워드 쪽, 꼬리) — 키워드와 꼬리 사이를 2000자 띄운다. 묶은 정규식({0,1024}?)은 못 맞추지만 기본 감사는 길이 제한 없이 잡는다
LONG_GAP_CASES = [
    ("gen-telnetd-login-shell", "/usr/sbin/telnetd -p 23", " -l /bin/sh &"),
    ("gen-getty-autologin", "/sbin/getty -n 115200 ttyS0", " -l /bin/sh"),
    ("gen-static-digest-nonce", "Digest realm=\"cam\"", ' nonce="tick"'),
]


@pytest.mark.parametrize("hid, head, tail", LONG_GAP_CASES)
def test_default_audit_large_bounded_yaml_gap_is_unbounded(tmp_path, hid, head, tail):
    """YAML 의 큰 상한(예: {0,1024}?)은 fw_strings_hunt 의 선형 시간을 위한 것이다. 기본 감사는 같은 줄이면 간격 길이와 관계없이 잡는다
    (HEAD 의 무제한 패턴과 같은 판정 — 덧대기로 숨기지 못한다)."""
    from fwtriage_mcp.rootfs import _GapChain, yaml_line_matcher

    h = {x.id: x for x in load_patterns().string_heuristics}[hid]
    line = head + " " + "x" * 2000 + tail
    assert h.rx.search(line) is None, "묶은 원래 정규식은 1024자 넘는 간격을 못 맞춘다 (fw_strings_hunt 경로)"
    m = yaml_line_matcher(h)
    assert isinstance(m, _GapChain) and m.search(line, 0, len(line)) is not None
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + line + "\n"})
    aud = _audit(root)
    aud.audit_startup()
    assert hid in {i["id"] for i in aud.items if i.get("line") == 2}, aud.items


#: (YAML id, 줄) — 안쪽 반복은 HEAD 그대로다('-l' 뒤 공백 [ \t]*, nonce 값 [^"%]+, Digest 뒤 공백). 3차의 {0,8}·{1,512}·{1,16} 상한이 숨기던 모양
INNER_REPEAT_CASES = [
    ("gen-telnetd-login-shell", "/usr/sbin/telnetd -p 23 -l          /bin/sh &"),
    ("gen-getty-autologin", "/sbin/getty -L ttyS0 115200 vt100 -n -l\t\t\t\t\t\t\t\t\t/bin/sh"),
    ("gen-static-digest-nonce", 'Digest realm="cam", nonce="' + "a" * 600 + '"'),
    ("gen-static-digest-nonce", "Digest" + " " * 40 + 'realm="cam" nonce="tick"'),
]


@pytest.mark.parametrize("hid, line", INNER_REPEAT_CASES)
def test_yaml_inner_repeats_match_like_head(tmp_path, hid, line):
    """fw_strings_hunt 의 원래 정규식과 기본 감사 모두 HEAD 처럼 맞춘다 (긴 공백·긴 nonce 로 숨기지 못한다)."""
    from fwtriage_mcp.rootfs import yaml_line_matcher

    h = {x.id: x for x in load_patterns().string_heuristics}[hid]
    assert h.rx.search(line) is not None
    assert yaml_line_matcher(h).search(line, 0, len(line)) is not None
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + line + "\n"})
    aud = _audit(root)
    aud.audit_startup()
    assert hid in {i["id"] for i in aud.items if i.get("line") == 2}, aud.items


def test_small_bounded_gaps_stay_regex_in_default_audit():
    """상한이 작은 반복(sd-* 의 {0,120}·{0,160} 문맥 창)은 간격으로 나누지 않고 원래 정규식으로 평가한다."""
    from fwtriage_mcp.rootfs import LINE_GAP_UNBOUND_MIN, _GapChain, yaml_line_matcher

    assert LINE_GAP_UNBOUND_MIN == 256
    for h in load_patterns().string_heuristics:
        if h.id.startswith("sd-") and h.rx is not None and h.scope in ("text", "any"):
            assert not isinstance(yaml_line_matcher(h), _GapChain), h.id


def test_audit_startup_still_detects_normal_lines_after_bounding(tmp_path):
    root = write_tree(tmp_path / "ok", {"etc/init.d/rcS": "#!/bin/sh\nnc -l -p 23 -e /bin/sh &\n/usr/sbin/dropbear -B -p 22 &\ntelnetd -l /bin/sh &\n"
                                                           "mount -t vfat /dev/mmcblk0p1 /mnt/sd\n"})
    aud = _audit(root)
    st = aud.audit_startup()
    ids = {i["id"] for i in aud.items}
    assert {"builtin-netcat-shell", "builtin-dropbear-blank-password", "gen-telnetd-login-shell"} <= ids
    assert {s["service"] for s in st["services"]} >= {"netcat-listener", "dropbear", "telnetd"}
    assert [m["mount_point"] for m in st["mounts"]] == ["/mnt/sd"]


def test_udev_rules_parse_is_linear():
    _, dt = _timed(parse_udev_rules, 'KERNEL=="x", \\\n' * 80000)
    assert dt < SLOW
    _, dt = _timed(parse_udev_rules, "ENV{" * 80000)
    assert dt < SLOW
    _, dt = _timed(mask_credentials, "password=x" * 20000)
    assert dt < SLOW


# ---------------------------------------------------------------------------
# R6·R7: 마스킹
# ---------------------------------------------------------------------------


def test_mask_credentials_masks_the_matched_span_and_quoted_values():
    assert mask_credentials("mount -t cifs -o username=admin,password=admin //nas/rec /mnt/sd") == "mount -t cifs -o username=admin,password=ad*** //nas/rec /mnt/sd"
    assert mask_credentials("wget http://cam/admin/cfg.cgi?password=admin -O /x") == "wget http://cam/admin/cfg.cgi?password=ad*** -O /x"
    assert "horse" not in mask_credentials('PASSWORD="correct horse battery" ./x')
    out = _mask_excerpt("openssl enc -d -aes-128-cbc -iv 0102030405060708 -K 00112233445566778899aabbccddeeff -in /mnt/sd/fw.enc | sh")
    assert "0102030405060708" not in out and "00112233445566778899aabbccddeeff" not in out
    out = _mask_excerpt("openssl enc -d -aes-256-cbc -k 'correct horse battery' -pass pass:S3cretPw -in /mnt/sd/pkg.enc | sh")
    assert "horse" not in out and "battery" not in out and "S3cretPw" not in out and "pass:S3" in out
    assert "env:KEY" in _mask_excerpt("openssl enc -d -pass env:KEY -in /mnt/sd/x | sh")


def test_end_to_end_results_carry_no_secret(tmp_path):
    root = write_tree(tmp_path / "m", {"etc/init.d/rcS": (
        "#!/bin/sh\nmount -t vfat -o username=admin,password=admin /dev/mmcblk0p1 /mnt/sd\nsh /mnt/sd/autorun.sh &\n"
        "openssl enc -d -aes-128-cbc -iv 0102030405060708 -K 00112233445566778899aabbccddeeff -in /mnt/sd/fw.enc | sh\n"
        "openssl enc -d -aes-256-cbc -k 'correct horse battery' -in /mnt/sd/pkg.enc | sh\n")})
    res = _surface(root)
    blob = json.dumps(res, ensure_ascii=False)
    for secret in ("password=admin", "00112233445566778899aabbccddeeff", "horse battery"):
        assert secret not in blob, secret
    assert {"decrypt-then-exec"} <= _rules(_checks(res)["SD-01"])


# ---------------------------------------------------------------------------
# R8·R27: 읽기 전용 fs, eMMC
# ---------------------------------------------------------------------------


def test_readonly_filesystems_on_mmcblk_are_not_writable_storage(tmp_path):
    root = write_tree(tmp_path / "ro", {
        "etc/init.d/rcS": ("#!/bin/sh\nmount -t squashfs /dev/mmcblk0p4 /app\n/app/start.sh &\nmount -t cramfs -o loop /dev/mmcblk0p5 /opt/res\nsh /opt/res/init.sh &\n"
                           "mount -t erofs /dev/mmcblk0p6 /vendor\n/vendor/bin/vendor_init.sh &\n"),
        "etc/fstab": "/dev/mmcblk0p3 /usr/local squashfs defaults 0 0\n",
        "etc/init.d/S50app": "#!/bin/sh\n/usr/local/bin/app.sh &\n",
        "app/start.sh": "#!/bin/sh\necho app\n",
    })
    aud = _audit(root)
    st = aud.audit_startup()
    assert not [i for i in aud.items if i["id"] == "builtin-exec-from-writable-storage"]
    assert not {m["mount_point"] for m in st["mounts"]} & {"/app", "/opt/res", "/vendor", "/usr/local"}
    assert _checks(_surface(root))["SD-01"]["status"] == "not-found"


def test_emmc_vfat_boot_and_emmc_only_daemon_are_not_sd(tmp_path):
    boot = write_tree(tmp_path / "boot", {"etc/init.d/rcS": "#!/bin/sh\nmount -t ext4 /dev/mmcblk0p2 /data\nmount -t vfat -o ro /dev/mmcblk0p1 /boot\nsh /boot/board_init.sh\n"})
    res = _surface(boot, _plain_flash())
    assert _checks(res)["SD-01"]["status"] == "not-found" and res["mount_points"] == []
    assert {m["mount_point"] for m in res["other_mmc_mounts"]} == {"/data", "/boot"}
    emmc = write_tree(tmp_path / "emmc", {"etc/fstab": "/dev/mmcblk0p5 /data ext4 defaults 0 0\n",
                                          "usr/bin/storaged": build_min_elf(imports=("open",)) + b"\0/dev/mmcblk0p5\0/dev/mmcblk0\0"})
    res = _surface(emmc, _plain_flash())
    assert res["risk_found"] == [] and _checks(res)["SD-04"]["status"] == "not-found"
    card = write_tree(tmp_path / "card", {"usr/bin/cardd": build_min_elf(imports=("open",)) + b"\0/dev/mmcblk1p1\0SD card inserted\0"})
    c = _checks(_surface(card, _plain_flash()))["SD-04"]
    assert c["status"] == "found" and _rules(c) == {"daemon-mmcblk"}


# ---------------------------------------------------------------------------
# R9·R10: verify, 버튼 읽기
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, off", [("n", True), ("0", True), ("off", True), ("disable", True), ("none", True), ("x", True), ("", True), (" yes", True),
                                      ("1", False), ("y", False), ("Y", False), ("t", False), ("T", False), ("yes", False), ("true", False), (None, False)])
def test_verify_follows_env_get_yesno(raw, off):
    env = {"bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x300000; bootm 0x82000000 || run sdboot", "sdboot": "fatload mmc 0:1 0x82000000 uImage"}
    if raw is not None:
        env["verify"] = raw
    b = sd_boot_analysis(env, storage="flash-crc")
    assert b["verify_off"] is off and b["severity_hint"] == ("high" if off else "medium")


def test_button_gate_counts_only_gpio_reads(tmp_path):
    led = {"etc/init.d/S80update": "#!/bin/sh\nif [ -f /mnt/sd/update.bin ]; then\n    echo 1 > /sys/class/gpio/gpio45/value\n    flashcp -v /mnt/sd/update.bin /dev/mtd2\nfi\n"}
    c = _checks(_surface(write_tree(tmp_path / "led", led), _plain_flash()))["SD-02"]
    assert c["severity_hint"] == "high" and c["context"]["button_only"] is False and not any(e.get("gated_by") for e in c["evidence"])
    key = {"etc/init.d/S80update": "#!/bin/sh\nif [ \"$(get_reset_button_state)\" = 1 ]; then\n    flashcp -v /mnt/sd/update.bin /dev/mtd2\nfi\n"}
    c = _checks(_surface(write_tree(tmp_path / "key", key), _plain_flash()))["SD-02"]
    assert c["severity_hint"] == "medium" and c["context"]["button_only"] is True
    # 같은 줄의 && 앞 GPIO 읽기
    inline = {"etc/init.d/S80update": "#!/bin/sh\n[ \"$(cat /sys/class/gpio/gpio12/value)\" = 0 ] && flashcp -v /mnt/sd/update.bin /dev/mtd2\n"}
    assert _checks(_surface(write_tree(tmp_path / "inl", inline), _plain_flash()))["SD-02"]["severity_hint"] == "medium"


# ---------------------------------------------------------------------------
# R11·R12·R13·R14: 디렉터리 복사, cd, 히트 상한, SD-09 단계
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", [
    "cp /mnt/sd/*.bin /tmp && flashcp -v /tmp/app.bin /dev/mtd2",
    "cp /mnt/sd/app.bin /tmp/\nflashcp -v /tmp/app.bin /dev/mtd2",
    "cp /mnt/sd/kernel /tmp && dd if=/tmp/kernel of=/dev/mtdblock2 bs=64k",
    "cp /mnt/sd/app.bin /tmp/app.bin\nflashcp -v /tmp/app.bin /dev/mtd2",
])
def test_copy_to_directory_then_flash_is_found(tmp_path, body):
    c = _checks(_surface(write_tree(tmp_path / "u", {"etc/init.d/S80upgrade": "#!/bin/sh\n" + body + "\n"}), _plain_flash()))["SD-02"]
    assert c["status"] == "found" and "copy-then-flash" in _rules(c)


def test_cd_into_card_then_relative_exec(tmp_path):
    c = _checks(_surface(write_tree(tmp_path / "a", {"etc/init.d/rcS": "#!/bin/sh\nif [ -f /mnt/sd/debug.sh ]; then\n    cd /mnt/sd && ./debug.sh &\nfi\n"})))["SD-01"]
    ev = [e for e in c["evidence"] if e["rule"] == "relative-exec"]
    assert ev and ev[0]["sd_path"] == "/mnt/sd/debug.sh" and ev[0]["cwd"] == "/mnt/sd" and ev[0]["severity"] == "high"
    c = _checks(_surface(write_tree(tmp_path / "b", {"etc/init.d/rcS": "#!/bin/sh\ncd /mnt/sdcard\nsh ./tools/fix.sh\n"})))["SD-01"]
    assert any(e["rule"] == "sh" and e["sd_path"] == "/mnt/sdcard/tools/fix.sh" for e in c["evidence"])
    assert _checks(_surface(write_tree(tmp_path / "c", {"etc/init.d/rcS": "#!/bin/sh\ncd /tmp && ./x.sh\n"})))["SD-01"]["status"] == "not-found"


def test_binary_hit_cap_marks_phase_incomplete(tmp_path, monkeypatch):
    strings = [f"/mnt/sd/record/ch0/{i:04d}.mp4" for i in range(60)] + ["insmod /mnt/sd/drv/hook.ko"]
    app = build_min_elf(imports=("system",)) + b"\0" + b"\0".join(s.encode() for s in strings) + b"\0"
    root = write_tree(tmp_path / "rec", {"usr/bin/recorder": app})
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert c["status"] == "found" and "binary-exec-string" in _rules(c)  # 옛 상한(파일당 40)이면 버려졌다
    monkeypatch.setattr(sdsurface, "BIN_HITS_PER_PATTERN_FILE", 5)
    res = _surface(root, _plain_flash())
    assert res["phases"]["rootfs_binary"] == "truncated" and any("히트 상한" in x for x in res["limitations"])
    assert _checks(res)["SD-01"]["status"] == "unknown"  # not-found 가 아니다


def test_sd09_unknown_when_cgi_binary_was_skipped(tmp_path):
    big_cgi = build_min_elf(imports=("system",)) + b"\0ls /mnt/sd/record\0" + b"\0" * (2 << 20)
    root = write_tree(tmp_path / "cgi", {"var/www/cgi-bin/sd.cgi": big_cgi, "var/www/index.html": "x\n"})
    assert _checks(_surface(root, _plain_flash(), max_binary_file=1 << 20))["SD-09"]["status"] == "unknown"
    assert _checks(_surface(root, _plain_flash()))["SD-09"]["status"] == "found"


# ---------------------------------------------------------------------------
# R17·R24: 한 줄 시험의 범위, 따옴표 속 괄호, /mnt/tftpboot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body, rule", [
    ("[ -f /mnt/sd/wifi.conf ] && cp /mnt/sd/wifi.conf /etc/wifi.conf\n/usr/sbin/telnetd &\n", None),  # 다음 줄은 조건 밖
    ("[ -f /mnt/sd/config.ini ] && echo 'sd config present'\nflashcp -v /tmp/backup.bin /dev/mtd4\n", None),
    ("[ -f /mnt/sd/x ] || telnetd &\n", None),  # || 는 부정
    ("if [ -f /mnt/sd/x ]; then echo found; fi\ntelnetd &\n", None),
    ("if ! [ -f /mnt/sd/x ]; then\n    telnetd &\nfi\n", None),
    ("[ -f /mnt/sd/x ] && telnetd &\n", "trigger-service"),
    ("if [ -f /mnt/sd/x ]; then\n    telnetd &\nfi\n", "trigger-service"),
    ("if [ -e /mnt/sd/x ]\nthen\n    nc -l -p 4444 -e /bin/sh &\nfi\n", "trigger-service"),
    ("if [ \"$(cat /sys/class/gpio/gpio1/value)\" = 0 ] && [ -f /mnt/sd/fw.bin ]; then\n    flashcp /mnt/sd/fw.bin /dev/mtd2\nfi\n", "trigger-flash"),
])
def test_one_line_test_only_covers_its_own_line(tmp_path, body, rule):
    c = _checks(_surface(write_tree(tmp_path / "t", {"etc/init.d/rcS": "#!/bin/sh\n" + body}), _plain_flash()))
    trig = {e["rule"] for cid in ("SD-01", "SD-02") for e in c[cid]["evidence"] if e["rule"].startswith("trigger-")}
    assert trig == ({rule} if rule else set()), (body, trig)


@pytest.mark.parametrize("files, expect", [
    ({"etc/init.d/rcS": "#!/bin/sh\necho \"backup done (/mnt/sd/backup/cfg.tar)\"\n"}, "not-found"),
    ({"usr/bin/recd": build_min_elf(imports=("printf",)) + b"\0record file saved (/mnt/sd/record/0001.mp4)\0"}, "not-found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nmount -t nfs 10.0.0.1:/srv/tftp /mnt/tftpboot\nsh /mnt/tftpboot/dev_init.sh\n"}, "not-found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nlogger 'run (/mnt/sd/x.sh) later'\n"}, "not-found"),
    ({"etc/init.d/rcS": "#!/bin/sh\n( /mnt/sd/x.sh & )\n"}, "found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nsh -c \"/mnt/sd/x.sh\" &\n"}, "found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nsh /mnt/tf/x.sh\n"}, "found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nsh /mnt/tfcard0/x.sh\n"}, "found"),
    ({"etc/init.d/rcS": "#!/bin/sh\nsh /mnt/sdk/env.sh\n"}, "not-found"),
])
def test_paren_in_quotes_and_non_card_dirs_are_not_exec(tmp_path, files, expect):
    assert _checks(_surface(write_tree(tmp_path / "p", files), _plain_flash()))["SD-01"]["status"] == expect


# ---------------------------------------------------------------------------
# R21·R22·R23·R25: fw_setenv 스크립트, fstrim 애플릿, 순회 잘림, 결정적 순회
# ---------------------------------------------------------------------------


def test_fw_setenv_only_script_is_not_skipped_by_prefilter(tmp_path):
    root = write_tree(tmp_path / "fe", {"etc/init.d/S99bootmode": "#!/bin/sh\nfw_setenv bootcmd 'mmc rescan; fatload mmc 0:1 0x82000000 uImage; bootm 0x82000000'\n"
                                                                   "fw_setenv bootcmd_up 'run sdupdate'\n",
                                        "etc/fw_env.config": "/dev/mtd1 0x0 0x10000 0x10000\n"})
    c = _checks(_surface(root, _plain_flash()))
    assert "fw_setenv-mmc" in _rules(c["SD-03"]) and "fw_setenv-update" in _rules(c["SD-02"])


def test_fstrim_applet_name_is_not_an_invocation(tmp_path):
    applets = b"\0".join([b"[", b"ash", b"fsck", b"fstrim", b"mdev", b"mount"])
    bb = build_min_elf(imports=("system",)) + b"\0" + applets + b"\0\0Usage: fstrim [OPTIONS] MOUNTPOINT\0rw\0discard\0nodiscard\0"
    files = {"etc/fstab": "/dev/mmcblk0p1 /mnt/sd vfat rw,noexec,nosuid,nodev 0 0\n", "bin/busybox": bb}
    res = _surface(write_tree(tmp_path / "bb", files), _plain_flash())
    assert _checks(res)["SD-08"]["status"] == "not-found" and res["risk_found"] == []
    files["usr/bin/maint"] = build_min_elf(imports=("system",)) + b"\0fstrim -v /mnt/sd\0"
    c = _checks(_surface(write_tree(tmp_path / "inv", files), _plain_flash()))["SD-08"]
    assert c["status"] == "found" and _rules(c) == {"fstrim"}
    c = _checks(_surface(write_tree(tmp_path / "sh", {**files, "etc/init.d/S90trim": "#!/bin/sh\nfstrim /mnt/sd\n"}), _plain_flash()))["SD-08"]
    assert {"fstrim"} <= _rules(c)


def test_walk_truncation_marks_rootfs_phases_incomplete(tmp_path):
    files = {f"aaa/f{i:03d}.txt": "x\n" for i in range(50)}
    files["zzz/init.d/rcS"] = "#!/bin/sh\nsh /mnt/sd/autorun.sh &\n"
    root = write_tree(tmp_path / "w", files, base=False)
    res = _surface(root, _plain_flash(), max_entries=40)
    c = _checks(res)
    assert res["phases"]["rootfs_text"] == "truncated" and res["phases"]["rootfs_binary"] == "truncated"
    assert c["SD-01"]["status"] == c["SD-04"]["status"] == c["SD-09"]["status"] == "unknown"


def test_many_startup_files_are_scanned_deterministically(tmp_path):
    files = {f"etc/init.d/S{i:03d}svc": "#!/bin/sh\necho svc\n" for i in range(600)}
    # 저장 장치를 다루는 사용자 uevent helper (mdev·빈 값은 카드 처리기 근거가 아니다 — 4차 #14)
    files["etc/init.d/S300hotplug"] = "#!/bin/sh\necho /sbin/sd_hotplug.sh > /proc/sys/kernel/hotplug\n"
    files["sbin/sd_hotplug.sh"] = "#!/bin/sh\nmount -t vfat /dev/$MDEV /media/$MDEV\n"
    c = _checks(_surface(write_tree(tmp_path / "many", files), _plain_flash()))["SD-04"]
    assert c["status"] == "found" and "uevent-helper" in _rules(c)
    assert re.search(r"sorted\(self\.startup_set\)", (REPO / "mcp-servers" / "fwtriage-mcp" / "fwtriage_mcp" / "sdsurface.py").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 리뷰 뒤 보강: 따옴표로 감싼 카드 경로, /dev/sdX 디스크, env 상한 → unknown, signals_total, R26 경로 안전
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("line, rule", [
    ('sh "$SD/x.sh"', "sh"), ('"/mnt/sd/x.sh" &', "direct-exec"), ('. "$SD/env.sh"', "source"), ('insmod "$SD/drv.ko"', "kernel-module"),
    ('[ -f "$SD/x" ] && telnetd &', "trigger-service"), ("sh '/mnt/sd/y.sh'", "sh"),
])
def test_quoted_card_paths_are_still_executed(tmp_path, line, rule):
    c = _checks(_surface(write_tree(tmp_path / "q", {"etc/init.d/rcS": "#!/bin/sh\nSD=/mnt/sd\n" + line + "\n"}), _plain_flash()))["SD-01"]
    assert rule in _rules(c), (line, _rules(c))


def test_dev_sdx_disk_needs_sd_like_mount_point(tmp_path):
    hdd = write_tree(tmp_path / "hdd", {"etc/init.d/rcS": "#!/bin/sh\nmount -t ext4 /dev/sda1 /mnt/disk1\nsh /mnt/disk1/start.sh\n"})
    res = _surface(hdd, _plain_flash())
    assert _checks(res)["SD-01"]["status"] == "not-found" and res["mount_points"] == []
    assert any(m["mount_point"] == "/mnt/disk1" and "SATA" in m["note"] for m in res["other_mmc_mounts"])
    usb = write_tree(tmp_path / "usb", {"etc/init.d/rcS": "#!/bin/sh\nmount -t vfat /dev/sda1 /mnt/usb\nsh /mnt/usb/autorun.sh\n"})
    res = _surface(usb, _plain_flash())
    assert [m["path"] for m in res["mount_points"]] == ["/mnt/usb"] and _checks(res)["SD-01"]["status"] == "found"


def test_env_caps_make_uboot_checks_unknown_not_not_found(tmp_path):
    from fwtriage.sd_builders import build_sd_flash

    env = {"bootcmd": "run x; sf probe 0; bootm", "x": "run " + "a " * 3000, "a": "Z" * 4000, "bootdelay": "1"}  # run 펼침 상한 초과, mmc 신호 없음
    res = _surface(None, build_sd_flash(env=env))
    c = _checks(res)
    assert res["phases"]["image_env"] == "truncated" and any("run 펼침" in x for x in res["limitations"])
    assert c["SD-03"]["status"] == "unknown" and c["SD-02"]["status"] == "unknown"
    many = {"bootcmd": "fatload mmc 0 0x82000000 uImage", **{f"v{i}": f"fatload mmc 0 0x{i:x} f{i}" for i in range(40)}}
    b = sd_boot_analysis(many, storage="flash-crc")
    assert b["signals_total"] == 41 and len(b["signals"]) == 24


def test_new_resolution_paths_stay_inside_rootfs(tmp_path):
    """R26: mdev 상대 명령·udev 상대 RUN·uevent helper·처리기의 .sh·fw_env.config 가 밖을 가리키는 링크여도 호스트 파일을 읽지 않는다."""
    host = tmp_path / "host"
    (host / "dir").mkdir(parents=True)
    (host / "sd_handler.sh").write_text("#!/bin/sh\nsh /mnt/sd/HOSTONLY_mdev.sh\n")
    (host / "sd_udev.sh").write_text("#!/bin/sh\nsh /mnt/sd/HOSTONLY_udev.sh\n")
    (host / "helper.sh").write_text("#!/bin/sh\nsh /mnt/sd/HOSTONLY_helper.sh\n")
    (host / "dir" / "next.sh").write_text("#!/bin/sh\nsh /mnt/sd/HOSTONLY_frontier.sh\n")
    (host / "fw_env.config").write_text("/dev/HOSTONLY_mtd 0x0 0x10000\n")
    rel_up = "../" * 20 + str(host).lstrip("/")
    root = write_tree(tmp_path / "root", {
        "etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 *sd_handler.sh\nmmcblk[0-9] 0:0 660 @/etc/hotplug/sd2.sh\n",
        "etc/hotplug/sd2.sh": "#!/bin/sh\n/opt/link/next.sh\n",
        "lib/udev/rules.d/80-sd.rules": 'KERNEL=="mmcblk*", RUN+="sd_udev.sh"\n',
        "etc/init.d/rcS": f"#!/bin/sh\necho /{rel_up}/helper.sh > /proc/sys/kernel/hotplug\n",
    }, symlinks={"lib/mdev/sd_handler.sh": str(host / "sd_handler.sh"), "lib/udev/sd_udev.sh": rel_up + "/sd_udev.sh",
                 "opt/link": str(host / "dir"), "etc/fw_env.config": str(host / "fw_env.config")})
    res = _surface(root, _plain_flash())
    aud = _audit(root)
    st = aud.audit_startup()
    assert "HOSTONLY" not in json.dumps(res, ensure_ascii=False) + json.dumps(st, ensure_ascii=False)
    assert all(h.get("handler_script") in (None, "/etc/hotplug/sd2.sh") for h in res["hotplug_handlers"])
    assert _checks(res)["SD-03"]["context"]["env_userspace"]["fw_env_config"] is None


# ---------------------------------------------------------------------------
# 3차 검증 (V1·V1b·V4·V4b·V7): mdev/udev 분류, 실행 모양, 가드·블록 범위, cwd·재귀 복사
# ---------------------------------------------------------------------------

MOUNT_SD = "mount -t vfat -o noexec,nosuid,nodev /dev/mmcblk0p1 /mnt/sd\n"


@pytest.mark.parametrize("regex, env, kind", [
    ("$MODALIAS=.*", [], "other"),  # BusyBox 예제: 모듈 자동 적재(환경 변수 규칙) — 장치 catch-all 이 아니다
    ("[hs]d[a-z][0-9]*", [], "sd"), ("[a-z]*[0-9]*", [], "catch-all"), ("[a-z0-9]+", [], "catch-all"), (".+[0-9]", [], "catch-all"),
    ("[[:alpha:]]*[[:digit:]]*", [], "catch-all"), ("^mmcblk[0-9]$", [], "sd"), ("mmcblk[3-9]", [], "sd"), ("sd[a-z]{1,2}[0-9]{0,2}", [], "sd"),
    ("$SUBSYSTEM=block", [], "catch-all"), ("$SUBSYSTEM=mmc", [], "sd"), ("$SUBSYSTEM=net", [], "other"), ("$DEVPATH=.*/mmc0/.*", [], "sd"),
    (".*", ["SUBSYSTEM=net"], "other"), ("ram([0-9]*)", [], "other"), ("snd/pcm.*", [], "other"), ("(?:.*){30}X", [], "unclassifiable"),
])
def test_classify_mdev_matcher_full_match_on_samples(regex, env, kind):
    """mdev 장치 정규식은 우리 ERE 해석기(톰슨 NFA)로 장치 이름 표본에 '전체 일치'로만 맞춘다 (BusyBox mdev 와 같은 의미, re 미사용)."""
    assert classify_mdev_matcher(regex, env) == kind


def test_mdev_ere_interpreter_is_linear_on_hostile_patterns():
    hostile = ["(a|a|a|a)*" * 12 + "b", "((((((((a*)*)*)*)*)*)*)*)*b", "(.*)(.*)(.*)(.*)(.*)(.*)(.*)(.*)(.*)(.*)X", "[a-z]{16}[0-9]{16}" * 3, "(a{16}){16}"]
    out, dt = _timed(lambda: [classify_mdev_matcher(r, []) for r in hostile])
    assert dt < 2.0 and all(k in ("other", "unclassifiable") for k in out), (out, dt)


@pytest.mark.parametrize("match, kind", [
    ({"KERNEL": "*"}, "catch-all"), ({"SUBSYSTEM": "block"}, "catch-all"), ({"SUBSYSTEM": "block", "ENV{ID_FS_TYPE}": "vfat|exfat"}, "sd"),
    ({"SUBSYSTEM": "block", "KERNEL": "mtdblock*"}, "other"), ({"KERNEL": "sd*[!0-9]"}, "sd"), ({"ACTION": "add"}, "other"),
])
def test_classify_udev_match_catch_all(match, kind):
    assert classify_udev_match(match) == kind


def test_stock_modalias_line_is_not_an_sd_handler(tmp_path):
    """V1(b): SD 와 무관한 펌웨어에 BusyBox 예제의 '$MODALIAS=.* … @modprobe' 한 줄만 있으면 SD-04 not-found, risk_found 에 없음."""
    root = write_tree(tmp_path / "r", {"etc/mdev.conf": 'null 0:0 666\n$MODALIAS=.* 0:0 660 @modprobe "$MODALIAS"\n.* 0:0 660\n',
                                       "sbin/modprobe": "#!/bin/sh\necho mod\n"})
    res = _surface(root, _plain_flash())
    assert _checks(res)["SD-04"]["status"] == "not-found" and "SD-04" not in res["risk_found"]
    assert not res["hotplug_handlers"]


@pytest.mark.parametrize("rule", ["[a-z]*[0-9]* 0:0 660 @/usr/sbin/automount.sh", "[hs]d[a-z][0-9]* root:disk 660 */usr/sbin/automount.sh"])
def test_generic_and_busybox_disk_rules_are_sd_handlers(tmp_path, rule):
    """V1b: 일반 catch-all·BusyBox 예제 디스크 규칙의 처리기(/etc/hotplug 밖)가 /media/$MDEV 에 마운트하면 SD-04 found."""
    root = write_tree(tmp_path / "r", {"etc/mdev.conf": rule + "\n",
                                       "usr/sbin/automount.sh": "#!/bin/sh\nmount -t vfat -o noexec,nosuid,nodev /dev/$MDEV /media/$MDEV\n"})
    res = _surface(root, _plain_flash())
    c = _checks(res)["SD-04"]
    assert c["status"] == "found" and {e["rule"] for e in c["evidence"]} == {"mdev-rule"}
    assert any(m["path"] == "/media/$MDEV" for m in res["mount_points"])


def test_catch_all_handler_media_mdev_paths_are_card_paths(tmp_path):
    """V1(c): 모든 장치 규칙의 처리기 안의 /media/$MDEV/autorun.sh 실행은 카드 내용 실행이다. SD 와 무관한 규칙의 처리기는 아니다."""
    root = write_tree(tmp_path / "r", {
        "etc/mdev.conf": ".* 0:0 660 @/etc/hotplug/all.sh\nmmcblk[0-9]p[0-9] 0:0 660 */etc/hotplug/sd.sh\n",
        "etc/hotplug/all.sh": "#!/bin/sh\n[ -f /media/$MDEV/autorun.sh ] && sh /media/$MDEV/autorun.sh\n",
        "etc/hotplug/sd.sh": "#!/bin/sh\necho sd\n",
    })
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert c["status"] == "found" and ("sh", "hotplug", "/media/$MDEV/autorun.sh") in {(e["rule"], e["context"], e["sd_path"]) for e in c["evidence"]}
    root2 = write_tree(tmp_path / "r2", {"etc/mdev.conf": "ttyUSB[0-9]* 0:0 660 @/usr/sbin/modem.sh\n",
                                         "usr/sbin/modem.sh": "#!/bin/sh\nsh /var/run/$MDEV/init.sh\n"})
    assert _checks(_surface(root2, _plain_flash()))["SD-01"]["status"] == "not-found"


EXEC_SHAPES = [
    # (본문, 기대 SD-01, 규칙 하나 이상)
    ('R="$(/mnt/sd/check.sh)"\n', "found", "direct-exec"),
    ('echo "$(sh /mnt/sd/x.sh)"\n', "found", "sh"),
    ('V="`/mnt/sd/ver.sh`"\n', "found", "direct-exec"),
    ('if [ "$(/mnt/sd/check_card.sh)" = "ok" ]; then echo ok; fi\n', "found", "direct-exec"),
    ('logger -t sd "$(/mnt/sd/diag)"\n', "found", "direct-exec"),
    ("su root -c '/mnt/sd/run.sh'\n", "found", "sh"),
    ('eval "/mnt/sd/run.sh"\n', "found", "direct-exec"),
    ('case "$1" in\n  start) /mnt/sd/start.sh & ;;\nesac\n', "found", "direct-exec"),
    ("find /mnt/sd/scripts -name '*.sh' -exec sh {} \\;\n", "found", "find-exec"),
    ("find /mnt -maxdepth 1 -exec /mnt/sd/x.sh {} \\;\n", "found", "direct-exec"),
    ("echo '$(/mnt/sd/x)'\n", "not-found", None),  # 작은따옴표 안의 명령 치환은 실행되지 않는다
    ('echo "running /mnt/sd/autorun.sh is disabled"\n', "not-found", None),
    ('logger "sd check (/mnt/sd/autorun.sh)"\n', "not-found", None),
    ("find /mnt/sd -name '*.log' -exec rm {} \\;\n", "not-found", None),
    ('RUN_DIR=/mnt/sd/run\n', "not-found", None),
]


@pytest.mark.parametrize("body, status, rule", EXEC_SHAPES)
def test_exec_shapes_quotes_and_command_positions(tmp_path, body, status, rule):
    """V4·V4b: 큰따옴표 안의 $( )·역따옴표, su -c, eval, case 갈래, find -exec 는 실행이고, 작은따옴표·문구 안·rm -exec 는 아니다."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body})
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert c["status"] == status, (body, c["evidence"])
    if rule:
        assert rule in _rules(c), (body, _rules(c))


def test_quote_state_command_substitution_inside_double_quotes():
    assert sdsurface._quote_state('if [ "$(') == (False, False) and sdsurface._quote_state('echo "$(sh ') == (False, False)
    assert sdsurface._quote_state('V="`') == (False, False) and sdsurface._quote_state('x="$(a) b ') == (True, False)
    assert sdsurface._quote_state("echo '$(") == (True, False)


GUARD_CASES = [
    # (본문, trigger-service 여야 하는지)
    ("[ -f /mnt/sd/debug.flag ] || exit 0\n/usr/sbin/telnetd -l /bin/sh &\n", True),
    ("test -f /mnt/sd/debug.flag || { echo no card; exit 1; }\ntelnetd &\n", True),
    ("[ ! -f /mnt/sd/debug.flag ] && exit 0\ntelnetd &\n", True),
    ("[ ! -f /mnt/sd/debug.flag ] || exit 0\ntelnetd &\n", False),
    ("[ -f /mnt/sd/debug.flag ] && exit 0\ntelnetd &\n", False),
    ("[ ! -f /mnt/sd/debug.flag ] || telnetd &\n", True),
    ("[ -f /mnt/sd/debug.flag ] && echo found; telnetd &\n", False),
    ("[ -f /mnt/sd/debug.flag ] && mkdir -p /tmp/x && telnetd &\n", True),
    ("[ -f /mnt/sd/debug ] && {\n    /usr/sbin/telnetd -l /bin/sh &\n}\n", True),
    ("[ -f /mnt/sd/debug ] && {\n    echo hi\n}\ntelnetd &\n", False),
    ("if [ ! -f /mnt/sd/debug ]; then\n  echo no card\n  exit 0\nfi\ntelnetd &\n", True),
    ("if [ ! -f /mnt/sd/debug ]; then\n  telnetd &\nfi\n", False),
    ("while [ ! -f /mnt/sd/ready ]; do sleep 1; done\ntelnetd &\n", True),
    ("until [ -f /mnt/sd/ready ]; do sleep 1; done\ntelnetd &\n", True),
    ("until [ -f /mnt/sd/ready ]; do telnetd; done\n", False),
    ("if [ -f /mnt/sd/debug ]; then\n" + "  echo step\n" * 30 + "  /usr/sbin/telnetd &\nfi\n", True),
    ("if [ -f /mnt/sd/debug ]\nthen\n  if [ -x /usr/sbin/telnetd ]; then\n    /usr/sbin/telnetd &\n  fi\nfi\n", True),
    ("if [ -f /mnt/sd/debug ]; then\n  echo debug\nelse\n  telnetd &\nfi\n", False),
    ("if [ -x /bin/true ]; then\n  echo a\nelif [ -f /mnt/sd/debug ]; then\n  telnetd &\nfi\n", True),
    # return 가드는 감싸는 함수 본문까지만
    ("start() {\n  [ -f /mnt/sd/debug.flag ] || return\n  telnetd &\n}\nstart\n", True),
    ("check() {\n  [ -f /mnt/sd/debug.flag ] || return 1\n  echo ok\n}\ncheck\ntelnetd &\n", False),
]


@pytest.mark.parametrize("body, triggered", GUARD_CASES)
def test_trigger_guard_polarity_and_block_scope(tmp_path, body, triggered):
    """가드 '|| exit/return' 은 같은 블록·함수·파일의 나머지를 카드 파일에 묶고, 부정 모양은 반대 갈래만 본다. if 본문은 줄 수 상한 없이 fi 까지."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body})
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert ("trigger-service" in _rules(c)) == triggered, (body, c["evidence"])


def test_block_structure_is_linear_on_many_blocks(tmp_path):
    """블록 구조는 파일당 스택 한 번 — if 블록 2만 개(순차·중첩)와 카드 파일 시험 2만 개에서도 빠르다."""
    seq = "".join(f"if [ -f /mnt/sd/f{i} ]; then\n  echo {i}\nfi\n" for i in range(10000))
    nest = "".join(f"if [ -f /mnt/sd/n{i} ]; then\n" for i in range(10000)) + "telnetd &\n" + "fi\n" * 10000
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + seq + nest})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < 3 * SLOW, dt
    assert "trigger-service" in _rules(_checks(res)["SD-01"])


CWD_CASES = [
    ("(cd /mnt/sd && tar czf /tmp/logs.tgz log)\n./local_tool &\n", "not-found", None),
    ("(\ncd /mnt/sd\ntar czf /tmp/l.tgz log\n)\n./local_tool &\n", "not-found", None),
    ("X=$(cd /mnt/sd && pwd)\n./local_tool &\n", "not-found", None),
    ("cd /mnt/sd\nls\ncd\n./local_tool &\n", "not-found", None),
    ("cd /mnt/sd\ncd ~\n./local_tool &\n", "not-found", None),
    ("cd /mnt/sd\ncd -\n./local_tool &\n", "not-found", None),
    ("cd /mnt/sd && ./debug.sh\n", "found", "relative-exec"),
    ("cd /mnt/sd\nsh autorun.sh\n", "found", "sh"),
    ("(cd /mnt/sd && ./debug.sh)\n", "found", "relative-exec"),
    ("cp -r /mnt/sd/update /tmp/\nsh /tmp/update/run.sh\n", "found", "copy-then-exec"),
    ("cp -a /mnt/sd/update /tmp/upd\n/tmp/upd/bin/run &\n", "found", "copy-then-exec"),
    ("cp -r /mnt/sd/update /tmp\nsh /tmp/other.sh\n", "not-found", None),
    ("cp /mnt/sd/update /tmp/\nsh /tmp/update/run.sh\n", "not-found", None),  # 재귀 아님 (디렉터리 내용은 복사되지 않는다)
]


@pytest.mark.parametrize("body, status, rule", CWD_CASES)
def test_cwd_scoping_and_recursive_copy(tmp_path, body, status, rule):
    """V7: 서브셸 '( … )'·'$( … )' 안의 cd 는 밖으로 새지 않고, 인자 없는 cd·cd ~·cd - 는 cwd 를 모름으로. cp -r 로 복사한 카드 디렉터리 안의 실행은 copy-then-exec."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body})
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert c["status"] == status, (body, c["evidence"])
    if rule:
        assert rule in _rules(c)


def test_line_index_without_literal_constraint_scans_every_line():
    """리터럴 제약이 없거나(None·빈 목록) 모두 걸러지면 모든 줄을 후보로 낸다 — 규칙을 조용히 건너뛰지 않는다."""
    from fwtriage_mcp.rootfs import _LineIndex

    idx = _LineIndex("a\nbb\n\nccc")
    every = [(0, 1), (2, 4), (5, 5), (6, 9)]
    assert list(idx.candidates(None)) == every and list(idx.candidates([])) == every and list(idx.candidates(["", "x\ny"])) == every
    assert list(idx.candidates(["BB"], True)) == [(2, 4)] and list(idx.candidates(["c"])) == [(6, 9)]


def test_audit_startup_heuristic_with_empty_literals_still_fires(tmp_path):
    import copy

    ps = copy.deepcopy(load_patterns())
    for h in ps.string_heuristics:
        if h.id == "gen-telnetd-login-shell":
            h.literals = []
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\ntelnetd -l /bin/sh &\n"})
    aud = Auditor(root, Ctl(max_seconds=60), ps, persistent_paths=[], profile={}, max_file_size=16 << 20, crack=False, crack_seconds=1, words=[],
                  max_entries=20000)
    aud.walk()
    aud.audit_startup()
    assert "gen-telnetd-login-shell" in {i["id"] for i in aud.items}


def test_stock_udev_helper_rules_are_not_sd_handlers(tmp_path):
    """SD 와 무관한 펌웨어의 표준 udev 규칙(SUBSYSTEM=="block"·KERNEL=="sd*" 의 blkid·scsi_id·modprobe)은 카드 삽입 처리기가 아니다."""
    rules = ('SUBSYSTEM=="block", ACTION=="add", IMPORT{program}="/sbin/blkid -o udev -p $tempnode"\n'
             'SUBSYSTEM=="block", KERNEL=="sd*", PROGRAM="/lib/udev/scsi_id --whitelisted $devnode"\n'
             'ACTION=="add", SUBSYSTEM=="block", RUN+="/sbin/modprobe -b $env{MODALIAS}"\n'
             'KERNEL=="*", OWNER="root", GROUP="root", MODE="0660"\n')
    root = write_tree(tmp_path / "r", {"lib/udev/rules.d/60-persistent-storage.rules": rules})
    res = _surface(root, _plain_flash())
    assert _checks(res)["SD-04"]["status"] == "not-found" and "SD-04" not in res["risk_found"]
    root2 = write_tree(tmp_path / "r2", {"lib/udev/rules.d/80-auto.rules": 'ACTION=="add", SUBSYSTEM=="block", RUN+="/usr/sbin/automount.sh %k"\n',
                                         "usr/sbin/automount.sh": "#!/bin/sh\nmount -t vfat /dev/$1 /media/$1\n"})
    c = _checks(_surface(root2, _plain_flash()))["SD-04"]
    assert c["status"] == "found" and [e.get("match_kind") for e in c["evidence"]] == ["catch-all"]


def test_mdev_state_paths_in_sd_handler_are_not_card_paths(tmp_path):
    """SD 처리기 안이라도 /var/run/$MDEV 같은 상태 파일 경로는 카드 마운트 지점이 아니다 (/media·/mnt·/run/media 아래만)."""
    root = write_tree(tmp_path / "r", {"etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 */usr/sbin/sd_hotplug.sh\n",
                                       "usr/sbin/sd_hotplug.sh": "#!/bin/sh\nmkdir -p /var/run/$MDEV\necho $$ > /var/run/$MDEV/pid\nsh /var/lock/$MDEV/run.sh\n"})
    c = _checks(_surface(root, _plain_flash()))
    assert c["SD-06"]["status"] == "not-found" and c["SD-01"]["status"] == "not-found"


# ---------------------------------------------------------------------------
# 4차 검증 (다중 렌즈 #1~#27): 메모리·시간 상한, 줄 이어쓰기, 사전 필터, SD-free 오탐, 실행·플래시 모양
# ---------------------------------------------------------------------------

def _audit_p(root: Path, persistent: list[str] | None = None, ctl: Ctl | None = None) -> Auditor:
    aud = Auditor(root, ctl or Ctl(max_seconds=120), load_patterns(), persistent_paths=persistent or [], profile={}, max_file_size=16 << 20,
                  crack=False, crack_seconds=1, words=[], max_entries=20000)
    aud.walk()
    return aud


def test_symlinked_startup_script_read_once_and_items_capped(tmp_path):
    """#19: 'login -f root' 줄 수만 개짜리 스크립트와 그 심볼릭 링크 20개 — 옛 코드는 항목 143만 개·1.1 GiB.
    같은 최종 파일은 한 번만 읽고, 같은 파일의 같은 규칙 항목은 상한까지만 적고 나머지는 센다 (summary.items_suppressed·limitations)."""
    from fwtriage_mcp.rootfs import ITEM_CAP_PER_RULE_FILE

    real = "#!/bin/sh\n" + "login -f root\n" * 30000
    links = {f"etc/init.d/S{n:04d}link": "/opt/real.sh" for n in range(20)}
    root = write_tree(tmp_path / "r", {"opt/real.sh": real}, symlinks=links)
    aud = _audit_p(root)
    tracemalloc.start()
    try:
        res, dt = _timed(aud.run)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    login = [i for i in res["items"] if i["id"] == "builtin-login-f-root"]
    assert len(login) == ITEM_CAP_PER_RULE_FILE and len({i["file"] for i in login}) == 1  # 링크 20개를 한 번만 읽었다
    assert res["summary"]["items_suppressed"] >= 30000 - ITEM_CAP_PER_RULE_FILE
    assert any("항목 상한" in x for x in res["limitations"])
    assert len(res["startup_files"]) == 21 and dt < SLOW and peak < (96 << 20), (dt, peak)


def test_sd_surface_with_symlinked_startup_scripts_is_bounded(tmp_path):
    real = "#!/bin/sh\n" + "login -f root\n" * 30000
    links = {f"etc/init.d/S{n:04d}link": "/opt/real.sh" for n in range(20)}
    root = write_tree(tmp_path / "r", {"opt/real.sh": real}, symlinks=links)
    tracemalloc.start()
    try:
        _, dt = _timed(_surface, root, _plain_flash())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert dt < 2 * SLOW and peak < (128 << 20), (dt, peak)


def test_scan_buffer_keep_from_remembers_only_overlap_keys():
    """#20: 청크 사이 중복 방지 키는 다음 청크가 다시 볼 겹침 구간 위치만 기억한다 (이미지 크기와 상관없는 메모리)."""
    from fwtriage_mcp.hunt import HuntState, scan_buffer

    heur = sdsurface.string_heuristics(load_patterns(), [])
    data = b"sdcard\0" * 40000
    st = HuntState(heur, max_hits=10, per_pattern_cap=10, per_file_pattern_cap=10)
    seen: set = set()
    keep = len(data) - 4096
    scan_buffer(st, data, 0, ("x", None), False, min_len=5, utf16=False, seen=seen, keep_from=keep)
    assert seen and all(k[1] >= keep for k in seen) and len(seen) < 2000
    assert sum(st.counts.values()) > 10 * len(seen)


def test_image_string_scan_memory_does_not_grow_with_image(monkeypatch):
    """#20: 옛 코드는 이미지 전체에 걸친 seen 집합으로 64 MiB 에서 1.7 GiB. 작은 청크로 줄여 여러 청크를 지나도 메모리가 늘지 않는다."""
    monkeypatch.setattr(sdsurface, "SD_CHUNK", 256 << 10)
    peaks = []
    for mib in (1, 4):
        img = b"sdcard\0" * (mib * 1048576 // 7)
        sd = SdSurface(Ctl(max_seconds=120), load_patterns())
        tracemalloc.start()
        try:
            sd.scan_image(img, len(img), "dumps/x.bin", env_scan(img, len(img), Ctl(max_seconds=60), include_default=True))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        peaks.append(peak)
    assert peaks[1] < peaks[0] * 2.5 + (8 << 20), peaks  # 네 배 이미지 → 거의 같은 최대치 (옛: 비례)


def test_long_printable_string_scan_is_linear_and_honours_budget():
    """#21: 아주 긴 인쇄 가능 문자열 하나에 SD 낱말이 빽빽하면 옛 코드는 일치마다 문자열 끝까지 문맥을 찾아 4 MiB 에 33초.
    문맥은 저장하는 히트만, 줄 경계는 앞뒤 241자 안에서 찾고, 시간 예산은 일치 4096개마다 본다."""
    img = b"\0" + b"sdcard " * (4 * 1048576 // 7) + b"\0"
    sd = SdSurface(Ctl(max_seconds=120), load_patterns())
    _, dt = _timed(sd.scan_image, img, len(img), "dumps/x.bin", env_scan(img, len(img), Ctl(max_seconds=60), include_default=True))
    assert dt < SLOW, dt
    ctl = Ctl(max_seconds=0.05)
    sd2 = SdSurface(ctl, load_patterns())
    _, dt = _timed(sd2.scan_image, img, len(img), "dumps/x.bin", env_scan(img, len(img), Ctl(max_seconds=60), include_default=True))
    assert dt < 2.0 and sd2.phases["image_strings"] == "truncated"


def test_scan_buffer_honours_cancel_inside_a_chunk():
    import threading

    from fwtriage_mcp.common import Cancelled
    from fwtriage_mcp.hunt import HuntState, scan_buffer

    ev = threading.Event()
    ev.set()
    st = HuntState(sdsurface.string_heuristics(load_patterns(), []), max_hits=10, per_pattern_cap=10, per_file_pattern_cap=10)
    with pytest.raises(Cancelled):
        scan_buffer(st, b"sdcard\0" * 200000, 0, ("x", None), False, min_len=5, utf16=False, seen=set(), ctl=Ctl(ev))


def _ref_context(corpus, a, b):
    ls = corpus.rfind("\n", 0, a) + 1
    le = corpus.find("\n", b)
    if le < 0:
        le = len(corpus)
    line = corpus[ls:le]
    if len(line) > 240:
        rel = a - ls
        lo = max(0, rel - 80)
        line = ("…" if lo else "") + line[lo : lo + 230]
    return line


def test_bounded_hunt_context_equals_reference():
    """#21: 줄 경계를 앞뒤 241자 안에서만 찾는 _context 가 예전(줄 끝까지 찾던) 결과와 같다 — fw_strings_hunt 출력 그대로."""
    import random

    from fwtriage_mcp.hunt import _context

    rnd = random.Random(11)
    for _ in range(20000):
        n = rnd.choice([1, 5, 80, 239, 240, 241, 242, 300, 700, 1500])
        s = "".join(rnd.choice("ab\n" if rnd.random() < 0.2 else "abcdefgh ") for _ in range(n))
        if rnd.random() < 0.3:
            s = s.replace("\n", "")
        a = rnd.randrange(0, n)
        b = min(n, a + rnd.choice([0, 1, 3, 10, 100, 250, 400]))
        assert _context(s, a, b) == _ref_context(s, a, b), (s[:40], a, b)


def _ref_scan_buffer(state, data, base, where, text_file, *, min_len, utf16, seen):
    """HEAD 의 scan_buffer (그대로 옮김) — 새 구현과 결과가 같은지 비교용."""
    import bisect as _bisect

    from fwtriage_mcp.common import printable
    from fwtriage_mcp.hunt import _NL_RX, extract_strings

    for h in state.heuristics:
        if h.scope == "raw" and h.rx_bytes is not None:
            for m in h.rx_bytes.finditer(data):
                if m.end() == m.start():
                    continue
                off = base + m.start()
                if (h.id, off) in seen:
                    continue
                seen.add((h.id, off))
                ctx = printable(data[max(0, m.start() - 24): m.end() + 48], 160)
                state.record(h, where, off, printable(m.group(0), 120), ctx, scope="raw", encoding="bytes")
    if text_file:
        text = data.decode("latin-1")
        base_line = 0
        lower_cache = []

        def lower():
            if not lower_cache:
                lower_cache.append(text.lower())
            return lower_cache[0]

        nl = None
        for h in state.heuristics:
            if h.rx is None or not h.applies("text") or not h.prefilter(text, lower):
                continue
            for m in h.rx.finditer(text):
                g = m.group(0)
                if not g:
                    continue
                lead = len(g) - len(g.lstrip(" \t\r\n;&|(/"))
                start = m.start() + (lead if lead < len(g) else 0)
                if nl is None:
                    nl = [mm.start() for mm in _NL_RX.finditer(text)]
                li = _bisect.bisect_right(nl, start - 1) if start else 0
                line = li + 1 + base_line
                key = (h.id, -(base + line)) if base == 0 else (h.id, base + start)
                if key in seen:
                    continue
                seen.add(key)
                ls = nl[li - 1] + 1 if li > 0 else 0
                le = nl[li] if li < len(nl) else len(text)
                line_text = text[ls:le]
                ctx = _ref_context(text, start, m.end())
                if line_text.lstrip().startswith("#"):
                    state.record_commented(h, where, base + start, line if base == 0 else None, ctx)
                    continue
                state.record(h, where, base + start, g[lead:] if lead < len(g) else g, ctx, scope="text", encoding="latin1", line=line if base == 0 else None)
        return
    corpus, starts, offs, encs = extract_strings(data, min_len, utf16)
    if not corpus:
        return
    lower_cache2 = []

    def lower2():
        if not lower_cache2:
            lower_cache2.append(corpus.lower())
        return lower_cache2[0]

    for h in state.heuristics:
        if h.rx is None or not h.applies("strings") or not h.prefilter(corpus, lower2):
            continue
        for m in h.rx.finditer(corpus):
            if m.end() == m.start():
                continue
            i = _bisect.bisect_right(starts, m.start()) - 1
            if i < 0:
                continue
            within = m.start() - starts[i]
            off = base + offs[i] + within * (2 if encs[i] == "utf16le" else 1)
            if (h.id, off) in seen:
                continue
            seen.add((h.id, off))
            state.record(h, where, off, m.group(0), _ref_context(corpus, m.start(), m.end()), scope="strings", encoding=encs[i])


@pytest.mark.parametrize("text_file", [False, True])
def test_hunt_scan_file_output_identical_to_reference(tmp_path, monkeypatch, text_file):
    """#20/#21: hunt.py 를 고친 뒤에도 fw_strings_hunt 출력이 예전과 같다 — 작은 청크(4 KiB, 겹침 256 B)로 청크 경계·겹침 구간 중복·
    첫 텍스트 청크의 줄 단위 중복(그리고 예전의 첫·둘째 청크 겹침 이중 집계)까지 그대로인지 무작위 입력으로 비교한다."""
    import random

    from fwtriage_mcp import hunt as H

    monkeypatch.setattr(H, "CHUNK", 4096)
    monkeypatch.setattr(H, "OVERLAP", 256)
    rnd = random.Random(3 if text_file else 4)
    words = ["telnetd", "-l", "/bin/sh", "uvsh", "Loopback", "sdcard", "/mnt/sd/x.sh", "password=", "admin", "root:", "Digest", 'nonce="x"', "getty",
             "dropbear", "-B", "nc", "-e", "mount", "vfat", "/dev/mmcblk0p1", "syslogd", "-O", "%s", "a" * 300, " ", "#", "; ", "|", "admin:admin"]
    if text_file:
        lines = []
        for _ in range(1500):
            ln = " ".join(rnd.choice(words) for _ in range(rnd.randint(0, 10)))
            lines.append(("# " + ln) if rnd.random() < 0.1 else ln)
        data = ("\n".join(lines) + "\n").encode("latin-1")
    else:
        parts = []
        for _ in range(2500):
            if rnd.random() < 0.7:
                parts.append(" ".join(rnd.choice(words) for _ in range(rnd.randint(1, 8))).encode("latin-1") + b"\0")
            else:
                parts.append(" ".join(rnd.choice(words) for _ in range(rnd.randint(1, 5))).encode("utf-16-le") + b"\0\0")
        data = b"".join(parts)
    f = tmp_path / "blob"
    f.write_bytes(data)
    sel, _ = load_patterns().select(None)
    new = H.HuntState(sel, max_hits=3000, per_pattern_cap=300, per_file_pattern_cap=75)
    H.scan_file(new, str(f), ("p", "/f"), len(data), Ctl(max_seconds=120), min_len=4, utf16=True, max_file_size=64 << 20)
    ref = H.HuntState(sel, max_hits=3000, per_pattern_cap=300, per_file_pattern_cap=75)
    seen: set = set()
    pos = 0
    tf = None
    while pos < len(data):
        chunk = data[pos:pos + 4096 + 256]
        if tf is None:
            from fwtriage_mcp.fswalk import is_text

            tf = is_text(chunk[:65536])
        _ref_scan_buffer(ref, chunk, pos, ("p", "/f"), tf, min_len=4, utf16=True, seen=seen)
        if len(chunk) < 4096 + 256:
            break
        pos += 4096
    assert tf == text_file
    assert new.hits == ref.hits and new.counts == ref.counts and new.commented == ref.commented and new.commented_count == ref.commented_count
    assert new.file_counts == ref.file_counts and sum(ref.counts.values()) > 100


def test_env_expansion_shares_one_budget_and_honours_ctl():
    """#22: CRC env 16개 + 내장 기본 8개가 ';' 홍수로 run 펼침을 하면 옛 코드는 ctl 없이 20초(64개면 60초). 스캔 전체 예산·ctl 로 묶는다."""
    def crc_env(i):
        env = {"bootcmd": "run a a", "bootdelay": "1", "a": "run zz;" + ";" * 11000, "tag": str(i)}
        env.update({f"v{k:03d}": "run a a" for k in range(200)})
        return build_uboot_env(env, size=0x4000)

    img = b"".join(crc_env(i) for i in range(16)) + b"\xff" * 4096
    scan = env_scan(img, len(img), Ctl(max_seconds=60), max_hits=64, include_default=True)
    assert len(scan["envs"]) == 16
    _, dt = _timed(attach_sd_boot, scan)
    assert dt < SLOW and all(e["sd_boot"]["expansion_truncated"] for e in scan["envs"][-2:])
    scan2 = env_scan(img, len(img), Ctl(max_seconds=60), max_hits=64, include_default=True)
    ctl = Ctl(max_seconds=0.05)
    _, dt = _timed(attach_sd_boot, scan2, ctl)
    assert dt < 2.0 and ctl.timed_out


def test_hotplug_classification_checks_budget_per_rule(tmp_path):
    """#23: 서로 다른 적대적 mdev 정규식(규칙마다 수천 상태 NFA) 수백 개 — 옛 코드는 256규칙마다만 시간을 봐 max_seconds=1 에 25초."""
    rules = "".join(f"((.?.?.?.?.?.?.?.?){{16}}){{3}}x{i} 0:0 660 @/sbin/h.sh\n" for i in range(400))
    root = write_tree(tmp_path / "r", {"etc/mdev.conf": rules, "sbin/h.sh": "#!/bin/sh\necho h\n"})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=1))
    assert dt < 1 + SLOW, dt
    assert res["phases"]["rootfs_text"] == "truncated"


def test_same_hotplug_pattern_is_classified_once(monkeypatch):
    calls = []
    real = sdsurface._classify_mdev_matcher
    monkeypatch.setattr(sdsurface, "_classify_mdev_matcher", lambda r, e: calls.append(r) or real(r, e))
    sdsurface._MDEV_CLASS_CACHE.clear()
    for _ in range(50):
        classify_mdev_matcher("mmcblk[0-9]p[0-9]x", [])
    assert len(calls) == 1


def test_uevent_helper_scan_is_linear(tmp_path):
    """#24: rcS 1 MiB 가 'echo … > /proc/sys/kernel/hotplug' 줄 2만5천 개 — 옛 코드는 일치마다 파일 전체를 나눠 17초."""
    body = "#!/bin/sh\n" + "echo /sbin/h.sh > /proc/sys/kernel/hotplug\n" * 25000
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": body, "sbin/h.sh": "#!/bin/sh\nmount -t vfat /dev/$MDEV /media/$MDEV\n"})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=60))
    assert dt < SLOW, dt
    assert "uevent-helper" in _rules(_checks(res)["SD-04"])


@pytest.mark.parametrize("shape", ["elif", "brace"])
def test_block_lookups_are_linear(tmp_path, shape):
    """#25: elif 3만4천 줄(옛: 23초)·중첩 중괄호 1만6천(옛: 6초) — 갈래·감싸는 if 를 미리 만든 표에서 찾는다."""
    if shape == "elif":
        body = "if [ -f /mnt/sd/x ]; then :\n" + "elif [ -f /mnt/sd/x ]; then :\n" * 34000 + "fi\n"
    else:
        body = "{\n" * 16000 + "flashcp /mnt/sd/update.bin /dev/mtd0\n" * 16000
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + body})
    _, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < 2 * SLOW, dt


def test_dense_sd_tokens_cost_is_bounded(tmp_path):
    """#26: '/mnt/sd/x;' 가 빽빽한 0.95 MiB 스크립트 — 옛 코드는 512자 앞 문맥마다 _SERVER_ROOT_ARG_RX 등 정규식 15개로 34초."""
    line = "/mnt/sd/x;" * 1600 + "\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + line * (1_000_000 // len(line))})
    _, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < 2 * SLOW, dt
    t0 = time.monotonic()
    for _ in range(200):
        sdsurface._SERVER_ROOT_ARG_RX.search(("/do" * 300)[-512:])
    assert time.monotonic() - t0 < 1.0


def test_writable_prefix_check_is_constant_per_path(tmp_path):
    """#27: 쓰기 가능 접두 4만(같은 '/m' 되풀이)·서로 다른 실행 경로 11만(파일마다 1 MiB 아래) — 옛 코드는 경로마다 접두 전체를 훑어 max_seconds=1 에 16초."""
    mounts = "#!/bin/sh\n" + "mount -tvfat /dev/x /m\n" * 40000
    paths = "#!/bin/sh\n" + "".join(f";/a{i:06d}" for i in range(110000)) + "\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/S00mounts": mounts, "etc/init.d/S99paths": paths})
    aud = _audit_p(root, ctl=Ctl(max_seconds=60))
    _, dt = _timed(aud.audit_startup)
    assert dt < SLOW and aud.startup_scan_complete, dt


CONT_CASES = [
    # (본문, 항목 id, 첫 물리 줄) — 줄 이어쓰기로 한 명령 (HEAD 는 0열 이어쓰기만 우연히 잡았다, 들여쓴 줄도 잡는다)
    ("nc -p 4444 \\\n-l -e /bin/sh &\n", "builtin-netcat-shell", 2),
    ("nc -l -p 4444 \\\n    -e /bin/sh &\n", "builtin-netcat-shell", 2),
    ("/usr/sbin/dropbear -R -p 22 \\\n  -B &\n", "builtin-dropbear-blank-password", 2),
    ("echo 'root:admin123' |\n  chpasswd\n", "builtin-chpasswd-literal", 2),
    ("/usr/sbin/telnetd -p 23 \\\n   -l /bin/sh &\n", "gen-telnetd-login-shell", 2),
]


@pytest.mark.parametrize("body, hid, line", CONT_CASES)
def test_default_audit_joins_continued_lines(tmp_path, body, hid, line):
    """#1/#12: 줄 끝 '\\'(홀수 개)·'|'·'||'·'&&' 로 이어진 줄은 한 논리 줄로 규칙을 적용하고, 항목 줄 번호는 첫 물리 줄이다."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + body})
    aud = _audit_p(root)
    aud.audit_startup()
    hits = [i for i in aud.items if i["id"] == hid]
    assert hits and hits[0]["line"] == line and "\n" not in hits[0]["excerpt"], aud.items


def test_escaped_backslash_is_not_a_continuation():
    from fwtriage_mcp.rootfs import logical_text

    assert logical_text("a \\\\\nb\n") == "a \\\\\nb\n"
    assert logical_text("a \\\\\\\nb\n") == "a \\\\  b\n"
    assert logical_text("x &\ny;\nz\n") == "x &\ny;\nz\n"
    t = "x &&\n  y ||\n z |\n w\n"
    assert len(logical_text(t)) == len(t) and logical_text(t).count("\n") == 1


PREFILTER_CASES = [
    "MNT=/mnt\nSD=$MNT/sd\nmount -t vfat /dev/mmcblk0p1 $SD\nsh $SD/autorun.sh &\n",
    "mnt=/mnt\nsd=$mnt/sd\nmount -t vfat /dev/mmcblk0p1 $sd\nsh $sd/autorun.sh &\n",
    "MNT_PATH=/mnt\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\nsh $MNT_PATH/sd/autorun.sh &\n",
]


@pytest.mark.parametrize("body", PREFILTER_CASES)
def test_variable_built_card_paths_are_classified(tmp_path, body):
    """#3: 카드 경로를 변수로만 만드는 시작 스크립트도 분류한다 (옛 리터럴 사전 필터는 파일을 건너뛰고 rootfs_text 를 complete 로 두었다)."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + body})
    c = _checks(_surface(root))["SD-01"]
    assert c["status"] == "found" and "sh" in _rules(c), c


SD_FREE_TREES = {
    "mdev uevent helper": {"etc/init.d/rcS": "#!/bin/sh\necho /sbin/mdev > /proc/sys/kernel/hotplug\nmdev -s\n"},
    "eudev clears helper": {"etc/init.d/S10udev": "#!/bin/sh\necho \"\" > /proc/sys/kernel/hotplug\nudevd --daemon\n"},
    "permission-only mmcblk rule": {"etc/mdev.conf": "null 0:0 666\nmmcblk0p[0-9] 0:6 660\n"},
    "wifi hotplug script": {"etc/mdev.conf": "wlan[0-9] 0:0 660 */etc/hotplug/wifi.sh\n",
                            "etc/hotplug/wifi.sh": "#!/bin/sh\nlogger -t hotplug \"wifi $ACTION $MDEV\"\n[ \"$ACTION\" = add ] && /usr/sbin/wifi_up $MDEV\n"},
    "custom non-storage helper": {"etc/init.d/rcS": "#!/bin/sh\necho /sbin/hp > /proc/sys/kernel/hotplug\n",
                                  "sbin/hp": "#!/bin/sh\nlogger \"$ACTION $DEVPATH\"\nmount -o remount,rw /\n"},
}


@pytest.mark.parametrize("name", list(SD_FREE_TREES))
def test_sd_free_firmware_has_no_sd04(tmp_path, name):
    """#14/#15/#16: SD 와 무관한(eMMC 전용 포함) 펌웨어 — mdev·빈 uevent helper, 권한만 정하는 mmcblk 규칙, $MDEV 만 쓰는 wlan 처리기는 SD-04 근거가 아니다."""
    res = _surface(write_tree(tmp_path / "r", SD_FREE_TREES[name]), _plain_flash())
    assert _checks(res)["SD-04"]["status"] == "not-found" and "SD-04" not in res["risk_found"], res["hotplug_handlers"]


def test_storage_specific_uevent_helper_is_sd04(tmp_path):
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\necho /sbin/sd_hp.sh > /proc/sys/kernel/hotplug\n",
                                       "sbin/sd_hp.sh": "#!/bin/sh\n[ \"$ACTION\" = add ] && mount -t vfat /dev/$MDEV /media/$MDEV\n"})
    c = _checks(_surface(root, _plain_flash()))["SD-04"]
    assert c["status"] == "found" and _rules(c) == {"uevent-helper"}


def test_kernel_module_option_strings_are_not_sd08(tmp_path):
    """#17: fat.ko 의 옵션 이름표(',shortname=mixed'·',discard')는 마운트 옵션이 아니다 — 굳힌 SD 마운트는 계속 not-found."""
    fat = b"\x7fELF" + b"\0" * 60 + b",shortname=mixed\0,shortname=lower\0,discard\0umask=0000\0iocharset=%s\0sd card\0" + b"\0" * 64
    files = {"lib/modules/4.9.37/kernel/fs/fat/fat.ko": fat,
             "etc/init.d/rcS": "#!/bin/sh\nmount -t vfat -o noexec,nosuid,nodev,umask=0022 /dev/mmcblk0p1 /mnt/sd\n"}
    res = _surface(write_tree(tmp_path / "r", files))
    c = _checks(res)["SD-08"]
    assert c["status"] == "not-found" and "SD-08" not in res["risk_found"], c


def test_image_mount_option_strings_need_card_context():
    img = b"\xff" * 4096 + b",shortname=mixed\0,discard\0umask=0000\0" + b"\xff" * 4096
    sd = SdSurface(Ctl(max_seconds=60), load_patterns())
    sd.scan_image(img, len(img), "dumps/x.bin", env_scan(img, len(img), Ctl(max_seconds=60), include_default=True))
    assert not sd.ev["SD-08"]


STOP_CASES = [
    ("[ -f /mnt/sd/telnet.disable ] && killall telnetd\n", False),
    ("[ -f /mnt/sd/x.flag ] && pkill dropbear\n", False),
    ("[ -f /mnt/sd/x.flag ] && kill $(pidof sshd)\n", False),
    ("[ -f /mnt/sd/x.flag ] && /etc/init.d/sshd stop\n", False),
    ("[ -f /mnt/sd/x.flag ] && echo \"disabling telnetd now\"\n", False),
    ("[ -f /mnt/sd/x.flag ] && sed -i '/telnet/d' /etc/inetd.conf\n", False),
    ("[ -f /mnt/sd/x.flag ] && /etc/init.d/sshd start\n", True),
    ("[ -f /mnt/sd/x.flag ] && start-stop-daemon -S -b -x /usr/sbin/dropbear\n", True),
    ("[ -f /mnt/sd/x.flag ] && /bin/busybox telnetd &\n", True),
    ("[ -f /mnt/sd/x.flag ] && sh -c 'telnetd -l /bin/sh'\n", True),
]


@pytest.mark.parametrize("body, started", STOP_CASES)
def test_trigger_service_counts_only_starts(tmp_path, body, started):
    """#11: 카드 파일이 원격 셸을 '끄는'(killall·pkill·kill·stop) 줄이나 문구 안의 이름은 trigger-service 가 아니다."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body})
    c = _checks(_surface(root, _plain_flash()))["SD-01"]
    assert ("trigger-service" in _rules(c)) == started, (body, c["evidence"])


def test_kill_before_upgrade_reports_flash_not_backdoor(tmp_path):
    body = "if [ -f /mnt/sd/upgrade.bin ]; then\n  killall -9 telnetd ipcam\n  flashcp -v /mnt/sd/upgrade.bin /dev/mtd2\n  reboot\nfi\n"
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))
    assert c["SD-01"]["status"] == "not-found" and {"trigger-flash", "flash-write"} <= _rules(c["SD-02"])


EXEC_SH_C_CASES = [
    ("etc/udev/rules.d/10-sd.rules", 'KERNEL=="mmcblk[0-9]p[0-9]", ACTION=="add", RUN+="/bin/sh -c \'/mnt/sd/autorun.sh\'"\n', "udev-exec"),
    ("etc/udev/rules.d/10-sd.rules", 'KERNEL=="mmcblk[0-9]p[0-9]", ACTION=="add", RUN+="/bin/sh /mnt/sd/autorun.sh"\n', "udev-exec"),
    ("etc/systemd/system/sdrun.service", "[Service]\nExecStart=/bin/sh -c '/mnt/sd/autorun.sh'\n", "systemd-exec"),
    ("etc/systemd/system/sdrun.service", "[Service]\nExecStart=\"/mnt/sd/autorun.sh\"\n", "systemd-exec"),
    ("etc/crontabs/root", "*/5 * * * * /bin/sh -c '/mnt/sd/cron.sh'\n", "cron-exec"),
    ("etc/inittab", "::once:/bin/sh -c '/mnt/sd/autorun.sh'\n", "inittab-exec"),
]


@pytest.mark.parametrize("rel, body, rule", EXEC_SH_C_CASES)
def test_sh_c_in_udev_systemd_cron_inittab_is_exec(tmp_path, rel, body, rule):
    """#5: udev RUN+=·systemd ExecStart=·cron·inittab 의 '/bin/sh -c "카드"'·'/bin/sh 카드' 는 실행이다 (high)."""
    files = {"etc/fstab": "/dev/mmcblk0p1 /mnt/sd vfat defaults 0 0\n", rel: body}
    c = _checks(_surface(write_tree(tmp_path / "r", files), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and rule in _rules(c), c["evidence"]
    assert any(e["severity"] == "high" for e in c["evidence"])


FLASH_CASES = [
    "FW=/mnt/sd/fw.bin\ndd if=\"$FW\" of=/dev/mtdblock2 bs=64k\n",
    "dd if='/mnt/sd/fw.bin' of=/dev/mtdblock2\n",
    "cat /mnt/sd/fw.bin | dd of=/dev/mtdblock2\n",
    "gunzip -c /mnt/sd/fw.bin.gz | dd of=/dev/mtdblock2\n",
    "ubiformat /dev/mtd3 -f /mnt/sd/system.ubi -y\n",
    "mtd_debug write /dev/mtd2 0 0x100000 /mnt/sd/image.bin\n",
    "cp /mnt/sd/fw.bin /dev/mtdblock2\n",
]


@pytest.mark.parametrize("body", FLASH_CASES)
def test_flash_write_shapes(tmp_path, body):
    """#6: 따옴표 if=·파이프로 dd·ubiformat -f·mtd_debug write·cp 대상 /dev/mtd* 도 SD-02 flash-write."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-02"]
    assert c["status"] == "found" and "flash-write" in _rules(c), (body, c["evidence"])


GATE_CASES = [
    "[ -f /mnt/sd/debug.flag ] &&\n    telnetd -l /bin/sh &\n",
    "start_dbg(){ telnetd -l /bin/sh & }\n[ -f /mnt/sd/debug.flag ] && start_dbg\n",
    "start_dbg() {\n  telnetd -l /bin/sh &\n}\n[ -f /mnt/sd/debug.flag ] && start_dbg\n",
    "if [ -d /mnt/sd -a -f /mnt/sd/telnet.flag ]; then telnetd & fi\n",
    "grep -q telnet=1 /mnt/sd/debug.cfg && telnetd &\n",
    "if [ ! -f /mnt/sd/telnet.flag ]; then\n  echo no\nelse\n  telnetd &\nfi\n",
    "[ -f /mnt/sd/telnet.flag ] && socat TCP-LISTEN:23,fork EXEC:/bin/sh &\n",
]


@pytest.mark.parametrize("body", GATE_CASES)
def test_card_gated_service_shapes(tmp_path, body):
    """#7: 줄 끝 && 다음 줄, 셸 함수로 감싼 시작, '-a' 묶은 시험, grep -q 내용 시험, else 갈래, socat EXEC 셸도 trigger-service."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert "trigger-service" in _rules(c), (body, c["evidence"])


LAUNCHER_CASES = ["env PATH=/bin /mnt/sd/autorun.sh &\n", "timeout 30 /mnt/sd/autorun.sh\n", "command /mnt/sd/autorun.sh\n",
                  "start-stop-daemon -S -b -x /mnt/sd/autorun.sh\n"]


@pytest.mark.parametrize("body", LAUNCHER_CASES)
def test_launcher_prefixes_are_exec(tmp_path, body):
    """#8(일부): env·timeout·command·start-stop-daemon -x 뒤의 카드 프로그램은 실행이다."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and "direct-exec" in _rules(c), (body, c["evidence"])


def test_syslogd_attached_option_value(tmp_path):
    """#9: 'syslogd -O/mnt/sd/messages' (getopt 가 붙은 값을 허용) 도 SD-06 syslogd-to-card."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + "syslogd -O/mnt/sd/messages\n"}), _plain_flash()))["SD-06"]
    assert c["status"] == "found" and "syslogd-to-card" in _rules(c)


def test_shebangless_handlers_and_sh_targets_are_followed(tmp_path):
    """#10: 셰뱅 없는 mdev 처리기(system() 이 ENOEXEC 대체로 셸 실행)와 'sh 파일' 로 부르는 셰뱅 없는 파일도 따라간다."""
    root = write_tree(tmp_path / "r", {"etc/mdev.conf": "mmcblk[0-9]p[0-9] 0:0 660 @/sbin/sd_insert\n", "sbin/sd_insert": "/usr/sbin/telnetd -l /bin/sh &\n",
                                       "etc/init.d/rcS": "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\nsh /usr/bin/start_app &\n",
                                       "usr/bin/start_app": "/mnt/sd/autorun.sh &\n"})
    aud = _audit_p(root)
    st = aud.audit_startup()
    assert {"/sbin/sd_insert", "/usr/bin/start_app"} <= set(st["startup_files"])
    assert any(i["id"] == "gen-telnetd-login-shell" and i["file"] == "/sbin/sd_insert" for i in aud.items)
    c = _checks(_surface(root))["SD-01"]
    assert any(e["file"] == "/usr/bin/start_app" for e in c["evidence"]), c["evidence"]


WINDOW_CASES = [
    ("sh" + " " * 600 + "/mnt/sd/autorun.sh &\n", "SD-01", "sh"),
    ("[ -f" + " " * 300 + "/mnt/sd/telnet.flag ] && telnetd -l /bin/sh &\n", "SD-01", "trigger-service"),
    ("[ -f /mnt/sd/telnet.flag ]" + " " * 5000 + "&& telnetd -l /bin/sh &\n", "SD-01", "trigger-service"),
    ("cat /mnt/sd/run.txt" + " " * 300 + "| sh\n", "SD-01", "pipe-to-shell"),
]


@pytest.mark.parametrize("body, cid, rule", WINDOW_CASES)
def test_whitespace_padding_does_not_hide_shapes(tmp_path, body, cid, rule):
    """#4(일부): 32칸 넘는 공백 덧대기는 접어서 문맥 창 밖으로 밀어내지 못한다."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))[cid]
    assert rule in _rules(c), (body[:40], c["evidence"])


@pytest.mark.parametrize("body, rule", [("sh < /mnt/sd/autorun.sh\n", "sh"), ("ls /mnt/sd/*.sh | xargs -n1 sh\n", "pipe-to-shell")])
def test_shell_reading_card_file_is_exec(tmp_path, body, rule):
    """#8(일부): 'sh < 카드파일'·'ls 카드/*.sh | xargs -n1 sh' 도 카드 내용 실행이다."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert rule in _rules(c), (body, c["evidence"])


def test_negated_elif_chain_is_linear(tmp_path):
    """#25(부정 갈래): 'elif [ ! -f 카드 ]' 3만4천 줄 — else 갈래 종류는 이분 탐색 색인으로 바로 찾는다 (목록을 처음부터 찾지 않음)."""
    body = "if [ ! -f /mnt/sd/x ]; then :\n" + "elif [ ! -f /mnt/sd/x ]; then :\n" * 34000 + "else\n  telnetd &\nfi\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + body})
    _, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < 2 * SLOW, dt


def test_sourced_shebangless_file_after_separator_is_followed(tmp_path):
    """#10: '[ -f x ] && . x'·'foo; . x' 로 읽는 셰뱅 없는 파일도 시작 스크립트로 따라간다."""
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n[ -f /etc/default/app ] && . /etc/default/app\necho x; . /usr/lib/helper\n",
                                       "etc/default/app": "telnetd -l /bin/sh &\n", "usr/lib/helper": "nc -l -p 4444 -e /bin/sh &\n"})
    aud = _audit_p(root)
    st = aud.audit_startup()
    assert {"/etc/default/app", "/usr/lib/helper"} <= set(st["startup_files"])
    ids = {(i["id"], i["file"]) for i in aud.items}
    assert ("gen-telnetd-login-shell", "/etc/default/app") in ids and ("builtin-netcat-shell", "/usr/lib/helper") in ids


def test_syslogd_option_padding_within_window(tmp_path):
    """#4(W5): syslogd 옵션 300자 뒤의 '-O 카드' 도 찾는다 (옵션 간격을 512자 앞 문맥에 맞췄다)."""
    body = "syslogd " + "-s 200 " * 43 + "-O /mnt/sd/messages\n"
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-06"]
    assert "syslogd-to-card" in _rules(c), c["evidence"]


# ---------------------------------------------------------------------------
# 5라운드 (#13·#7~#11·#16·#17·#0): 블록 구조 선형·시간 예산, SD 없는 펌웨어 오탐, 히트 분류 시간 예산, 디렉터리 복사 기억 상한, sh -c 안의 cd
# ---------------------------------------------------------------------------

#: '[ -f 카드 ] && :' 가 블록 구조 계산을 시작한다 (_trigger → func_body → _structure)
_STRUCT_HEAD = "[ -f /mnt/sd/x ] && :\n"


@pytest.mark.parametrize("shape", ["fi", "done", "esac", "else", "elif"])
def test_block_structure_linear_on_deep_braces_with_unmatched_closers_or_branches(tmp_path, shape):
    """#13: 중괄호 4만 겹 아래의 짝 없는 fi/done/esac 4만 줄(옛: 55~76초), 'if true; then' + 중괄호 4만 겹 + else/elif 4만 줄(옛: 30초).

    else/elif 는 스택 칸마다 기억한 가장 안쪽 if 로, 짝 없는 닫기는 종류별 열린 블록 수로 O(1) — 파일을 끝까지 보고 not-found."""
    n = 40000
    if shape in ("else", "elif"):
        body = "if true; then\n" + "{\n" * n + (shape + (" true; then" if shape == "elif" else "") + "\n") * n
    else:
        body = "{\n" * n + (shape + "\n") * n
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + _STRUCT_HEAD + body})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < SLOW, dt
    assert res["phases"]["rootfs_text"] == "complete" and _checks(res)["SD-01"]["status"] == "not-found", res["limitations"]


def _old_structure(lines: list[str]) -> tuple[list[tuple], list, list, dict]:
    """옛 _FileState._structure (else/elif·닫기마다 스택을 거슬러 찾는 이차 버전) — 새 선형 버전과 결과가 같은지 비교하는 기준."""
    blocks: list[dict] = []
    stack: list[dict] = []
    encl: list = []
    encl_if: list = []
    iflike: list[dict] = []
    owner: dict[int, int] = {}
    funcs: dict[str, int] = {}
    func_pending = None
    for j, line in enumerate(lines):
        encl_if.append(iflike[-1]["line"] if iflike else None)
        heads = sdsurface._stmt_heads(line) if line.strip() else []
        fh = bool(heads) and sdsurface._FUNC_HEAD_RX.match(line) is not None
        if fh and heads[0][0] == "function" and line.rstrip().endswith("{") and not any(w == "{" for w, _ in heads):
            heads.append(("{", line.rstrip().rfind("{")))
        fname = None
        if fh:
            fm = sdsurface._FUNC_NAME_RX.match(line)
            fname = fm.group(1) if fm else None
        for w, pos in heads:
            kind = sdsurface._OPEN_KW.get(w)
            bname = None
            if kind is None and w == "{":
                if fh or func_pending:
                    kind, bname = "func", (fname if fh else func_pending)
                else:
                    kind = "brace"
                func_pending = None
            if kind is not None:
                b = {"idx": len(blocks), "kind": kind, "line": j, "pos": pos, "close": -1, "close_pos": 0, "branches": [], "bk": []}
                blocks.append(b)
                stack.append(b)
                if kind in ("if", "loop"):
                    iflike.append(b)
                    encl_if[j] = j
                if bname:
                    funcs.setdefault(bname, b["idx"])
            elif w in ("else", "elif"):
                for b in reversed(stack):
                    if b["kind"] == "if":
                        b["branches"].append((j, pos))
                        b["bk"].append(w)
                        owner.setdefault(j, b["idx"])
                        break
            elif w in sdsurface._CLOSE_KW:
                kinds = sdsurface._CLOSE_KW[w]
                k = len(stack) - 1
                while k >= 0 and stack[k]["kind"] not in kinds:
                    k -= 1
                if k >= 0:
                    for b in stack[k:]:
                        b["close"], b["close_pos"] = j, pos
                    del stack[k:]
                    while iflike and iflike[-1]["close"] >= 0:
                        iflike.pop()
        if fh and "{" not in line:
            func_pending = fname or "?"
        elif heads and not fh:
            func_pending = None
        encl.append(stack[-1]["idx"] if stack else None)
    n = len(lines)
    for b in blocks:
        if b["close"] < 0:
            b["close"], b["close_pos"] = n, 0
    out = [(b["kind"], b["line"], b["pos"], b["close"], b["close_pos"], b["branches"], b["bk"]) for b in blocks]
    return out, encl, encl_if, {"owner": owner, "funcs": funcs}


def test_linear_block_structure_equals_old_stack_walk_on_random_scripts():
    """#13: 새 블록 구조(near_if·종류별 열린 수)는 옛 스택 거슬러 찾기와 블록·갈래·감싸는 블록·감싸는 if·함수 표가 같다 (무작위 셸 조각, 짝 안 맞는 닫기 포함)."""
    import random

    vocab = ["if [ -f /a ]; then", "if a; then b; fi", "fi", "else", "elif b; then", "while x; do", "until y; do", "for i in 1 2; do", "done",
             "case $1 in", "esac", "{", "}", "{ x; }", "start() {", "stop()", "function g {", ": ;", "echo fi done esac", "then", "do",
             "if x; then :; else :; fi", "a && { b; }", "( cd /tmp )", "'fi' \"done\" # fi"]
    rnd = random.Random(20261021)
    for _ in range(300):
        lines = [rnd.choice(vocab) for _ in range(rnd.randint(1, 60))]
        fs = sdsurface._FileState("/r", "r", "boot", True, lines, lines, None)
        fs._structure()
        old, old_encl, old_encl_if, old_maps = _old_structure(lines)
        new = [(b.kind, b.line, b.pos, b.close, b.close_pos, b.branches, b.branch_kinds) for b in fs._blocks]
        assert new == old, lines
        idx = {id(b): k for k, b in enumerate(fs._blocks)}
        assert [idx[id(b)] if b is not None else None for b in fs._encl] == old_encl, lines
        assert fs._encl_if == old_encl_if, lines
        assert {j: idx[id(b)] for j, b in fs._branch_owner.items()} == old_maps["owner"], lines
        assert {k: idx[id(v)] for k, v in fs.functions.items() if not isinstance(v, str)} == old_maps["funcs"], lines


def test_block_structure_stops_on_budget_and_cancel(tmp_path, monkeypatch):
    """#13: 블록 구조를 만드는 도중 시간 예산이 끝나면 그 파일은 끝까지 보지 못한 것 — SD-01 은 not-found 가 아니라 unknown + 시간 예산 한계.
    취소는 Cancelled 로 바로 멈춘다 (옛: _structure 안에서는 max_seconds·취소를 보지 않아 1 MiB 에서 26분)."""
    from fwtriage_mcp.common import Cancelled

    body = "#!/bin/sh\n" + MOUNT_SD + _STRUCT_HEAD + "{\n" * 20000 + "fi\n" * 20000 + "[ -f /mnt/sd/telnet.flag ] && telnetd &\n"
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": body})
    orig = sdsurface._FileState._structure
    state: dict = {}

    def expiring(self):
        if self.ctl is not None and self._blocks is None:
            state["calls"] = state.get("calls", 0) + 1
            if state.get("cancel") is not None:
                state["cancel"].set()  # 구조를 만드는 도중 취소
            else:
                self.ctl.deadline = time.monotonic() - 1  # 구조를 만드는 도중 시간 예산이 끝난 것처럼
        try:
            return orig(self)
        except (sdsurface._TextBudgetExpired, Cancelled) as exc:
            state["stopped_inside"] = type(exc).__name__  # 구조 계산 안에서 멈췄다 (다음 줄·토큰 확인까지 끝까지 만들지 않음)
            raise

    monkeypatch.setattr(sdsurface._FileState, "_structure", expiring)
    res = _surface(root, ctl=Ctl(max_seconds=120))
    c = _checks(res)["SD-01"]
    assert state["calls"] >= 1 and state.get("stopped_inside") == "_TextBudgetExpired" and res["phases"]["rootfs_text"] == "truncated"
    assert c["status"] == "unknown" and "trigger-service" not in _rules(c), c
    assert any("시간 예산" in x for x in res["limitations"]), res["limitations"]
    import threading

    state.clear()
    state["cancel"] = threading.Event()
    with pytest.raises(Cancelled):
        _surface(root, ctl=Ctl(state["cancel"], max_seconds=120))
    assert state.get("stopped_inside") == "Cancelled"
    # 작은 파일(일이 상한 아래)은 예산을 보지 않고 끝까지 — 근거는 그대로
    monkeypatch.setattr(sdsurface._FileState, "_structure", orig)
    small = write_tree(tmp_path / "s", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + "if [ -f /mnt/sd/telnet.flag ]; then\n  telnetd &\nfi\n"})
    assert "trigger-service" in _rules(_checks(_surface(small))["SD-01"])


def test_whole_file_precomputations_check_budget():
    """#13: 줄 플래그·다음 서비스/플래시 줄·서명 흔적도 파일 전체를 훑으므로 같은 일 단위로 시간 예산을 본다 (끝나면 _TextBudgetExpired)."""
    lines = ["telnetd -l /bin/sh &", "flashcp /tmp/a /dev/mtd1", "openssl dgst -verify k.pem x"] * 20000
    unsigned = ["echo verify later", "{", "fi"] * 20000  # 서명 흔적이 없어 끝까지 훑는다
    for what in ("flags", "svc", "flash", "sig", "structure"):
        src = unsigned if what == "sig" else lines
        fs = sdsurface._FileState("/r", "r", "boot", True, src, src, None)
        fs.ctl = Ctl(max_seconds=0.001)
        time.sleep(0.01)
        with pytest.raises(sdsurface._TextBudgetExpired):
            if what == "flags":
                fs.flags
            elif what in ("svc", "flash"):
                fs.next_hit(what, 0)
            elif what == "sig":
                fs.signature_hint
            else:
                fs._structure()
        assert fs._blocks is None and fs._flags is None and not fs._next  # 부분 결과를 남기지 않는다
    fs = sdsurface._FileState("/r", "r", "boot", True, lines, lines, None)
    assert fs.signature_hint == "openssl … -verify" and fs.next_hit("svc", 0) == 0 and fs.flags["flash_erase"][1] is False


#: SD 슬롯 없는 NVR(SATA·USB 디스크)·eMMC 전용 펌웨어 — risk_found 도, high 근거도 없어야 한다 (#7·#8·#9)
SD_FREE_R5_TREES = {
    "nvr sata hdd at /mnt/sda1": {
        "etc/init.d/rcS": "#!/bin/sh\nfor i in /etc/init.d/S??*; do $i start; done\n",
        "etc/init.d/S30hdd": "#!/bin/sh\nmkdir -p /mnt/sda1\nmount -t ext4 -o noatime /dev/sda1 /mnt/sda1\nsyslogd -O /mnt/sda1/log/messages\n"
                             "[ -x /mnt/sda1/tools/fsck.sh ] && /mnt/sda1/tools/fsck.sh &\n",
        "etc/lighttpd/lighttpd.conf": 'server.document-root = "/var/www"\nalias.url = ( "/record/" => "/mnt/sda1/record/" )\n'},
    "usb disk at /media/sdb2": {
        "etc/init.d/S40usb": "#!/bin/sh\nmount -t vfat /dev/sdb2 /media/sdb2\ncp /media/sdb2/config.ini /etc/app/\nsyslogd -O /media/sdb2/messages\n"},
    "nvr hdd at /media/hdd1 (ext4)": {"etc/init.d/S30hdd": "#!/bin/sh\nmount -t ext4 /dev/sda1 /media/hdd1\n/media/hdd1/app/start.sh &\n"},
    "nvr daemon strings": {
        "usr/bin/nvrd": build_min_elf(imports=("system", "mount")) + b"\0syslogd -O /mnt/sda1/log/messages\0sh /mnt/sda1/record/start.sh &\0"
                        b"/mnt/sda1/upgrade/update.bin\0mount -t ext4 -o umask=0000 /dev/sda1 /mnt/sda1\0/media/sdb1/backup/core_pattern\0\0"},
    "emmc ext4 /userdata/media": {"etc/init.d/S20data": "#!/bin/sh\nmount -t ext4 /dev/mmcblk0p8 /userdata/media\n"},
    "emmc ext4 /data/media": {"etc/init.d/S20data": "#!/bin/sh\nmount -t ext4 -o noatime /dev/mmcblk0p8 /data/media\n"},
    "emmc ext4 /storage": {"etc/init.d/S20data": "#!/bin/sh\nmount -t ext4 /dev/mmcblk0p9 /storage\n"},
    "emmc exec from /mnt/storage": {"etc/init.d/S20data": "#!/bin/sh\nmount -t ext4 /dev/mmcblk0p9 /mnt/storage\n"
                                                         "[ -x /mnt/storage/app/start.sh ] && /mnt/storage/app/start.sh &\n"},
    "emmc fstab /mnt/storage": {"etc/fstab": "proc /proc proc defaults 0 0\n/dev/mmcblk0p9 /mnt/storage ext4 defaults,noatime 0 2\n"},
    "emmc f2fs /media (no -t)": {"etc/init.d/S20data": "#!/bin/sh\nmount /dev/mmcblk0p10 /media\n"},
    "emmc boot partition udev rule": {
        "etc/udev/rules.d/99-emmc-boot.rules": 'KERNEL=="mmcblk0boot[01]", ACTION=="add", RUN+="/bin/sh -c \'echo 1 > /sys/block/%k/force_ro\'"\n'},
    "emmc boot partition udev glob": {"etc/udev/rules.d/99-emmc-boot.rules": 'KERNEL=="mmcblk[0-9]boot*", RUN+="/usr/bin/emmc-bootpart-ro %k"\n',
                                      "usr/bin/emmc-bootpart-ro": "#!/bin/sh\necho 1 > /sys/block/$1/force_ro\n"},
    "emmc boot partition mdev rule": {"etc/mdev.conf": "mmcblk0boot[0-1] 0:0 440 @/sbin/emmc_boot_ro.sh\nnull 0:0 666\n",
                                      "sbin/emmc_boot_ro.sh": "#!/bin/sh\necho 1 > /sys/block/$MDEV/force_ro\n"},
    "emmc rpmb udev rule": {"etc/udev/rules.d/90-rpmb.rules": 'KERNEL=="mmcblk0rpmb", ACTION=="add", RUN+="/usr/bin/rpmb_provision.sh"\n',
                            "usr/bin/rpmb_provision.sh": "#!/bin/sh\nlogger rpmb ready\n"},
}


def _no_sd_risk(res: dict) -> list:
    """risk_found 와 high 근거 (SD 없는 펌웨어에서는 둘 다 비어야 한다). not-found 점검의 severity_hint 는 기준값이라 보지 않는다."""
    return res["risk_found"] + [(c["id"], e["rule"], e.get("file"), e.get("line")) for c in res["checks"] for e in c["evidence"] if e["severity"] == "high"]


@pytest.mark.parametrize("name", list(SD_FREE_R5_TREES))
def test_sd_free_nvr_and_emmc_firmware_has_no_sd_risk(tmp_path, name):
    """#7·#8·#9: SD 슬롯 없는 NVR(/dev/sdX 를 /mnt/sda1·/media/sdb2 에 — SCSI 디스크 이름 디렉터리, ext4 /media/hdd1)과 eMMC 전용 펌웨어
    (ext4 /userdata/media·/storage·/mnt/storage, mmcblk0boot·rpmb 규칙)는 risk_found·high 근거가 없다. 마운트는 메모와 함께 other_mmc_mounts 로."""
    res = _surface(write_tree(tmp_path / "r", SD_FREE_R5_TREES[name]), _plain_flash())
    assert _no_sd_risk(res) == [], (name, [(c["id"], c["evidence"][:2]) for c in res["checks"] if c["evidence"]])
    assert res["mount_points"] == [] and res["hotplug_handlers"] == [], (res["mount_points"], res["hotplug_handlers"])
    if any("mount" in str(v) and ("/dev/sd" in str(v) or "/dev/mmcblk" in str(v)) for v in SD_FREE_R5_TREES[name].values() if isinstance(v, str)):
        assert res["other_mmc_mounts"] and all(m["note"] for m in res["other_mmc_mounts"]), res["other_mmc_mounts"]


@pytest.mark.parametrize("mp", ["/mnt/sd", "/mnt/sdcard", "/mnt/sdmmc", "/mnt/sd0", "/mnt/sd_card", "/mnt/sd1", "/media/sdcard", "/mnt/sdhc", "/mnt/sdcard0"])
def test_card_named_mount_points_still_count_as_sd(tmp_path, mp):
    """#7: SCSI 디스크 이름(sda·sdb1·sdaa1)만 뺀다 — /mnt/sd·sdcard·sdmmc·sd0·sd_card·sd1·/media/sdcard 는 그대로 카드 경로다."""
    assert sdsurface._BUILTIN_SD_RX.match(mp)
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": f"#!/bin/sh\nmount -t vfat -o noexec,nosuid,nodev /dev/mmcblk0p1 {mp}\nsh {mp}/autorun.sh &\n"})
    res = _surface(root, _plain_flash())
    assert [m["path"] for m in res["mount_points"]] == [mp] and "sh" in _rules(_checks(res)["SD-01"])


@pytest.mark.parametrize("fs_type, device, mp, sd", [
    ("ext4", "/dev/sda1", "/mnt/sda1", False), ("vfat", "/dev/sdb2", "/media/sdb2", False), ("ext4", "/dev/sda1", "/mnt/sdaa1", False),
    ("vfat", "/dev/mmcblk0p1", "/mnt/sda1", True),  # /dev/mmcblk 마운트는 SCSI 디스크 이름이어도 SD 이름
    ("vfat", "/dev/sda1", "/mnt/usb", True), ("vfat", "/dev/sda1", "/media/usb0", True),
    ("ext4", "/dev/mmcblk0p8", "/userdata/media", False), ("ext4", "/dev/mmcblk0p9", "/mnt/storage", False), (None, "/dev/mmcblk0p9", "/media", False),
    ("vfat", "/dev/mmcblk1p1", "/media", True), ("exfat", "/dev/mmcblk1p1", "/storage/extcard", True), ("vfat", "/dev/mmcblk1p1", "/storage", True),
    ("ext4", "/dev/sda1", "/media/hdd1", False), ("vfat", "/dev/sda1", "/media/hdd1", True), ("ext4", "/dev/mmcblk0p1", "/mnt/sdcard", True),
])
def test_is_sd_mount_scsi_disk_names_and_generic_media_need_fat(fs_type, device, mp, sd):
    """#7·#8: /dev/sdX 를 장치 이름 디렉터리(/mnt/sda1·/media/sdb2)에 마운트하면 SD 가 아니고, 일반 이름(media·storage)은 FAT 계열 fs 일 때만 SD 후보."""
    ok, note = sdsurface._is_sd_mount(fs_type, device, mp)
    assert ok is sd, (fs_type, device, mp, note)
    if not ok:
        assert note and ("eMMC" in note or "SATA" in note)


def test_emmc_hardware_partition_patterns_are_not_sd_but_broad_mmc_rules_stay_sd():
    """#9: eMMC 하드웨어 파티션(mmcblkNbootM·rpmb)만 맞추는 규칙은 'other' — 'mmcblk*'·'$DEVNAME=mmcblk.*' 같은 넓은 규칙은 그대로 'sd' (catch-all 아님)."""
    for match in ({"KERNEL": "mmcblk0boot[01]"}, {"KERNEL": "mmcblk[0-9]boot*"}, {"KERNEL": "mmcblk0rpmb"}, {"KERNEL": "mmcblk1boot1"}):
        assert classify_udev_match(match) == "other", match
    for regex in ("mmcblk0boot[0-1]", "mmcblk[0-9]boot[01]", "$DEVNAME=mmcblk0boot.*", "mmcblk0rpmb"):
        assert classify_mdev_matcher(regex, []) == "other", regex
    assert classify_udev_match({"KERNEL": "mmcblk*"}) == "sd" and classify_mdev_matcher("$DEVNAME=mmcblk.*", []) == "sd"
    assert classify_mdev_matcher("mmcblk[0-9].*", []) == "sd" and classify_mdev_matcher("mmcblk[0-9]p[0-9]", []) == "sd"


def test_nvr_disk_strings_do_not_make_binary_card_context(tmp_path):
    """#7: NVR 데몬의 '/mnt/sda1' 문자열(YAML sd-* 경로 히트)은 카드 문맥이 아니다 — 같은 바이너리의 umask=0000 이 SD-08, syslogd -O 가 SD-06 이 되지 않는다.
    같은 문자열이 카드 경로면 그대로 근거다."""
    res = _surface(write_tree(tmp_path / "nvr", SD_FREE_R5_TREES["nvr daemon strings"]), _plain_flash())
    assert _no_sd_risk(res) == [] and not any(c["evidence"] for c in res["checks"]), [(c["id"], c["evidence"][:1]) for c in res["checks"] if c["evidence"]]
    card = build_min_elf(imports=("system", "mount")) + b"\0syslogd -O /mnt/sdcard/log/messages\0mount -t vfat -o umask=0000 /dev/mmcblk0p1 /mnt/sdcard\0\0"
    c = _checks(_surface(write_tree(tmp_path / "card", {"usr/bin/camd": card}), _plain_flash()))
    assert c["SD-06"]["status"] == "found" and c["SD-08"]["status"] == "found", (c["SD-06"]["evidence"], c["SD-08"]["evidence"])


#: 평범한 SPI-NOR/SPI-NAND 카메라 env (HiSilicon/XM 기본 verify=n) — 여기에 도우미 변수 하나씩을 더한다 (#10·#11·기준 3)
_NOR_ENV = {"bootcmd": "sf probe 0;sf read 0x82000000 0x50000 0x300000;bootm 0x82000000", "bootdelay": "1", "baudrate": "115200", "verify": "n",
            "bootargs": "mem=36M console=ttyAMA0,115200 root=/dev/mtdblock2 rootfstype=squashfs mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(rest)",
            "ipaddr": "192.168.1.10", "serverip": "192.168.1.2"}
NOR_ENV_CASES = {
    "hisi verify=n only": {},
    "xm tftp helpers": {"da": "mw.b 0x82000000 ff 1000000;tftp 0x82000000 u-boot.bin.img;sf probe 0;flwrite",
                        "up": "mw.b 0x82000000 ff 1000000;tftp 0x82000000 update.img;sf probe 0;flwrite",
                        "tk": "mw.b 0x82000000 ff 1000000;tftp 0x82000000 uImage; bootm 0x82000000"},
    "ubi boot.scr": {"ubiscript": "ubi part rootfs; ubifsload 0x82000000 /boot/boot.scr; source 0x82000000"},
    "netboot boot.scr": {"netscript": "tftp 0x82000000 boot.scr; source 0x82000000"},
    "netboot uEnv import": {"loadenv": "tftp 0x82000000 uEnv.txt; env import -t 0x82000000 ${filesize}"},
    "usb boot.scr": {"usbscript": "usb start; fatload usb 0:1 0x82000000 boot.scr; source 0x82000000"},
    "nand boot.scr": {"nandscript": "nand read 0x82000000 0x100000 0x1000; source 0x82000000; echo boot.scr"},
    "bare boot.scr name": {"script": "boot.scr", "bootscript": "echo Running ${script}"},
    "tftp autoupdate in bootcmd": {"bootcmd": "run autoupdate; sf probe 0;sf read 0x82000000 0x50000 0x300000;bootm 0x82000000",
                                   "autoupdate": "if tftp 0x82000000 fw.bin; then sf probe 0; sf update 0x82000000 0x50000 ${filesize}; fi"},
    "tftp auto_update helper": {"auto_update": "tftp 0x82000000 update.img && sf probe 0 && sf erase 0x50000 0x700000 && sf write 0x82000000 0x50000 ${filesize}",
                                "bootcmd": "run auto_update; sf probe 0; sf read 0x82000000 0x50000 0x300000; bootm 0x82000000"},
}


@pytest.mark.parametrize("name", list(NOR_ENV_CASES))
def test_ordinary_spi_nor_nand_env_has_no_sd_boot_or_update(name):
    """#10·#11·기준 3: UBI·TFTP·USB·NAND 에서 읽는 boot.scr·uEnv.txt, 이름만 있는 boot.scr, TFTP 자동 업그레이드(autoupdate·auto_update 도우미)는
    mmc_boot·update_from_card 가 아니다 — fw_uboot_env 의 SD next_step 조건(envs_with_mmc_boot·update_from_card)이 0, fw_sd_surface 의 SD-02 근거 없음·SD-03 not-found."""
    env = {**_NOR_ENV, **NOR_ENV_CASES[name]}
    b = sd_boot_analysis(env, storage="flash-crc")
    assert not b["mmc_boot"] and not b["boot_script"] and not b["update_from_card"] and b["severity_hint"] is None and b["signals"] == [], b
    scan = {"envs": [{"env": env}], "embedded_default_envs": [{"env": env}]}
    summ = attach_sd_boot(scan)
    assert summ["envs_with_mmc_boot"] == 0 and summ["update_from_card"] == 0 and summ["verify_off"] == 2, summ
    from fwtriage.sd_builders import build_sd_flash

    res = _surface(None, build_sd_flash(env=env, default_env=env))
    c = _checks(res)
    assert res["risk_found"] == [] and not c["SD-02"]["evidence"] and c["SD-03"]["status"] == "not-found", (c["SD-02"]["evidence"], c["SD-03"])
    if name in ("ubi boot.scr", "netboot boot.scr", "netboot uEnv import"):
        assert any("mmc 가 아닌 곳" in n for n in b["notes"]), b["notes"]
    if name == "usb boot.scr":
        assert any("USB 이동식 매체" in n for n in b["notes"]), b["notes"]
    if name == "bare boot.scr name":
        assert any("이름만 있고" in n for n in b["notes"]), b["notes"]


@pytest.mark.parametrize("extra, kind", [
    ({"sdboot": "mmc rescan; fatload mmc 0:1 0x82000000 boot.scr && source 0x82000000"}, "boot_script"),
    ({"loadbootenv": "load mmc ${mmcdev} ${loadaddr} uEnv.txt", "importbootenv": "env import -t ${loadaddr} ${filesize}"}, "boot_script"),
    ({"bootcmd": "run loadscr; sf probe 0; bootm", "loadscr": "if mmc dev 0; then load ${devtype} ${devnum}:1 ${scriptaddr} boot.scr; source ${scriptaddr}; fi"}, "boot_script"),
    ({"script": "boot.scr", "loadbootscript": "load mmc ${mmcdev}:${mmcpart} ${loadaddr} ${script}", "bootscript": "run loadbootscript; source"}, "boot_script"),
    ({"boot_a_script": "load ${devtype} ${devnum}:${distro_bootpart} ${scriptaddr} ${prefix}boot.scr; source ${scriptaddr}"}, "boot_script"),
    ({"bootcmd": "run sdupdate; bootm", "sdupdate": "fatload mmc 0 0x82000000 demo.bin; sf probe 0; sf update 0x82000000 0 ${filesize}"}, "update_from_card"),
    ({"bootcmd": "run autoupdate; sf probe 0; bootm", "autoupdate": "mmc rescan; fatload mmc 0 0x82000000 fw.bin && sf probe 0 && sf update 0x82000000 0 ${filesize}"},
     "update_from_card"),
    ({"bootcmd": "hiupdate; sf probe 0; bootm"}, "update_from_card"),
])
def test_real_card_boot_script_and_update_are_still_found(extra, kind):
    """#10·#11: mmc 에서 읽는 boot.scr·uEnv.txt(장치가 변수인 load ${devtype}·이름 변수 + load mmc 포함), 명시적 SD 업데이트 명령, mmc 에서 읽어 플래시에 쓰는
    autoupdate 도우미는 그대로 SD 신호다."""
    b = sd_boot_analysis({**_NOR_ENV, **extra}, storage="flash-crc")
    assert b[kind] and (b["mmc_boot"] or kind == "update_from_card"), b
    from fwtriage.sd_builders import build_sd_flash

    c = _checks(_surface(None, build_sd_flash(env={**_NOR_ENV, **extra})))
    assert c["SD-03" if kind == "boot_script" else "SD-02"]["status"] == "found"


def test_fw_setenv_boot_script_and_update_follow_the_same_source_rules(tmp_path):
    """#10·#11: fw_setenv 로 쓰는 값도 같은 규칙 — TFTP 에서 읽는 boot.scr·'run autoupdate' 는 SD-03/SD-02 가 아니고, mmc 에서 읽는 boot.scr·sdupdate 는 근거다."""
    neg = write_tree(tmp_path / "n", {"etc/init.d/rcS": "#!/bin/sh\nfw_setenv bootcmd 'tftp 0x82000000 boot.scr; source 0x82000000'\n"
                                                         "fw_setenv bootcmd_up 'run autoupdate'\nfw_setenv loadenv 'ubifsload 0x82000000 uEnv.txt'\n"})
    c = _checks(_surface(neg))
    assert not c["SD-03"]["evidence"] and not c["SD-02"]["evidence"], (c["SD-03"]["evidence"], c["SD-02"]["evidence"])
    pos = write_tree(tmp_path / "p", {"etc/init.d/rcS": "#!/bin/sh\nfw_setenv bootcmd 'fatload mmc 0:1 0x82000000 boot.scr; source 0x82000000'\n"
                                                         "fw_setenv bootcmd_up 'run sdupdate'\n"})
    c = _checks(_surface(pos))
    assert _rules(c["SD-03"]) == {"fw_setenv-mmc"} and _rules(c["SD-02"]) == {"fw_setenv-update"}


def _c5_image(groups: int, pad: int = 25) -> bytes:
    """#16 의 c5 모양: 카드 마운트 지점 200개를 만드는 문자열 + 문맥이 짧은 카드 아닌 경로('/a ')로 찬 히트 4종 × groups."""
    p = " " + "/a " * pad
    parts = [" ".join(f"/mnt/sd{k:02x}/a.sh" for k in range(200)) + "\0"]
    parts += [f"/tmp/sd/{i:04x}" + p for i in range(groups)] + [f"sdcard{i:04x} sdcard" + p for i in range(groups)]
    parts += [f"/dev/mmcblk{i:04x}" + p for i in range(groups)] + [f"/tmp/sd/{i:04x}.sh" + p for i in range(groups)]
    return b"\0" * 16 + "".join(parts).encode() + b"\0" * 16


def test_image_hit_classification_honours_budget():
    """#16: 이미지 문자열 히트 2만 묶음을 분류하는 단계도 시간 예산을 본다 (옛: max_seconds=1 에 11초, timed_out=false) — 끝나면 image_strings 잘림·timed_out."""
    img = _c5_image(5100)
    ctl = Ctl(max_seconds=1.0)
    sd = SdSurface(ctl, load_patterns())
    _, dt = _timed(sd.scan_image, img, len(img), "dumps/x.bin", {"envs": [], "embedded_default_envs": []})
    assert dt < 4.0, dt
    assert ctl.timed_out and sd.phases["image_strings"] == "truncated" and any("시간 예산" in x for x in sd.limitations), (sd.phases, sd.limitations)
    res = sd.result(rootfs_given=False, image_given=True)
    assert _checks(res)["SD-02"]["status"] != "not-found" and _checks(res)["SD-02"].get("context", {}).get("fit_signature_keys") is None


@pytest.mark.parametrize("source", ["image", "rootfs"])
def test_hit_group_loop_checks_ctl_every_few_groups(tmp_path, monkeypatch, source):
    """#16: 묶음 HIT_GROUPS_CTL_EVERY 개마다 ctl 을 본다 — 예산이 끝난 뒤에는 그만큼만 더 분류하고 멈춘다 (rootfs 바이너리도 단계를 잘림으로)."""
    calls = {"n": 0}
    orig = SdSurface._classify_string

    def counting(self, g, **kw):
        calls["n"] += 1
        if calls["n"] == 5:
            self.ctl.deadline = time.monotonic() - 1
        return orig(self, g, **kw)

    monkeypatch.setattr(SdSurface, "_classify_string", counting)
    if source == "image":
        img = _c5_image(300, pad=2)
        sd = SdSurface(Ctl(max_seconds=120), load_patterns())
        sd.scan_image(img, len(img), "dumps/x.bin", {"envs": [], "embedded_default_envs": []})
        phase = "image_strings"
    else:
        strings = [f"/mnt/sd/dir{i}/file{i}.conf" for i in range(400)]
        root = write_tree(tmp_path / "r", {"usr/bin/appd": build_min_elf(imports=("fopen",)) + b"\0" + "\0".join(strings).encode() + b"\0\0"})
        ctl = Ctl(max_seconds=120)
        sd = SdSurface(ctl, load_patterns())
        aud = _audit(root, Ctl(max_seconds=120))
        sd.scan_rootfs(aud, aud.audit_startup(), aud.audit_web())
        phase = "rootfs_binary"
    assert 5 <= calls["n"] <= 5 + sdsurface.HIT_GROUPS_CTL_EVERY, calls
    assert sd.ctl.timed_out and sd.phases[phase] == "truncated"


@pytest.mark.parametrize("copies, tokens", [(8000, 8000)])
def test_directory_copy_memory_is_deduped_and_lookup_constant(tmp_path, copies, tokens):
    """#17: 같은 디렉터리로의 복사 8천 번(같은 원본 이름) + 그 디렉터리 아래 토큰 8천 개 — 이름마다 처음 복사 한 칸만 기억하고 사전으로 찾는다 (옛: 16초, 4배씩)."""
    body = "#!/bin/sh\n" + "cp /tmp/sd /t\n" * copies + ("/t/x " * 100 + "\n") * (tokens // 100)
    root = write_tree(tmp_path / "r", {"etc/init.d/rcS": body})
    res, dt = _timed(_surface, root, ctl=Ctl(max_seconds=120))
    assert dt < SLOW, dt
    assert res["phases"]["rootfs_text"] == "complete" and _checks(res)["SD-01"]["status"] == "not-found"
    many = "#!/bin/sh\n" + ("cp" + " /tmp/sd" * 126 + " /t\n") * 200 + ("/t/x " * 100 + "\n") * 40  # 옛: 목록 2만5천 × 토큰 4천
    _, dt = _timed(_surface, write_tree(tmp_path / "m", {"etc/init.d/rcS": many}), ctl=Ctl(max_seconds=120))
    assert dt < 2 * SLOW, dt


@pytest.mark.parametrize("body, rule, sd_path", [
    ("cp /mnt/sd/run.sh /tmp/\n/tmp/run.sh &\n", "copy-then-exec", "/mnt/sd/run.sh"),
    ("cp /mnt/sd/*.sh /tmp/\nsh /tmp/start.sh\n", "copy-then-exec", "/mnt/sd/start.sh"),
    ("cp /mnt/sd/a.sh /tmp/\ncp /mnt/sd/b.sh /tmp/\n" * 3 + "cp /mnt/sd2/b.sh /tmp/\n. /tmp/b.sh\n", "copy-then-exec", "/mnt/sd/b.sh"),
    ("cp /mnt/sd/x.bin /tmp/\ncp /mnt/sd/*.img /tmp/\nflashcp /tmp/rootfs.img /dev/mtd3\n", "copy-then-flash", "/mnt/sd/rootfs.img"),
])
def test_directory_copy_then_exec_still_found(tmp_path, body, rule, sd_path):
    """#17: 디렉터리로 복사한 뒤 실행·플래시는 그대로 (원본 이름은 처음 복사가 근거, glob 원본은 이름과 맞춘다)."""
    cid = "SD-01" if rule == "copy-then-exec" else "SD-02"
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))[cid]
    assert any(e["rule"] == rule and e.get("sd_path") == sd_path for e in c["evidence"]), c["evidence"]


@pytest.mark.parametrize("body", [
    "".join(f"cp /mnt/sd/*.s{i} /tmp/\n" for i in range(sdsurface.DIR_GLOBS + 1)),  # 같은 디렉터리로 서로 다른 glob 원본 5개
    "".join(f"cp /mnt/sd/f{i}.bin /tmp/\n" for i in range(sdsurface.DIR_NAMES + 1)),  # 같은 디렉터리로 서로 다른 이름 65개
    "".join(f"cp /mnt/sd/f.bin /tmp/d{i}/\n" for i in range(sdsurface.COPY_KEYS + 1)),  # 대상 디렉터리 201개
])
def test_directory_copy_caps_mark_text_phase_incomplete(tmp_path, body):
    """#17·(c): 복사 기억 상한에 걸려 버린 복사가 있으면 그 뒤의 복사-실행을 놓칠 수 있다 — SD-01 은 not-found 가 아니라 unknown + 한계."""
    res = _surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash())
    assert res["phases"]["rootfs_text"] == "truncated" and _checks(res)["SD-01"]["status"] == "unknown"
    assert any("기억 상한" in x for x in res["limitations"]), res["limitations"]


def test_directory_copy_glob_lookup_is_bounded():
    """#17: glob 원본 비교(DP)는 이름이 NAME_MAX 이하일 때만, 디렉터리마다 glob 몇 개만 — 긴 이름·긴 glob 토큰이 많아도 일정한 비용."""
    lines = ["cp /mnt/sd/" + "[a-z]" * 20 + "*" + " /t/"] + [" ".join("/t/" + "x" * 250 for _ in range(60))] * 200
    fs = sdsurface._FileState("/r", "r", "boot", True, lines, lines, None)
    sd = SdSurface(Ctl(max_seconds=120), load_patterns())
    sd._remember_dir_copy(fs, "/t", "/mnt/sd/" + "[a-z]" * 20 + "*", "/mnt/sd", 1)
    _, dt = _timed(lambda: [sd._dir_lookup(fs, "/t/" + "x" * 250) for _ in range(500)])
    assert dt < SLOW, dt
    assert sd._dir_lookup(fs, "/t/" + "x" * 300) is None  # NAME_MAX 보다 긴 이름은 비교하지 않는다
    fs.ctl = Ctl(max_seconds=0.001)
    time.sleep(0.01)
    with pytest.raises(sdsurface._TextBudgetExpired):
        for _ in range(2000):
            sd._dir_lookup(fs, "/t/" + "x" * 250)


SH_C_CD_CASES = [
    ("sh -c 'cd /mnt/sd && ./run.sh' &\n", "relative-exec"),
    ("sh -c \"cd /mnt/sd; ./run.sh\" &\n", "relative-exec"),
    ("nohup /bin/sh -xc 'cd /mnt/sd && ./run.sh' &\n", "relative-exec"),
    ("su root -c 'cd /mnt/sd && ./run.sh'\n", "relative-exec"),
    ("bash -lc 'cd /mnt/sd && sh run.sh'\n", "sh"),
    ("eval \"cd /mnt/sd\"\n./run.sh &\n", "relative-exec"),  # eval 은 지금 셸 — cd 가 다음 줄까지 남는다
    ("env -i sh /mnt/sd/autorun.sh &\n", "sh"),
    ("env - sh /mnt/sd/autorun.sh &\n", "sh"),
    ("env PATH=/bin sh /mnt/sd/autorun.sh &\n", "sh"),
]


@pytest.mark.parametrize("body, rule", SH_C_CD_CASES)
def test_cd_inside_exec_quote_and_env_launcher_are_exec(tmp_path, body, rule):
    """#0: sh -c '…'·su -c '…'·eval "…" 의 여는 따옴표 바로 뒤 cd 는 명령 시작이다 ('cd 카드 && ./run.sh'), 'env [-i|-|VAR=…] sh 카드' 도 실행이다."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and rule in _rules(c), (body, c["evidence"])


@pytest.mark.parametrize("body", [
    "echo \"cd /mnt/sd && ./run.sh\"\n",
    "printf 'cd /mnt/sd; ./run.sh\\n'\n",
    "logger \"cd /mnt/sd && ./run.sh\"\n",
    "logger \"running sh -c 'cd /mnt/sd && ./run.sh'\"\n",
    "echo \"start; sh -c 'cd /mnt/sd && ./run.sh'\"\n",
    "echo env sh /mnt/sd/autorun.sh\n",
    "sh -c 'cd /mnt/sd && echo ok' &\n./local_app &\n",  # 자식 셸 안의 cd 는 닫는 따옴표에서 되돌린다 — 다음 줄의 ./x 는 카드가 아니다
    "su -c \"cd /mnt/sd\" admin\n./local_app &\n",
])
def test_quoted_cd_in_messages_and_child_shell_scope_are_not_exec(tmp_path, body):
    """#0: echo·printf·logger 문구 속의 cd·'sh -c' 는 cwd 를 바꾸지 않고, sh -c·su -c 문자열 안의 cd 는 그 문자열 밖으로 새지 않는다 (오탐 없음)."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "not-found", (body, c["evidence"])


def test_exec_quote_cd_scan_is_linear():
    """#0: 실행 문자열 탐지(명령 위치 정규식 + 맨 바깥 따옴표 한 번 훑기)는 'sh -c' 가 가득한 1 MiB 파일에서도 선형이다."""
    unit = "sh -c 'cd /x && ./r' ; "
    line = (unit * (16000 // len(unit)))
    body = "#!/bin/sh\n" + (line + "\n") * 64
    events, dt = _timed(lambda: [sdsurface._exec_quote_events(x) for x in body.split("\n")])
    assert dt < SLOW and sum(len(e) for e in events) == 64 * (16000 // len(unit)) * 3, dt
    for pre in ["; env " * 85, "; env -i " * 56, "; env A=" + "x" * 250 + " " * 2, ";env -i sh" + " -a" * 160]:
        _, dt = _timed(lambda: [sdsurface._PRE_SH.search(pre[-512:]) for _ in range(2000)])
        assert dt < SLOW, (pre[:20], dt)


@pytest.mark.parametrize("body, rule", [
    ("LD_LIBRARY_PATH=/mnt/sd/lib /mnt/sd/debug/run.sh &\n", "direct-exec"),
    ("LD_LIBRARY_PATH=/mnt/sd/lib \\\n    /mnt/sd/debug/run.sh &\n", "direct-exec"),
    ("A=1 B='x y' /mnt/sd/bin/debugd &\n", "direct-exec"),
    ("HOME=/root sh /mnt/sd/autorun.sh &\n", "sh"),
])
def test_assignment_prefix_before_card_program_is_exec(tmp_path, body, rule):
    """5차 #6: 'VAR=값 카드프로그램' 은 대입 뒤의 낱말을 실행한다 (기본 감사의 builtin-exec-from-writable-storage 와 같은 판정)."""
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and rule in _rules(c), (body, c["evidence"])


@pytest.mark.parametrize("body", [
    "echo FOO=1 /mnt/sd/debug/run.sh\n",
    "CARD=/mnt/sd/debug/run.sh\n",
    "logger \"LD_LIBRARY_PATH=/mnt/sd/lib /mnt/sd/run.sh\"\n",
])
def test_assignment_values_and_arguments_are_not_exec(tmp_path, body):
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "not-found", (body, c["evidence"])


def test_assignment_prefix_regex_cost_is_bounded():
    """대입 접두 대안은 낱말마다 길이 상한이 있어, 대입·구분자가 빽빽한 512자 앞 문맥에서도 토큰당 비용이 묶인다."""
    for pre in [";a=b" * 128, "a=b " * 128, ";A=" + "x" * 500, "; A=\"" + "y " * 200, ";" + "B=1 " * 120 + "sh"]:
        _, dt = _timed(lambda: [(sdsurface._PRE_CMD.search(pre[-512:]), sdsurface._PRE_SH.search(pre[-512:])) for _ in range(2000)])
        assert dt < SLOW, (pre[:20], dt)


# ---------------------------------------------------------------------------
# 6차 검증: systemd 유닛의 Exec*= 인자(#17), 안내 문구 속 cd(#19), start-stop-daemon 멈춤(#21), U-Boot 장치 변수(#3·#15), 대입 접두 비용(#0)
# ---------------------------------------------------------------------------

def _sd_risk(res: dict) -> list[str]:
    return sorted(c["id"] for c in res["checks"] if c["status"] == "found" and c.get("found_means") == "risk")


UNIT_RECORDER = "[Unit]\nDescription=recorder\n[Service]\nExecStart=/usr/bin/recorder /mnt/sdcard/record\n[Install]\nWantedBy=multi-user.target\n"


def test_systemd_exec_argument_is_not_sd_exec_on_sd_free_tree(tmp_path):
    """SD 없는 SPI-NOR 트리의 공용 SKU 유닛: 'ExecStart=/usr/bin/recorder /mnt/sdcard/record' 의 카드 경로는 인자다 (대입으로 읽지 않는다)."""
    root = write_tree(tmp_path / "r", {"etc/systemd/system/recorder.service": UNIT_RECORDER, "etc/init.d/rcS": "#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd\n"})
    res = _surface(root, _plain_flash())
    assert _checks(res)["SD-01"]["status"] == "not-found" and _sd_risk(res) == [], _checks(res)["SD-01"]


def test_systemd_exec_program_on_card_and_shell_assign_prefix_stay_found(tmp_path):
    unit = "[Service]\nExecStart=/mnt/sdcard/bin/app -d\n"
    rcs = "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sdcard\nLD_LIBRARY_PATH=/mnt/sdcard/lib /mnt/sdcard/run.sh &\n"
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/systemd/system/app.service": unit, "etc/init.d/rcS": rcs}), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and {"systemd-exec", "direct-exec"} <= _rules(c), c["evidence"]


@pytest.mark.parametrize("body", [
    "echo \"manual update: umount /tmp/x; cd /mnt/sd; sh update.sh\"\n",
    "logger -t upd \"SD models: umount /tmp/x; cd /mnt/sd && sh update.sh\"\n",
    "echo \"Usage: insert card; cd /mnt/sd; sh update.sh\"\n",
    "echo 'manual update: umount /tmp/x; cd /mnt/sd; sh update.sh'\n",
    "echo \"x; cd /mnt/sd; ./update.sh\"\n",
    "echo \"Insert the SD card, then cd /mnt/sd; sh update.sh\"\n",
    "echo \"card models: sync; cd /mnt/sd\"\n./start_app.sh &\n",  # 문구 속 cd 가 다음 줄의 cwd 로 새지 않는다
])
def test_cd_inside_message_quotes_is_not_exec_on_sd_free_tree(tmp_path, body):
    res = _surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\nmount -t jffs2 /dev/mtdblock3 /mnt/mtd\n" + body}), _plain_flash())
    assert _checks(res)["SD-01"]["status"] == "not-found" and _sd_risk(res) == [], (body, _checks(res)["SD-01"]["evidence"])


@pytest.mark.parametrize("body, rule", [
    ("sh -c \"umount /tmp/x; cd /mnt/sd; sh update.sh\"\n", "sh"),
    ("X=\"$(cd /mnt/sd && ./run.sh)\"\n", "relative-exec"),
    ("echo \"r: $(cd /mnt/sd; sh update.sh)\"\n", "sh"),
    ("cd /mnt/sd && sh update.sh\n", "sh"),
])
def test_cd_in_exec_strings_and_command_substitution_stays_found(tmp_path, body, rule):
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + body}), _plain_flash()))["SD-01"]
    assert c["status"] == "found" and rule in _rules(c), (body, c["evidence"])


@pytest.mark.parametrize("line, found", [
    ("start-stop-daemon -K -q -x /mnt/sd/bin/sdtool 2>/dev/null", False),
    ("start-stop-daemon --stop --exec /mnt/sd/app", False),
    ("start-stop-daemon -x /mnt/sd/app -K", False),
    ("start-stop-daemon -T -x /mnt/sd/app", False),
    ("start-stop-daemon -S -b -x /mnt/sd/app", True),
    ("start-stop-daemon -S -x /mnt/sd/app -- -K", True),  # '--' 뒤는 데몬 인자
])
def test_ssd_stop_forms_do_not_execute_card_program(tmp_path, line, found):
    c = _checks(_surface(write_tree(tmp_path / "r", {"etc/init.d/rcS": "#!/bin/sh\n" + MOUNT_SD + line + "\n"}), _plain_flash()))["SD-01"]
    assert (c["status"] == "found") is found, (line, c["evidence"])


@pytest.mark.parametrize("env, mmc", [
    ({"bootdev": "mmc", "loadscript": "fatload ${bootdev} 0:1 0x82000000 boot.scr; source 0x82000000",
      "bootcmd": "run loadscript; sf probe 0; sf read 0x82000000 0x50000 0x300000; bootm 0x82000000"}, True),
    ({"interface": "mmc", "loaduenv": "load ${interface} ${dev}:1 ${loadaddr} uEnv.txt", "bootcmd": "run loaduenv; env import -t ${loadaddr}; sf probe 0"}, True),
    ({"bootdev": "mmc", "bootcmd": "if fatload $bootdev 0:1 ${loadaddr} boot.scr; then source ${loadaddr}; else sf probe 0; sf read 0x1 0x2 0x3; bootm; fi"}, True),
    ({"bootdev": "ubi", "loadscript": "fatload ${bootdev} 0 0x82000000 boot.scr; source 0x82000000"}, False),
    ({"bootdev": "mmc0 extra", "loadscript": "fatload ${bootdev} 0 0x82000000 boot.scr; source 0x82000000"}, False),
    ({"loadscript": "fatload ${bootdev} 0:1 0x82000000 boot.scr; source 0x82000000"}, False),  # 값이 env 에 없음
])
def test_uboot_device_variable_is_read_from_the_same_env(env, mmc):
    r = sd_boot_analysis(env, storage="flash-crc")
    assert r["mmc_boot"] is mmc and r["boot_script"] is mmc, r
    if mmc:
        assert any("boot-script" in sg["kinds"] for sg in r["signals"]) and all("${" in sg["value"] or "$bootdev" in sg["value"] for sg in r["signals"]
                                                                              if sg["var"] != "bootcmd" or "bootdev" in env), r


def test_assignment_prefix_cost_is_linear_in_window():
    """대입이 빽빽한 앞 문맥('x=!x=!…'): '!' 가 값 안에 들어가지 않아 시작마다 값을 다시 훑지 않는다 (문맥 길이에 선형)."""
    for unit in ("x=!", "x=!/mnt/sd/x!", "a=$(", "a=${b}!"):
        small = unit * (512 // len(unit))
        big = unit * (8192 // len(unit))
        for rx in (sdsurface._PRE_CMD, sdsurface._PRE_SH):
            _, t_small = _timed(lambda: [rx.search(small) for _ in range(50)])
            _, t_big = _timed(lambda: [rx.search(big) for _ in range(50)])
            assert t_big < max(0.25, 40 * t_small), (unit, rx.pattern[:30], t_small, t_big)


def test_strings_hunt_single_file_budget_acts_between_chunks(tmp_path, monkeypatch):
    """6차 #2: 파일 하나만 볼 때도 조각 사이에서 시간 예산을 본다 — 예산이 지나면 나머지 조각은 읽지 않고 truncated (조각 안은 끝까지)."""
    from fwtriage_mcp import hunt as hunt_mod

    monkeypatch.setattr(hunt_mod, "CHUNK", 4096)
    monkeypatch.setattr(hunt_mod, "OVERLAP", 256)
    f = tmp_path / "case" / "big.txt"
    f.parent.mkdir()
    f.write_text("telnetd -l /bin/sh &\n" * 4000)
    ps = load_patterns()
    full = hunt(f, False, tmp_path / "case", Ctl(max_seconds=60), ps.string_heuristics, max_hits=100, per_pattern_cap=10, max_file_size=1 << 20)
    assert full["summary"]["truncated"] is False and full["summary"]["bytes_scanned"] == f.stat().st_size
    ctl = Ctl(max_seconds=1e-6)
    time.sleep(0.01)
    cut = hunt(f, False, tmp_path / "case", ctl, ps.string_heuristics, max_hits=100, per_pattern_cap=10, max_file_size=1 << 20)
    assert cut["summary"]["truncated"] is True and 0 < cut["summary"]["bytes_scanned"] <= 4096 + 256, cut["summary"]
    # 앞 조각이 이미 파일 끝까지 읽었으면(꼬리가 겹침 구간 안) 예산이 지나도 다 본 것이다 — truncated 가 아니고 꼬리의 히트도 있다
    tail = tmp_path / "case" / "tail.txt"
    tail.write_bytes(b"x" * 4096 + b"\ntelnetd -l /bin/sh &\n")
    ctl = Ctl(max_seconds=1e-6)
    time.sleep(0.01)
    done = hunt(tail, False, tmp_path / "case", ctl, ps.string_heuristics, max_hits=100, per_pattern_cap=10, max_file_size=1 << 20)
    assert done["summary"]["truncated"] is False and done["summary"]["bytes_scanned"] == tail.stat().st_size, done["summary"]
    assert done["summary"]["hits_total"] >= 1, done["summary"]
