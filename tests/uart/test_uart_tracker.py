"""uart-mcp 문맥 추적기 단위 테스트 (녹화 로그를 청크로 잘라 먹인다)."""

from __future__ import annotations

from pathlib import Path

import pytest

from uart_mcp.profile import build_profile
from uart_mcp.tracker import ContextTracker

REC = Path(__file__).resolve().parents[1] / "mock-targets" / "recorded"

GENERIC = build_profile("generic-ipcam", {})


def feed(tr: ContextTracker, data: bytes, base: int = 0, chunk: int = 37) -> int:
    for i in range(0, len(data), chunk):
        tr.feed(data[i:i + chunk], base + i)
    return base + len(data)


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
def test_uboot_session_reaches_uboot_context(profile):
    tr = ContextTracker(GENERIC)
    data = (REC / f"{profile}-uboot-session.log").read_bytes()
    feed(tr, data)
    assert tr.phase == "uboot"
    assert tr.context == "uboot"
    assert tr.prompt is not None and tr.prompt.context == "uboot"
    assert tr.autoboot_message and tr.facts.get("bootdelay_seen") in (1, 2)
    assert tr.boot_seq == 1


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
def test_boot_log_goes_booting_then_login(profile):
    tr = ContextTracker(GENERIC)
    data = (REC / f"{profile}-boot.log").read_bytes()
    feed(tr, data, chunk=101)
    # 마지막은 askfirst 메시지 → login 문맥, phase linux, 부팅은 한 번만 센다(커널의 'Check Flash Memory Controller' 무시)
    assert tr.phase == "linux"
    assert tr.context == "login" and tr.prompt and tr.prompt.kind == "askfirst"
    assert tr.boot_seq == 1
    assert tr.facts.get("kernel_version")
    assert tr.facts.get("cmdline")


def test_shell_session_learns_shell_prompt():
    tr = ContextTracker(GENERIC)
    data = (REC / "hisilicon-like-shell-session.log").read_bytes()
    feed(tr, data, chunk=64)
    assert tr.context == "linux-shell"
    assert tr.learned.get("linux-shell") == "# "


def test_ambiguous_prompt_without_evidence_is_unknown():
    tr = ContextTracker(GENERIC)
    tr.feed(b"\r\nhisilicon # ", 0)
    assert tr.context == "unknown" and tr.prompt.ambiguous == ["uboot", "linux-shell"]
    # U-Boot 증거(<INTERRUPT>)가 오면 uboot
    tr.feed(b"<INTERRUPT>\r\nhisilicon # ", 14)
    assert tr.phase == "uboot" and tr.context == "uboot"


def test_uboot_like_prompt_in_linux_phase_is_unknown():
    tr = ContextTracker(GENERIC)
    end = feed(tr, b"Starting kernel ...\r\n\r\nLinux version 4.9.37 (x) #1\r\nroot@cam# ")
    # 'root@cam# ' 는 U-Boot 일반 정규식에만 맞음 → 리눅스 phase 에서는 unknown (더 엄격)
    assert tr.phase == "linux" and tr.context == "unknown"
    tr.feed(b"\r\n/ # ", end)
    assert tr.context == "linux-shell"


def test_uboot_text_in_linux_output_makes_context_stricter_not_looser():
    tr = ContextTracker(GENERIC)
    end = feed(tr, b"Please press Enter to activate this console. \r\n(none) login: root\r\nPassword: \r\n# ")
    assert tr.context == "linux-shell"
    # 리눅스에서 strings 가 U-Boot 배너를 출력 → phase uboot, 셸 프롬프트 '# ' 는 리눅스 정규식에만 맞음 → unknown
    feed(tr, b"strings /dev/mtd0 | head -1\r\nU-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)\r\n# ", end)
    assert tr.context == "unknown"


def test_version_output_does_not_count_as_reboot():
    tr = ContextTracker(GENERIC)
    data = (REC / "hisilicon-like-uboot-session.log").read_bytes()
    end = feed(tr, data)
    seq = tr.boot_seq
    feed(tr, b"version\r\n\r\nU-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300\r\nhisilicon # ", end)
    assert tr.boot_seq == seq and tr.context == "uboot"


def test_flash_write_warning_event():
    tr = ContextTracker(GENERIC)
    feed(tr, b"*** Warning - bad CRC, using default environment\r\n\r\n*** Write default environment to flash\r\nSaving Environment to SPI Flash...\r\n")
    assert tr.flash_warnings and tr.facts.get("env_bad_crc") is True
    assert any(e["type"] == "flash_write_warning" for e in tr.drain_events())


def test_hush_ps2_and_password_prompts():
    tr = ContextTracker(GENERIC)
    end = feed(tr, (REC / "hisilicon-like-uboot-session.log").read_bytes())
    tr.feed(b"if true\r\n> ", end)
    assert tr.prompt.kind == "hush_ps2" and tr.context == "uboot"
    tr2 = ContextTracker(GENERIC)
    tr2.feed(b"(none) login: root\r\nPassword: ", 0)
    assert tr2.context == "password" and tr2.prompt.kind == "password"


# ---------------------------------------------------------------------------
# 게이트 범위 검토 회귀: 우리 입력의 되풀이는 증거가 아니다
# ---------------------------------------------------------------------------


def _at_uboot() -> tuple[ContextTracker, int]:
    tr = ContextTracker(GENERIC)
    end = feed(tr, (REC / "hisilicon-like-uboot-session.log").read_bytes())
    assert tr.context == "uboot" and tr.learned["uboot"] == "hisilicon # "
    return tr, end


def _send(tr: ContextTracker, end: int, line: str, reply: bytes) -> int:
    """세션 commit 처럼: 쓰기 전에 note_tx, 그다음 기기 에코 + 출력."""
    tr.note_tx([line], "")
    return feed(tr, line.encode() + b"\r\n" + reply, end)


@pytest.mark.parametrize("line,reply", [
    ("echo Linux version 9.9", b"Linux version 9.9\r\n"),
    ('echo "Linux version" 9.9', b"Linux version 9.9\r\n"),
    ("echo Starting kernel ...", b"Starting kernel ...\r\n"),
    ("echo [    1.234567] init started", b"[    1.234567] init started\r\n"),
    ("echo Please press Enter to activate this console.", b"Please press Enter to activate this console.\r\n"),
])
def test_parroted_linux_evidence_does_not_flip_uboot(line, reply):
    tr, end = _at_uboot()
    seq = tr.boot_seq
    _send(tr, end, line, reply + b"hisilicon # ")
    assert tr.phase == "uboot" and tr.context == "uboot" and tr.boot_seq == seq, (tr.phase, tr.context)
    assert "kernel_version" not in tr.facts


def test_parroted_boot_markers_are_not_reboots():
    tr, end = _at_uboot()
    seq = tr.boot_seq
    _send(tr, end, "echo DRAM:  64 MiB; echo Hit any key to stop autoboot:  2",
          b"DRAM:  64 MiB\r\nHit any key to stop autoboot:  2\r\nhisilicon # ")
    assert tr.boot_seq == seq and tr.context == "uboot"


def test_unparroted_spoof_cannot_promote_learned_uboot_prompt():
    # 변수로 되풀이 검사를 피해도(setenv a Linux; echo $a version 9.9) 학습한 U-Boot 프롬프트는 linux-shell 이 되지 않는다
    tr, end = _at_uboot()
    end = _send(tr, end, "setenv a Linux; echo $a version 9.9", b"Linux version 9.9\r\nhisilicon # ")
    assert tr.phase == "linux" and tr.context == "unknown"
    # 진짜 리눅스 셸 프롬프트는 그대로 linux-shell
    feed(tr, b"\r\n/ # ", end)
    assert tr.context == "linux-shell"


def test_pending_echo_in_tail_is_not_a_prompt_or_login():
    for typed in ("echo login: ", "echo Password: ", "echo Please press Enter to activate this console.", "echo #", "echo Hit any key to stop autoboot"):
        tr2, end2 = _at_uboot()
        tr2.note_tx([], typed)
        tr2.feed(typed.encode(), end2)
        assert tr2.prompt is None and tr2.context == "uboot" and tr2.phase == "uboot", (typed, tr2.prompt, tr2.context)


def test_genuine_device_evidence_still_counts():
    tr, end = _at_uboot()
    end = _send(tr, end, "foo", b"Unknown command 'foo' - try 'help'\r\nhisilicon # ")
    assert tr.context == "uboot"
    # 셸에서 실제 커널 메시지/명령 없음 응답은 리눅스 증거 (보낸 줄과 다름)
    tr2 = ContextTracker(GENERIC)
    tr2.note_tx(["foo"], "")
    feed(tr2, b"\r\nhisilicon # foo\r\n-sh: foo: not found\r\n/ # ")
    assert tr2.phase == "linux" and tr2.context == "linux-shell"


def test_echo_of_line_just_sent_is_masked_until_its_newline():
    """줄 전체를 한 번에 보내도 기기는 에코를 한 글자씩 돌려준다 — 줄바꿈 전의 꼬리(askfirst/login 문구 포함)는 증거가 아니다."""
    tr, end = _at_uboot()
    line = "echo Please press Enter to activate this console."
    tr.note_tx([line], "")
    for i in range(1, len(line) + 1):  # 에코가 조금씩 도착
        tr.feed(line[i - 1:i].encode(), end)
        end += 1
        assert tr.phase == "uboot" and tr.context == "uboot" and tr.prompt is None, (line[:i], tr.context)
    end = feed(tr, b"\r\nPlease press Enter to activate this console.\r\nhisilicon # ", end)
    assert tr.phase == "uboot" and tr.context == "uboot" and tr.prompt.text == "hisilicon # "


def test_interrupted_pending_echo_is_not_evidence_but_interrupt_is():
    """Ctrl-C 로 버린 미완성 입력의 에코는 '<INTERRUPT>' 와 같은 줄에 남는다 — 에코는 빼고 <INTERRUPT> 는 U-Boot 증거로 쓴다."""
    tr, end = _at_uboot()
    typed = "echo Please press Enter to activate this console."
    tr.note_tx([], typed)
    end = feed(tr, typed.encode(), end)
    tr.note_tx([], "", discarded=typed)  # Ctrl-C
    feed(tr, b"<INTERRUPT>\r\nhisilicon # ", end)
    assert tr.phase == "uboot" and tr.context == "uboot", (tr.phase, tr.context)
    # 리눅스 셸의 ^C 표시도 같은 방식
    tr2 = ContextTracker(GENERIC)
    end2 = feed(tr2, b"Please press Enter to activate this console. \r\n(none) login: root\r\nPassword: \r\n/ # ")
    tr2.note_tx([], "echo <INTERRUPT> Unknown command 'x' - try 'help'")
    end2 = feed(tr2, b"echo <INTERRUPT> Unknown command 'x' - try 'help'", end2)
    tr2.note_tx([], "", discarded="echo <INTERRUPT> Unknown command 'x' - try 'help'")
    feed(tr2, b"^C\r\n/ # ", end2)
    assert tr2.phase == "linux" and tr2.context == "linux-shell"


def test_overwriting_learned_uboot_prompt_does_not_remove_protection():
    """uart_set_context(context='uboot', prompt=…) 로 learned 를 바꿔도, U-Boot 로 확인한 프롬프트는 계속 셸로 올리지 않는다."""
    tr, end = _at_uboot()
    tr.learned["uboot"] = "zzz> "  # 에이전트가 다른 문자열을 학습시킴
    tr.uboot_prompts_seen.add("zzz> ")
    _send(tr, end, "setenv a Linux; echo $a version 9.9", b"Linux version 9.9\r\nhisilicon # ")
    assert tr.phase == "linux" and tr.context == "unknown"
