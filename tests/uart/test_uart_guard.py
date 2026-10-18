"""uart-mcp 송신 계획/분류(guard) 단위 테스트 — 게이트 입력이 코어보다 느슨해지지 않는지."""

from __future__ import annotations

import pytest

from pweh.safety import LineAssembler, Risk
from uart_mcp.guard import GuardState, classify_line, plan_login_input, plan_payload, static_check, uboot_line_effects

D, M, I, O = Risk.DESTRUCTIVE, Risk.MODIFY, Risk.INTERACT, Risk.OBSERVE
PP = ("/mnt/mtd", "/data")


def st(ctx: str = "uboot", **kw) -> GuardState:
    base = dict(context=ctx, env=None, last_command=None, persistent_paths=PP, unknown_risk="modify", uboot_max_line=250,
                linux_max_line=1000)
    base.update(kw)
    return GuardState(**base)


def plan(data: str | bytes, ctx: str = "uboot", asm: LineAssembler | None = None, **kw):
    payload = data.encode("latin-1") if isinstance(data, str) else data
    return plan_payload(payload, asm or LineAssembler(), st(ctx, **kw))


def test_basic_uboot_lines():
    assert plan("printenv\r").classification.risk == I
    assert plan("md.b 0x42000000 0x40\r").classification.risk == I
    assert plan("saveenv\r").classification.risk == D
    assert plan("sf erase 0 10000\r").classification.risk == D
    assert plan("mw.b 0x42000000 0xff 0x10\r").classification.risk == D
    assert plan("run nosuchvar\r").classification.risk == D
    p = plan("printenv")  # 줄 끝 없음 → 아직 실행되지 않음
    assert p.classification.risk == O and p.pending_after == "printenv"


def test_split_write_assembles_device_line():
    p1 = plan("sa")
    assert p1.classification.risk == O and p1.pending_after == "sa"
    p2 = plan_payload(b"veenv\r", p1.assembler_after, st())
    assert p2.line_texts() == ["saveenv"] and p2.classification.risk == D
    # 편집: Backspace 반영
    p3 = plan("sf erasx\x08e 0 100\r")
    assert p3.line_texts() == ["sf erase 0 100"] and p3.classification.risk == D
    # Ctrl-C 는 줄을 버린다
    p4 = plan_payload(b"\x03printenv\r", p1.assembler_after, st())
    assert p4.line_texts() == ["printenv"] and p4.classification.risk == I


def test_uncertain_and_control_chars():
    assert plan("sav\t\r").classification.risk == D  # 탭 자동완성
    p = plan("\x1b[A\r")  # 히스토리 호출 후 Enter
    assert p.classification.risk == D and p.lines[0].uncertain
    assert plan("\x03").classification.risk == I
    assert plan("\x04").classification.risk == M  # Ctrl-D (셸 종료 가능)


def test_crlf_in_uboot_is_extra_repeat_line():
    p = plan("printenv\r\n")
    assert [ln.text for ln in p.lines] == ["printenv", ""] and p.lines[1].synthetic
    assert "repeat" in p.lines[1].classification.rule_id
    # 리눅스에서는 CRLF 를 한 줄 끝으로 본다
    p2 = plan("ls\r\n", "linux-shell")
    assert p2.line_texts() == ["ls"]


def test_empty_line_repeats_last_command():
    assert plan("\r", last_command="mw.b 0x42000000 0 1").classification.risk == D
    assert plan("\r", last_command="md.b 0 10").classification.risk == I
    assert plan("\r").classification.risk == I
    # 한 페이로드 안에서도 앞 줄을 반영 (printenv 다음 빈 줄 = printenv 반복)
    p = plan("printenv\r\r", last_command="sf erase 0 100")
    assert p.classification.risk == I and p.last_command_after == "printenv"
    # 리눅스에서 빈 줄은 안전 (직전 U-Boot 명령과 무관)
    assert plan("\r", "linux-shell", last_command="saveenv").classification.risk == O


def test_long_line_refused_in_uboot():
    assert plan("echo " + "A" * 300 + "\r").classification.risk == D
    assert plan("echo " + "A" * 200 + "\r").classification.risk == I


def test_cross_check_linux_context_catches_uboot_verbs():
    for line in ("saveenv", "sf erase 0 10000", "nan e 0 100", "env save", "mw 0x10000000 0", "cp 0x42000000 0x14000000 0x100"):
        c = classify_line(line, "linux-shell", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
        assert c.risk == D, (line, c)
    ok = classify_line("cat /proc/mtd", "linux-shell", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert ok.risk == I
    # 리눅스에서 흔한 cp 는 그대로 (MODIFY)
    cp = classify_line("cp /tmp/a /tmp/b", "linux-shell", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert cp.risk == M


def test_cross_check_uboot_context_catches_linux_writes():
    for line in ("echo x > /dev/mtdblock2", "flash_erase /dev/mtd0 0 0", "dd if=/dev/zero of=/dev/mtd1"):
        c = classify_line(line, "uboot", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
        assert c.risk == D, (line, c)
    assert classify_line("printenv", "uboot", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify").risk == I


def test_login_context_is_not_a_bypass_for_generic_sends():
    # 일반 송신에서 login/password 문맥은 unknown(두 분류기의 worst)
    assert plan("saveenv\r", "login").classification.risk == D
    assert plan("flash_erase /dev/mtd0 0 0\r", "password").classification.risk == D
    assert plan("root\r", "login").classification.risk == M


def test_login_input_plan_masks_password():
    p = plan_login_input(b"s3cret!\r", LineAssembler(), st("password"), masked=True)
    assert p.classification.risk == I and p.classification.matched == "<masked>"
    assert "s3cret" not in str(p.to_dict())
    with pytest.raises(ValueError):
        plan_login_input(b"a\rb\r", LineAssembler(), st("login"), masked=False)
    asm = LineAssembler()
    asm.feed("pend")
    with pytest.raises(ValueError):
        plan_login_input(b"root\r", asm, st("login"), masked=False)


def test_env_tracking_effects():
    env = {"bootcmd": "sf probe 0; bootm 0x42000000", "safe": "printenv"}
    e1, wiped = uboot_line_effects("setenv foo 'saveenv'", env, None, "modify")
    assert not wiped and e1["foo"] == "saveenv"
    assert plan("run foo\r", env=e1).classification.risk == D
    assert plan("run safe\r", env=e1).classification.risk == M  # run 은 최소 MODIFY
    # run/boot/env default 같은 추적 불가 명령은 env 를 버린다 → run 은 다시 DESTRUCTIVE(알 수 없음)
    e2, wiped2 = uboot_line_effects("run safe", e1, None, "modify")
    assert wiped2 and e2 is None
    e3, wiped3 = uboot_line_effects("env default -a", env, None, "modify")
    assert wiped3 and e3 is None
    e4, wiped4 = uboot_line_effects("md.b 0 10; printenv", env, None, "modify")
    assert not wiped4 and e4 == env
    # 앞 송신의 setenv 효과가 다음 송신(프롬프트가 다시 보인 뒤) 분류에 반영된다
    p1 = plan("setenv x 1\r", env=dict(env))
    p2 = plan_payload(b"run x\r", p1.assembler_after, st(env=p1.env_after, last_command=p1.last_command_after))
    assert p2.classification.risk == M
    # 한 페이로드에서 앞 줄이 실행되는 동안 보낸 뒤 줄은 앞부분이 소비될 수 있어 DESTRUCTIVE (로컬 규칙 9)
    p = plan("setenv x 1\rrun x\r", env=dict(env))
    assert p.lines[0].classification.risk == M
    assert p.lines[1].classification.risk == D and p.lines[1].classification.rule_id == "uart.device-busy"


def test_multiline_env_value_cannot_hide_destructive_command():
    # hush/run_command_list 는 값 안의 줄바꿈을 명령 구분자로 쓴다 → 분류도 그렇게
    env = {"x": "printenv\nsaveenv", "y": "printenv\r\nmd.b 0 10"}
    assert plan("run x\r", env=env).classification.risk == D
    assert plan("run y\r", env=env).classification.risk == M
    assert static_check(["run x"], "uboot", env=env, last_command=None, persistent_paths=PP, unknown_risk="modify")


def test_static_check_for_jobs():
    ok = static_check(["sf probe 0", "sf read 0x42000000 0x0 0x10000", "md.b 0x42000000 0x10000", "crc32 0x42000000 0x10000"],
                      "uboot", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert ok == []
    bad = static_check(["md.b 0x42000000 0x10", "sf erase 0 10000"], "uboot", env=None, last_command=None, persistent_paths=PP,
                       unknown_risk="modify")
    assert [b[0] for b in bad] == ["sf erase 0 10000"]
    # 문맥이 확정되지 않으면(unknown) md.b 도 MODIFY 로 보여 작업을 시작하지 않는다
    assert static_check(["md.b 0x42000000 0x10"], "unknown", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
    shell = static_check(["dd if=/dev/mtd3 bs=65536 skip=0 count=1 2>/dev/null | base64",
                          "dd if=/dev/mtd3 bs=65536 skip=0 count=1 2>/dev/null | md5sum"], "linux-shell", env=None,
                         last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert shell == []


def test_sysrq_window_after_break():
    p = plan("b", "linux-shell", sysrq_until=100.0, now=50.0)
    assert p.classification.risk == M and p.classification.rule_id == "uart.sysrq-window"
    assert plan("b", "linux-shell", sysrq_until=10.0, now=50.0).classification.risk == O


# ---------------------------------------------------------------------------
# 게이트 범위 검토(gate-coverage) 회귀: 조립기 가정·문맥 오판·간접 실행·비트 폭·승인 지문
# ---------------------------------------------------------------------------


def test_crlf_split_across_payloads_is_repeat_line():
    """'cmd\\r' 다음 호출의 '\\n' 은 U-Boot 에서 빈 줄(직전 명령 반복)이다 — 코어 조립기는 CRLF 를 합치므로 prev_char 로 판단."""
    p1 = plan("mw.b 0x42000000 0xa5 0x10\r")
    assert p1.last_char == "\r"
    p2 = plan_payload(b"\n", p1.assembler_after, st(last_command=p1.last_command_after, prev_char=p1.last_char))
    assert p2.line_texts() == [""] and p2.lines[0].synthetic
    assert p2.classification.risk == D and "repeat" in p2.classification.rule_id
    # 리눅스에서는 CRLF 가 한 줄 끝 (빈 줄은 안전)
    p3 = plan_payload(b"\n", plan("ls\r", "linux-shell").assembler_after, st("linux-shell", prev_char="\r"))
    assert p3.classification.risk == O


def test_device_busy_line_and_pending_are_uncertain():
    # 부팅/명령 실행 중에 보낸 줄은 앞부분이 소비될 수 있다 ('xsaveenv' 의 x 만 먹히면 saveenv)
    busy = dict(device_ready=False, busy_reason="기기가 부팅 중일 때 보낸 입력")
    p = plan("xsaveenv\r", **busy)
    assert p.classification.risk == D and p.classification.rule_id == "uart.device-busy"
    assert plan("xsaveenv\r").classification.risk == M  # 준비된 기기에서는 알 수 없는 명령(MODIFY)
    # 빈 줄(autoboot Enter 키)은 소비될 글자가 없다 → 그대로
    assert plan("\r", last_command="printenv", **busy).classification.risk == I
    # 남는 미완성 입력은 uncertain → 프롬프트가 돌아온 뒤 완성해도 DESTRUCTIVE, Ctrl-C 로 비우면 풀림
    p1 = plan("echo ", **busy)
    assert p1.classification.risk == O and p1.assembler_after.pending_uncertain
    p2 = plan_payload(b"saveenv\r", p1.assembler_after, st())
    assert p2.line_texts() == ["echo saveenv"] and p2.classification.risk == D and p2.classification.rule_id == "uart.uncertain-input"
    p3 = plan_payload(b"\x03printenv\r", p1.assembler_after, st())
    assert p3.classification.risk == I
    # 한 페이로드에서 앞 줄이 완성된 뒤의 입력도 '실행 중에 보낸 입력'
    p4 = plan("md.b 0x42000000 0x10\rxsaveenv\r")
    assert [ln.classification.risk for ln in p4.lines] == [I, D] and p4.lines[1].classification.rule_id == "uart.device-busy"
    p5 = plan("printenv\recho ")
    assert p5.classification.risk == I and p5.assembler_after.pending_uncertain


def test_bare_enter_with_unknown_device_history():
    unknown = dict(last_command_known=False)
    for ctx in ("uboot", "unknown", "login", "booting"):
        c = plan("\r", ctx, **unknown).classification
        assert c.risk == D and c.rule_id.endswith("uart.repeat-unknown"), (ctx, c)
    assert plan("printenv\r\r", **unknown).classification.risk == I  # 같은 페이로드에서 보낸 줄의 반복은 안다
    assert plan("\r", "linux-shell", **unknown).classification.risk == O
    assert plan("\r", **unknown, last_command="md.b 0 10").classification.risk == I
    # 모르는 명령의 반복은 env 를 바꿀 수 있다 → 추적 env 폐기
    p = plan("\r", env={"x": "printenv"}, **unknown)
    assert p.env_after is None and p.env_invalidated


@pytest.mark.parametrize("line", [
    "env run x", "env r x", "en r x", "time sf erase 0 10000", "t sf erase 0 10000", "tim saveenv", "time time saveenv",
    "run y", "run t", "$t", "true && env run x", "if true; then env run x; fi",
])
def test_command_runners_are_classified_by_inner_command(line):
    env = {"x": "sf erase 0 10000", "y": "env run x", "t": "time saveenv"}
    c = classify_line(line, "uboot", env=env, last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert c.risk == D, (line, c)
    # 문맥 미확정에서도 같은 규칙
    assert classify_line(line, "unknown", env=env, last_command=None, persistent_paths=PP, unknown_risk="modify").risk == D


def test_command_runners_keep_reads_usable_and_repeat_uses_local_rules():
    env = {"z": "printenv", "x": "saveenv", "bootcmd": "sf probe 0; sf read 0x42000000 0x50000 0x10000; bootm 0x42000000"}
    kw = dict(env=env, last_command=None, persistent_paths=PP, unknown_risk="modify")
    assert classify_line("env run z", "uboot", **kw).risk == M  # run 처럼 최소 MODIFY
    assert classify_line("time md.b 0x42000000 0x10", "uboot", **kw).risk == I  # time 은 안쪽 명령(md = 조회) 기준
    assert classify_line("test -n x", "uboot", **kw).risk == I
    assert classify_line("boot", "uboot", **kw).risk == M and classify_line("bootm 0x42000000", "uboot", **kw).risk == M
    # 빈 Enter 가 반복할 직전 명령에도 로컬 규칙 적용
    c = classify_line("", "uboot", env=env, last_command="env run x", persistent_paths=PP, unknown_risk="modify")
    # 코어와 로컬 규칙이 둘 다 DESTRUCTIVE 로 본다 (동률이면 코어 규칙 id)
    assert c.risk == D and c.rule_id.startswith(("uboot.repeat>uart.uboot.env-run", "uboot.repeat>uboot.env.run"))
    # 작업 사전 검사(static_check)도 같은 분류기
    assert static_check(["time saveenv"], "uboot", env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")


def test_linux_context_cross_check_covers_uboot_cp_with_variables():
    kw = dict(env=None, last_command=None, persistent_paths=PP, unknown_risk="modify")
    for line in ("cp ${loadaddr} 0x0 0x100", "cp.b $addr 0 100", "cp 82000000 0 ${filesize}"):
        assert classify_line(line, "linux-shell", **kw).risk == D, line
    assert classify_line("reset", "linux-shell", **kw).risk == M  # U-Boot 에서는 재부팅
    assert classify_line("cp /tmp/a /tmp/b", "linux-shell", **kw).risk == M


def test_bytesize_masking_and_high_bit_bytes():
    hidden = bytes(c | 0x80 for c in b"saveenv\r")  # 7비트 기기는 'saveenv\r' 을 받는다
    p7 = plan(hidden, bytesize=7)
    assert p7.line_texts() == ["saveenv"] and p7.classification.risk == D
    p8 = plan(hidden)  # 8비트 세션: 원래 바이트로는 줄이 끝나지 않지만 하위 7비트로도 분류
    assert p8.classification.risk == D and p8.classification.rule_id.startswith("uart.high-bit")
    assert plan("echo café\r".encode("utf-8")).classification.risk == D  # 상위 비트 문자가 섞인 줄
    p = plan(b"sav\xe5")  # 줄 끝 없이 보낸 상위 비트 문자 → 이후 줄은 Ctrl-C 전까지 uncertain
    assert p.classification.risk == O and p.assembler_after.pending_uncertain
    assert plan(b"printenv\r", bytesize=7).classification.risk == I  # ASCII 는 그대로


def test_approval_refs_bind_env_values_and_repeat_target():
    from uart_mcp.guard import approval_refs

    env = {"x": "mw.b 0x42000000 0xa5 0x10", "y": "run x", "len": "0x1000", "bootcmd": "run y"}
    refs = approval_refs(["run y"], "uboot", env=env, last_command=None, last_command_known=True)
    assert refs["env_refs"] == {"x": env["x"], "y": "run x"}  # run 값 안의 참조도 따라간다
    assert approval_refs(["sf erase 0 $len"], "uboot", env=env, last_command=None, last_command_known=True)["env_refs"] == {"len": "0x1000"}
    assert set(approval_refs(["boot"], "uboot", env=env, last_command=None, last_command_known=True)["env_refs"]) == {"bootcmd", "x", "y"}
    assert approval_refs([""], "uboot", env=None, last_command="mw.b 0 1 1", last_command_known=True) == {"repeat_of": "mw.b 0 1 1"}
    assert approval_refs([""], "uboot", env=None, last_command=None, last_command_known=False) == {"repeat_of": "<unknown>"}
    assert approval_refs(["run y"], "linux-shell", env=env, last_command=None, last_command_known=True) == {}
    assert approval_refs(["mw.b 0x42000000 0xa5 0x10"], "uboot", env=None, last_command=None, last_command_known=True) == {}


def test_relative_write_after_cd_across_payloads_uses_tracked_cwd():
    """cd 를 보낸 다음 페이로드의 상대 경로 쓰기는 추적한 cwd 기준으로 분류한다 (Plan.cwd_after → GuardState.cwd)."""
    first = plan_payload(b"cd /usr/bin\r", LineAssembler(), st("linux-shell"))
    assert first.cwd_tracked and first.cwd_after == "/usr/bin"
    second = plan_payload(b"cp /tmp/x md5sum\r", first.assembler_after, st("linux-shell", cwd=first.cwd_after))
    assert second.classification.risk == D and second.classification.rule_id == "linux.write.system", second.classification
    same_payload = plan_payload(b"cd /sbin\rtouch z\r", LineAssembler(), st("linux-shell"))
    assert any(ln.classification.rule_id == "linux.write.system" for ln in same_payload.lines), same_payload.lines
    away = plan_payload(b"cp /tmp/x y\r", LineAssembler(), st("linux-shell", cwd="/tmp"))
    assert away.classification.risk == M
