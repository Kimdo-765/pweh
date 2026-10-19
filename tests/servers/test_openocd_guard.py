"""openocd-mcp 안전 분류기(guard) 회귀 테스트 — 검토 단계에서 찾은 게이트 우회 형태.

각 우회 형태는 xPack OpenOCD 0.12.0-7 의 Jim Tcl 에서 본문이 실제로 실행됨을 확인했다(echo 를 표식으로 사용).
수정 전에는 아래 DESTRUCTIVE 형태들이 INTERACT/MODIFY 로 분류되어 기본 정책(modify 허용)에서 그대로 실행되었다.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp import Client

from openocd_mcp import guard
from pweh.safety import Risk

from .fake_openocd import FakeOpenOCD
from mcp_helpers import call

# ---------------------------------------------------------------------------
# 분류기 단위
# ---------------------------------------------------------------------------

BYPASS_FORMS = [
    # 코어의 줄 단위 주석 제거(splitlines)가 Jim 과 달라 문장이 사라지던 형태
    'set x "\n# "; mww 0 0',
    "catch {\v# } ; mww 0 0",
    "set q 1\x1c# ; mww 0 0",
    "echo a\r# ; mww 0 0",
    # 중괄호 식 안의 명령 치환 (위 형태와 결합하면 코어가 놓침)
    "if {[catch {catch {\v#}; mww 0 0}]} {}",
    "while {[mww 0 0] ne {}} {break}",
    "if 1 then {echo a} elseif {[mww 0 0]} {echo b}",
    # 이중 치환: 중괄호 없는 식의 치환 결과를 expr 가 다시 해석
    'expr "\\x5bmww 0 0\\x5d"',
    "expr $x",
    "if $y {}",
    "while $cond {break}",
    "for {} $t {} {}",
    # 옵션 뒤 본문 / 하위 명령 본문 / 마지막 인자 본문
    'catch -error "mww 0 0"',
    'catch -error -- "mww 0 0"',
    "catch $opt {mww 0 0}",
    'dict for {k v} {a b} "mww 0 0"',
    'dict with dd "mww 0 0"',
    'dict update de a av "mww 0 0"',
    'loop i 0 1 "mww 0 0"',
    # OpenOCD 이벤트 핸들러 (나중에 reset init 등 MODIFY 동작이 실행)
    'cam.cpu configure -event reset-init "mww 0x20110000 1"',
    "cam.cpu configure -event reset-init {::mww 0 0}",
    "cam.cpu configure -event reset-init {m\\ww 0 0}",
    "cam.cpu configure -event reset-init $body",
    "cam.cpu configure -event reset-init [set b]",
    'jtag configure cam.cpu -event setup "mww 0 0"',
    'target create cam.cpu arm926ejs -chain-position cam.cpu -event reset-init "mww 0 0"',
    # 명령 접두를 받는 -command (lsort 는 비교마다 'mww a b' 를 호출)
    "lsort -command mww {0 0}",
    "lsearch -command mww {0x0} 0x0",
    "regsub -command mww abc b",
    "lsort -command $cmd {0 0}",
    # Jim 0.84 의 lsort 는 -command 줄임말을 받는다 (실측: 'lsort -c cmpx {p q}' 가 'cmpx p q' 실행 — 수정 전 INTERACT)
    "lsort -c mww {0x20000000 0x20000004}",
    "lsort -comm mww {0x20000000 0x20000004}",
    # -command 접두에 데이터가 덧붙어 실행된다: 접두만 보면 알 수 없는 명령(MODIFY)이지만 'esp32 flashbootstrap 1.8' 이 실행됨
    # (실측: lsort -command {dummy.cpu arm} {semihosting enable} 가 semihosting 을 켰다)
    "lsort -command esp32 {flashbootstrap 1.8}",
    "lsort -index 0 -command esp32 {{flashbootstrap a} {1.8 b}}",
    "lsearch -command esp32 {1.8} flashbootstrap",
    "switch -command esp32 1.8 {flashbootstrap {}}",
    "switch -c {dummy.cpu arm} enable {semihosting {}}",
    "lsort -command esp32 $x",  # 덧붙는 값이 동적
    "lsort -command esp32 {a b c d e f g h i j k l m}",  # 후보가 너무 많아 확정 불가
    # switch 의 한 단어 목록 안 본문 (실측: 아래 본문이 모두 실행됨 — 수정 전에는 목록 전체를 한 스크립트로 읽어 'echo {…}' 로 보았다)
    "switch echo {echo {arm semihosting enable}}",
    "switch x {echo z x mww\\ 0x20000000\\ 0}",
    'switch x "x $y"',  # 목록이 동적
    # 알 수 없는 명령의 본문 인자 / 이벤트 루프 / 훅
    'stdout readable "mww 0 0"',
    "update",
    "vwait done",
    'xtrace {if 1 "mww 0 0"}',
    "curry mww 0",
    # 이 서버가 끈 telnet/GDB 명령 서버를 다시 열면 그 포트의 명령은 게이트를 거치지 않는다 (xPack 에서 telnet 명령 실행 확인)
    "telnet port 4444",
    "telnet_port 4444",
    "gdb port 3333",
    "gdb_port 3333",
    "gdb port $p",
    "cam.cpu configure -gdb-port 3333",
    # semihosting: OpenOCD 는 값을 대소문자 없이 enable/on/true/yes/1 로 해석한다 (xPack 에서 모두 켜지는 것을 확인)
    "arm semihosting ENABLE",
    "arm semihosting on",
    "arm semihosting 1",
    "set x enable; arm semihosting $x",
    "arm semihosting [string tolower EnAbLe]",
    "esp32s3.cpu0 arm semihosting_fileio On",
    "cam.cpu configure -event examine-end {arm semihosting ON}",
    # 알려진 하위 명령 그룹의 하위 명령 자리가 동적 (코어는 '[…]' 를 떼어 'flash'(인자 없음, INTERACT)로 보았다)
    "flash [string cat erase_sector] 0 0 last",
    "nand [list erase] 0 0 1",
    "arm [string cat semi hosting] on",
    "cam.cpu arm $x on",
    # Espressif 포크의 플래시 프로그래밍 proc 을 숨긴 형태
    'capture "program_esp fw.bin 0x0 verify"',
    "::program_esp fw.bin 0x0",
    "p\\rogram_esp fw.bin 0x0",
    "cpu0 program_esp fw.bin 0x0",
    'catch -error "program_esp_bins build flasher_args.json"',
    'cam.cpu configure -event gdb-attach "program_esp_bins build flasher_args.json reset"',
    'capture "program fw.elf verify reset"',
    # esp/xtensa 를 (일부만 정의한) 하위 명령 표에 넣어도 점 없는 타깃 이름(target create esp …)으로서의 규칙은 그대로
    "esp mww 0 0",
    "xtensa load_image fw.bin 0x0",
    'esp foo "mww 0 0"',
    'esp32s3.cpu0 esp foo "mww 0 0"',
]


@pytest.mark.parametrize("cmd", BYPASS_FORMS)
def test_bypass_forms_are_destructive(cmd):
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE, (cmd, c)


@pytest.mark.parametrize(
    "cmd,risk",
    [
        # 흔한 안전한 형태는 기존 위험도를 유지해야 한다 (과잉 차단 방지)
        ("mdw 0x0 4", Risk.INTERACT),
        ('capture "mdw 0 4"', Risk.INTERACT),
        ('echo "hello world"', Risk.INTERACT),
        ("expr {1 + 2}", Risk.INTERACT),
        ("expr 1 + 2", Risk.INTERACT),
        ("if {[catch {halt}]} {echo x}", Risk.MODIFY),
        ("catch -noerror {halt}", Risk.MODIFY),
        ("cam.cpu configure -event reset-init {echo hi}", Risk.MODIFY),
        ("lsort -command {string compare} {b a}", Risk.MODIFY),
        ("targets cam.cpu; halt", Risk.MODIFY),
        ("jtag newtap cam cpu -irlen 4 -expected-id 0x07926f0f", Risk.MODIFY),
        ("telnet port disabled", Risk.MODIFY),  # 서버 자신이 쓰는 형태 (끄기)
        ("gdb port disabled", Risk.MODIFY),
        ("cam.cpu configure -gdb-port disabled", Risk.MODIFY),
        # semihosting 조회·끄기는 그대로 (openocd_start 의 무력화 확인과 같은 명령)
        ("arm semihosting", Risk.MODIFY),
        ("arm semihosting disable", Risk.MODIFY),
        ("arm semihosting OFF", Risk.MODIFY),
        ("esp32s3.cpu0 arm semihosting disable", Risk.MODIFY),
        ("help arm semihosting", Risk.INTERACT),
        # 하위 명령이 고정이면 인자의 변수는 하위 명령 규칙과 무관
        ("flash info $b", Risk.INTERACT),
        ("jtag cget $tap -event setup", Risk.INTERACT),
        ("esp apptrace status", Risk.INTERACT),
        ("esp32 read_memory 0x3ff00000 32 1", Risk.MODIFY),  # 단일 코어 ESP 의 타깃 이름(esp32)은 예전처럼
    ],
)
def test_benign_forms_keep_their_risk(cmd, risk):
    assert guard.classify_command(cmd).risk == risk, cmd


def test_storing_a_dangerous_string_is_not_executing_it():
    # 변수에 담는 것만으로는 실행되지 않는다 — 이후 스크립트/식 위치에서 쓰면 그때 DESTRUCTIVE
    assert guard.classify_command('set x "\\x5bmww 0 0\\x5d"').risk < Risk.DESTRUCTIVE
    for use in ("eval $x", "catch $x", "if 1 $x", "expr $x", "uplevel #0 $x", "$x"):
        assert guard.classify_command(use).risk == Risk.DESTRUCTIVE, use


# 검토(critical): 코어의 'flashbootstrap' 규칙이 두/세 번째 단어만 보고 continue 해서 아래가 INTERACT 로 떨어졌다.
# (실측: 기본 정책 MCP 서버에서 'program flashbootstrap' 이 OpenOCD 로 전달됨 — 실행 cwd 의 파일 flashbootstrap 을 굽는다)
@pytest.mark.parametrize("cmd", [
    "program flashbootstrap", "flash write_image flashbootstrap", "load_image flashbootstrap", 'program "flashbootstrap"',
    "catch {program flashbootstrap}", 'catch "program flashbootstrap"', 'capture "load_image flashbootstrap"',
    "if 1 {flash write_image erase flashbootstrap}", "program esp32 flashbootstrap", "esp32 flashbootstrap 3.3",
    "esp32.cpu0 esp32 flashbootstrap 1.8", "catch {esp32s3 flashbootstrap none}",
])
def test_flashbootstrap_never_downgrades(cmd):
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE, (cmd, c)


@pytest.mark.parametrize("cmd,rule", [
    # semihosting 을 켜는 핸들러를 다시 설치하는 표준 ESP proc (검토 E1/E2 — 수정 전: 알 수 없는 명령 = MODIFY 허용)
    ("configure_openocd_events", "openocd.esp.semihosting-proc"),
    ("configure_event_examine_end", "openocd.esp.semihosting-proc"),
    ("create_esp_target xtensa", "openocd.esp.semihosting-proc"),
    ("::configure_openocd_events", "openocd.esp.semihosting-proc"),
    ("catch {configure_openocd_events}", "openocd.esp.semihosting-proc"),
    ("esp32s3.cpu0 configure -event reset-init configure_event_examine_end", "openocd.esp.semihosting-proc"),
    ('esp32s3.cpu0 configure -event reset-init "configure_event_examine_end"', "openocd.esp.semihosting-proc"),
    ("pweh_semihosting_guard check", "openocd.semihosting-proc"),
    # 호스트 파일 쓰기
    ("profile 1 /home/user/.bashrc", "openocd.profile"),
    ("tpiu0 configure -output /home/user/.profile", "openocd.trace.output"),
])
def test_semihosting_procs_and_host_writers_are_destructive(cmd, rule):
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE and rule in c.rule_id, (cmd, c)


def test_session_semihost_procs_are_destructive():
    procs = {"cam_dbg_on", "dummy.cpu arm semihosting"}
    for cmd in ("cam_dbg_on", "catch {cam_dbg_on}", "if 1 cam_dbg_on", "cam.cpu configure -event examine-end cam_dbg_on",
                "dummy.cpu arm semihosting", "::cam_dbg_on"):
        c = guard.classify_command(cmd, semihost_procs=procs)
        assert c.risk == Risk.DESTRUCTIVE and c.rule_id == "openocd.local.semihosting-proc", (cmd, c)
    # 목록이 없으면 그대로 (알 수 없는 명령 = MODIFY)
    assert guard.classify_command("cam_dbg_on").risk == Risk.MODIFY
    assert guard.classify_command("cam_dbg_off", semihost_procs=procs).risk == Risk.MODIFY


@pytest.mark.parametrize("text,found", [
    ("init", ["init"]), ("catch init", ["init"]), ("catch {init}", ["init"]), ('catch "init"', ["init"]), ("::init", ["::init"]),
    ("ocd_init", ["ocd_init"]), ("target init", ["target init"]), ("transport init", ["transport init"]), ("jtag init", ["jtag init"]),
    ("dap init", ["dap init"]), ("flash init", ["flash init"]), ("jtag arp_init", ["jtag arp_init"]),
    ("jtag arp_init-reset", ["jtag arp_init-reset"]), ("jtag_init", ["jtag_init"]), ("init_reset startup", ["init_reset startup"]),
    ("if {1} {init}", ["init"]), ("eval init", ["init"]), ("capture {target init}", ["target init"]), ("echo [init]", ["init"]),
    ("after 10 init", ["init"]), ("adapter driver dummy\ninit\nreset halt", ["init"]),
    # init 끝에서(가드의 post-init 전에) 실행될 명령 예약
    ("lappend post_init_commands {echo hi}", ["lappend post_init_commands {echo hi}"]),
    ("set ::post_init_commands {}", ["set ::post_init_commands {}"]), ("lappend pre_shutdown_commands {echo hi}", []),
    # switch 의 한 단어 목록 안 본문·apply 람다 (수정 전: 목록 전체를 'a init' 한 문장으로 읽어 놓쳤다 — 실측: 모두 init 실행)
    ("switch a {a init}", ["init"]), ("switch -glob x {* init}", ["init"]), ("switch -regexp a {a init}", ["init"]),
    ("switch -exact -- a {a init}", ["init"]), ("switch -e a {a init}", ["init"]), ("switch a {a - b init}", ["init"]),
    ("switch a {\n a init\n b x\n}", ["init"]), ("switch a a init b {}", ["init"]), ("switch x {default {target init}}", ["target init"]),
    ("switch x {x jtag_init}", ["jtag_init"]), ("apply {{} init}", ["init"]), ("apply {x init} 1", ["init"]),
    # 정의만 하고 나중에 실행되는 본문과 subst 의 명령 치환 (분류는 이미 DESTRUCTIVE — 승인돼도 init 조기 실행이 되지 않게 거부)
    ("proc p {} init", ["init"]), ("defer init", ["init"]), ("subst {[init]}", ["init"]),
    # init 이 아닌 것
    ("reset init", []), ("echo init", []), ("set x init", []), ("arm semihosting", []), ("cam.cpu configure -event reset-init {echo hi}", []),
    ("switch x {x {echo init}}", []), ("switch x {init {echo hi}}", []),
])
def test_init_family_commands(text, found):
    assert guard.init_family_commands(text) == found, text


@pytest.mark.parametrize("text", ["lsort -c init {a b}", "lsort -command init {a b}", "lsearch -command init {a} b", "switch -c init a {b {}}"])
def test_init_family_in_command_prefix(text):
    assert guard.init_family_commands(text)[0] == "init", text


# OpenOCD 는 post_init_commands(init 끝)·pre_shutdown_commands(shutdown 직전)의 원소를 eval 한다(실측, 아래 external 테스트).
# 수정 전: 'lappend pre_shutdown_commands "mww 0 0"' 이 INTERACT 로 허용되어 openocd_stop 때 승인 없이 실행되었다.
@pytest.mark.parametrize("cmd", [
    'lappend pre_shutdown_commands "mww 0 0"', "lappend pre_shutdown_commands mww\\ 0\\ 0", "lappend ::pre_shutdown_commands {mww 0 0}",
    'lappend post_init_commands "arm semihosting enable"', "set pre_shutdown_commands {{mww 0 0} {echo hi}}",
    "lappend pre_shutdown_commands $c", 'append pre_shutdown_commands " {mww 0 0}"', 'set v pre_shutdown_commands; lappend $v "mww 0 0"',
])
def test_hook_variable_values_are_scripts(cmd):
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE, (cmd, c)


def test_hook_variable_benign_values_and_plain_lists_keep_risk():
    assert guard.classify_command("lappend pre_shutdown_commands {echo bye}").risk == Risk.INTERACT
    assert guard.classify_command('lappend mylist "mww 0 0"').risk == Risk.INTERACT  # 일반 리스트에 담는 것은 실행이 아님
    assert guard.classify_command('set x "mww 0 0"').risk == Risk.INTERACT


@pytest.mark.external
def test_real_openocd_runs_hook_variables(tmp_path):
    """실제 xPack OpenOCD 에서 post_init_commands / pre_shutdown_commands 원소가 실행된다 (위 규칙의 근거)."""
    import os
    import subprocess

    from pweh.toolsdir import tools_dir

    binary = os.environ.get("PWEH_OPENOCD") or str(tools_dir() / "bin" / "openocd")
    scripts = tools_dir() / "openocd" / "xpack-openocd-0.12.0-7" / "openocd" / "scripts"
    if not (Path(binary).is_file() and os.access(binary, os.X_OK) and scripts.is_dir()):
        pytest.skip("xPack OpenOCD 가 필요합니다")
    p = subprocess.run([binary, "-s", str(scripts), "-c", "gdb port disabled", "-c", "telnet port disabled", "-c", "tcl port disabled",
                        "-f", "interface/dummy.cfg", "-c", "transport select jtag",
                        "-c", 'lappend post_init_commands {echo "HOOK-POST-INIT"}', "-c", 'lappend pre_shutdown_commands "echo HOOK-PRE-SHUTDOWN"',
                        "-c", "init", "-c", "shutdown"],
                       cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    out = p.stdout.decode(errors="replace")
    assert "HOOK-POST-INIT" in out.splitlines() and "HOOK-PRE-SHUTDOWN" in out.splitlines(), out[-2000:]


def test_semihosting_intent():
    for cmd in ("arm semihosting enable", "catch {arm semihosting on}", "set v 1; arm semihosting $v", "esp32s3.cpu0 arm semihosting ENABLE",
                "configure_openocd_events", "foo_semihost_bar", "my_on", "switch x {x {arm semihosting enable}}"):
        assert guard.semihosting_intent(cmd, semihost_procs={"my_on"}), cmd
    # proc 정의만으로는 켜지 않는다 (호출은 세션 proc 목록으로 DESTRUCTIVE)
    for cmd in ("arm semihosting", "arm semihosting disable", "mww 0 0", "halt", "my_off", "proc p {} {arm semihosting enable}"):
        assert not guard.semihosting_intent(cmd, semihost_procs={"my_on"}), cmd


@pytest.mark.parametrize("cmd,risk", [
    # switch/lsort 의 새 규칙이 흔한 안전한 형태를 올리지 않는다
    ("switch abc {abc {echo hi} default {echo no}}", Risk.MODIFY),
    ("switch -exact -- abc {abc {echo hi}}", Risk.MODIFY),
    ("lsort -command {string compare} {b a}", Risk.MODIFY),
    ("lsort -integer {3 1 2}", Risk.INTERACT),
    ("switch x {x reset}", Risk.MODIFY),
])
def test_switch_and_prefix_rules_keep_benign_risk(cmd, risk):
    assert guard.classify_command(cmd).risk == risk, cmd


@pytest.mark.external
def test_real_jim_runs_switch_list_bodies_and_command_prefixes(tmp_path):
    """위 규칙의 근거: 실제 xPack OpenOCD(Jim 0.84)에서 switch 목록 안 본문, lsort -command 줄임말, 덧붙는 데이터가 실행된다."""
    import os
    import subprocess

    from pweh.toolsdir import tools_dir

    binary = os.environ.get("PWEH_OPENOCD") or str(tools_dir() / "bin" / "openocd")
    scripts = tools_dir() / "openocd" / "xpack-openocd-0.12.0-7" / "openocd" / "scripts"
    if not (Path(binary).is_file() and os.access(binary, os.X_OK) and scripts.is_dir()) or "fakebin" in binary:
        pytest.skip("xPack OpenOCD 가 필요합니다")
    cmds = [
        "proc cmpx {args} {echo \"CMD-RAN $args\"; return 0}",
        "switch a {a {echo BODY-braced}}", "switch x {echo z x echo\\ BODY-backslash}", "switch -g x {* {echo BODY-glob}}",
        "switch -e a {a - b {echo BODY-fallthrough}}", "switch echo {echo {echo BODY-known-pattern}}",
        "lsort -c cmpx {p q}", "lsort -command {cmpx pre} {r s}", "switch -c cmpx str {pat {}}",
        "apply {{} {echo BODY-apply}}", "shutdown",
    ]
    argv = [binary, "-s", str(scripts), "-c", "gdb port disabled", "-c", "telnet port disabled", "-c", "tcl port disabled"]
    for c in cmds:
        argv += ["-c", c]
    p = subprocess.run(argv, cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    lines = p.stdout.decode(errors="replace").splitlines()
    for want in ("BODY-braced", "BODY-backslash", "BODY-glob", "BODY-fallthrough", "BODY-known-pattern", "BODY-apply",
                 "CMD-RAN p q", "CMD-RAN pre r s", "CMD-RAN pat str"):
        assert any(ln == want or (want.startswith("CMD-RAN") and ln.startswith(want[:9]) and set(ln.split()[1:]) == set(want.split()[1:]))
                   for ln in lines), (want, lines[-30:])


def test_job_safety_check_rejects_bypass_forms(tmp_path):
    jtag = tmp_path / "jtag"
    jtag.mkdir()
    from pweh.errors import SafetyDenied

    for cmd in ('set x "\n# "; mww 0 0', 'catch -error "mww 0 0"', "lsort -command mww {0 0}"):
        with pytest.raises(SafetyDenied):
            guard.ensure_job_commands_safe([cmd], allowed_dirs=[jtag])


# ---------------------------------------------------------------------------
# MCP 수준: 기본 정책 거부, 승인 시 정확히 1회
# ---------------------------------------------------------------------------

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


@pytest.fixture
def fake():
    srv = FakeOpenOCD()
    srv.start()
    yield srv
    srv.stop()


def _new_case(auth) -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title="guard", authorization=auth).id


HIDDEN_WRITE = 'set x "\n# "; mww 0x80000000 0x11223344'


@pytest.mark.anyio
async def test_hidden_write_denied_by_default(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    before = bytes(fake.dev.regions[0].data[:8])
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        for cmd in (HIDDEN_WRITE, 'catch -error "mww 0x80000000 0x11223344"', "lsort -command mww {0x80000000 0x1}",
                    'cam.cpu configure -event reset-init "mww 0x80000000 1"'):
            r = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert r.get("ok") is False and r.get("status") == "denied", (cmd, r)
        assert not any(x[0] in ("mww", "set") for x in fake.dev.executed), fake.dev.executed  # OpenOCD 로 보내지지 않음
        assert bytes(fake.dev.regions[0].data[:8]) == before


@pytest.mark.anyio
async def test_program_esp_and_semihosting_enable_denied_by_default(workspace, auth, fake):
    """Espressif 플래시 프로그래밍 proc 과 semihosting 켜기(대소문자·on·변수 형태 포함)는 기본 정책에서 OpenOCD 로 보내지 않는다."""
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        for cmd in ("program_esp fw.bin 0x10000 verify reset exit", "program_esp_bins build flasher_args.json reset",
                    "program fw.elf verify reset", "arm semihosting ON", "set v on; arm semihosting $v",
                    "flash [string cat erase_sector] 0 0 last", "esp gcov"):
            r = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert r.get("ok") is False and r.get("status") == "denied", (cmd, r)
            assert r["gate"]["classification"]["risk"] == "destructive", (cmd, r)
        sent = [x[0] for x in fake.dev.executed]
        assert not any(n in ("program_esp", "program_esp_bins", "program", "arm", "set", "flash", "esp") for n in sent), sent


@pytest.mark.anyio
async def test_start_extra_commands_event_handler_denied(workspace, auth, tmp_path, monkeypatch):
    """openocd_start 의 extra_commands 에 넣은 따옴표 이벤트 핸들러도 같은 분류기로 막혀 프로세스가 뜨지 않는다."""
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime, reset_runtimes

    from .test_openocd_semihosting import write_guarded_fake_bin

    binp = write_guarded_fake_bin(tmp_path / "fakebin" / "openocd")
    monkeypatch.setenv("PWEH_OPENOCD", str(binp))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        for extra in (['cam.cpu configure -event reset-init "mww 0x80000000 1"'], ['set x "\n# "; mww 0 0'],
                      ["dict for {k v} {a b} \"mww 0 0\""], ["telnet port 4444"], ["gdb port 3333"]):
            r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", extra_commands=extra, tcl_port=0)
            assert r.get("status") == "denied" and r["gate"]["classification"]["risk"] == "destructive", (extra, r)
    jtag = get_runtime("openocd-mcp").cases.get(cid).dir / "jtag"
    assert not list(jtag.glob("openocd-*.log"))  # 프로세스가 뜨지 않음


@pytest.mark.anyio
async def test_hidden_write_runs_exactly_once_with_approval(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        r1 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE)
        assert r1["status"] == "approval_required" and r1["gate"]["classification"]["risk"] == "destructive", r1
        assert not any(x[0] == "mww" for x in fake.dev.executed)
        ap = r1["approval_id"]
        rt = get_runtime("openocd-mcp")
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        r2 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE, approval_id=ap)
        assert r2["ok"], r2
        assert bytes(fake.dev.regions[0].data[:4]) == bytes.fromhex("44332211")
        assert sum(1 for x in fake.dev.executed if x[0] == "mww") == 1
        r3 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE, approval_id=ap)
        assert r3["ok"] is False and r3["status"] == "denied"  # 1회용
        assert sum(1 for x in fake.dev.executed if x[0] == "mww") == 1


@pytest.mark.anyio
async def test_flash_write_approval_bound_to_file_and_single_use(workspace, auth, fake, monkeypatch):
    """openocd_flash_write: 승인은 파일 sha256 에 묶이고(바뀌면 무효), 승인 직후 바뀌어도 실행하지 않으며, 정확히 1회만 실행된다."""
    from openocd_mcp.server import server
    from pweh.runtime import Runtime, get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    rt = get_runtime("openocd-mcp")
    img = rt.cases.get(cid).subdir("dumps") / "fw.bin"
    img.write_bytes(b"\x01" * 64)
    bank = fake.dev.banks[0]
    original = bytes(bank.data[:64])

    def written() -> int:
        return sum(1 for x in fake.dev.executed if x[:2] == ["flash", "write_image"])

    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        args = dict(case_id=cid, path="dumps/fw.bin", address=0)
        r1 = await call(c, "openocd_flash_write", **args)
        assert r1["status"] == "approval_required", r1
        ap = r1["approval_id"]
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        img.write_bytes(b"\x02" * 64)  # 승인 뒤 파일 교체 → 사람이 본 sha256 과 다름
        r2 = await call(c, "openocd_flash_write", **args, approval_id=ap)
        assert r2.get("ok") is False and r2["status"] == "denied", r2
        assert written() == 0 and bytes(bank.data[:64]) == original

        # 게이트 통과 직후(실행 전) 파일이 바뀌면 실행하지 않는다 (TOCTOU 재확인)
        r3 = await call(c, "openocd_flash_write", **args)
        ap3 = r3["approval_id"]
        rt.approvals.decide(ap3, approve=True, code=rt.approvals.get(ap3)["code"], via="test")
        orig_auth = Runtime.authorize

        async def swap_after_gate(self, **kw):
            d = await orig_auth(self, **kw)
            if kw.get("tool") == "openocd_flash_write" and kw.get("approval_id"):
                img.write_bytes(b"\x03" * 64)
            return d

        monkeypatch.setattr(Runtime, "authorize", swap_after_gate)
        r4 = await call(c, "openocd_flash_write", **args, approval_id=ap3)
        assert "_error" in r4 and "바뀌었습니다" in r4["_error"], r4
        monkeypatch.setattr(Runtime, "authorize", orig_auth)
        assert written() == 0 and bytes(bank.data[:64]) == original

        # 현재 내용으로 새 승인 → 정확히 1회 실행
        r5 = await call(c, "openocd_flash_write", **args)
        ap5 = r5["approval_id"]
        rt.approvals.decide(ap5, approve=True, code=rt.approvals.get(ap5)["code"], via="test")
        r6 = await call(c, "openocd_flash_write", **args, approval_id=ap5)
        assert r6["ok"] and r6["verify"]["ok"], r6
        assert bytes(bank.data[:64]) == b"\x03" * 64 and written() == 1
        r7 = await call(c, "openocd_flash_write", **args, approval_id=ap5)
        assert r7.get("ok") is False and r7["status"] == "denied" and written() == 1  # 1회용
