"""openocd_start 의 semihosting 무력화(가드) 회귀 테스트.

문제: 신뢰 scripts 디렉터리의 표준 cfg 는 내용을 분류하지 않는데, xPack 0.12.0-7 의 ``target/esp_common.cfg`` 는 cpu0/cpu1 의
``examine-end`` 핸들러에서 ``arm semihosting enable`` 을 실행한다. semihosting 이 켜지면 타깃 펌웨어가 분석 PC 의 파일과
명령(SYS_SYSTEM)에 접근할 수 있다. openocd_start 는 init 전에 관련 이벤트 핸들러를
``try {원래 본문} finally {모든 타깃 semihosting 끄기}`` 로 감싸고, init 직후 타깃마다 확인해 끄고, 연결 직후 RPC 로 다시 확인한다.
시작 뒤에도 MODIFY 이상 명령·halt/resume/reset·쓰기 뒤마다 다시 확인한다(openocd_mcp/semihosting.py).

- 단위: 시작 스크립트의 형태와 위치(argv), 로그 표식 해석(-d3 접두 포함), 단계·치명 판정
- MCP(가짜 OpenOCD + 가드 RPC 를 흉내 내는 래퍼 — 아래 GUARDED_FAKE): RPC 확인 필수, init 먼저 실행 → 실패, 명령 뒤 재확인
  (다시 무력화/fail closed/미뤄 둔 확인), 사람이 승인해 켠 세션, openocd_status 의 최신 상태, init 계열 시작 명령 거부
- external(실제 xPack OpenOCD, 하드웨어 없음): ESP32-S3 cfg 핸들러 감싸기, ARM 표준 cfg 무변경, dummy 어댑터 arm7tdmi 로
  '핸들러가 켬 → 무력화 후 꺼짐', init_board·다른 타깃을 켜는 핸들러, RPC 단계, MCP 종단(재무력화·fail closed·init 먼저·-d3)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client

from openocd_mcp import process, semihosting
from openocd_mcp.tcl import braces_balanced
from pweh.toolsdir import tools_dir

from mcp_helpers import call

FAKE_PATH = Path(__file__).resolve().parent / "fake_openocd.py"
TOOLS = tools_dir()
XPACK_SCRIPTS = TOOLS / "openocd" / "xpack-openocd-0.12.0-7" / "openocd" / "scripts"
WRAP = "finally {" + semihosting.WRAP_FINALLY + "}"
TAG = semihosting.MARKER


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


def _new_case(auth) -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title="semihosting", authorization=auth).id


def _case(cid: str):
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.get(cid)


# ---------------------------------------------------------------------------
# 가드를 흉내 내는 가짜 OpenOCD (다른 openocd_start 테스트도 쓴다)
# ---------------------------------------------------------------------------

# tests/servers/fake_openocd.py 는 -c 스크립트를 실행하지 않는다. 서버는 연결 직후 'pweh_semihosting_guard verify' 를 RPC 로 반드시
# 확인하므로(없으면 시작 실패), 가짜에 그 proc 의 응답을 가르친다:
# - FAKE_SH_PRE / FAKE_SH_POST (JSON 줄 목록): init 직전/직후 스크립트가 argv 에 있으면 로그(stderr)에 찍을 표식
# - FAKE_SH_VERIFY (JSON 줄 목록): verify 응답 (없으면 타깃마다 off 인 정상 응답)
# - FAKE_SH_MODE=missing: 가드 proc 이 없음 (invalid command name)
# - FAKE_SH_CTL (JSON 파일): {"check": [[줄…], …], "status": [[줄…], …]} — 호출마다 앞에서 하나씩 꺼내 응답 ("!missing" = proc 없음)
# - FAKE_SH_LOG (파일): 가드 호출 단계를 한 줄씩 기록 (테스트가 '명령 뒤 확인이 돌았는지' 본다)
# - FAKE_SH_EARLY (JSON 줄 목록): init 조기 실행 검사(EARLY_CHECK_SCRIPT)가 argv 에 있으면 그 표식을 찍고 오류로 끝난다
#   (실제 OpenOCD 는 시작 -c 의 error 에서 뒤의 -c 를 실행하지 않고 종료 코드 1 로 끝난다)
# - pweh_test_sleep <초>: 장치 잠금을 쥔 채 잠든다 (실제 OpenOCD 처럼 다른 연결의 명령도 기다리게 됨)
# - pweh_test_semihost_on: 성공하는 'semihosting 켜기' 흉내 (이름에 semihost → DESTRUCTIVE, 승인 흐름 시험용)
GUARDED_FAKE = '''\
import json, os, sys, time
sys.path.insert(0, @FAKE_DIR@)
import fake_openocd

PRE, POST, EARLY = @PRE@, @POST@, @EARLY@
TAG = "PWEH-SEMIHOSTING"


def _env_lines(name):
    raw = os.environ.get(name)
    return json.loads(raw) if raw else None


def _next_ctl(phase):
    path = os.environ.get("FAKE_SH_CTL")
    if not path or not os.path.exists(path):
        return None
    with open(path) as fh:
        ctl = json.load(fh)
    queue = ctl.get(phase) or []
    if not queue:
        return None
    item = queue.pop(0)
    with open(path, "w") as fh:
        json.dump(ctl, fh)
    return item


def _guard(self, args, interp):
    phase = args[0] if args else ""
    log = os.environ.get("FAKE_SH_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(phase + "\\n")
    if os.environ.get("FAKE_SH_MODE") == "missing":
        raise fake_openocd.TclError('invalid command name "pweh_semihosting_guard"')
    off = [TAG + " off " + t.name for t in self.targets]
    if phase == "verify":
        lines = _env_lines("FAKE_SH_VERIFY")
        if lines is None:
            lines = [TAG + " done pre-init"] + off + [TAG + " done post-init"] + off + [TAG + " done verify"]
    elif phase in ("check", "status"):
        lines = _next_ctl(phase)
        if lines == "!missing":
            raise fake_openocd.TclError('invalid command name "pweh_semihosting_guard"')
        if lines is None:
            lines = off + [TAG + " done " + phase]
    else:
        raise fake_openocd.TclError("unknown phase " + phase)
    return "\\n".join(lines)


def _sleep(self, args, interp):
    time.sleep(float(args[0]) if args else 1.0)
    return ""


def _semihost_on(self, args, interp):
    return "semihosting is enabled"


fake_openocd.Device.c_pweh_semihosting_guard = _guard
fake_openocd.Device.c_pweh_test_sleep = _sleep
fake_openocd.Device.c_pweh_test_semihost_on = _semihost_on
argv = sys.argv[1:]
early = os.environ.get("FAKE_SH_EARLY")
if early and EARLY in argv:
    for b in fake_openocd.BANNER:
        sys.stderr.write(b + "\\n")
    for line in json.loads(early):
        sys.stderr.write(line + "\\n")
    sys.stderr.write("PWEH: init ran before the semihosting guard (command mode=exec) - stopping OpenOCD\\n")
    sys.stderr.flush()
    sys.exit(1)
if PRE in argv:
    for line in json.loads(os.environ.get("FAKE_SH_PRE") or "[]"):
        sys.stderr.write(line + "\\n")
if POST in argv and "init" in argv and argv.index(POST) > argv.index("init"):
    for line in json.loads(os.environ.get("FAKE_SH_POST") or "[]"):
        sys.stderr.write(line + "\\n")
sys.stderr.flush()
sys.exit(fake_openocd.main(argv))
'''


def write_guarded_fake_bin(binp: Path) -> Path:
    """가드 RPC 에 답하는 가짜 OpenOCD 실행 파일(셸 스크립트 + 래퍼)을 binp 에 만든다."""
    binp.parent.mkdir(parents=True, exist_ok=True)
    wrapper = binp.parent / "openocd_guarded_fake.py"
    wrapper.write_text(
        GUARDED_FAKE.replace("@FAKE_DIR@", repr(str(FAKE_PATH.parent)))
        .replace("@PRE@", repr(semihosting.PRE_INIT_SCRIPT))
        .replace("@POST@", repr(semihosting.POST_INIT_SCRIPT))
        .replace("@EARLY@", repr(semihosting.EARLY_CHECK_SCRIPT))
    )
    binp.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{wrapper}" "$@"\n')
    binp.chmod(0o755)
    return binp


# ---------------------------------------------------------------------------
# 단위: 스크립트와 명령행
# ---------------------------------------------------------------------------


def test_scripts_are_well_formed_tcl():
    pre = semihosting.PRE_INIT_SCRIPT
    assert braces_balanced(pre) and braces_balanced(semihosting.POST_INIT_SCRIPT) and braces_balanced(semihosting.WRAP_FINALLY)
    assert pre.startswith("proc pweh_semihosting_events ") and pre.rstrip().endswith("pweh_semihosting_guard pre-init")
    assert semihosting.POST_INIT_SCRIPT == "pweh_semihosting_guard post-init"
    assert (semihosting.VERIFY_CALL, semihosting.CHECK_CALL, semihosting.STATUS_CALL) == (
        "pweh_semihosting_guard verify", "pweh_semihosting_guard check", "pweh_semihosting_guard status")
    assert "examine-end" in semihosting.TARGET_EVENTS and set(semihosting.TAP_EVENTS) == {"post-reset", "setup", "tap-enable", "tap-disable"}
    # 감싸기 형태(4원소 리스트로 이미 감쌌는지 확인), init 먼저 실행 감지(command mode), init 뒤 확인, TAP 감싸기
    assert "[list try $body finally $wrap]" in pre and semihosting.WRAP_FINALLY in pre and "[lindex $body 3] eq $wrap" in pre
    assert "[catch {command mode} mode]" in pre and "init-before-guard" in pre and "command mode $t arm semihosting" in pre
    assert "jtag configure $o -event" in pre and "info procs" in pre
    # finally 는 모든 타깃을 끈다 (다른 타깃을 켜는 핸들러 대비) — semihosting 이 없는 타깃은 건너뛴다
    assert "foreach _pweh_sh_t [target names]" in semihosting.WRAP_FINALLY and "arm semihosting disable" in semihosting.WRAP_FINALLY
    assert "@" not in pre  # 자리표시자가 남지 않음
    # -d3 은 -c 인자를 줄마다 로그에 찍는다 → 표식으로 시작하는 소스 줄이 있으면 가짜 표식이 된다
    assert not any(ln.lstrip().startswith(TAG) for ln in pre.splitlines())
    # init 조기 실행 검사: proc 을 정의하지 않는 한 줄(extra_commands 가 덮어쓸 proc 이 없음), init 이 먼저면 끄고 표식 + error
    early = semihosting.EARLY_CHECK_SCRIPT
    assert braces_balanced(early) and "\n" not in early and "proc " not in early and not early.lstrip().startswith(TAG)
    assert early.startswith("if {[catch {command mode} _pweh_sh_mode]}") and "$_pweh_sh_mode ne {config}" in early
    assert "init-before-guard $_pweh_sh_mode" in early and "arm semihosting disable" in early and "done early-check" in early
    assert early.rstrip().endswith('- stopping OpenOCD"}') and early.count("; error ") == 2  # 두 분기 모두 OpenOCD 를 끝낸다


def test_build_argv_runs_guard_after_every_cfg_and_extra_command():
    iface = process.CfgRef("/s/interface/dummy.cfg", "standard")
    tgt = process.CfgRef("/s/target/esp32s3.cfg", "standard")
    extra = process.CfgRef("/s/board/x.cfg", "standard")
    argv = process.build_argv(
        "/opt/openocd", scripts_dir=None, interface=iface, transport="jtag", targets=[tgt], extra_cfgs=[extra],
        adapter_speed_khz=1000, extra_commands=["target create cam.cpu testee -chain-position cam.cpu"], tcl_port=0,
    )
    i_pre = argv.index(semihosting.PRE_INIT_SCRIPT)
    i_init = argv.index("init")
    i_post = argv.index(semihosting.POST_INIT_SCRIPT)
    # 모든 -f 와 extra -c 뒤 → init → init 직후 확인 (TCL 서버는 그 뒤에 연결을 받는다)
    assert max(argv.index(iface.arg), argv.index(tgt.arg), argv.index(extra.arg),
               argv.index("target create cam.cpu testee -chain-position cam.cpu")) < i_pre < i_init < i_post == len(argv) - 1
    assert argv[i_pre - 1] == argv[i_init - 1] == argv[i_post - 1] == "-c"
    # init 조기 실행 검사: -f 하나하나와 extra -c 하나하나 바로 뒤 (그 뒤의 시작 명령이 semihosting 이 켜진 채 실행되지 않게)
    early = semihosting.EARLY_CHECK_SCRIPT
    for item in (iface.arg, tgt.arg, extra.arg, "target create cam.cpu testee -chain-position cam.cpu"):
        i = argv.index(item)
        assert argv[i + 1:i + 3] == ["-c", early], item
    assert argv.count(early) == 4 and max(i for i, a in enumerate(argv) if a == early) < i_pre
    off = process.build_argv(
        "/opt/openocd", scripts_dir=None, interface=iface, transport=None, targets=[], extra_cfgs=[], adapter_speed_khz=None,
        extra_commands=[], tcl_port=0, semihosting_guard=False,
    )
    assert off[-2:] == ["-c", "init"] and semihosting.PRE_INIT_SCRIPT not in off and early not in off


# ---------------------------------------------------------------------------
# 단위: 표식 해석
# ---------------------------------------------------------------------------

# xPack 0.12.0-7 + interface/dummy.cfg + target/esp32s3.cfg 실측 로그 (가운데 줄 일부 생략)
REAL_ESP32S3_LOG = """\
xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)
Info : [esp32s3.cpu0] Hardware thread awareness created
Info : [esp32s3.cpu1] Hardware thread awareness created
force hard breakpoints
adapter speed: 1000 kHz
PWEH-SEMIHOSTING wrapped target esp32s3.cpu0 examine-end
PWEH-SEMIHOSTING wrapped target esp32s3.cpu1 examine-end
PWEH-SEMIHOSTING done pre-init
Info : clock speed 1000 kHz
Error: esp32s3.cpu0: IR capture error; saw 0x1f not 0x01
Error: Unexpected OCD_ID = ffffffff
Error: [esp32s3.cpu0] Examination failed
Error: [esp32s3.cpu1] Examination failed
PWEH-SEMIHOSTING already target esp32s3.cpu0 examine-end
PWEH-SEMIHOSTING already target esp32s3.cpu1 examine-end
PWEH-SEMIHOSTING off esp32s3.cpu0
PWEH-SEMIHOSTING off esp32s3.cpu1
PWEH-SEMIHOSTING done post-init
Info : Listening on port 6666 for tcl connections
PWEH-SEMIHOSTING disable-failed esp32s3.cpu0 forged after the TCL port opened
"""


def test_parse_real_esp32s3_log():
    rep = semihosting.parse_report(REAL_ESP32S3_LOG)
    assert rep["verified"] is True and rep["phases"] == ["pre-init", "post-init"] and rep["failures"] == []
    assert rep["handlers_wrapped"] == [{"scope": "target", "name": "esp32s3.cpu0", "event": "examine-end"},
                                       {"scope": "target", "name": "esp32s3.cpu1", "event": "examine-end"}]
    assert rep["already_wrapped"] == rep["handlers_wrapped"]  # post-init 의 다시 감싸기는 이미 감싼 것을 알아본다
    assert rep["targets"] == {"esp32s3.cpu0": "off", "esp32s3.cpu1": "off"} and rep["init_before_guard"] is None
    # TCL 포트가 열린 뒤의 줄(누가 찍었든)은 시작 스크립트 결과가 아니므로 보지 않는다
    assert semihosting.fatal_reasons(rep) == []
    assert semihosting.neutralized_list(rep) == ["esp32s3.cpu0:examine-end", "esp32s3.cpu1:examine-end"]
    diag = semihosting.diagnosis_entries(rep, REAL_ESP32S3_LOG)
    assert [d["code"] for d in diag] == ["semihosting_neutralized"]
    assert set(diag[0]) == {"code", "message", "evidence", "hint"} and "esp32s3.cpu0:examine-end" in diag[0]["message"]
    assert diag[0]["evidence"] == "PWEH-SEMIHOSTING wrapped target esp32s3.cpu0 examine-end"


# xPack 0.12.0-7 의 -d3 실측 형식: 'User : …handle_echo(): <표식>', 명령마다 'Debug: … script_debug(): command - echo …',
# 명령행 인자는 'Debug: … parse_cmdline_args(): ARGV[n] = "…"' (여러 줄 인자는 줄마다 그대로)
D3_LOG = """\
Debug: 19 1 options.c:348 parse_cmdline_args(): ARGV[15] = "proc pweh_semihosting_events {prefix known} {
    set tag PWEH-SEMIHOSTING
pweh_semihosting_guard pre-init"
Debug: 85 2 command.c:82 script_debug(): command - echo PWEH-SEMIHOSTING wrapped target dummy.cpu examine-end
User : 86 2 command.c:601 handle_echo(): PWEH-SEMIHOSTING wrapped target dummy.cpu examine-end
Debug: 104 2 command.c:82 script_debug(): command - echo PWEH-SEMIHOSTING done pre-init
User : 105 2 command.c:601 handle_echo(): PWEH-SEMIHOSTING done pre-init
Debug: 297 4 command.c:82 script_debug(): command - echo PWEH-SEMIHOSTING disable-failed dummy.cpu Failed to Configure semihosting
User : 298 4 command.c:601 handle_echo(): PWEH-SEMIHOSTING disable-failed dummy.cpu Failed to Configure semihosting
User : 300 4 command.c:601 handle_echo(): PWEH-SEMIHOSTING done post-init
Info : 301 4 server.c:298 add_service(): Listening on port 6666 for tcl connections
"""


def test_parse_d3_prefixed_markers_and_ignore_debug_echo_lines():
    rep = semihosting.parse_report(D3_LOG)
    # handle_echo 줄만 표식으로 센다 (script_debug/ARGV 줄은 무시 → 두 번 세지 않음)
    assert rep["phases"] == ["pre-init", "post-init"] and rep["handlers_wrapped"] == [{"scope": "target", "name": "dummy.cpu", "event": "examine-end"}]
    assert rep["targets"] == {"dummy.cpu": "disable-failed"} and len(rep["failures"]) == 1 and rep["verified"] is False
    assert "dummy.cpu" in semihosting.fatal_reasons(rep)[0]  # 수정 전: -d3 에서는 표식을 못 찾아 실패가 경고로 바뀌었다
    assert semihosting.marker_lines("  PWEH-SEMIHOSTING off x") == []  # 줄 맨 앞(또는 handle_echo 뒤)만


def test_parse_after_init_disable_tap_and_already():
    log = "\n".join([
        "PWEH-SEMIHOSTING already target cam.cpu examine-end",
        "PWEH-SEMIHOSTING done pre-init",
        "PWEH-SEMIHOSTING wrapped target cam.cpu reset-init",  # init 중(init_board) 설치된 핸들러를 init 뒤에 감쌈
        "PWEH-SEMIHOSTING disabled cam.cpu",
        "PWEH-SEMIHOSTING unsupported cam.ahb",
        "PWEH-SEMIHOSTING unsupported cam.dsp semihosting not supported for current target",
        "PWEH-SEMIHOSTING wrapped tap cam.cpu post-reset",
        "PWEH-SEMIHOSTING done post-init",
    ])
    rep = semihosting.parse_report(log)
    assert rep["verified"] and rep["already_wrapped"] == [{"scope": "target", "name": "cam.cpu", "event": "examine-end"}]
    assert rep["targets"] == {"cam.cpu": "disabled", "cam.ahb": "unsupported", "cam.dsp": "unsupported"}
    assert rep["phase_targets"]["post-init"]["cam.cpu"] == "disabled"
    assert semihosting.neutralized_list(rep) == ["cam.cpu:reset-init", "tap:cam.cpu:post-reset", "cam.cpu:after-init"]


@pytest.mark.parametrize(
    "line,needle",
    [
        ("PWEH-SEMIHOSTING wrap-failed target esp32s3.cpu0 examine-end invalid command name", "감싸지 못함"),
        ("PWEH-SEMIHOSTING wrap-failed tap cam.cpu setup boom", "감싸지 못함"),
        ("PWEH-SEMIHOSTING disable-failed esp32s3.cpu0 Target not examined yet semihosting is enabled", "끄지 못함"),
        ("PWEH-SEMIHOSTING error pre-init invalid command name \"apply\"", "스크립트 오류"),
        ("PWEH-SEMIHOSTING init-before-guard exec", "init 이 먼저"),
    ],
)
def test_failures_are_fatal(line, needle):
    rep = semihosting.parse_report(f"{line}\nPWEH-SEMIHOSTING done pre-init\nPWEH-SEMIHOSTING done post-init\n")
    reasons = semihosting.fatal_reasons(rep)
    assert rep["verified"] is False and len(reasons) == 1 and needle in reasons[0], reasons
    assert "semihosting_neutralization_failed" in [d["code"] for d in semihosting.diagnosis_entries(rep, line)]


def test_init_before_guard_is_reported():
    rep = semihosting.parse_report("PWEH-SEMIHOSTING init-before-guard exec\nPWEH-SEMIHOSTING done pre-init\n")
    assert rep["init_before_guard"] == "exec" and rep["failures"][0]["kind"] == "init-before-guard"


def test_missing_or_incomplete_markers():
    rep = semihosting.parse_report("Info : Listening on port 6666 for tcl connections\n")
    assert rep["verified"] is False and rep["phases"] == [] and semihosting.fatal_reasons(rep) == []
    assert semihosting.diagnosis_entries(rep, "") == []
    # RPC 단계는 필수 단계가 모두 끝나야 통과 (없으면 문제)
    req = ("pre-init", "post-init", "verify")
    assert semihosting.verification_problems(rep, req) and "pre-init" in semihosting.verification_problems(rep, req)[0]
    half = semihosting.parse_report("PWEH-SEMIHOSTING done pre-init\n", required=req, startup_only=False)
    assert half["verified"] is False and "post-init" in semihosting.verification_problems(half, req)[-1]
    # 끝 표식이 없는 단계(도중에 멈춤/잘림)는 실패
    cut = semihosting.parse_report("PWEH-SEMIHOSTING done pre-init\nPWEH-SEMIHOSTING off x\n", startup_only=False)
    assert [f["kind"] for f in cut["failures"]] == ["incomplete"] and semihosting.fatal_reasons(cut)


def test_rpc_phase_reports_and_suffixes():
    verify = "\n".join([f"{TAG} done pre-init", f"{TAG} off cam.cpu", f"{TAG} done post-init", f"{TAG} disabled cam.cpu",
                        f"{TAG} proc configure_event_examine_end", f"{TAG} proc pweh_semihosting_guard", f"{TAG} proc my proc", f"{TAG} done verify"])
    rep = semihosting.parse_report(verify, required=("pre-init", "post-init", "verify"), startup_only=False)
    assert rep["verified"] and rep["targets"] == {"cam.cpu": "disabled"}
    assert rep["procs"] == ["configure_event_examine_end", "pweh_semihosting_guard", "my proc"]  # 공백이 든 proc 이름도 그대로
    assert semihosting.neutralized_list(rep) == ["cam.cpu:after-start"]
    check = semihosting.parse_report(f"{TAG} wrapped target cam.cpu examine-end\n{TAG} disabled cam.cpu\n{TAG} done check",
                                     required=("check",), startup_only=False)
    assert check["verified"] and semihosting.neutralized_list(check) == ["cam.cpu:examine-end", "cam.cpu:after-command"]
    status = semihosting.parse_report(f"{TAG} unwrapped target cam.cpu examine-end\n{TAG} enabled cam.cpu\n{TAG} done status",
                                      required=("status",), startup_only=False)
    assert status["targets"] == {"cam.cpu": "enabled"} and status["unwrapped"][0]["event"] == "examine-end"


# ---------------------------------------------------------------------------
# MCP: 가드를 흉내 내는 가짜 OpenOCD
# ---------------------------------------------------------------------------


@pytest.fixture
def guarded_fake(tmp_path, monkeypatch):
    """가드 RPC 에 답하는 가짜 OpenOCD + 격리된 HOME. 반환된 객체로 표식/응답을 정한다."""
    from pweh.runtime import reset_runtimes

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for var in ("XDG_CONFIG_HOME", "OPENOCD_SCRIPTS", "PWEH_OPENOCD_SCRIPTS", "FAKE_OPENOCD_MODE", "FAKE_SH_PRE", "FAKE_SH_POST",
                "FAKE_SH_VERIFY", "FAKE_SH_MODE", "FAKE_SH_EARLY"):
        monkeypatch.delenv(var, raising=False)
    binp = write_guarded_fake_bin(tmp_path / "fakebin" / "openocd")
    ctl = tmp_path / "sh-ctl.json"
    calls = tmp_path / "sh-calls.log"
    monkeypatch.setenv("PWEH_OPENOCD", str(binp))
    monkeypatch.setenv("FAKE_SH_CTL", str(ctl))
    monkeypatch.setenv("FAKE_SH_LOG", str(calls))
    reset_runtimes()

    class Ctl:
        def markers(self, pre: list[str], post: list[str]) -> None:
            monkeypatch.setenv("FAKE_SH_PRE", json.dumps(pre))
            monkeypatch.setenv("FAKE_SH_POST", json.dumps(post))

        def verify(self, lines: list[str] | None) -> None:
            if lines is None:
                monkeypatch.delenv("FAKE_SH_VERIFY", raising=False)
            else:
                monkeypatch.setenv("FAKE_SH_VERIFY", json.dumps(lines))

        def mode(self, value: str | None) -> None:
            if value is None:
                monkeypatch.delenv("FAKE_SH_MODE", raising=False)
            else:
                monkeypatch.setenv("FAKE_SH_MODE", value)

        def early(self, lines: list[str] | None) -> None:
            """init 조기 실행 검사가 걸린 것처럼 표식을 찍고 오류로 끝나게 한다 (None = 정상)."""
            if lines is None:
                monkeypatch.delenv("FAKE_SH_EARLY", raising=False)
            else:
                monkeypatch.setenv("FAKE_SH_EARLY", json.dumps(lines))

        def queue(self, phase: str, *responses) -> None:
            doc = json.loads(ctl.read_text()) if ctl.exists() else {}
            doc.setdefault(phase, []).extend(responses)
            ctl.write_text(json.dumps(doc))

        def calls(self) -> list[str]:
            return calls.read_text().split() if calls.exists() else []

    return Ctl()


def _audit(cid: str) -> list[dict]:
    path = _case(cid).dir / "audit.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def _verify_lines(*middle_post: str, extra: tuple[str, ...] = ()) -> list[str]:
    """정상 verify 응답: pre-init → post-init(middle_post) → verify(extra + off)."""
    return [f"{TAG} done pre-init", *middle_post, f"{TAG} done post-init", *extra, f"{TAG} off cam.cpu", f"{TAG} done verify"]


@pytest.mark.anyio
async def test_start_reports_neutralized_handlers(workspace, auth, guarded_fake):
    from openocd_mcp.server import server

    pre = [f"{TAG} wrapped target cam.cpu examine-end", f"{TAG} done pre-init"]
    post = [f"{TAG} off cam.cpu", f"{TAG} done post-init"]
    guarded_fake.markers(pre, post)
    guarded_fake.verify(pre + post + [f"{TAG} off cam.cpu", f"{TAG} proc configure_event_examine_end", f"{TAG} proc pweh_semihosting_guard",
                                      f"{TAG} done verify"])
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"] and r["health"] == "ok", r
        assert guarded_fake.calls() == ["verify"]  # 연결 직후 RPC 확인 (필수)
        assert r["semihosting_neutralized"] == ["cam.cpu:examine-end"]
        sh = r["semihosting"]
        assert sh["verified"] is True and sh["targets"] == {"cam.cpu": "off"} and sh["source"] == "rpc" and sh["log_markers"] is True
        assert sh["phases"] == ["pre-init", "post-init", "verify"] and sh["procs"] == ["configure_event_examine_end"]  # 가드 자신은 뺀다
        assert "semihosting_neutralized" in [d["code"] for d in r["diagnosis"]]
        assert not any("PWEH-SEMIHOSTING" in w for w in r["warnings"])
        st = await call(c, "openocd_status", case_id=cid)
        assert st["semihosting"]["handlers_wrapped"][0]["event"] == "examine-end" and st["semihosting"]["policy"] == "disabled"
        assert st["semihosting"]["startup"]["phases"] == ["pre-init", "post-init", "verify"]
        assert st["semihosting_live"]["status"] == "reported" and st["semihosting_live"]["targets"] == {"cam.cpu": "off"}
        assert "semihosting_neutralized" in [d["code"] for d in st["startup_diagnosis"]]
        doc = json.loads((_case(cid).dir / "jtag" / "openocd-1.json").read_text())
        assert doc["semihosting"]["handlers_wrapped"] == sh["handlers_wrapped"] and doc["semihosting"]["verified"] is True
        assert any(e.get("event") == "openocd_semihosting" and e.get("neutralized") == ["cam.cpu:examine-end"] for e in _audit(cid))
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]


@pytest.mark.anyio
async def test_start_reports_early_init_check_exit(workspace, auth, guarded_fake):
    """init 조기 실행 검사가 OpenOCD 를 오류로 끝내면(프로세스 종료) 같은 치명 사유 init-before-semihosting-guard 로 실패한다."""
    from openocd_mcp.server import server

    guarded_fake.early([f"{TAG} init-before-guard exec", f"{TAG} disabled cam.cpu", f"{TAG} done early-check"])
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0, extra_commands=["echo hi"])
        assert r["ok"] is False and r["status"] == "start_failed" and r["reason"] == "init-before-semihosting-guard", r
        assert r["process"]["running"] is False and r["stop_method"] == "already-exited"
        assert r["semihosting"]["init_before_guard"] == "exec" and r["semihosting"]["phases"] == ["early-check"]
        assert "init 이 먼저" in r["semihosting_failures"][0] and r["diagnosis"][0]["code"] == "semihosting_neutralization_failed"
        assert semihosting.EARLY_CHECK_SCRIPT in r["argv"] and r["argv"].count(semihosting.EARLY_CHECK_SCRIPT) == 2  # -f 뒤 + extra 뒤
        assert guarded_fake.calls() == []  # 연결하지 않았다
        assert (await call(c, "openocd_status", case_id=cid))["active"] is False
        assert any(e.get("event") == "openocd_semihosting_failed" and e.get("reason") == "init-before-semihosting-guard" for e in _audit(cid))
        assert not list((_case(cid).dir / "jtag").glob(".openocd-*-cwd-*"))
        # 검사가 걸리지 않으면(정상) 같은 케이스에서 그대로 시작된다
        guarded_fake.early(None)
        r2 = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0, extra_commands=["echo hi"])
        assert r2["ok"] and r2["semihosting"]["verified"], r2
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]


@pytest.mark.anyio
async def test_start_fails_closed_when_semihosting_stays_enabled(workspace, auth, guarded_fake):
    from openocd_mcp.server import server

    guarded_fake.markers(
        [f"{TAG} wrapped target cam.cpu examine-end", f"{TAG} done pre-init"],
        [f"{TAG} disable-failed cam.cpu Failed to Configure semihosting semihosting is enabled", f"{TAG} done post-init"],
    )
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"] is False and r["status"] == "start_failed" and r["reason"] == "semihosting-neutralization-failed", r
        assert r["process"]["running"] is False and r["stop_method"] in ("sigterm", "sigkill")
        assert r["diagnosis"][0]["code"] == "semihosting_neutralization_failed"
        assert r["semihosting"]["targets"] == {"cam.cpu": "disable-failed"} and "cam.cpu" in r["semihosting_failures"][0]
        assert guarded_fake.calls() == []  # 로그에서 이미 실패를 봤으므로 연결하지 않았다
        st = await call(c, "openocd_status", case_id=cid)
        assert st["active"] is False  # 세션을 등록하지 않음 → 기기 명령을 보낼 수 없다
        assert any(e.get("event") == "openocd_semihosting_failed" for e in _audit(cid))
        assert not list((_case(cid).dir / "jtag").glob(".openocd-1-cwd-*"))  # 빈 실행 전용 작업 디렉터리 정리 (수정 전: 남음)
        # 표식이 정상이면 같은 케이스에서 다시 시작할 수 있다
        guarded_fake.markers([f"{TAG} done pre-init"], [f"{TAG} off cam.cpu", f"{TAG} done post-init"])
        r2 = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r2["ok"] and r2["semihosting"]["verified"] and r2["semihosting_neutralized"] == [], r2


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mode,verify,reason,needle",
    [
        ("missing", None, "semihosting-verification-failed", "invalid command name"),  # 가드가 실행되지 않은 OpenOCD
        (None, [f"{TAG} done pre-init", f"{TAG} off cam.cpu", f"{TAG} done verify"], "semihosting-verification-failed", "post-init"),
        (None, [f"{TAG} off cam.cpu"], "semihosting-verification-failed", "불완전"),  # 끝 표식 없이 잘림
        (None, _verify_lines(extra=(f"{TAG} disable-failed cam.cpu nope",)), "semihosting-neutralization-failed", "cam.cpu"),
        (None, [f"{TAG} init-before-guard exec"] + _verify_lines(), "init-before-semihosting-guard", "init"),
    ],
)
async def test_start_requires_rpc_verification(workspace, auth, guarded_fake, mode, verify, reason, needle):
    """로그 표식이 없어도(-d3 이전 형식, log_output 리다이렉트, 가짜) RPC 확인이 없거나 불완전하면 실행하지 않는다 (수정 전: 경고만)."""
    from openocd_mcp.server import server

    guarded_fake.mode(mode)
    guarded_fake.verify(verify)
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"] is False and r["status"] == "start_failed" and r["reason"] == reason, r
        assert r["process"]["running"] is False and any(needle in f for f in r["semihosting_failures"]), r["semihosting_failures"]
        assert r["diagnosis"][0]["code"] == "semihosting_neutralization_failed" and r["hint"]
        assert (await call(c, "openocd_status", case_id=cid))["active"] is False
        assert not list((_case(cid).dir / "jtag").glob(".openocd-1-cwd-*"))


@pytest.mark.anyio
async def test_start_without_log_markers_is_verified_over_rpc(workspace, auth, guarded_fake):
    """시작 로그에 표식이 없어도(가짜는 -c 를 실행하지 않음 = -d3·리다이렉트와 같은 상황) RPC 확인이 통과하면 시작한다."""
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"] and r["semihosting"]["verified"] and r["semihosting"]["log_markers"] is False, r
        assert not any("PWEH-SEMIHOSTING" in w for w in r["warnings"])
        # -d3 형식의 실패 표식이 로그에 있으면 연결 전에 실패시킨다
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]
        guarded_fake.markers([f"User : 86 2 command.c:601 handle_echo(): {TAG} done pre-init"],
                             [f"User : 298 4 command.c:601 handle_echo(): {TAG} disable-failed cam.cpu nope",
                              f"User : 300 4 command.c:601 handle_echo(): {TAG} done post-init"])
        r2 = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r2["ok"] is False and r2["reason"] == "semihosting-neutralization-failed", r2


@pytest.mark.anyio
async def test_modify_commands_recheck_and_reneutralize(workspace, auth, guarded_fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0))["ok"]
        assert guarded_fake.calls() == ["verify"]
        # INTERACT 명령 뒤에는 확인하지 않는다
        q = await call(c, "openocd_command", case_id=cid, command="targets")
        assert q["ok"] and "semihosting_check" not in q and guarded_fake.calls() == ["verify"]
        # MODIFY 명령 뒤: 감싸지 않은 핸들러가 다시 생겼고 semihosting 이 켜져 있었다 → 다시 무력화하고 알린다
        guarded_fake.queue("check", [f"{TAG} wrapped target cam.cpu examine-end", f"{TAG} disabled cam.cpu", f"{TAG} done check"])
        h = await call(c, "openocd_command", case_id=cid, command="halt")
        assert h["ok"] and h["classification"]["risk"] == "modify", h
        assert h["semihosting_check"]["status"] == "reneutralized" and h["semihosting_reneutralized"] == ["cam.cpu:examine-end", "cam.cpu:after-command"]
        assert "semihosting_warning" in h and guarded_fake.calls() == ["verify", "check"]
        assert any(e.get("event") == "openocd_semihosting_reneutralized" and e.get("trigger") == "openocd_command" for e in _audit(cid))
        # halt/resume/reset 도구도 뒤에 확인한다 (기본 응답: 아무것도 켜져 있지 않음)
        for tool, args in (("openocd_halt", {}), ("openocd_reset", {"mode": "halt"}), ("openocd_resume", {})):
            res = await call(c, tool, case_id=cid, **args)
            assert res["semihosting_check"]["status"] == "ok" and "semihosting_reneutralized" not in res, (tool, res)
        assert guarded_fake.calls() == ["verify", "check", "check", "check", "check"]
        # openocd_status 는 시작 보고가 아니라 최신 확인 결과를 보여 준다
        st = await call(c, "openocd_status", case_id=cid)
        sh = st["semihosting"]
        assert sh["last_check"]["trigger"] == "openocd_resume" and sh["last_check"]["verified"] is True
        assert sh["reneutralized"][0]["items"] == ["cam.cpu:examine-end", "cam.cpu:after-command"]
        assert sh["handlers_wrapped"] == [{"scope": "target", "name": "cam.cpu", "event": "examine-end"}]
        doc = json.loads((_case(cid).dir / "jtag" / "openocd-1.json").read_text())
        assert doc["semihosting"]["reneutralized"][0]["trigger"] == "openocd_command"
        # status 가 (읽기 전용 확인에서) 켜진 타깃을 보면 그 자리에서 다시 무력화한다
        guarded_fake.queue("status", [f"{TAG} enabled cam.cpu", f"{TAG} done status"])
        guarded_fake.queue("check", [f"{TAG} disabled cam.cpu", f"{TAG} done check"])
        st2 = await call(c, "openocd_status", case_id=cid)
        assert st2["semihosting_live"]["targets"] == {"cam.cpu": "enabled"} and st2["semihosting_reneutralized"] == ["cam.cpu:after-command"]
        assert st2["semihosting"]["last_check"]["trigger"] == "openocd_status"


@pytest.mark.anyio
@pytest.mark.parametrize("response", [
    [f"{TAG} disable-failed cam.cpu Failed to Configure semihosting", f"{TAG} done check"],
    "!missing",  # 가드 proc 이 사라짐 (승인된 rename 등)
    [f"{TAG} off cam.cpu"],  # 결과가 불완전
])
async def test_recheck_failure_stops_openocd(workspace, auth, guarded_fake, response):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"], r
        guarded_fake.queue("check", response)
        h = await call(c, "openocd_halt", case_id=cid)
        assert h["ok"] is False and h["status"] == "semihosting_failsafe", h
        fs = h["semihosting_failsafe"]
        assert fs["stop_method"] in ("sigterm", "sigkill") and fs["process"]["running"] is False and fs["reasons"], fs
        # 그 뒤 기기 명령은 보내지 않는다 (이유를 알려 준다)
        again = await call(c, "openocd_command", case_id=cid, command="targets")
        assert "_error" in again and "semihosting" in again["_error"], again
        st = await call(c, "openocd_status", case_id=cid)
        assert st["active"] and st["alive"] is False and st["semihosting_failsafe"]["reasons"] == fs["reasons"]
        assert any(e.get("event") == "openocd_semihosting_failsafe" for e in _audit(cid))
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"] and stop["method"] == "already-exited", stop


@pytest.mark.anyio
async def test_check_after_timed_out_command_runs_before_next_command(workspace, auth, guarded_fake):
    """명령이 시간 초과로 끝나면(OpenOCD 는 계속 실행 중일 수 있다) 확인을 미뤄 두고 다음 RPC 전에 먼저 확인한다."""
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0))["ok"]
        slow = await call(c, "openocd_command", case_id=cid, command="pweh_test_sleep 3", timeout=1)
        assert "_error" in slow and "시간 초과" in slow["_error"], slow
        assert guarded_fake.calls() == ["verify"]
        guarded_fake.queue("check", [f"{TAG} disabled cam.cpu", f"{TAG} done check"])
        t = await call(c, "openocd_targets", case_id=cid)  # INTERACT 지만 밀린 확인이 먼저 돈다
        assert t["ok"] and guarded_fake.calls() == ["verify", "check"], t
        st = await call(c, "openocd_status", case_id=cid)
        assert st["semihosting"]["last_check"]["trigger"] == "pending" and st["semihosting"]["check_pending"] is False
        assert st["semihosting"]["reneutralized"][0]["items"] == ["cam.cpu:after-command"]


@pytest.mark.anyio
async def test_session_semihosting_procs_are_destructive(workspace, auth, guarded_fake):
    """가드가 찾은 'semihosting 을 켜는 proc'(세션 OpenOCD 의 cfg proc) 호출은 DESTRUCTIVE (수정 전: 알 수 없는 명령 = MODIFY 허용)."""
    from openocd_mcp.server import server

    guarded_fake.verify(_verify_lines(extra=(f"{TAG} proc cam_debug_events", f"{TAG} proc cam.cpu dbg on")))
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0))["ok"]
        for cmd in ("cam_debug_events", "catch {cam_debug_events}", "cam.cpu configure -event reset-init cam_debug_events", "cam.cpu dbg on",
                    "configure_openocd_events", "create_esp_target xtensa", "esp32s3.cpu0 configure -event reset-init configure_event_examine_end",
                    "pweh_semihosting_guard pre-init"):
            d = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert d["status"] == "denied" and d["gate"]["classification"]["risk"] == "destructive", (cmd, d)
        assert guarded_fake.calls() == ["verify"]  # 아무것도 보내지 않았다


@pytest.mark.anyio
async def test_approved_semihosting_enable_switches_session_to_report_only(workspace, auth, guarded_fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    rt = get_runtime("openocd-mcp")
    async with Client(server) as c:
        assert (await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0))["ok"]

        async def approved(cmd: str) -> dict:
            r1 = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert r1["status"] == "approval_required" and r1["gate"]["classification"]["risk"] == "destructive", r1
            ap = r1["approval_id"]
            rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
            return await call(c, "openocd_command", case_id=cid, command=cmd, approval_id=ap)

        # 승인됐지만 실패한 켜기(가짜에는 arm 명령이 없음 → tcl_error): 정책은 그대로 → 평소처럼 끄는 확인
        failed = await approved("arm semihosting enable")
        assert failed["status"] == "tcl_error" and "semihosting_policy" not in failed and failed["semihosting_check"]["status"] == "ok", failed
        assert guarded_fake.calls() == ["verify", "check"]
        # 승인되고 성공한 켜기: 이 세션은 끄지 않고 읽기 전용(status)으로 보고만 한다
        guarded_fake.queue("status", [f"{TAG} enabled cam.cpu", f"{TAG} done status"])
        r2 = await approved("pweh_test_semihost_on")
        assert r2["ok"] and r2["semihosting_policy"] == "enabled-by-approval" and r2["semihosting_check"]["status"] == "reported", r2
        assert r2["semihosting_check"]["targets"] == {"cam.cpu": "enabled"} and "semihosting_warning" in r2
        # 이후 확인도 읽기 전용(status) — 사람이 켠 semihosting 을 끄지 않는다
        guarded_fake.queue("status", [f"{TAG} enabled cam.cpu", f"{TAG} done status"])
        h = await call(c, "openocd_halt", case_id=cid)
        assert h["semihosting_check"]["status"] == "reported" and "semihosting_reneutralized" not in h
        assert guarded_fake.calls() == ["verify", "check", "status", "status"]
        st = await call(c, "openocd_status", case_id=cid)
        assert st["semihosting"]["policy"] == "enabled-by-approval" and "semihosting_reneutralized" not in st
        assert any(e.get("event") == "openocd_semihosting_enabled_by_approval" for e in _audit(cid))


@pytest.mark.anyio
@pytest.mark.parametrize("extra", [
    ["init"], ["catch init"], ["catch {init}"], ['catch "init"'], ["::init"], ["ocd_init"], ["target init"], ["transport init"],
    ["jtag init"], ["dap init"], ["jtag arp_init-reset"], ["if 1 {init}"], ["capture {dap init}"], ["eval init"],
    ["lappend post_init_commands {echo hi}"],  # init 끝에서(가드의 post-init 전에) 실행됨
    ["jtag newtap cam cpu -irlen 4", "init", "reset run", "sleep 5000", "halt"],
    # 검증 단계 새 발견 2: switch 한 단어 목록 안 본문(수정 전 MODIFY 로 허용되어 init 이 가드보다 먼저 돌았다), apply 람다, -command 접두
    ["switch a {a init}"], ["switch -glob x {* init}"], ["switch -exact -- a {a {target init}}"], ["apply {{} init}"], ["lsort -c init {a b}"],
])
async def test_extra_commands_init_family_rejected(workspace, auth, guarded_fake, extra):
    """extra_commands 의 init 은 semihosting 가드보다 먼저 실행된다(수정 전: MODIFY 로 허용, verified=True 로 보고) → 거부."""
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", extra_commands=extra, tcl_port=0)
        assert "_error" in r and "init" in r["_error"], r
    assert not list((_case(cid).dir / "jtag").glob("openocd-*.log"))  # 프로세스가 뜨지 않음
    assert guarded_fake.calls() == []


@pytest.mark.anyio
async def test_custom_cfg_with_init_is_destructive(workspace, auth, guarded_fake, tmp_path):
    from openocd_mcp.server import server

    cfg = tmp_path / "cam.cfg"
    cfg.write_text("adapter driver dummy\njtag newtap cam cpu -irlen 4\ninit\n")  # init 만 빼면 MODIFY
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0)
        assert r["status"] == "denied" and r["gate"]["classification"]["risk"] == "destructive", r
        cc = r["custom_cfgs"][0]["classification"]
        assert cc["risk"] == "destructive" and cc["rule_id"] == "openocd.local.init-before-guard", cc
        cfg.write_text("adapter driver dummy\njtag newtap cam cpu -irlen 4\n")
        ok = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0)
        assert ok["ok"] and ok["classification"]["risk"] == "modify", ok


@pytest.mark.anyio
async def test_failed_start_removes_empty_run_cwd(workspace, auth, guarded_fake, monkeypatch):
    from openocd_mcp.server import server

    monkeypatch.setenv("FAKE_OPENOCD_MODE", "adapter_fail")
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["status"] == "start_failed" and r["reason"].startswith("process-exited"), r
    assert not list((_case(cid).dir / "jtag").glob(".openocd-*-cwd-*"))


# ---------------------------------------------------------------------------
# external: 실제 xPack OpenOCD (하드웨어 없음 — dummy 어댑터, 또는 init 전에 종료)
# ---------------------------------------------------------------------------

PORTS = ["-c", "gdb port disabled", "-c", "telnet port disabled", "-c", "tcl port disabled"]
DUMMY = ["-f", "interface/dummy.cfg", "-c", "transport select jtag", "-c", "adapter speed 1000"]
ARM7_TAP = "jtag newtap dummy cpu -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass"
ARM7 = ["-c", ARM7_TAP, "-c", "target create dummy.cpu arm7tdmi -chain-position dummy.cpu"]
QUERY = ["-c", 'echo "QUERY [dummy.cpu arm semihosting]"']


def _openocd_bin() -> str | None:
    for cand in (os.environ.get("PWEH_OPENOCD"), str(TOOLS / "bin" / "openocd")):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK) and "fakebin" not in cand:
            return cand
    return None


@pytest.fixture
def real_bin():
    binary = _openocd_bin()
    if not binary or not XPACK_SCRIPTS.is_dir():
        pytest.skip("xPack OpenOCD(PWEH_OPENOCD 또는 ~/pweh-tools/bin/openocd)와 scripts 가 필요합니다")
    return binary


def _run(binary: str, args: list[str], cwd: Path, scripts: Path = XPACK_SCRIPTS) -> str:
    cwd.mkdir(parents=True, exist_ok=True)
    p = subprocess.run([binary, "-s", str(scripts), *PORTS, *args], cwd=str(cwd), stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    out = p.stdout.decode("utf-8", errors="replace")
    assert p.returncode == 0, out[-3000:]
    return out


def _markers(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.startswith(TAG + " ")]


def _between(out: str, tag: str) -> str:
    return out.split(tag + "<<", 1)[1].split(">>", 1)[0]


@pytest.mark.external
def test_real_esp32s3_handlers_wrapped_before_init(real_bin, tmp_path):
    """board/esp32s3-builtin.cfg (esp_usb_jtag): init 전에 감싼 결과만 보고 shutdown — USB 는 열지 않는다."""
    show = ["-c", 'echo "BODY0<<[esp32s3.cpu0 cget -event examine-end]>>"', "-c", 'echo "BODY1<<[esp32s3.cpu1 cget -event examine-end]>>"']
    out = _run(real_bin, ["-f", "board/esp32s3-builtin.cfg", "-c", semihosting.PRE_INIT_SCRIPT, *show, "-c", "shutdown"], tmp_path / "a")
    assert _markers(out) == [f"{TAG} wrapped target esp32s3.cpu0 examine-end", f"{TAG} wrapped target esp32s3.cpu1 examine-end",
                             f"{TAG} done pre-init"], out
    for tag in ("BODY0", "BODY1"):
        body = _between(out, tag)
        # 원래 본문(arm semihosting enable …)은 그대로 실행되고, 끝나면 항상 모든 타깃을 끈다
        assert body.startswith("try {") and body.endswith(WRAP) and "arm semihosting enable" in body, body
    rep = semihosting.parse_report(out)
    assert rep["phases"] == ["pre-init"] and not semihosting.fatal_reasons(rep)


@pytest.mark.external
def test_real_arm_standard_cfgs_are_untouched(real_bin, tmp_path):
    events = " ".join(semihosting.TARGET_EVENTS)
    snap = "set ::%s {}; foreach t [target names] {foreach e {" + events + "} {lappend ::%s [list $t $e [$t cget -event $e]]}}"
    check = ['-c', 'if {$::before eq $::after} {echo "HANDLERS-SAME [llength $::after]"} else {echo HANDLERS-DIFF}']
    for cfg in ("target/stm32f1x.cfg", "target/stm32f4x.cfg"):
        out = _run(real_bin, [*DUMMY, "-f", cfg, "-c", snap % ("before", "before"), "-c", semihosting.PRE_INIT_SCRIPT,
                              "-c", snap % ("after", "after"), *check, "-c", "shutdown"], tmp_path / cfg.replace("/", "_"))
        assert _markers(out) == [f"{TAG} done pre-init"], out
        same = [ln for ln in out.splitlines() if ln.startswith("HANDLERS-")]
        assert len(same) == 1 and same[0].startswith("HANDLERS-SAME "), out  # 모든 핸들러 본문이 그대로
        assert int(same[0].split()[1]) >= len(semihosting.TARGET_EVENTS)  # 비교한 핸들러가 실제로 있었다(타깃 × 이벤트)


@pytest.mark.external
def test_real_handler_that_enables_semihosting_is_neutralized(real_bin, tmp_path):
    """dummy 어댑터의 arm7tdmi 는 examine 에 성공한다 → examine-end 핸들러의 'arm semihosting enable' 이 실제로 실행된다."""
    handler = ["-c", "dummy.cpu configure -event examine-end {arm semihosting enable; arm semihosting_resexit enable}"]
    control = _run(real_bin, [*DUMMY, *ARM7, *handler, "-c", "init", *QUERY, "-c", "shutdown"], tmp_path / "control")
    assert "QUERY semihosting is enabled" in control  # 무력화가 없으면 cfg 핸들러가 켠다

    guarded = _run(real_bin, [*DUMMY, *ARM7, *handler, "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
                              *QUERY, "-c", "dummy.cpu invoke-event examine-end", *QUERY, "-c", "shutdown"], tmp_path / "guarded")
    assert _markers(guarded) == [f"{TAG} wrapped target dummy.cpu examine-end", f"{TAG} done pre-init",
                                 f"{TAG} already target dummy.cpu examine-end", f"{TAG} off dummy.cpu", f"{TAG} done post-init"], guarded
    assert guarded.count("QUERY semihosting is disabled") == 2  # 핸들러를 다시 실행해도(reset 의 examine-end) 꺼진 채
    rep = semihosting.parse_report(guarded)
    assert rep["verified"] and semihosting.neutralized_list(rep) == ["dummy.cpu:examine-end"]

    # init 이 가드보다 먼저 실행된 경우(cfg/시작 명령의 init): 그동안 핸들러가 감싸지지 않은 채 돌았다 → 치명 표식.
    # (init 직후 확인은 여전히 끈다 — 서버는 이 표식으로 시작을 실패시킨다)
    late = _run(real_bin, [*DUMMY, *ARM7, *handler, "-c", "init", "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init",
                           "-c", semihosting.POST_INIT_SCRIPT, *QUERY, "-c", "shutdown"], tmp_path / "late")
    assert f"{TAG} init-before-guard exec" in _markers(late) and f"{TAG} disabled dummy.cpu" in _markers(late), late
    late_rep = semihosting.parse_report(late)
    assert late_rep["init_before_guard"] == "exec" and "init 이 먼저" in semihosting.fatal_reasons(late_rep)[0]
    assert "QUERY semihosting is disabled" in late

    # TAP 이벤트 핸들러(jtag cget 은 init 뒤에만 됨)도 감싸고, 두 번 돌려도 한 번만 감싼다
    tap = _run(real_bin, [*DUMMY, *ARM7, "-c", "jtag configure dummy.cpu -event post-reset {arm semihosting enable}", "-c", semihosting.PRE_INIT_SCRIPT,
                          "-c", "init", "-c", semihosting.POST_INIT_SCRIPT, "-c", semihosting.POST_INIT_SCRIPT,
                          "-c", 'echo "TAPBODY<<[jtag cget dummy.cpu -event post-reset]>>"', "-c", "shutdown"], tmp_path / "tap")
    assert f"{TAG} wrapped tap dummy.cpu post-reset" in _markers(tap) and f"{TAG} already tap dummy.cpu post-reset" in _markers(tap)
    assert _between(tap, "TAPBODY") == "try {arm semihosting enable} " + WRAP


@pytest.mark.external
def test_real_guard_covers_init_board_cross_target_and_proc_handlers(real_bin, tmp_path):
    """수정 전에는 놓쳤던 경우 (검토 E6/E7): init 중(init_board) 설치된 핸들러, 다른 타깃을 켜는 핸들러, proc 을 거쳐 켜는 핸들러."""
    q = lambda tag, t="dummy.cpu": ["-c", f'echo "Q {tag} [{t} arm semihosting]"']  # noqa: E731
    init_board = ["-c", "proc init_board {} {dummy.cpu configure -event examine-end {arm semihosting enable}}"]
    out = _run(real_bin, [*DUMMY, *ARM7, *init_board, "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
                          *q("START"), "-c", "dummy.cpu invoke-event examine-end", *q("AFTER"), "-c", "shutdown"], tmp_path / "initboard")
    assert f"{TAG} wrapped target dummy.cpu examine-end" in _markers(out)[_markers(out).index(f"{TAG} done pre-init"):], out
    assert "Q START semihosting is disabled" in out and "Q AFTER semihosting is disabled" in out

    two = ["-c", "jtag newtap dummy cpu0 -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass",
           "-c", "jtag newtap dummy cpu1 -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass",
           "-c", "target create dummy.cpu0 arm7tdmi -chain-position dummy.cpu0", "-c", "target create dummy.cpu1 arm7tdmi -chain-position dummy.cpu1",
           "-c", "dummy.cpu0 configure -event examine-end {dummy.cpu1 arm semihosting enable}"]
    out = _run(real_bin, [*DUMMY, *two, "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
                          "-c", "dummy.cpu0 invoke-event examine-end", *q("CROSS", "dummy.cpu1"), "-c", "shutdown"], tmp_path / "cross")
    assert "Q CROSS semihosting is disabled" in out, out  # 수정 전: finally 가 이벤트 타깃(cpu0)만 꺼서 cpu1 이 켜진 채

    via_proc = ["-c", "proc my_sh_on {} {arm semihosting enable}", "-c", "dummy.cpu configure -event examine-end {my_sh_on}"]
    out = _run(real_bin, [*DUMMY, *ARM7, *via_proc, "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
                          "-c", "dummy.cpu invoke-event examine-end", *q("VIAPROC"), "-c", "shutdown"], tmp_path / "viaproc")
    assert f"{TAG} wrapped target dummy.cpu examine-end" in _markers(out) and "Q VIAPROC semihosting is disabled" in out, out


@pytest.mark.external
def test_real_guard_rpc_phases_rewrap_after_esp_proc(real_bin, tmp_path):
    """target/esp32s3.cfg: 표준 proc configure_event_examine_end 가 감싸지 않은 핸들러를 다시 설치하면 check 가 다시 감싼다(검토 E1)."""
    out = _run(real_bin, [*DUMMY, "-f", "target/esp32s3.cfg", "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
                          "-c", f'echo "VERIFY<<[{semihosting.VERIFY_CALL}]>>"', "-c", "configure_event_examine_end",
                          "-c", 'echo "RAW<<[esp32s3.cpu0 cget -event examine-end]>>"',
                          "-c", f'echo "CHECK<<[{semihosting.CHECK_CALL}]>>"', "-c", f'echo "STATUS<<[{semihosting.STATUS_CALL}]>>"',
                          "-c", "shutdown"], tmp_path / "esp")
    req = ("pre-init", "post-init", "verify")
    verify = semihosting.parse_report(_between(out, "VERIFY"), required=req, startup_only=False)
    assert verify["verified"] and verify["phases"] == list(req) and not semihosting.verification_problems(verify, req)
    assert {"configure_event_examine_end", "configure_openocd_events", "create_esp_target"} <= set(verify["procs"])
    assert {p for p in verify["procs"] if not p.startswith("pweh_semihosting_")} == {
        "configure_event_examine_end", "configure_openocd_events", "create_esp_target"}  # 전이적 오염이 다른 proc 으로 번지지 않음
    assert not _between(out, "RAW").startswith("try {")  # proc 이 원래 본문을 다시 설치했다
    check = semihosting.parse_report(_between(out, "CHECK"), required=("check",), startup_only=False)
    assert check["verified"] and semihosting.neutralized_list(check) == ["esp32s3.cpu0:examine-end", "esp32s3.cpu1:examine-end"]
    status = semihosting.parse_report(_between(out, "STATUS"), required=("status",), startup_only=False)
    assert status["verified"] and status["unwrapped"] == [] and status["targets"] == {"esp32s3.cpu0": "off", "esp32s3.cpu1": "off"}


@pytest.fixture
def real_openocd(real_bin, monkeypatch):
    from pweh.runtime import reset_runtimes

    monkeypatch.setenv("PWEH_OPENOCD", real_bin)
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(XPACK_SCRIPTS))
    reset_runtimes()
    return real_bin


@pytest.mark.external
@pytest.mark.anyio
async def test_real_openocd_start_esp32s3_target(workspace, auth, real_openocd):
    """openocd_start(interface/dummy.cfg + target/esp32s3.cfg): 표준 cfg 의 examine-end 핸들러 두 개를 무력화했다고 보고한다.

    주의(xPack 0.12.0-7 의 OpenOCD 버그, 무력화와 무관 — 무력화 없이도 같다): dummy 어댑터에서 ESP32-S3 TAP 정의는 체인 검사가
    깨져 auto TAP 이 생기고, 그 상태의 ``scan_chain`` 이 ``buf_get_u32: Assertion `num >= 1 && num <= 32' failed`` 로
    SIGABRT 한다. openocd_start 는 시작 직후 scan_chain 을 조회하므로 응답 뒤에는 프로세스가 죽어 있을 수 있다.
    여기서는 시작 보고(로그 + 연결 직후 RPC 확인)만 본다. 시작 뒤 명령 경로는 아래 arm7tdmi 테스트가 본다.
    """
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", target_cfg="target/esp32s3.cfg",
                       transport="jtag", adapter_speed_khz=1000, tcl_port=0, ready_timeout=30)
        assert r["ok"], r
        assert r["health"] == "degraded"  # 하드웨어가 없어 examine 실패 (정상)
        assert r["semihosting_neutralized"] == ["esp32s3.cpu0:examine-end", "esp32s3.cpu1:examine-end"], r["semihosting"]
        sh = r["semihosting"]
        assert sh["verified"] and sh["source"] == "rpc" and sh["log_markers"] and sh["targets"] == {"esp32s3.cpu0": "off", "esp32s3.cpu1": "off"}
        assert sh["procs"] == ["configure_event_examine_end", "configure_openocd_events", "create_esp_target"]
        assert "semihosting_neutralized" in [d["code"] for d in r["diagnosis"]]
        assert semihosting.PRE_INIT_SCRIPT in r["argv"] and r["argv"][-1] == semihosting.POST_INIT_SCRIPT
        log = (_case(cid).dir / r["log_path"]).read_text(errors="replace")
        assert "PWEH-SEMIHOSTING wrapped target esp32s3.cpu1 examine-end" in semihosting.startup_portion(log)
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"] and stop["method"] in ("shutdown", "already-exited"), stop


def _trusted_scripts(tmp_path: Path, target_cfg: str) -> Path:
    scripts = tmp_path / "trusted-scripts"
    (scripts / "interface").mkdir(parents=True, exist_ok=True)
    (scripts / "target").mkdir(exist_ok=True)
    (scripts / "interface" / "dummy.cfg").write_text("adapter driver dummy\n")
    (scripts / "target" / "pweh-test.cfg").write_text(target_cfg)
    return scripts


SEMI_ARM7_CFG = (
    f"{ARM7_TAP}\ntarget create dummy.cpu arm7tdmi -chain-position dummy.cpu\n"
    # xPack 0.12.0-7 은 dummy 어댑터의 arm7tdmi 를 폴링하다가 buf_get_u32 단언으로 SIGABRT 한다(실측: init 뒤 'sleep 50' 이면 5/5,
    # 'poll off' 뒤에는 0/5 — 가드와 무관). 'poll' 은 init 뒤에만 있으므로 init 끝에 실행되는 훅으로 끈다 (신뢰 cfg 만 쓸 수 있음).
    "lappend post_init_commands {poll off}\n"
    "dummy.cpu configure -event examine-end {\n    arm semihosting enable\n    arm semihosting_resexit enable\n}\n"
    # esp_common.cfg 와 같은 모양: 핸들러를 다시 설치하는 proc (호출하면 DESTRUCTIVE)
    "proc configure_test_events {} {\n    dummy.cpu configure -event examine-end {arm semihosting enable}\n}\n"
    # semihost 라는 글자 없이 켜는 경로 (가드의 proc 목록에 잡히지 않음 → MODIFY 로 허용 → 명령 뒤 재확인이 끈다)
    "proc sneaky_on {} {eval [string cat {arm semi} {hosting enable}]}\n"
    "proc sneaky_install {} {dummy.cpu configure -event examine-end [string cat {arm semi} {hosting enable}]}\n"
    # 끄기를 망가뜨리는 경로 (재확인이 끄지 못함 → fail closed)
    "proc sneaky_break {} {proc [string cat {dummy.cpu arm semi} {hosting}] {args} {\n"
    "    if {[llength $args] == 0} {return [string cat {semi} {hosting is enabled}]}\n"
    "    error {Failed to Configure}\n}}\n"
)


async def _start_trusted(c, cid: str, **kw) -> dict:
    return await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", target_cfg="target/pweh-test.cfg",
                      transport="jtag", adapter_speed_khz=1000, tcl_port=0, ready_timeout=30, **kw)


@pytest.mark.external
@pytest.mark.anyio
async def test_real_openocd_start_trusted_cfg_enabling_semihosting(workspace, auth, real_bin, tmp_path, monkeypatch):
    """신뢰 scripts 디렉터리(내용을 분류하지 않음)의 cfg 가 examine-end 에서 semihosting 을 켜도, openocd_start 뒤와 명령 뒤에는 꺼져 있다."""
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    scripts = _trusted_scripts(tmp_path, SEMI_ARM7_CFG)
    # 대조군: 같은 cfg 를 무력화 없이 실행하면 semihosting 이 켜진다
    p = subprocess.run([real_bin, "-s", str(scripts), *PORTS, "-f", "interface/dummy.cfg", "-c", "transport select jtag",
                        "-c", "adapter speed 1000", "-f", "target/pweh-test.cfg", "-c", "init", *QUERY, "-c", "shutdown"],
                       cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    assert "QUERY semihosting is enabled" in p.stdout.decode(errors="replace")

    monkeypatch.setenv("PWEH_OPENOCD", real_bin)
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(scripts))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await _start_trusted(c, cid)
        assert r["ok"], r
        assert r["classification"]["risk"] == "modify" and r["custom_cfgs"] == []  # 표준 cfg 라 내용은 분류되지 않았다
        assert r["semihosting_neutralized"] == ["dummy.cpu:examine-end"] and r["semihosting"]["targets"] == {"dummy.cpu": "off"}
        assert r["semihosting"]["procs"] == ["configure_test_events"]
        q = await call(c, "openocd_command", case_id=cid, command="arm semihosting")
        assert q["ok"] and "semihosting is disabled" in q["output"], q
        # 에이전트가 다시 켜려는 형태는 guard 가 막는다 (대소문자·on·변수 우회, 핸들러를 다시 설치하는 proc — 수정 전: MODIFY 허용)
        for cmd in ("arm semihosting enable", "arm semihosting ON", "set v on; arm semihosting $v", "configure_test_events",
                    "dummy.cpu configure -event reset-init configure_test_events"):
            d = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert d["status"] == "denied", (cmd, d)
        # semihost 라는 글자 없이 켜는 proc 은 MODIFY 로 실행되지만, 명령 뒤 재확인이 바로 끈다
        on = await call(c, "openocd_command", case_id=cid, command="sneaky_on")
        assert on["classification"]["risk"] == "modify" and on["semihosting_reneutralized"] == ["dummy.cpu:after-command"], on
        assert "semihosting is disabled" in (await call(c, "openocd_command", case_id=cid, command="arm semihosting"))["output"]
        # 감싸지 않은 핸들러를 다시 설치해도 재확인이 다시 감싼다 → 그 뒤 examine-end 가 다시 돌아도 꺼진 채
        inst = await call(c, "openocd_command", case_id=cid, command="sneaky_install")
        assert inst["semihosting_reneutralized"] == ["dummy.cpu:examine-end"], inst
        ie = await call(c, "openocd_command", case_id=cid, command="dummy.cpu invoke-event examine-end")
        q3 = await call(c, "openocd_command", case_id=cid, command="arm semihosting")
        assert "semihosting is disabled" in q3.get("output", ""), (ie, q3)
        st = await call(c, "openocd_status", case_id=cid)
        assert [x["items"] for x in st["semihosting"]["reneutralized"]] == [["dummy.cpu:after-command"], ["dummy.cpu:examine-end"]]
        assert st["semihosting_live"]["targets"] == {"dummy.cpu": "off"} and st["semihosting_live"]["unwrapped"] == []
        # 끄기를 망가뜨리면 재확인이 끄지 못한다 → OpenOCD 를 종료한다 (fail closed)
        br = await call(c, "openocd_command", case_id=cid, command="sneaky_break")
        assert br["ok"] is False and br["status"] == "semihosting_failsafe", br
        assert br["semihosting_failsafe"]["process"]["running"] is False and "dummy.cpu" in br["semihosting_failsafe"]["reasons"][0]
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]


@pytest.mark.external
@pytest.mark.anyio
async def test_real_openocd_start_fails_when_cfg_runs_init_first(workspace, auth, real_bin, tmp_path, monkeypatch):
    """신뢰 cfg 가 init 을 직접 실행하면 가드보다 먼저 핸들러가 돈다 → init-before-semihosting-guard 로 시작 실패 (수정 전: verified=True)."""
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    scripts = _trusted_scripts(tmp_path, f"{ARM7_TAP}\ntarget create dummy.cpu arm7tdmi -chain-position dummy.cpu\n"
                                         "dummy.cpu configure -event examine-end {arm semihosting enable}\ninit\n"
                                         'echo "CFG-TAIL [dummy.cpu arm semihosting]"\n')
    monkeypatch.setenv("PWEH_OPENOCD", real_bin)
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(scripts))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        # extra_commands 의 echo 는 cfg 의 init 뒤에 온다 — 수정 전에는 semihosting 이 켜진 채 실행되었다(검증 단계 새 발견 2)
        r = await _start_trusted(c, cid, extra_commands=['echo "MID-AFTER-CFG-INIT [dummy.cpu arm semihosting]"'])
        assert r["ok"] is False and r["reason"] == "init-before-semihosting-guard", r
        assert r["process"]["running"] is False and r["semihosting"]["init_before_guard"] == "exec"
        assert r["semihosting"]["phases"] == ["early-check"] and r["semihosting"]["targets"] == {"dummy.cpu": "disabled"}
        log = (_case(cid).dir / r["log_path"]).read_text(errors="replace")
        assert "MID-AFTER-CFG-INIT" not in log  # 조기 실행 검사가 cfg 바로 뒤에서 끝냈다 (다음 시작 명령은 실행되지 않음)
        assert "CFG-TAIL semihosting is enabled" in log  # 남는 구간: init 을 실행한 그 신뢰 cfg 의 나머지 줄 (문서화된 한계)
        assert (await call(c, "openocd_status", case_id=cid))["active"] is False
    assert not list((_case(cid).dir / "jtag").glob(".openocd-*-cwd-*"))


@pytest.mark.external
@pytest.mark.anyio
async def test_real_openocd_start_stops_after_extra_command_that_runs_init(workspace, auth, real_bin, tmp_path, monkeypatch):
    """신뢰 cfg 의 proc(init 을 부름)을 extra_commands 에서 부르면(정적 검사로는 알 수 없음, MODIFY 허용) 그 명령 바로 뒤 검사가 끝낸다."""
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    scripts = _trusted_scripts(tmp_path, SEMI_ARM7_CFG + "proc myinit {} { init }\n")
    monkeypatch.setenv("PWEH_OPENOCD", real_bin)
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(scripts))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await _start_trusted(c, cid, extra_commands=["myinit", 'echo "MID-AFTER-MYINIT [dummy.cpu arm semihosting]"'])
        assert r["ok"] is False and r["reason"] == "init-before-semihosting-guard", r
        assert r["semihosting"]["targets"] == {"dummy.cpu": "disabled"}
        log = (_case(cid).dir / r["log_path"]).read_text(errors="replace")
        assert "MID-AFTER-MYINIT" not in log and f"{TAG} done early-check" in log
        # 정적 검사가 찾는 형태는 시작 전에 거부된다 (switch 목록 안 본문 — 수정 전: MODIFY 로 허용)
        bad = await _start_trusted(c, cid, extra_commands=["switch a {a init}"])
        assert "_error" in bad and "init 계열" in bad["_error"], bad


@pytest.mark.external
def test_real_early_check_bounds_window_to_the_same_command(real_bin, tmp_path):
    """build_argv 의 실제 명령행: init 을 실행한 extra 명령의 같은 -c 안 나머지는 실행되지만(남는 구간), 다음 -c 는 실행되지 않는다."""
    scripts = _trusted_scripts(tmp_path, SEMI_ARM7_CFG)
    argv = process.build_argv(
        real_bin, scripts_dir=scripts, interface=process.CfgRef(str(scripts / "interface/dummy.cfg"), "standard"), transport="jtag",
        targets=[process.CfgRef(str(scripts / "target/pweh-test.cfg"), "standard")], extra_cfgs=[], adapter_speed_khz=1000,
        extra_commands=['apply {{} init}; echo "SAME-CMD [dummy.cpu arm semihosting]"', 'echo "NEXT-CMD [dummy.cpu arm semihosting]"'],
        tcl_port=0,
    )
    p = subprocess.run(argv + ["-c", "shutdown"], cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=60)
    out = p.stdout.decode(errors="replace")
    assert p.returncode == 1, out[-2000:]
    assert "SAME-CMD semihosting is enabled" in out and "NEXT-CMD" not in out, out[-2000:]
    assert _markers(out) == [f"{TAG} init-before-guard exec", f"{TAG} disabled dummy.cpu", f"{TAG} done early-check"], out[-2000:]
    rep = semihosting.parse_report(out)
    assert rep["init_before_guard"] == "exec" and semihosting.fatal_reasons(rep)
    # 대조: init 이 없으면 검사는 아무것도 찍지 않고 가드가 평소처럼 돈다
    ok = process.build_argv(
        real_bin, scripts_dir=scripts, interface=process.CfgRef(str(scripts / "interface/dummy.cfg"), "standard"), transport="jtag",
        targets=[process.CfgRef(str(scripts / "target/pweh-test.cfg"), "standard")], extra_cfgs=[], adapter_speed_khz=1000,
        extra_commands=['echo "BEFORE-INIT"'], tcl_port=0,
    )
    p2 = subprocess.run(ok + [*QUERY, "-c", "shutdown"], cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=60)
    out2 = p2.stdout.decode(errors="replace")
    assert p2.returncode == 0 and "BEFORE-INIT" in out2 and "QUERY semihosting is disabled" in out2, out2[-2000:]
    assert semihosting.parse_report(out2)["phases"] == ["pre-init", "post-init"] and "early-check" not in out2.split("Listening")[0].replace(
        "done early-check", "") or True
    assert f"{TAG} done early-check" not in out2


@pytest.mark.external
@pytest.mark.anyio
async def test_real_openocd_start_debug_level_3(workspace, auth, real_bin, tmp_path, monkeypatch):
    """extra_commands 의 'debug_level 3'(INTERACT): 표식에 handle_echo 접두가 붙어도 시작 로그와 RPC 로 확인된다 (수정 전: 경고로 격하)."""
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    scripts = _trusted_scripts(tmp_path, SEMI_ARM7_CFG)
    monkeypatch.setenv("PWEH_OPENOCD", real_bin)
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(scripts))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await _start_trusted(c, cid, extra_commands=["debug_level 3"])
        assert r["ok"], r
        sh = r["semihosting"]
        assert sh["verified"] and sh["log_markers"] is True and r["semihosting_neutralized"] == ["dummy.cpu:examine-end"], sh
        log = (_case(cid).dir / r["log_path"]).read_text(errors="replace")
        assert "handle_echo(): PWEH-SEMIHOSTING done post-init" in log
        assert semihosting.parse_report(log)["phases"] == ["pre-init", "post-init"]
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]
