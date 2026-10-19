"""openocd_start 가 띄운 OpenOCD 에서 semihosting 을 끄고(무력화) 그 상태를 계속 확인하는 Tcl 가드와 결과 해석.

왜 필요한가
-----------
semihosting 이 켜지면 **타깃 펌웨어**가 OpenOCD 를 통해 호스트 파일을 열고/쓰고/지우고, ``SYS_SYSTEM`` 으로 호스트 명령까지
실행할 수 있다(OpenOCD semihosting_common.c). 분석 대상 펌웨어는 신뢰할 수 없으므로 분석 PC 를 넘겨주는 것과 같다.
에이전트가 보내는 ``arm semihosting enable`` 은 guard 가 DESTRUCTIVE 로 막지만, 신뢰 scripts 디렉터리의 표준 cfg 는 내용을
분류하지 않는다. 그런데 표준 cfg 가 이벤트 핸들러로 semihosting 을 켠다: xPack 0.12.0-7 의 ``target/esp_common.cfg``
(84~110행)는 cpu0/cpu1 의 ``examine-end`` 핸들러에서 ``arm semihosting enable`` · ``arm semihosting_resexit enable`` ·
``arm semihosting_basedir`` 를 실행한다(Espressif 포크도 같다). ESP32/ESP32-S2/ESP32-S3 를 표준 cfg 로 시작하면 타깃을
검사(examine)하는 순간 semihosting 이 켜진다. 같은 cfg 의 proc ``configure_event_examine_end`` /
``configure_openocd_events`` / ``create_esp_target`` 를 다시 부르면 감싸지 않은 핸들러가 다시 설치된다.

가드 (Tcl proc ``pweh_semihosting_guard <단계>``, :data:`PRE_INIT_SCRIPT` 가 정의)
-------------------------------------------------------------------------------
- init 조기 실행 검사 (:data:`EARLY_CHECK_SCRIPT`, ``-c``, ``-f`` 하나하나와 extra_commands 하나하나 뒤 — proc 없는 한 줄):
  ``[command mode]`` 가 ``config`` 가 아니면 init 이 이미 실행됐다(신뢰 cfg 끝의 ``init``, trusted cfg 의 proc, 정적 검사가 못 찾은
  형태). 모든 타깃의 semihosting 을 바로 끄고 ``init-before-guard`` 표식(치명)과 ``done early-check`` 를 남긴 뒤 ``error`` 로
  OpenOCD 를 끝낸다 — 시작 ``-c`` 의 오류는 뒤의 ``-c`` 를 실행하지 않고 종료 코드 1 로 끝난다(실측). 그래서 init 을 먼저 실행한
  cfg/명령 *뒤의* 시작 명령은 semihosting 이 켜진 채 실행되지 않는다. 남는 구간: init 을 실행한 그 신뢰 cfg 파일의 나머지 줄,
  또는 그 extra_commands 항목 하나의 나머지(같은 ``-c`` 안 ``;`` 뒤 — 정적 검사와 DESTRUCTIVE 승인을 모두 통과한 경우만).
- ``pre-init`` (``-c``, 모든 cfg·extra_commands 뒤, ``init`` 직전): ``[command mode]`` 가 ``config`` 가 아니면 init 이 이미
  실행된 것이다(실측: init 전 ``config``, 뒤 ``exec``) → ``init-before-guard`` 표식(치명 — 서버는
  ``init-before-semihosting-guard`` 로 시작 실패). 그 다음 타깃마다 이벤트 핸들러 본문(``<타깃> cget -event <이름>``)을 읽어
  *관련* 핸들러(본문에 ``semihost`` 가 있거나, semihosting 을 켜는 proc 이름이 들어 있음)를
  ``try {원래 본문} finally {<모든 타깃 semihosting 끄기>}`` 로 바꾼다(:data:`WRAP_FINALLY`). 원래 본문은 그대로 실행되고(같은
  프레임, 오류·return 도 그대로 전파) 끝나면 항상 **모든 타깃**의 semihosting 이 꺼진다(다른 타깃을 켜는 핸들러 대비).
  관련 없는 핸들러와 ARM 표준 cfg(예: target/stm32f1x.cfg)는 건드리지 않는다.
- ``post-init`` (``-c``, ``init`` 직후 — TCL 서버가 연결을 받기 전): ``command mode`` 가 ``exec`` 인지 확인하고, init 중에
  설치된 핸들러(init_board/init_targets)까지 다시 감싼 뒤, JTAG TAP 이벤트 핸들러(``jtag cget`` 은 init 뒤에만 된다)도 감싸고,
  타깃마다 ``command mode <타깃> arm semihosting`` 으로 조용히 확인한 뒤(없는 하위 명령을 부르면 OpenOCD 가 도움말 전체를
  로그에 찍는다) ``<타깃> arm semihosting`` 조회가 enabled 면 끄고 다시 조회해 확인한다.
- ``verify`` (TCL RPC, 서버가 연결 직후 **반드시** 부른다): ``post-init`` 과 같은 확인·감싸기·끄기를 다시 하고, 시작 단계
  표식(전역 변수에 기록 — 로그 형식/리다이렉트와 무관)과 이번 표식을 함께 돌려준다. 이 결과가 없거나 불완전하면 서버는
  OpenOCD 를 끄고 시작 실패로 돌려준다(semihosting 이 꺼졌다고 확신할 수 없으면 실행하지 않는다).
- ``check`` (TCL RPC, MODIFY 이상 명령·halt/resume/reset·쓰기 뒤): ``verify`` 와 같지만 이번 표식만 돌려준다.
  켜진 타깃을 찾아 끄면 ``semihosting_reneutralized``, 끄지 못하면 서버가 OpenOCD 를 종료한다(fail closed).
- ``status`` (TCL RPC, openocd_status): 읽기 전용 — 타깃별 상태(``enabled``/``off``…)와 감싸지 않은 관련 핸들러(``unwrapped``).

RPC 단계는 semihosting 을 켜는 proc(본문에 ``semihost`` 가 있거나 그런 proc 을 부르는 proc — 전이적, 최대 16단계) 목록도
``proc <이름>`` 표식으로 돌려준다. 서버는 이 목록을 세션에 두고 그 proc 호출을 DESTRUCTIVE 로 분류한다(guard.classify_command).

표식 형식: ``PWEH-SEMIHOSTING <종류> …`` 한 줄. 단계의 끝은 ``PWEH-SEMIHOSTING done <단계>``. 로그(시작 구간)에서는
``-d3`` 이상의 ``User : … handle_echo(): `` 접두도 받아들이고, ``Debug: … script_debug(): command - echo …`` 같은 줄은 무시한다.

실측(xPack 0.12.0-7, 하드웨어 없이): ``<타깃> cget -event`` / ``configure -event`` 는 init 전에 쓸 수 있고, ``eventlist`` ·
``was_examined`` · ``jtag cget`` 은 init 뒤에만 된다. ``arm semihosting``(조회 포함)은 EXEC 전용이라 init 전(``target init``
뒤에도)에는 실패한다 → init 전에 semihosting 을 켤 수 있는 경로는 init 자체(examine-end)뿐이다. dummy 어댑터의 arm7tdmi 타깃은
examine 에 성공하므로 ``examine-end`` 핸들러의 ``arm semihosting enable`` 이 실제로 semihosting 을 켜는 것과, 감싼 뒤에는
꺼진 상태로 끝나는 것을 확인했다(tests/servers/test_openocd_semihosting.py 의 external 테스트).
"""

from __future__ import annotations

import re
from typing import Any

MARKER = "PWEH-SEMIHOSTING"
GUARD_PROC = "pweh_semihosting_guard"

# OpenOCD target.c nvp_target_event (xPack 0.12.0-7 의 오류 메시지 'try one of:' 와 같다). 새 이벤트는 실행 중에 그 메시지에서 더한다.
TARGET_EVENTS = (
    "gdb-halt", "halted", "resumed", "resume-start", "resume-end", "step-start", "step-end", "gdb-start", "gdb-end",
    "reset-start", "reset-assert-pre", "reset-assert", "reset-assert-post", "reset-deassert-pre", "reset-deassert-post",
    "reset-init", "reset-end", "examine-start", "examine-fail", "examine-end", "debug-halted", "debug-resumed",
    "gdb-attach", "gdb-detach", "gdb-flash-write-start", "gdb-flash-write-end", "gdb-flash-erase-start",
    "gdb-flash-erase-end", "trace-config",
)
# OpenOCD jtag/tcl.c (jtag cget <tap> -event 오류 메시지와 같다)
TAP_EVENTS = ("post-reset", "setup", "tap-enable", "tap-disable")

# 감싼 핸들러의 finally 본문: 켜져 있는 모든 타깃의 semihosting 을 끈다(다른 타깃을 켜는 핸들러 대비). semihosting 이 없는
# 타깃은 command mode 로 건너뛰어 도움말을 찍지 않고, 조회(examine 이 필요 없음)가 enabled 인 타깃만 끈다 — 끄기는 examine 된
# 타깃만 받고(아니면 'Target not examined yet') ARM7/9 에서는 vector catch 를 지우므로, 무조건 끄면 init 중(다른 코어가 아직
# examine 전) 오류 줄이 생긴다(실측). 이벤트 본문은 호출한 프레임에서 실행되므로 변수 이름에 _pweh_sh_ 접두를 붙인다.
# 이 문자열과 정확히 같은 4원소 리스트(try 본문 finally WRAP)인지로 이미 감싼 핸들러를 알아본다(두 번 감싸지 않음).
WRAP_FINALLY = (
    "catch {foreach _pweh_sh_t [target names] {"
    "if {![catch {command mode $_pweh_sh_t arm semihosting} _pweh_sh_m] && $_pweh_sh_m eq {unknown}} continue; "
    "if {![catch {$_pweh_sh_t arm semihosting} _pweh_sh_q] && [string match -nocase {*is enabled*} $_pweh_sh_q]} "
    "{catch {$_pweh_sh_t arm semihosting disable}}}}"
)

# 주의: OpenOCD -d3 은 -c 인자(이 스크립트)를 줄마다 로그에 찍는다 → 표식 문자열로 시작하는 소스 줄을 두지 않는다($tag 로 만든다).
_TCL_PROCS = r"""proc pweh_semihosting_events {prefix known} {
    set names $known
    if {[catch {{*}$prefix pweh-no-such-event} msg] && [regexp {try one of: (.*)} $msg -> rest]} {
        foreach n [split [string map {{, or } {, }} $rest] ,] {
            set n [string trim $n]
            if {$n ne {} && [lsearch -exact $names $n] < 0} {lappend names $n}
        }
    }
    return $names
}
proc pweh_semihosting_flat {s} {
    return [string range [string map [list \n { } \r { }] $s] 0 299]
}
proc pweh_semihosting_mark {line {quiet 0}} {
    global pweh_semihosting_out
    set tag PWEH-SEMIHOSTING
    set line [string map [list \n { } \r { }] $line]
    lappend pweh_semihosting_out "$tag $line"
    if {!$quiet} {echo "$tag $line"}
}
proc pweh_semihosting_wrapped {body wrap} {
    if {[catch {llength $body} n] || $n != 4} {return 0}
    return [expr {[lindex $body 0] eq {try} && [lindex $body 2] eq {finally} && [lindex $body 3] eq $wrap}]
}
proc pweh_semihosting_procs {} {
    set all [info procs]
    set hit {}
    foreach p $all {
        if {[string match -nocase *semihost* $p] || (![catch {info body $p} b] && [string match -nocase *semihost* $b])} {
            lappend hit $p
        }
    }
    for {set round 0} {$round < 16} {incr round} {
        set more 0
        foreach p $all {
            if {[lsearch -exact $hit $p] >= 0 || [catch {info body $p} b]} continue
            foreach q $hit {
                if {[string first $q $b] >= 0} {lappend hit $p; incr more; break}
            }
        }
        if {!$more} break
    }
    return $hit
}
proc pweh_semihosting_relevant {body procs} {
    if {[string match -nocase *semihost* $body]} {return 1}
    foreach q $procs {
        if {[string first $q $body] >= 0} {return 1}
    }
    return 0
}
proc pweh_semihosting_wrap {scope wrap procs readonly quiet} {
    if {$scope eq {target}} {
        set objs [target names]
    } elseif {[catch {jtag names} objs]} {
        return
    }
    foreach o $objs {
        if {$scope eq {target}} {
            set get [list $o cget -event]
            set put [list $o configure -event]
            set known {@TARGET_EVENTS@}
        } else {
            set get [list jtag cget $o -event]
            set put [list jtag configure $o -event]
            set known {@TAP_EVENTS@}
        }
        foreach e [pweh_semihosting_events $get $known] {
            if {[catch {{*}$get $e} body] || ![pweh_semihosting_relevant $body $procs]} continue
            if {[pweh_semihosting_wrapped $body $wrap]} {pweh_semihosting_mark "already $scope $o $e" $quiet; continue}
            if {$readonly} {pweh_semihosting_mark "unwrapped $scope $o $e"; continue}
            if {[catch {{*}$put $e [list try $body finally $wrap]} err]} {
                pweh_semihosting_mark "wrap-failed $scope $o $e [pweh_semihosting_flat $err]"
            } elseif {[catch {{*}$get $e} now] || ![pweh_semihosting_wrapped $now $wrap]} {
                pweh_semihosting_mark "wrap-failed $scope $o $e handler unchanged after configure"
            } else {
                pweh_semihosting_mark "wrapped $scope $o $e"
            }
        }
    }
}
proc pweh_semihosting_targets {readonly quiet} {
    foreach t [target names] {
        set mode try
        catch {set mode [command mode $t arm semihosting]}
        if {$mode eq {unknown}} {pweh_semihosting_mark "unsupported $t" $quiet; continue}
        if {[catch {$t arm semihosting} q]} {pweh_semihosting_mark "unsupported $t [pweh_semihosting_flat $q]" $quiet; continue}
        if {![string match -nocase {*is enabled*} $q]} {pweh_semihosting_mark "off $t" $quiet; continue}
        if {$readonly} {pweh_semihosting_mark "enabled $t"; continue}
        set r {}
        if {[catch {$t arm semihosting disable} r] || [catch {$t arm semihosting} q] || [string match -nocase {*is enabled*} $q]} {
            pweh_semihosting_mark "disable-failed $t [pweh_semihosting_flat [concat $r $q]]"
        } else {
            pweh_semihosting_mark "disabled $t"
        }
    }
}
proc pweh_semihosting_guard {phase} {
    global pweh_semihosting_out pweh_semihosting_startup
    set pweh_semihosting_out {}
    if {$phase eq {pre-init} || ![info exists pweh_semihosting_startup]} {set pweh_semihosting_startup {}}
    set wrap {@WRAP@}
    set startup [expr {$phase eq {pre-init} || $phase eq {post-init}}]
    set quiet [expr {!$startup}]
    set readonly [expr {$phase eq {status}}]
    if {[catch {
        if {[catch {command mode} mode]} {error "command mode failed: $mode"}
        if {$phase eq {pre-init}} {
            if {$mode ne {config}} {pweh_semihosting_mark "init-before-guard $mode"}
            pweh_semihosting_wrap target $wrap [pweh_semihosting_procs] 0 0
        } elseif {[lsearch -exact {post-init verify check status} $phase] >= 0} {
            if {$mode ne {exec}} {error "init did not complete (command mode=$mode)"}
            set procs [pweh_semihosting_procs]
            pweh_semihosting_wrap target $wrap $procs $readonly $quiet
            pweh_semihosting_wrap tap $wrap $procs $readonly $quiet
            pweh_semihosting_targets $readonly $quiet
            if {!$startup} {
                foreach p $procs {pweh_semihosting_mark "proc $p" 1}
            }
        } else {
            error "unknown phase $phase"
        }
    } err]} {
        pweh_semihosting_mark "error $phase [pweh_semihosting_flat $err]"
    }
    pweh_semihosting_mark "done $phase"
    if {$startup} {
        foreach l $pweh_semihosting_out {lappend pweh_semihosting_startup $l}
        return {}
    }
    set out $pweh_semihosting_out
    if {$phase eq {verify}} {set out [concat $pweh_semihosting_startup $out]}
    return [join $out \n]
}"""

# init 조기 실행 검사 (-c, 모든 -f 와 extra_commands 하나하나 뒤): ``[command mode]`` 가 config 가 아니면 init 이 이미 실행된
# 것이다(신뢰 cfg 의 init, 정적 검사가 못 찾은 init). 그때까지 감싸지 않은 핸들러가 semihosting 을 켰을 수 있으므로 모든 타깃의
# semihosting 을 바로 끄고(WRAP_FINALLY 와 같은 순서) 치명 표식을 남긴 뒤 ``error`` 로 OpenOCD 를 끝낸다 — 시작 -c 의 오류는
# 뒤의 -c 를 실행하지 않고 프로세스를 끝낸다(xPack 0.12.0-7 실측: 오류 뒤 echo 가 찍히지 않고 종료 코드 1). 그래서 init 뒤에
# 오는 시작 명령(extra_commands 의 reset run·sleep 등)이 semihosting 이 켜진 채 실행되지 않는다.
# proc 을 정의하지 않는 한 줄 스크립트다: extra_commands 가 앞서 정의한 proc 을 덮어쓸 수 없고(proc/rename 은 DESTRUCTIVE),
# -d3 이 여러 줄 -c 인자의 둘째 줄부터를 그대로 로그에 찍어도 표식으로 시작하는 줄이 생기지 않는다. 표식 문자열은 변수로 만든다.
EARLY_CHECK_SCRIPT = (
    "if {[catch {command mode} _pweh_sh_mode]} {"
    "set _pweh_sh_tag PWEH-SEMIHOSTING; echo \"$_pweh_sh_tag error early-check command mode failed\"; "
    "echo \"$_pweh_sh_tag done early-check\"; error {PWEH: command mode failed before init - stopping OpenOCD}"
    "} elseif {$_pweh_sh_mode ne {config}} {"
    "set _pweh_sh_tag PWEH-SEMIHOSTING; echo \"$_pweh_sh_tag init-before-guard $_pweh_sh_mode\"; "
    "catch {foreach _pweh_sh_t [target names] {"
    "if {![catch {command mode $_pweh_sh_t arm semihosting} _pweh_sh_m] && $_pweh_sh_m eq {unknown}} continue; "
    "if {[catch {$_pweh_sh_t arm semihosting} _pweh_sh_q] || ![string match -nocase {*is enabled*} $_pweh_sh_q]} continue; "
    "set _pweh_sh_r {}; "
    "if {[catch {$_pweh_sh_t arm semihosting disable} _pweh_sh_r] || [catch {$_pweh_sh_t arm semihosting} _pweh_sh_q] "
    "|| [string match -nocase {*is enabled*} $_pweh_sh_q]} "
    "{echo \"$_pweh_sh_tag disable-failed $_pweh_sh_t [string range [string map [list \\n { } \\r { }] [concat $_pweh_sh_r $_pweh_sh_q]] 0 199]\"} "
    "else {echo \"$_pweh_sh_tag disabled $_pweh_sh_t\"}}} _pweh_sh_e; "
    "echo \"$_pweh_sh_tag done early-check\"; "
    "error \"PWEH: init ran before the semihosting guard (command mode=$_pweh_sh_mode) - stopping OpenOCD\"}"
)

# init 직전 -c: proc 들을 정의하고 핸들러를 감싼다. 시작 단계의 반환값은 빈 문자열이라 OpenOCD 가 결과를 로그에 찍지 않는다.
PRE_INIT_SCRIPT = (
    _TCL_PROCS.replace("@WRAP@", WRAP_FINALLY)
    .replace("@TARGET_EVENTS@", " ".join(TARGET_EVENTS))
    .replace("@TAP_EVENTS@", " ".join(TAP_EVENTS))
    + "\n" + GUARD_PROC + " pre-init"
)
# init 직후 -c
POST_INIT_SCRIPT = GUARD_PROC + " post-init"
# TCL RPC 로 부르는 단계 (데이터 봉투 안에서 실행 — 결과는 표식 줄들)
VERIFY_CALL = GUARD_PROC + " verify"
CHECK_CALL = GUARD_PROC + " check"
STATUS_CALL = GUARD_PROC + " status"

STARTUP_PHASES = ("pre-init", "post-init")
#: init 조기 실행 검사의 단계 이름 (표식 'done early-check' — 이 표식이 있으면 OpenOCD 는 이미 오류로 끝났다)
EARLY_CHECK_PHASE = "early-check"
# 단계별로 '켜져 있어 끈 타깃' 의 이름 꼬리 (semihosting_neutralized / semihosting_reneutralized)
_DISABLED_SUFFIX = {"post-init": "after-init", "verify": "after-start", "check": "after-command"}
# 여러 단계의 타깃 상태를 합칠 때의 우선순위 (높을수록 먼저)
_STATE_RANK = {"disable-failed": 5, "enabled": 4, "disabled": 3, "off": 2, "unsupported": 1}

# 맨 앞(접두 없음) 또는 -d3 이상의 'User : <n> <ms> <파일>:<줄> handle_echo(): ' 접두. 'Debug: … script_debug(): command - echo …'
# 처럼 표식이 줄 가운데 있는 줄은 맞지 않는다.
_LINE = re.compile(
    r"^(?:User\s*:\s*\d+\s+\d+\s+\S+\s+handle_echo\(\):\s)?" + re.escape(MARKER) + r" (?P<kind>[a-z-]+)(?: (?P<rest>.*))?$"
)
_LISTEN_TCL = re.compile(r"Listening on port \d+ for tcl connections")


def startup_portion(log_text: str) -> str:
    """TCL 서버가 연결을 받기 전(시작 스크립트가 모두 끝난 시점)까지의 로그. Listening 줄이 없으면 전체."""
    m = _LISTEN_TCL.search(log_text or "")
    return (log_text or "")[: m.start()] if m else (log_text or "")


def _detail(text: str | None) -> str:
    return (text or "").strip()[:300]


def marker_lines(text: str) -> list[tuple[str, str]]:
    """텍스트에서 표식 줄만 (종류, 나머지) 로. -d3 접두를 받아들이고 줄 가운데 있는 표식(디버그 줄)은 무시한다."""
    out = []
    for line in (text or "").split("\n"):
        m = _LINE.match(line.rstrip("\r"))
        if m:
            out.append((m.group("kind"), m.group("rest") or ""))
    return out


def parse_report(text: str, *, required: tuple[str, ...] = STARTUP_PHASES, startup_only: bool = True) -> dict[str, Any]:
    """``PWEH-SEMIHOSTING`` 표식 → 보고 dict.

    text: OpenOCD 시작 로그(``startup_only=True`` — TCL 포트가 열리기 전 부분만 본다) 또는 RPC 단계의 반환값(``False``).
    required: ``verified`` 가 되려면 끝나야 하는 단계 (시작 로그 = pre-init·post-init, RPC verify = + verify, check = check).

    반환 키:
    - ``policy``: 항상 ``"disabled"`` (서버는 semihosting 을 꺼 둔 채 운용한다)
    - ``phases``: 끝난 단계 순서대로 (``done <단계>`` 표식)
    - ``handlers_wrapped``: ``[{scope: target|tap, name, event}]`` — 감싼(무력화한) 이벤트 핸들러 (중복 없음)
    - ``already_wrapped``: 이미 감싸져 있던 핸들러 (같은 형식)
    - ``unwrapped``: (status 단계) 감싸지 않은 관련 핸들러 (같은 형식)
    - ``targets``: ``{타깃: off|disabled|enabled|unsupported|disable-failed}`` — 단계들을 합친 상태
      (disabled = 켜져 있어서 끔, enabled = status 단계에서 켜져 있음)
    - ``phase_targets``: ``{단계: {타깃: 상태}}``
    - ``procs``: semihosting 을 켜는 proc 이름 (RPC 단계)
    - ``failures``: ``[{kind, phase, …, detail}]`` — 감싸기/끄기 실패, init 이 먼저 실행됨, 스크립트 오류, 끝나지 않은 단계
    - ``init_before_guard``: init 이 가드보다 먼저 실행되었으면 그때의 ``command mode`` 값, 아니면 None
    - ``verified``: required 단계가 모두 끝났고 실패가 없음
    """
    report: dict[str, Any] = {
        "policy": "disabled", "phases": [], "handlers_wrapped": [], "already_wrapped": [], "unwrapped": [], "targets": {},
        "phase_targets": {}, "procs": [], "failures": [], "init_before_guard": None, "verified": False,
    }
    body = startup_portion(text) if startup_only else (text or "")
    pending: list[tuple[str, str]] = []

    def handler_entry(parts: list[str]) -> dict[str, str] | None:
        if len(parts) >= 3 and parts[0] in ("target", "tap"):
            return {"scope": parts[0], "name": parts[1], "event": parts[2]}
        return None

    def flush(phase: str) -> None:
        states = report["phase_targets"].setdefault(phase, {})
        for kind, rest in pending:
            parts = rest.split(" ", 3)
            if kind in ("wrapped", "already", "unwrapped"):
                h = handler_entry(parts)
                key = {"wrapped": "handlers_wrapped", "already": "already_wrapped", "unwrapped": "unwrapped"}[kind]
                if h is not None and h not in report[key]:
                    report[key].append(h)
            elif kind == "wrap-failed" and len(parts) >= 3:
                report["failures"].append({"kind": kind, "phase": phase, "scope": parts[0], "name": parts[1], "event": parts[2],
                                           "detail": _detail(parts[3] if len(parts) > 3 else "")})
            elif kind in ("off", "disabled", "unsupported", "enabled", "disable-failed") and parts and parts[0]:
                t = parts[0]
                states[t] = kind
                if kind == "disable-failed":
                    report["failures"].append({"kind": kind, "phase": phase, "target": t, "detail": _detail(rest[len(t):])})
            elif kind == "init-before-guard":
                report["init_before_guard"] = _detail(rest) or "unknown"
                report["failures"].append({"kind": kind, "phase": phase, "detail": _detail(rest)})
            elif kind == "proc" and rest.strip():
                if rest.strip() not in report["procs"]:
                    report["procs"].append(rest.strip())
            elif kind == "error":
                ph = parts[0] if parts else phase
                report["failures"].append({"kind": kind, "phase": ph, "detail": _detail(rest[len(ph):])})
        pending.clear()

    for kind, rest in marker_lines(body):
        if kind == "done":
            phase = rest.split(" ", 1)[0] if rest else ""
            flush(phase or "unknown")
            if phase and phase not in report["phases"]:
                report["phases"].append(phase)
        else:
            pending.append((kind, rest))
    if pending:
        # 끝 표식이 없는 단계 (스크립트가 도중에 멈췄거나 결과가 잘림)
        flush("incomplete")
        report["failures"].append({"kind": "incomplete", "phase": "incomplete", "detail": "단계 끝 표식(done)이 없음"})
    merged: dict[str, str] = {}
    for states in report["phase_targets"].values():
        for t, st in states.items():
            if t not in merged or _STATE_RANK.get(st, 0) > _STATE_RANK.get(merged[t], 0):
                merged[t] = st
    report["targets"] = merged
    report["verified"] = set(required) <= set(report["phases"]) and not report["failures"]
    return report


def neutralized_list(report: dict[str, Any]) -> list[str]:
    """응답의 ``semihosting_neutralized``/``semihosting_reneutralized``: 무력화한 것 목록.

    ``<타깃>:<이벤트>`` = 감싼 타깃 이벤트 핸들러, ``tap:<TAP>:<이벤트>`` = 감싼 TAP 이벤트 핸들러,
    ``<타깃>:after-init`` / ``after-start`` / ``after-command`` = 그 단계(post-init / RPC verify / 명령 뒤 check)에 켜져 있어서 끈 타깃.
    """
    out: list[str] = []
    for h in report.get("handlers_wrapped", []):
        item = f"{h['name']}:{h['event']}" if h["scope"] == "target" else f"tap:{h['name']}:{h['event']}"
        if item not in out:
            out.append(item)
    for phase, states in (report.get("phase_targets") or {}).items():
        suffix = _DISABLED_SUFFIX.get(phase, phase)
        for t, state in states.items():
            item = f"{t}:{suffix}"
            if state == "disabled" and item not in out:
                out.append(item)
    return out


def fatal_reasons(report: dict[str, Any]) -> list[str]:
    """OpenOCD 를 계속 쓰면 안 되는 이유(semihosting 이 꺼졌다고 확신할 수 없음). 없으면 빈 목록.

    표식이 아예 없는 경우는 여기서는 치명이 아니다 — 서버는 그 대신 RPC verify 결과(필수)로 판정한다(:func:`verification_problems`).
    """
    out = []
    for f in report.get("failures", []):
        if f["kind"] == "wrap-failed":
            out.append(f"{f['scope']} {f['name']} 의 {f['event']} 핸들러를 감싸지 못함: {f['detail']}")
        elif f["kind"] == "disable-failed":
            out.append(f"타깃 {f['target']} 의 semihosting 을 끄지 못함: {f['detail']}")
        elif f["kind"] == "init-before-guard":
            out.append(f"semihosting 가드보다 init 이 먼저 실행됨(command mode={f['detail'] or '?'}) — cfg 나 시작 명령이 init 을 직접 실행함")
        elif f["kind"] == "error":
            out.append(f"semihosting 무력화 스크립트 오류({f['phase']}): {f['detail']}")
        elif f["kind"] == "incomplete":
            out.append("semihosting 무력화 결과가 불완전함(단계 끝 표식이 없음)")
    return out


def verification_problems(report: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    """RPC 단계(verify/check) 결과의 문제: 실패 + 끝나지 않은 필수 단계. 비어 있어야 통과."""
    out = fatal_reasons(report)
    missing = [p for p in required if p not in report.get("phases", [])]
    if missing:
        out.append(f"semihosting 가드 단계가 끝나지 않음: {', '.join(missing)} (가드 스크립트가 실행되지 않았거나 결과가 불완전함)")
    return out


_HINT = (
    "semihosting 이 켜지면 타깃 펌웨어가 분석 PC 의 파일을 읽고 쓰고 SYS_SYSTEM 으로 명령을 실행할 수 있어 openocd_start 는 항상 "
    "꺼 두고, MODIFY 이상 명령·halt/resume/reset 뒤마다 다시 확인한다. 정말 필요하면(신뢰하는 자체 펌웨어) 사람 승인 후 openocd_command 로 "
    "'arm semihosting enable' (DESTRUCTIVE) — 그 뒤 이 세션은 끄지 않고 상태만 보고한다."
)


def diagnosis_entries(report: dict[str, Any], log_text: str = "") -> list[dict[str, str]]:
    """parsers.diagnose 와 같은 형식({code, message, evidence, hint})의 진단 항목 (실패가 있으면 그것을 먼저)."""
    out: list[dict[str, str]] = []
    reasons = fatal_reasons(report)
    if reasons:
        out.append({
            "code": "semihosting_neutralization_failed",
            "message": "semihosting 을 끄지 못해(또는 꺼졌다고 확인하지 못해) OpenOCD 를 종료함",
            "evidence": "; ".join(reasons)[:200],
            "hint": "init 을 직접 실행하는 cfg/시작 명령은 쓰지 않는다(openocd_start 가 가드 뒤에 init 을 실행한다). 그 밖에는 OpenOCD 버전"
                    "(Jim Tcl 의 try·{*}, 'command mode' 지원)과 cfg 를 확인하세요. semihosting 을 끌 수 없는 구성은 실행하지 않습니다.",
        })
    first = ""
    for line in startup_portion(log_text).split("\n"):
        m = _LINE.match(line.rstrip("\r"))
        if m and m.group("kind") in ("wrapped", "disabled"):
            first = f"{MARKER} {m.group('kind')} {m.group('rest') or ''}".strip()
            break
    neutralized = neutralized_list(report)
    if neutralized:
        out.append({
            "code": "semihosting_neutralized",
            "message": "cfg 의 이벤트 핸들러/설정이 켜는 semihosting 을 PWEH 가 무력화함: " + ", ".join(neutralized),
            "evidence": first[:200],
            "hint": _HINT,
        })
    return out


__all__ = [
    "CHECK_CALL", "EARLY_CHECK_PHASE", "EARLY_CHECK_SCRIPT", "GUARD_PROC", "MARKER", "POST_INIT_SCRIPT", "PRE_INIT_SCRIPT",
    "STARTUP_PHASES", "STATUS_CALL", "TAP_EVENTS",
    "TARGET_EVENTS", "VERIFY_CALL", "WRAP_FINALLY", "diagnosis_entries", "fatal_reasons", "marker_lines", "neutralized_list",
    "parse_report", "startup_portion", "verification_problems",
]
