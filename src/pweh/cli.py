"""``pweh`` 명령행 도구 (사람용).

주요 명령:
  pweh doctor                       환경 점검 (Python 패키지, 설정, 시리얼 포트 권한, 외부 도구, WSL USB 안내)
  pweh approve <id>                 위험 작업 승인 (대화형 터미널에서 사람이 확인 코드를 입력해야 함)
  pweh deny <id>                    위험 작업 거부
  pweh approvals [--all]            승인 요청 목록
  pweh attest <id>                  사람 증명 (대화형 터미널에서 사람이 항목마다 직접 답함 — 소유/허가 증명은 `pweh case attest`)
  pweh attest --list [--all]        사람 증명 요청 목록 (대화형 터미널 전용)
  pweh attest --revoke <id>         사람 증명 철회 (대화형 터미널 전용)
  pweh case new|list|show|attest    케이스 관리
  pweh report <case_id>             보고서 생성
  pweh mcp-config [--client ...]    MCP 클라이언트 설정 생성 (Claude Code / Codex / Cursor)
  pweh skills install [--target]    Skill 을 에이전트가 찾는 위치에 심볼릭 링크로 설치
  pweh audit [--case ID]            감사 로그 꼬리 보기
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import load_config
from .errors import PwehError

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_NAMES = (
    "pweh-start",
    "uart-shell-acquisition",
    "firmware-dump-via-uart",
    "esp32-flash-dump",
    "firmware-static-analysis",
    "logic-analyzer-protocol-decode",
    "cctv-auth-bypass-hunt",
)
SERVERS = {
    # MCP 서버 이름 → (콘솔 스크립트, 설명)
    "pweh-case": ("pweh-case-mcp", "케이스/단계 결과/발견사항/보고서"),
    "pweh-uart": ("pweh-uart-mcp", "UART 콘솔 (U-Boot, Linux 셸, 덤프)"),
    "pweh-openocd": ("pweh-openocd-mcp", "OpenOCD JTAG/SWD"),
    "pweh-sigrok": ("pweh-sigrok-mcp", "sigrok 로직 애널라이저"),
    "pweh-jtagulator": ("pweh-jtagulator-mcp", "JTAGulator 핀아웃 스캔"),
    "pweh-fwtriage": ("pweh-fwtriage-mcp", "오프라인 펌웨어 트리아지"),
    "pweh-esp": ("pweh-esp-mcp", "ESP32 esptool 읽기 전용 덤프 (WSL 에서 Windows esptool.exe·COM 포트 또는 Linux esptool)"),
}
REA_ENV_KEYS = (
    "GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_SIGROK_COMMAND", "REA_BINWALK_COMMAND", "REA_UNBLOB_COMMAND",
    "REA_GHIDRA_STARTUP_TIMEOUT_MS", "REA_FIRMWARE_PRLIMIT_COMMAND", "REA_SIGROK_PRLIMIT_COMMAND",
)
PWEH_ENV_KEYS = (
    "PWEH_TOOLS_DIR", "PWEH_SIGROK_CLI", "PWEH_OPENOCD", "PWEH_OPENOCD_SCRIPTS", "PWEH_OPENOCD_DUMMY", "PWEH_BINWALK",
    "PWEH_UNBLOB", "PWEH_MKSQUASHFS", "PWEH_UNSQUASHFS", "PWEH_MKIMAGE", "PWEH_MKENVIMAGE", "PWEH_DUMPIMAGE", "PWEH_ZIG",
    "PWEH_GHIDRA_HEADLESS", "PWEH_REA", "PWEH_LZ4", "PWEH_ESPTOOL", "PWEH_ESPTOOL_WIN",
)


def _print(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    elif isinstance(obj, str):
        print(obj)
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


# ---------------------------------------------------------------------------
# approve / deny
# ---------------------------------------------------------------------------


def _runtime():
    from .runtime import Runtime

    return Runtime("cli")


def cmd_approvals(args: argparse.Namespace) -> int:
    rt = _runtime()
    recs = rt.approvals.list(None if args.all else "pending")
    if args.json:
        _print([{k: v for k, v in r.items() if k != "code"} for r in recs], True)
        return 0
    if not recs:
        print("대기 중인 승인 요청이 없습니다." if not args.all else "승인 기록이 없습니다.")
        return 0
    for r in recs:
        print(f"{r['id']}  [{r['status']}]  {r['risk']:<11} {r['server']}.{r['tool']}  case={r.get('case_id')}  만료={r.get('expires_at')}")
        print(f"    {r.get('summary')}")
    return 0


def _show_approval(r: dict[str, Any]) -> None:
    print("=" * 72)
    print(f" 승인 요청 {r['id']}  (상태: {r['status']})")
    print("=" * 72)
    print(f" 서버/도구 : {r['server']} / {r['tool']}")
    print(f" 케이스    : {r.get('case_id')}")
    print(f" 위험도    : {str(r.get('risk')).upper()}   규칙: {r.get('rule_id')}")
    print(f" 사유      : {r.get('reason')}")
    print(f" 요약      : {r.get('summary')}")
    print(f" 생성/만료 : {r.get('created_at')} / {r.get('expires_at')}")
    print(" 작업 내용 :")
    for line in json.dumps(r.get("action"), ensure_ascii=False, indent=2).splitlines():
        print(f"   {line}")
    print("-" * 72)


def cmd_approve(args: argparse.Namespace) -> int:
    rt = _runtime()
    rec = rt.approvals.get(args.approval_id)
    _show_approval(rec)
    if rec["status"] != "pending":
        print(f"이 요청은 승인할 수 없는 상태입니다: {rec['status']}")
        return 1
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(
            "오류: `pweh approve` 는 사람이 대화형 터미널에서 직접 실행해야 합니다 (stdin/stdout 이 TTY 가 아님).\n"
            "AI 에이전트는 이 명령을 실행하면 안 됩니다.",
            file=sys.stderr,
        )
        return 2
    print("⚠️  이 작업은 기기에 영구적 변경 또는 하드웨어 손상을 일으킬 수 있습니다.")
    print("    내용을 이해했고 실행을 허용하려면 아래 확인 코드를 그대로 입력하세요. (거부: n, 취소: Enter)")
    print(f"    확인 코드: {rec['code']}")
    try:
        typed = input("입력> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n취소했습니다 (요청은 대기 상태로 남습니다).")
        return 1
    if not typed:
        print("취소했습니다 (요청은 대기 상태로 남습니다).")
        return 1
    if typed.lower() in ("n", "no"):
        rt.approvals.decide(args.approval_id, approve=False, code=None, via="cli-tty")
        rt.audit({"event": "approval_denied", "approval_id": args.approval_id}, rec.get("case_id"))
        print("거부했습니다.")
        return 0
    try:
        out = rt.approvals.decide(args.approval_id, approve=True, code=typed, via="cli-tty")
    except PwehError as exc:
        print(f"승인 실패: {exc}")
        return 1
    rt.audit({"event": "approval_granted", "approval_id": args.approval_id, "decided_by": out.get("decided_by")}, rec.get("case_id"))
    print(f"승인했습니다. 에이전트가 approval_id={args.approval_id} 로 다시 호출하면 1회 실행됩니다 (만료: {out['expires_at']}).")
    return 0


def cmd_deny(args: argparse.Namespace) -> int:
    rt = _runtime()
    rec = rt.approvals.get(args.approval_id)
    _show_approval(rec)
    rt.approvals.decide(args.approval_id, approve=False, code=None, via="cli")
    rt.audit({"event": "approval_denied", "approval_id": args.approval_id}, rec.get("case_id"))
    print("거부했습니다.")
    return 0


# ---------------------------------------------------------------------------
# attest (사람 증명 — `pweh case attest`(소유/허가 증명)와 다른 명령)
# ---------------------------------------------------------------------------

_YES = ("y", "yes", "예", "네")
_NO = ("n", "no", "아니오", "아니요")


def _attest_user() -> str:
    """결정한 사람의 OS 계정 이름(실제 uid 기준 — 환경 변수 $USER 로 바꿀 수 없다)."""
    from .safety.attestations import os_user

    return os_user()


def _attest_confirm_code() -> bool:
    """승인이 될 답을 기록하기 전에 화면의 무작위 확인 코드를 입력받는다(`pweh approve` 와 같은 수준 — 답을 미리 흘려 넣는 것만으로는 기록되지 않게)."""
    import secrets

    from .safety.attestations import ELICIT_CODE_ALPHABET

    code = "".join(secrets.choice(ELICIT_CODE_ALPHABET) for _ in range(4))
    print(f"    위 답으로 증명을 기록하려면 확인 코드를 그대로 입력하세요: {code}")
    try:
        typed = input("  (취소: Enter) 확인 코드> ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return typed == code


def _attest_refuse_without_tty() -> int | None:
    """approve 와 같은 TTY 검사. TTY 가 아니면 종료 코드 2 (아무것도 보여 주거나 바꾸지 않는다)."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        return None
    print(
        "오류: `pweh attest` 는 사람이 대화형 터미널에서 직접 실행해야 합니다 (stdin/stdout 이 TTY 가 아님).\n"
        "AI 에이전트는 이 명령을 실행하면 안 됩니다. 증명은 에이전트가 확인할 수 없는 사실을 사람이 직접 답하는 기록입니다.",
        file=sys.stderr,
    )
    return 2


def _show_attestation(r: dict[str, Any]) -> None:
    from .safety.attestations import ATTESTATION_KINDS

    req = r.get("requested_by") or {}
    print("=" * 72)
    print(f" 사람 증명 요청 {r['id']}  (상태: {r['status']})")
    print("=" * 72)
    print(f" 종류      : {r.get('kind')} — {ATTESTATION_KINDS.get(r.get('kind'), '(알 수 없는 종류)')}")
    print(f" 요약      : {r.get('summary')}")
    print(f" 케이스    : {r.get('case_id')}")
    print(f" 요청 서버 : {req.get('server')} / {req.get('tool')}")
    print(f" 바인딩    : {json.dumps(r.get('binding'), ensure_ascii=False)}")
    validity = r.get("valid_seconds")
    print(f" 생성/만료 : {r.get('created_at')} / {r.get('expires_at') or '철회할 때까지'}"
          + (f"  (승인 뒤 유효 {validity}초)" if validity and r.get("status") == "pending" else ""))
    print(" 대상(subject):")
    for line in json.dumps(r.get("subject"), ensure_ascii=False, indent=2).splitlines():
        print(f"   {line}")
    print(" 확인 항목:")
    for i, q in enumerate(r.get("questions") or [], 1):
        kind = "예/아니오" if q.get("type") == "yesno" else "값 입력"
        need = ", '예'여야 증명됨" if q.get("expected") == "yes" else ""
        print(f"   {i}. [{kind}{need}] {q.get('text')}")
    if r.get("answers"):
        print(f" 답        : {json.dumps(r.get('answers'), ensure_ascii=False)}")
    if r.get("decided_at"):
        print(f" 결정      : {r.get('decided_at')} by {r.get('decided_by')} via {r.get('decided_via')}")
    if r.get("revoked_at"):
        print(f" 철회      : {r.get('revoked_at')} by {r.get('revoked_by')}")
    print("-" * 72)


def _ask_attest_question(i: int, n: int, q: dict[str, Any]) -> str | None:
    """질문 하나. yesno → 'yes'/'no', value → 입력값. 빈 입력·EOF·Ctrl-C 는 None(취소)."""
    yesno = q.get("type") == "yesno"
    print(f"[{i}/{n}] {q.get('text')}")
    hint = "y/n" if yesno else "직접 확인한 값"
    while True:
        try:
            typed = input(f"  ({hint}, 취소: Enter) 답> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not typed:
            return None
        if not yesno:
            return typed
        low = typed.lower()
        if low in _YES:
            return "yes"
        if low in _NO:
            return "no"
        print("  y 또는 n 으로 답하세요.")


def _attest_list(rt: Any, show_all: bool) -> int:
    recs = rt.attestations.list(None if show_all else "pending")
    if not recs:
        print("대기 중인 증명 요청이 없습니다." if not show_all else "증명 기록이 없습니다.")
        return 0
    for r in recs:
        print(f"{r['id']}  [{r['status']}]  {r.get('kind', ''):<17} case={r.get('case_id')}  만료={r.get('expires_at') or '철회할 때까지'}")
        print(f"    {r.get('summary')}")
    return 0


def _attest_revoke(rt: Any, attestation_id: str) -> int:
    rec = rt.attestations.get(attestation_id)
    _show_attestation(rec)
    if rec["status"] not in ("pending", "approved"):
        print(f"이 증명은 철회할 수 없는 상태입니다: {rec['status']}")
        return 1
    try:
        typed = input("이 증명을 철회하려면 y 를 입력하세요 (취소: Enter) 답> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n취소했습니다.")
        return 1
    if typed not in _YES:
        print("취소했습니다.")
        return 1
    by = _attest_user()
    out = rt.attestations.revoke(attestation_id, by=by)
    rt.audit({"event": "attestation_revoked", "attestation_id": attestation_id, "kind": out.get("kind"), "revoked_by": by,
              "via": "cli-tty"}, out.get("case_id"))
    print("철회했습니다. 이 증명에 기대던 서버 동작은 다시 증명을 요청합니다.")
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    refused = _attest_refuse_without_tty()
    if refused is not None:
        return refused
    rt = _runtime()
    if args.list:
        if args.attestation_id:
            print("--list 와 증명 id 를 함께 줄 수 없습니다.", file=sys.stderr)
            return 2
        return _attest_list(rt, args.all)
    if args.revoke:
        if args.attestation_id:
            print("--revoke 와 증명 id 를 함께 줄 수 없습니다.", file=sys.stderr)
            return 2
        return _attest_revoke(rt, args.revoke)
    if not args.attestation_id:
        print("증명 id, --list, --revoke <id> 중 하나가 필요합니다.", file=sys.stderr)
        return 2
    rec = rt.attestations.get(args.attestation_id)
    _show_attestation(rec)
    if rec["status"] != "pending":
        print(f"이 요청은 답할 수 없는 상태입니다: {rec['status']}")
        return 1
    print("⚠️  아래 항목은 에이전트가 확인할 수 없는 사실입니다. 직접 확인한 경우에만 '예(y)'로 답하세요.")
    print("    값 항목에는 직접 측정·확인한 값을 입력하세요. 빈 입력(Enter)은 취소입니다(요청은 대기 상태로 남습니다).")
    questions = rec.get("questions") or []
    answers: dict[str, str] = {}
    for i, q in enumerate(questions, 1):
        ans = _ask_attest_question(i, len(questions), q)
        if ans is None:
            print("취소했습니다 (요청은 대기 상태로 남습니다).")
            return 1
        answers[q["id"]] = ans
        if q.get("type") == "yesno" and q.get("expected") == "yes" and ans == "no":
            print("이 항목이 '예'가 아니면 증명할 수 없습니다 → 증명하지 않음(거부)으로 기록합니다.")
            break
    from .safety.attestations import answers_satisfy, normalize_answers, normalize_questions

    try:
        would_approve, _ = answers_satisfy(normalize_questions(questions), normalize_answers(normalize_questions(questions), answers))
    except PwehError as exc:
        print(f"기록 실패: {exc}")
        return 1
    if would_approve and not _attest_confirm_code():
        print("확인 코드가 다르거나 입력하지 않았습니다 — 취소했습니다 (요청은 대기 상태로 남습니다).")
        return 1
    by = _attest_user()
    try:
        out = rt.attestations.decide(args.attestation_id, answers, via="cli-tty", by=by)
    except PwehError as exc:
        print(f"기록 실패: {exc}")
        return 1
    rt.audit({"event": "attestation_decided", "attestation_id": args.attestation_id, "kind": out.get("kind"),
              "status": out["status"], "decided_by": by, "decided_via": "cli-tty"}, out.get("case_id"))
    if out["status"] == "approved":
        print(f"증명을 기록했습니다 ({args.attestation_id}, 만료: {out.get('expires_at') or '철회할 때까지'}). "
              "에이전트가 같은 작업을 다시 호출하면 서버가 이 증명을 찾아 사용합니다.")
    else:
        print("증명하지 않음(거부)으로 기록했습니다. 서버는 이 작업을 진행하지 않습니다.")
    return 0


# ---------------------------------------------------------------------------
# case / report / audit
# ---------------------------------------------------------------------------


def cmd_case_new(args: argparse.Namespace) -> int:
    rt = _runtime()
    interactive = sys.stdin.isatty()

    def ask(value: str | None, prompt: str, required: bool = True) -> str | None:
        if value or not interactive:
            return value
        v = input(prompt).strip()
        if required and not v:
            raise SystemExit("필수 값입니다.")
        return v or None

    title = ask(args.title, "케이스 제목: ")
    basis = ask(args.basis, "근거 (owned / written-authorization): ")
    owner = ask(args.owner, "소유자/허가 주체: ")
    statement = ask(args.statement, "소유·허가 진술 (예: '제가 구매한 제 카메라입니다'): ")
    doc_ref = args.doc_ref
    if basis == "written-authorization":
        doc_ref = ask(doc_ref, "허가 문서 식별자/경로: ")
    target = {k: v for k, v in {"vendor": args.vendor, "model": args.model, "serial": args.serial, "firmware_version": args.firmware_version}.items() if v}
    auth = {"basis": basis, "owner": owner, "statement": statement, "document_ref": doc_ref,
            "attested_by": os.environ.get("USER", "operator"), "attested_via": "cli-tty" if interactive else "cli"}
    case = rt.cases.create(title=title or "case", target=target, authorization=auth, profile=args.profile, case_id=args.case_id)
    _print({"ok": True, "case": case.summary()}, True)
    return 0


def cmd_case_attest(args: argparse.Namespace) -> int:
    rt = _runtime()
    case = rt.cases.get(args.case_id)
    if not sys.stdin.isatty():
        print("오류: attest 는 대화형 터미널에서 실행해야 합니다.", file=sys.stderr)
        return 2
    basis = input("근거 (owned / written-authorization): ").strip()
    owner = input("소유자/허가 주체: ").strip()
    statement = input("진술: ").strip()
    doc_ref = input("허가 문서 식별자(서면 허가 시): ").strip() or None
    auth = case.set_authorization({"basis": basis, "owner": owner, "statement": statement, "document_ref": doc_ref,
                                   "attested_by": os.environ.get("USER", "operator"), "attested_via": "cli-tty"})
    _print({"ok": True, "authorization": auth}, True)
    return 0


def cmd_case_list(args: argparse.Namespace) -> int:
    _print(_runtime().cases.list(), True)
    return 0


def cmd_case_show(args: argparse.Namespace) -> int:
    case = _runtime().cases.get(args.case_id)
    _print({"summary": case.summary(), "findings": case.findings()}, True)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .report import write_report

    case = _runtime().cases.get(args.case_id)
    _print(write_report(case), True)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    rt = _runtime()
    from .audit import AuditLog

    log = AuditLog(rt.cases.get(args.case).dir / "audit.jsonl") if args.case else rt.global_audit
    for ev in log.tail(args.n):
        print(json.dumps(ev, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# mcp-config / skills
# ---------------------------------------------------------------------------


def _load_tools_env(path: str | None) -> dict[str, str]:
    """~/pweh-tools/env.sh 같은 파일을 bash 로 source 해서 관련 환경변수를 추출."""
    env: dict[str, str] = {}
    for k in REA_ENV_KEYS + PWEH_ENV_KEYS:
        if os.environ.get(k):
            env[k] = os.environ[k]
    from .toolsdir import tools_env

    candidate = path or str(tools_env())
    p = Path(os.path.expanduser(candidate))
    if p.exists() and shutil.which("bash"):
        try:
            out = subprocess.run(["bash", "-c", f'set -a; source "{p}" >/dev/null 2>&1; env -0'], capture_output=True, timeout=20, check=False).stdout
            for item in out.split(b"\0"):
                if b"=" in item:
                    k, v = item.decode("utf-8", "replace").split("=", 1)
                    if k in REA_ENV_KEYS + PWEH_ENV_KEYS or k == "PATH":
                        env[k] = v
        except (OSError, subprocess.SubprocessError):
            pass
    return env


def build_mcp_servers(include_rea: bool = True, tools_env: str | None = None, style: str = "absolute") -> dict[str, Any]:
    """MCP 서버 설정 생성.

    style:
      absolute  — 절대 경로 + env (Codex, 또는 저장소를 옮기지 않는 로컬 사용)
      portable  — Claude Code 용: bash -c 로 $CLAUDE_PROJECT_DIR/scripts/mcp-launch.sh 실행 (env.sh 자동 로드)
      cursor    — Cursor 용: ${workspaceFolder}/scripts/mcp-launch.sh
    """
    names = list(SERVERS) + (["rea"] if include_rea else [])
    launch = REPO_ROOT / "scripts" / "mcp-launch.sh"
    if style in ("portable", "cursor"):
        servers: dict[str, Any] = {}
        for name in names:
            target = "rea" if name == "rea" else SERVERS[name][0]
            if style == "portable":
                # 중괄호 없는 $VAR 는 Claude Code 의 ${...} 확장 대상이 아니므로 런타임에 bash 가 확장한다.
                cmd = f'd="$CLAUDE_PROJECT_DIR"; [ -n "$d" ] || d="$PWD"; exec "$d/scripts/mcp-launch.sh" {target}'
                servers[name] = {"type": "stdio", "command": "bash", "args": ["-c", cmd]}
            else:
                servers[name] = {"type": "stdio", "command": "${workspaceFolder}/scripts/mcp-launch.sh", "args": [target]}
        return servers

    bindir = Path(sys.executable).resolve().parent
    venv_bin = REPO_ROOT / ".venv" / "bin"
    if venv_bin.exists():
        bindir = venv_bin
    cfg = REPO_ROOT / "orchestrator" / "pipeline-config.yaml"
    tenv = _load_tools_env(tools_env)
    servers = {}
    for name, (script, _desc) in SERVERS.items():
        env = {"PWEH_CONFIG": str(cfg)}
        for k in PWEH_ENV_KEYS:
            if k in tenv:
                env[k] = tenv[k]
        servers[name] = {"type": "stdio", "command": str(bindir / script), "args": [], "env": env}
    if include_rea:
        # install.sh 가 <prefix>/bin/rea 에 깐 REA 는 env.sh 의 PWEH_REA / PATH 로만 보인다
        rea = tenv.get("PWEH_REA") or shutil.which("rea", path=tenv.get("PATH")) or str(Path.home() / ".local" / "bin" / "rea")
        env = {k: tenv[k] for k in REA_ENV_KEYS if k in tenv}
        if "PATH" in tenv:
            env["PATH"] = tenv["PATH"]
        env.setdefault("REA_GHIDRA_STARTUP_TIMEOUT_MS", "600000")
        servers["rea"] = {"type": "stdio", "command": rea, "args": ["--mcp"], "env": env}
    _ = launch
    return servers


def cmd_mcp_config(args: argparse.Namespace) -> int:
    style = args.style or {"claude": "portable", "cursor": "cursor", "codex": "absolute", "json": "absolute"}[args.client]
    servers = build_mcp_servers(include_rea=not args.no_rea, tools_env=args.tools_env, style=style)
    if args.client in ("claude", "cursor", "json"):
        doc = {"mcpServers": servers}
        text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
        if args.write:
            target = REPO_ROOT / (".mcp.json" if args.client in ("claude", "json") else ".cursor/mcp.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and not args.force:
                print(f"{target} 가 이미 있습니다. 덮어쓰려면 --force", file=sys.stderr)
                return 1
            target.write_text(text, encoding="utf-8")
            print(f"작성: {target}")
        else:
            print(text)
        return 0
    if args.client == "codex":
        lines = ["# ~/.codex/config.toml 에 추가 (pweh mcp-config --client codex 로 생성)"]
        for name, spec in servers.items():
            lines.append(f"\n[mcp_servers.{name}]")
            lines.append(f"command = {json.dumps(spec['command'])}")
            lines.append(f"args = {json.dumps(spec['args'])}")
            lines.append(f"cwd = {json.dumps(str(REPO_ROOT))}")
            lines.append("startup_timeout_sec = 60")
            lines.append(f"tool_timeout_sec = {900 if name == 'rea' else 600}")
            if spec.get("env"):
                inner = ", ".join(f"{json.dumps(k)} = {json.dumps(v)}" for k, v in spec["env"].items())
                lines.append(f"env = {{ {inner} }}")
        print("\n".join(lines))
        return 0
    print(f"알 수 없는 client: {args.client}", file=sys.stderr)
    return 1


def cmd_skills_install(args: argparse.Namespace) -> int:
    targets = {
        "claude-project": REPO_ROOT / ".claude" / "skills",
        "claude-user": Path.home() / ".claude" / "skills",
        "agents": REPO_ROOT / ".agents" / "skills",  # Codex / Cursor 프로젝트 스킬 위치
        "codex-user": Path.home() / ".codex" / "skills",
    }
    if args.target.startswith("dir:"):
        dest = Path(os.path.expanduser(args.target[4:]))
    elif args.target in targets:
        dest = targets[args.target]
    else:
        print(f"알 수 없는 target: {args.target} (가능: {', '.join(targets)}, dir:<경로>)", file=sys.stderr)
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    results = []
    for name in SKILL_NAMES:
        src = REPO_ROOT / "skills" / name
        link = dest / name
        if not (src / "SKILL.md").exists():
            results.append({"skill": name, "status": "missing-source"})
            continue
        if link.is_symlink() or link.exists():
            if link.is_symlink() and link.resolve() == src.resolve():
                results.append({"skill": name, "status": "already-installed", "path": str(link)})
                continue
            if not args.force:
                results.append({"skill": name, "status": "exists (use --force)", "path": str(link)})
                continue
            if link.is_symlink() or link.is_file():
                link.unlink()
            else:
                shutil.rmtree(link)
        rel = os.path.relpath(src, dest)
        link.symlink_to(rel if dest.is_relative_to(REPO_ROOT) else src, target_is_directory=True)
        results.append({"skill": name, "status": "installed", "path": str(link)})
    _print({"dest": str(dest), "results": results}, True)
    return 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def _tool_version(cmd: list[str], expect: str, ok_codes: tuple[int, ...] = (0,), timeout: float = 20.0) -> tuple[bool, str]:
    """도구의 버전 출력을 확인한다. (정상 여부, 버전 첫 줄 또는 실패 이유).

    실행 파일이 있어도 공유 라이브러리가 없거나 Python Traceback 으로 죽는 '깨진 설치'를 잡기 위해
    종료 코드와 첫 줄의 형식(expect 정규식)을 함께 본다.
    """
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"실행 실패: {exc}"
    text = (out.stdout or out.stderr or "").strip().splitlines()
    first = text[0][:120] if text else ""
    if out.returncode in ok_codes and re.search(expect, first):
        return True, first
    err = (out.stderr or out.stdout or "").strip().splitlines()
    return False, f"종료 코드 {out.returncode}: {err[-1][:120] if err else '(출력 없음)'}"


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool | None, detail: str = "", hint: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, "hint": hint})

    add("python", sys.version_info >= (3, 10), platform.python_version())
    for mod in ("mcp", "serial", "yaml", "jsonschema"):
        try:
            m = __import__(mod)
            add(f"python:{mod}", True, getattr(m, "__version__", getattr(m, "VERSION", "")) or "ok")
        except ImportError as exc:
            add(f"python:{mod}", False, str(exc), "pip install -e . 로 설치")
    try:
        cfg = load_config()
        add("config", True, str(cfg.path) if cfg.path else "(내장 기본값)")
        add("safety.destructive_policy", True, cfg.safety.destructive_policy)
        add("safety.approval_methods", True, ", ".join(cfg.safety.approval_methods))
        for d in (cfg.cases_dir, cfg.state_dir):
            d.mkdir(parents=True, exist_ok=True)
            add(f"writable:{d}", os.access(d, os.W_OK), "")
    except PwehError as exc:
        cfg = None
        add("config", False, str(exc))

    # 시리얼 포트
    try:
        from serial.tools import list_ports

        ports = [p.device for p in list_ports.comports()]
        add("serial:ports", True, ", ".join(ports) if ports else "(없음)", "" if ports else "USB-UART 어댑터를 연결하세요")
    except Exception as exc:  # pragma: no cover
        add("serial:ports", False, str(exc))
    try:
        import grp

        groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
        add("serial:dialout-group", "dialout" in groups or os.geteuid() == 0, ",".join(sorted(groups)),
            "sudo usermod -aG dialout $USER 후 재로그인 (또는 udev 규칙)")
    except Exception:
        pass
    try:
        if "microsoft" in Path("/proc/version").read_text().lower():
            add("wsl", None, "WSL2 감지", "USB 기기(UART 어댑터/로직 애널라이저/JTAG 프로브)는 Windows 에서 usbipd-win 으로 WSL 에 attach 해야 합니다: "
                "usbipd list → usbipd bind --busid X → usbipd attach --wsl --busid X")
    except OSError:
        pass

    tenv = _load_tools_env(None)
    for k, v in tenv.items():
        if k != "PATH":
            os.environ.setdefault(k, v)
    # (명령, 필요 기능, 버전 출력 첫 줄의 형식, 정상 종료 코드)
    tool_cmds: dict[str, tuple[list[str], str, str, tuple[int, ...]]] = {
        "sigrok-cli": ([os.environ.get("PWEH_SIGROK_CLI") or os.environ.get("REA_SIGROK_COMMAND") or "sigrok-cli", "--version"],
                       "sigrok-mcp / REA decode_signal_recording", r"^sigrok-cli \d", (0,)),
        "openocd": ([os.environ.get("PWEH_OPENOCD") or "openocd", "--version"], "openocd-mcp", r"Open On-Chip Debugger \d", (0,)),
        "rea": ([os.environ.get("PWEH_REA") or shutil.which("rea") or str(Path.home() / ".local/bin/rea"), "--version"],
                "펌웨어 추출/Ghidra 분석", r"^\d+\.\d+", (0,)),
        "binwalk": ([os.environ.get("REA_BINWALK_COMMAND") or "binwalk", "--version"], "REA inspect_firmware_regions", r"^binwalk \d", (0,)),
        "unblob": ([os.environ.get("REA_UNBLOB_COMMAND") or "unblob", "--version"], "REA extract_firmware", r"^\d+\.\d+", (0,)),
        # unsquashfs 4.5 의 -version 은 정상이어도 종료 코드 1
        "unsquashfs": ([os.environ.get("PWEH_UNSQUASHFS") or "unsquashfs", "-version"], "fwtriage squashfs 추출 폴백",
                       r"^unsquashfs version \d", (0, 1)),
    }
    for name, (cmd, purpose, expect, ok_codes) in tool_cmds.items():
        exe = cmd[0]
        found = shutil.which(exe) or (exe if Path(exe).exists() else None)
        if not found:
            add(f"tool:{name}", False, "없음", f"필요 기능: {purpose}. ~/pweh-tools/env.sh 를 source 했는지 확인")
            continue
        ok, ver = _tool_version([found, *cmd[1:]], expect, ok_codes)
        add(f"tool:{name}", ok, f"{found} :: {ver}",
            "" if ok else f"실행 파일은 있지만 버전 확인에 실패했습니다 (설치가 깨졌을 수 있음). 필요 기능: {purpose}. "
            "직접 실행해 보고 scripts/install.sh --check / --force --only <구성요소> 로 다시 설치")
    # 선택 도구: ESP32 esptool (pweh-esp). 없으면 '--'(선택), 있는데 버전 확인이 실패하면 '!!'
    for name, exe, purpose in (
        ("esptool", os.environ.get("PWEH_ESPTOOL") or shutil.which("esptool") or "", "pweh-esp 의 Linux esptool (/dev/tty* 포트)"),
        ("esptool.exe", os.environ.get("PWEH_ESPTOOL_WIN") or "", "pweh-esp 방법 A (WSL 에서 Windows esptool.exe + COM 포트)"),
    ):
        found = exe if exe and (Path(exe).exists() or shutil.which(exe)) else None
        if not found:
            add(f"tool:{name}", None, "없음 (선택)", f"ESP32 덤프가 필요할 때 scripts/install.sh --only esptool ({purpose})")
            continue
        ok, ver = _tool_version([found, "version"], r"^esptool(\.py)? v\d", (0,))
        add(f"tool:{name}", ok, f"{found} :: {ver}",
            "" if ok else f"실행 파일은 있지만 버전 확인에 실패했습니다. 필요 기능: {purpose}. scripts/install.sh --force --only esptool 로 다시 설치")
    gh = os.environ.get("GHIDRA_INSTALL_DIR")
    add("ghidra", bool(gh and Path(gh).exists()), gh or "GHIDRA_INSTALL_DIR 미설정", "REA 의 네이티브 디컴파일에 필요")
    jh = os.environ.get("JAVA_HOME")
    add("java", bool(jh and Path(jh).exists()) or bool(shutil.which("java")), jh or (shutil.which("java") or "없음"))
    mcpjson = REPO_ROOT / ".mcp.json"
    add("claude:.mcp.json", mcpjson.exists(), str(mcpjson), "pweh mcp-config --client claude --write")
    skills_dir = REPO_ROOT / ".claude" / "skills"
    installed = [n for n in SKILL_NAMES if (skills_dir / n / "SKILL.md").exists()]
    add("claude:skills", len(installed) == len(SKILL_NAMES), f"{len(installed)}/{len(SKILL_NAMES)}", "pweh skills install --target claude-project")

    if args.json:
        _print({"version": __version__, "checks": checks}, True)
    else:
        print(f"pweh {__version__} doctor")
        for c in checks:
            mark = "OK " if c["ok"] else ("-- " if c["ok"] is None else "!! ")
            print(f"[{mark}] {c['check']:<28} {c['detail']}")
            if c["hint"] and not c["ok"]:
                print(f"       → {c['hint']}")
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pweh", description="PWEH — 에이전트 주도 하드웨어 분석 파이프라인 CLI")
    p.add_argument("--version", action="version", version=f"pweh {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="환경 점검")
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_doctor)

    a = sub.add_parser("approve", help="위험 작업 승인 (사람이 대화형 터미널에서 실행)")
    a.add_argument("approval_id")
    a.set_defaults(fn=cmd_approve)
    dn = sub.add_parser("deny", help="위험 작업 거부")
    dn.add_argument("approval_id")
    dn.set_defaults(fn=cmd_deny)
    ap = sub.add_parser("approvals", help="승인 요청 목록")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(fn=cmd_approvals)
    at = sub.add_parser("attest", help="사람 증명: 항목마다 직접 답하기·목록·철회 (사람이 대화형 터미널에서 실행. 소유/허가 증명은 `pweh case attest`)")
    at.add_argument("attestation_id", nargs="?", help="증명 요청 id (att-…)")
    atg = at.add_mutually_exclusive_group()
    atg.add_argument("--list", action="store_true", help="증명 요청 목록 (기본: 대기 중만)")
    atg.add_argument("--revoke", metavar="ATTESTATION_ID", help="증명 철회")
    at.add_argument("--all", action="store_true", help="--list 에서 모든 상태 표시")
    at.set_defaults(fn=cmd_attest)

    c = sub.add_parser("case", help="케이스 관리")
    csub = c.add_subparsers(dest="case_cmd", required=True)
    cn = csub.add_parser("new", help="케이스 생성")
    for opt in ("title", "basis", "owner", "statement", "doc-ref", "vendor", "model", "serial", "firmware-version", "profile", "case-id"):
        cn.add_argument(f"--{opt}")
    cn.set_defaults(fn=cmd_case_new)
    cl = csub.add_parser("list")
    cl.set_defaults(fn=cmd_case_list)
    cs = csub.add_parser("show")
    cs.add_argument("case_id")
    cs.set_defaults(fn=cmd_case_show)
    ca = csub.add_parser("attest", help="소유/허가 증명 기록 (대화형)")
    ca.add_argument("case_id")
    ca.set_defaults(fn=cmd_case_attest)

    r = sub.add_parser("report", help="보고서 생성")
    r.add_argument("case_id")
    r.set_defaults(fn=cmd_report)

    au = sub.add_parser("audit", help="감사 로그")
    au.add_argument("--case")
    au.add_argument("-n", type=int, default=30)
    au.set_defaults(fn=cmd_audit)

    m = sub.add_parser("mcp-config", help="MCP 클라이언트 설정 생성")
    m.add_argument("--client", default="claude", choices=["claude", "cursor", "codex", "json"])
    m.add_argument("--write", action="store_true", help="claude: <repo>/.mcp.json, cursor: <repo>/.cursor/mcp.json 에 기록")
    m.add_argument("--force", action="store_true")
    m.add_argument("--no-rea", action="store_true")
    m.add_argument("--tools-env", help="외부 도구 env.sh 경로 (기본 ~/pweh-tools/env.sh)")
    m.add_argument("--style", choices=["absolute", "portable", "cursor"], help="claude 기본 portable, cursor 기본 cursor, codex 기본 absolute")
    m.set_defaults(fn=cmd_mcp_config)

    s = sub.add_parser("skills", help="Skill 설치")
    ssub = s.add_subparsers(dest="skills_cmd", required=True)
    si = ssub.add_parser("install")
    si.add_argument("--target", default="claude-project")
    si.add_argument("--force", action="store_true")
    si.set_defaults(fn=cmd_skills_install)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for attr in ("doc_ref", "firmware_version", "case_id"):
        if not hasattr(args, attr):
            setattr(args, attr, None)
    try:
        return int(args.fn(args) or 0)
    except PwehError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
