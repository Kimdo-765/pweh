"""pweh.clientcfg 테스트 — Codex 설정 생성·병합·신뢰 등록·홈 찾기·mcp-check·doctor 줄.

실제 사용자 Codex 홈(~/.codex, Windows 프로필의 .codex)과 ~/.claude* 는 건드리지 않는다:
HOME 은 임시 디렉터리, CODEX_HOME·USERPROFILE·PWEH_WINDOWS_PROFILE 은 지우고, Windows 프로필 찾기(windows_profile)는 가짜로 바꾼다.
쓰기 시험은 모두 임시 저장소·임시 Codex 홈을 직접 준다. Windows 프로필은 가짜 경로(…/Users/tester)만 쓴다.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pweh import cli, clientcfg

REPO = Path(__file__).resolve().parents[2]
SETTINGS = REPO / ".claude" / "settings.json"
_REAL_WINDOWS_PROFILE = clientcfg.windows_profile
_REAL_WHICH = shutil.which
_DEFAULT = object()

try:  # 교차 확인용 (선언한 의존성이 아니다 — 없으면 tomlkit 으로 읽는다)
    import tomllib as _strict_toml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Python 3.10
    try:
        import tomli as _strict_toml  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover
        _strict_toml = None


def loads(text: str) -> dict:
    if _strict_toml is not None:
        return _strict_toml.loads(text)
    import tomlkit

    return tomlkit.parse(text).unwrap()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """실제 홈·Codex 홈·Windows 프로필을 보지 않게 한다."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for k in ("CODEX_HOME", "USERPROFILE", clientcfg.WINDOWS_PROFILE_ENV, "PWEH_TOOLS_ENV", "PWEH_TOOLS_DIR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(clientcfg, "windows_profile", lambda report=None: (None, "WSL 이 아님"))
    monkeypatch.setattr(clientcfg, "_PROFILE_CACHE", {})
    yield home


def fake_servers(root: str | Path = "/opt/pweh-fake", *, rea: bool = True) -> dict:
    """cli.build_mcp_servers(style=absolute) 와 같은 모양의 가짜 서버 목록."""
    out = {}
    for name, (script, _desc) in cli.SERVERS.items():
        out[name] = {"type": "stdio", "command": f"{root}/.venv/bin/{script}", "args": [],
                     "env": {"PWEH_CONFIG": f"{root}/orchestrator/pipeline-config.yaml", "PWEH_TOOLS_DIR": f"{root}/tools"}}
    if rea:
        out["rea"] = {"type": "stdio", "command": f"{root}/bin/rea", "args": ["--mcp"], "env": {"REA_GHIDRA_STARTUP_TIMEOUT_MS": "600000"}}
    return out


def make_exes(root: Path) -> Path:
    """fake_servers(root) 의 명령 경로에 실행 파일을 만든다 (doctor 의 '실행 파일 없음' 검사용)."""
    for script, _d in cli.SERVERS.values():
        p = root / ".venv" / "bin" / script
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("#!/bin/sh\nexit 0\n")
        p.chmod(0o755)
    rea = root / "bin" / "rea"
    rea.parent.mkdir(parents=True, exist_ok=True)
    rea.write_text("#!/bin/sh\nexit 0\n")
    rea.chmod(0o755)
    return root


def write_cfg(home: Path, servers=None, *, scope="global", dry_run=False, include_rea=True, direct="all", repo: Path | None = None,
              homes=_DEFAULT) -> tuple[int, list[str]]:
    """homes 를 주지 않으면 [home] (명시 홈), None 이면 자동 찾기."""
    out: list[str] = []
    repo = repo or home.parent / "repo"
    repo.mkdir(exist_ok=True)
    rc = clientcfg.write_codex_config(repo=repo, servers=servers or fake_servers(rea=include_rea), settings_path=SETTINGS, scope=scope,
                                      codex_homes=[str(home)] if homes is _DEFAULT else homes, dry_run=dry_run, include_rea=include_rea,
                                      direct=direct, tools_env=None, say=out.append)
    return rc, out


def rea_tools_from_settings() -> list[str]:
    data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    want: list[str] = []
    for group in ("allow", "ask"):
        for e in data["permissions"][group]:
            if e.startswith("mcp__rea__") and e[len("mcp__rea__"):] not in want:
                want.append(e[len("mcp__rea__"):])
    return want


def backups(d: Path) -> list[Path]:
    return sorted(d.glob("config.toml.bak-pweh-*"))


ALL_NS = [f"mcp__{n.replace('-', '_')}" for n in cli.SERVERS]

USER_CFG = """# 내 Codex 설정 (주석 유지)
model = "gpt-5.5"  # 모델

[features]
web_search = true  # 사용자 기능

[mcp_servers.notes]
command = "notes-mcp"
args = ["--stdio"]

[mcp_servers.pweh-case]
command = "/old/path/pweh-case-mcp"
args = []

[mcp_servers.pweh-oldname]
command = "/old/pweh-oldname-mcp"

[projects."/srv/elsewhere"]
trust_level = "trusted"
"""


# ---------------------------------------------------------------------------
# 프로젝트 설정 (--scope project)
# ---------------------------------------------------------------------------


def test_project_file_content_order_and_rea_tools(tmp_path):
    repo = tmp_path / "repo"
    rc, out = write_cfg(tmp_path / "codex-home", scope="project", repo=repo)
    assert rc == 0
    path = repo / ".codex" / "config.toml"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0].startswith(clientcfg.PROJECT_MARKER)
    first_table = next(i for i, ln in enumerate(lines) if ln.startswith("["))
    assert lines.index("mcp_optional_startup_grace_ms = 15000") < first_table  # 최상위 키는 첫 표 앞
    assert lines[first_table] == "[features.code_mode]"
    headers = [ln.split(" #")[0] for ln in lines if ln.startswith("[") and not ln.endswith(".env]")]
    assert headers == ["[features.code_mode]", *[f"[mcp_servers.{n}]" for n in cli.SERVERS], "[mcp_servers.rea]"]
    data = loads(text)
    assert data["mcp_optional_startup_grace_ms"] == 15000
    assert data["features"] == {"code_mode": {"direct_only_tool_namespaces": ALL_NS}}
    assert list(data["mcp_servers"]) == [*cli.SERVERS, "rea"]
    for name, (script, _d) in cli.SERVERS.items():
        s = data["mcp_servers"][name]
        assert s == {"command": f"/opt/pweh-fake/.venv/bin/{script}", "args": [], "cwd": str(repo), "env_vars": ["WSL_DISTRO_NAME"],
                     "startup_timeout_sec": 60, "tool_timeout_sec": 600,
                     "env": {"PWEH_CONFIG": "/opt/pweh-fake/orchestrator/pipeline-config.yaml", "PWEH_TOOLS_DIR": "/opt/pweh-fake/tools"}}
    rea = data["mcp_servers"]["rea"]
    assert rea["enabled_tools"] == rea_tools_from_settings() and len(rea["enabled_tools"]) > 10
    assert rea["tool_timeout_sec"] == 900 and rea["startup_timeout_sec"] == 60 and rea["args"] == ["--mcp"] and "env_vars" not in rea
    assert clientcfg.read_options(text) == {"direct": "all", "rea": True, "tools_env": None}
    assert ">>" not in text
    assert any(line.startswith("작성: ") and line.endswith("config.toml (project)") for line in out)


def test_project_direct_and_no_rea_variants(tmp_path):
    rc, _ = write_cfg(tmp_path / "h", scope="project", repo=tmp_path / "r1", direct="case", include_rea=False)
    data = loads((tmp_path / "r1" / ".codex" / "config.toml").read_text())
    assert rc == 0 and data["features"]["code_mode"]["direct_only_tool_namespaces"] == ["mcp__pweh_case"] and "rea" not in data["mcp_servers"]
    rc, _ = write_cfg(tmp_path / "h", scope="project", repo=tmp_path / "r2", direct="none")
    text = (tmp_path / "r2" / ".codex" / "config.toml").read_text()
    assert rc == 0 and "features" not in loads(text) and "[features" not in text and "rea" in loads(text)["mcp_servers"]


def test_project_write_is_idempotent_and_backs_up_foreign_files(tmp_path):
    repo = tmp_path / "repo"
    write_cfg(tmp_path / "h", scope="project", repo=repo)
    path = repo / ".codex" / "config.toml"
    first = path.read_bytes()
    ino = path.stat().st_ino
    assert clientcfg.project_file_state(first.decode()) == "pweh" and first.decode().splitlines()[1].startswith(clientcfg.DIGEST_PREFIX)
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo)
    assert rc == 0 and path.read_bytes() == first and path.stat().st_ino == ino  # 같으면 쓰지 않는다
    assert any(line.startswith("변경 없음") for line in out) and backups(path.parent) == []
    # pweh 가 쓴 그대로인 파일은 생성 내용이 달라져도(옵션·경로가 바뀜) 백업 없이 바꾼다
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo, direct="case")
    assert rc == 0 and backups(path.parent) == [] and path.read_bytes() != first
    write_cfg(tmp_path / "h", scope="project", repo=repo)
    assert path.read_bytes() == first and backups(path.parent) == []
    # pweh 표식이 없는 다른 내용이면 백업한 뒤 바꾼다
    path.write_text('model = "mine"\n', encoding="utf-8")
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo)
    (bak,) = backups(path.parent)
    assert rc == 0 and path.read_bytes() == first and bak.read_text() == 'model = "mine"\n'
    assert any(line == f"백업: {bak}" for line in out)
    bak.unlink()
    # 빈 파일은 잃을 것이 없어 백업하지 않는다
    path.write_text("", encoding="utf-8")
    assert write_cfg(tmp_path / "h", scope="project", repo=repo)[0] == 0 and path.read_bytes() == first and backups(path.parent) == []


def test_project_hand_edits_are_backed_up_with_dropped_key_names(tmp_path):
    """표식을 남긴 채 사람이 고친 프로젝트 설정 (리뷰 s3 §1): 머리 주석이 약속한 대로 백업한 뒤 바꾸고, 사라질 표 이름만 알린다(값은 아님)."""
    repo = tmp_path / "repo"
    write_cfg(tmp_path / "h", scope="project", repo=repo)
    path = repo / ".codex" / "config.toml"
    first = path.read_text(encoding="utf-8")
    edited = first + ('\n# 내가 추가한 서버\n[mcp_servers.my-notes]\ncommand = "/usr/local/bin/notes-mcp"\n'
                      'env = { NOTES_TOKEN = "secret-123" }\n')
    path.write_text(edited, encoding="utf-8")
    assert clientcfg.project_file_state(edited) == "edited"
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo, direct="case", dry_run=True)
    text = "\n".join(out)
    assert rc == 0 and path.read_text(encoding="utf-8") == edited and backups(path.parent) == []
    assert "쓰면 백업한다" in text and "고친 내용이 있다" in text and "mcp_servers.my-notes" in text
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo, direct="case")
    (bak,) = backups(path.parent)
    assert rc == 0 and bak.read_text(encoding="utf-8") == edited and "my-notes" not in path.read_text(encoding="utf-8")
    note = next(line for line in out if "백업에만 남는" in line)
    assert "mcp_servers.my-notes" in note and "secret-123" not in note
    # 같은 옵션으로 다시 만들어도(파일이 생성 결과와 다를 뿐) 고친 파일이면 백업한다
    path.write_text(path.read_text(encoding="utf-8").replace("tool_timeout_sec = 600", "tool_timeout_sec = 5", 1), encoding="utf-8")
    write_cfg(tmp_path / "h", scope="project", repo=repo, direct="case")
    assert len(backups(path.parent)) == 2
    # 표식은 있지만 지문이 없는 파일(지문 줄을 지움)도 고친 파일로 본다
    sealed = path.read_text(encoding="utf-8")
    unsealed = "\n".join(ln for ln in sealed.splitlines() if not ln.startswith(clientcfg.DIGEST_PREFIX)) + "\n"
    assert clientcfg.project_file_state(unsealed) == "edited" and clientcfg.project_file_state(sealed) == "pweh"
    assert clientcfg.project_file_state(None) == "absent" and clientcfg.project_file_state("  \n") == "empty"
    assert clientcfg.project_file_state('model = "x"\n') == "foreign"


def test_project_write_refuses_symlinked_codex_dir_or_file(tmp_path):
    """<저장소>/.codex 나 config.toml 이 링크면(예: 사용자 Codex 홈을 가리킴) 프로젝트 설정으로 덮어쓰지 않는다 (dry-run 도 거부)."""
    user_home = tmp_path / "user-codex"
    user_home.mkdir()
    user_cfg = user_home / "config.toml"
    user_cfg.write_text('# my global Codex config\nmodel = "gpt-5.5"\n\n[mcp_servers.github]\ncommand = "gh-mcp"\n', encoding="utf-8")
    before = user_cfg.read_bytes()
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".codex").symlink_to(user_home, target_is_directory=True)
    repo2 = tmp_path / "repo2"
    (repo2 / ".codex").mkdir(parents=True)
    (repo2 / ".codex" / "config.toml").symlink_to(user_cfg)
    for repo in (repo1, repo2):
        for dry in (True, False):
            with pytest.raises(clientcfg.ClientConfigError) as ei:
                write_cfg(tmp_path / "h", scope="project", repo=repo, dry_run=dry)
            assert "심볼릭 링크" in str(ei.value) and str(user_home) in str(ei.value)
    assert user_cfg.read_bytes() == before and not list(user_home.glob("*.bak-pweh-*"))


def test_project_dry_run_writes_nothing(tmp_path):
    repo = tmp_path / "repo"
    rc, out = write_cfg(tmp_path / "h", scope="project", repo=repo, dry_run=True)
    assert rc == 0 and not (repo / ".codex").exists()  # 디렉터리도 만들지 않는다
    text = "\n".join(out)
    assert "+mcp_optional_startup_grace_ms = 15000" in text and "+[mcp_servers.pweh-case] # pweh-managed" in text and "/dev/null" in text


# ---------------------------------------------------------------------------
# 사용자 config.toml 병합 (--scope global)
# ---------------------------------------------------------------------------


def test_global_merge_preserves_user_content_backs_up_and_keeps_mode(tmp_path):
    home = tmp_path / "codex-home"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(USER_CFG, encoding="utf-8")
    cfg.chmod(0o640)
    rc, out = write_cfg(home)
    assert rc == 0
    text = cfg.read_text(encoding="utf-8")
    for c in ("# 내 Codex 설정 (주석 유지)", "# 모델", "# 사용자 기능"):
        assert c in text
    data = loads(text)
    assert data["model"] == "gpt-5.5" and data["features"]["web_search"] is True
    assert data["features"]["code_mode"] == {"direct_only_tool_namespaces": ALL_NS}
    assert data["mcp_servers"]["notes"] == {"command": "notes-mcp", "args": ["--stdio"]}
    assert data["projects"] == {"/srv/elsewhere": {"trust_level": "trusted"}}
    assert "pweh-oldname" not in data["mcp_servers"] and text.count("[mcp_servers.pweh-case]") == 1
    assert data["mcp_servers"]["pweh-case"]["command"] == "/opt/pweh-fake/.venv/bin/pweh-case-mcp"
    assert set(data["mcp_servers"]) == {"notes", *cli.SERVERS, "rea"}
    assert data["mcp_servers"]["rea"]["enabled_tools"] == rea_tools_from_settings()
    lines = text.splitlines()
    first_table = next(i for i, ln in enumerate(lines) if ln.startswith("["))
    assert lines.index("mcp_optional_startup_grace_ms = 15000") < first_table
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o640
    (bak,) = backups(home)
    assert bak.read_text(encoding="utf-8") == USER_CFG and stat.S_IMODE(bak.stat().st_mode) == 0o640
    assert f"백업: {bak}" in out and any(line.startswith(f"작성: {cfg}") for line in out)
    assert not list(home.glob(".config.toml.pweh-*"))  # 임시 파일이 남지 않는다
    # 다시 실행해도 같다 (중복 표·새 백업 없음)
    rc, out = write_cfg(home)
    assert rc == 0 and cfg.read_text(encoding="utf-8") == text and backups(home) == [bak]
    assert any(line.startswith("변경 없음") for line in out)


def test_global_merge_keeps_crlf_and_bom(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_bytes(b"\xef\xbb\xbf" + USER_CFG.replace("\n", "\r\n").encode("utf-8"))
    rc, _ = write_cfg(home)
    raw = cfg.read_bytes()
    assert rc == 0 and raw.startswith(b"\xef\xbb\xbf")
    assert raw.count(b"\n") == raw.count(b"\r\n") and b"[mcp_servers.pweh-esp] # pweh-managed\r\n" in raw
    assert loads(raw[3:].decode("utf-8"))["mcp_servers"]["notes"]["command"] == "notes-mcp"


IDEMPOTENT_CASES = {
    "no-file": None,
    "plain": '# 내 설정\nmodel = "gpt-5.5"\n\n[projects."/srv/elsewhere"]\ntrust_level = "trusted"\n',
    "user-direct": '[features.code_mode]\nenabled = true\ndirect_only_tool_namespaces = [\n  "mcp__notes",  # 내 것\n]\n',
    "user-rea": '[mcp_servers.rea]\ncommand = "/my/rea"\nargs = ["--mcp"]\n',
    "crlf-bom": "﻿" + '# 내 설정\r\nmodel = "gpt-5.5"\r\n\r\n[projects."/srv/elsewhere"]\r\ntrust_level = "trusted"\r\n',
}


@pytest.mark.parametrize("case", sorted(IDEMPOTENT_CASES))
def test_global_merge_is_idempotent(tmp_path, case):
    """다시 실행하면 같은 바이트 — 쓰기·백업 없음 (mcp_servers 아래에 pweh 표만 있는 흔한 경우 포함: 지우고 다시 더하면 빈 줄이 늘었다)."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    initial = IDEMPOTENT_CASES[case]
    if initial is not None:
        cfg.write_bytes(initial.encode("utf-8"))
    rc, _ = write_cfg(home)
    assert rc == 0
    first = cfg.read_bytes()
    baks = backups(home)
    for _ in range(2):
        rc, out = write_cfg(home)
        assert rc == 0 and cfg.read_bytes() == first and backups(home) == baks, out
        assert any(line.startswith(f"변경 없음: {cfg}") for line in out) and not any(line.startswith("작성:") for line in out)
    # 함수 수준: merge(merge(x)) == merge(x)
    specs = clientcfg.codex_server_specs(fake_servers(), Path("/r"), rea_tools=None)
    once, _ = clientcfg.merge_user_config(None if initial is None else initial.lstrip("﻿").replace("\r\n", "\n"), specs, ALL_NS,
                                          include_rea=True, where="x")
    twice, notes = clientcfg.merge_user_config(once, specs, ALL_NS, include_rea=True, where="x")
    assert twice == once and notes == []


def test_global_merge_changed_server_is_replaced_in_place(tmp_path):
    """서버 값이 바뀌면 그 줄만 바뀐다 (표를 끝으로 옮기거나 빈 줄을 늘리지 않는다). 원래 값으로 되돌리면 처음 바이트로 돌아온다."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(IDEMPOTENT_CASES["plain"], encoding="utf-8")
    write_cfg(home)
    first = cfg.read_text(encoding="utf-8")
    changed = fake_servers()
    changed["rea"] = {**changed["rea"], "env": {**changed["rea"]["env"], "PATH": "/other/bin:/usr/bin"}}
    changed["pweh-case"] = {**changed["pweh-case"], "command": "/new/.venv/bin/pweh-case-mcp"}
    rc, out = write_cfg(home, servers=changed)
    second = cfg.read_text(encoding="utf-8")
    assert rc == 0 and len(backups(home)) == 2
    import difflib

    delta = [ln for ln in difflib.ndiff(first.splitlines(), second.splitlines()) if ln[:1] in "+-"]
    assert sorted(delta) == sorted(['- command = "/opt/pweh-fake/.venv/bin/pweh-case-mcp"', '+ command = "/new/.venv/bin/pweh-case-mcp"',
                                    '+ PATH = "/other/bin:/usr/bin"']), delta
    write_cfg(home)
    assert cfg.read_text(encoding="utf-8") == first


def test_global_merge_top_level_insertion_before_first_table(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text('[mcp_servers.notes]\ncommand = "n"\n', encoding="utf-8")
    write_cfg(home)
    lines = cfg.read_text().splitlines()
    assert lines.index("mcp_optional_startup_grace_ms = 15000") < lines.index("[mcp_servers.notes]")
    assert loads(cfg.read_text())["mcp_optional_startup_grace_ms"] == 15000
    # 이미 있으면 사용자 값을 둔다
    cfg.write_text('mcp_optional_startup_grace_ms = 1000\n\n[mcp_servers.notes]\ncommand = "n"\n', encoding="utf-8")
    rc, out = write_cfg(home)
    assert rc == 0 and loads(cfg.read_text())["mcp_optional_startup_grace_ms"] == 1000
    assert any("1000 유지" in line for line in out)


def test_global_merge_features_variants(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    # 불리언 형식 → enabled 를 지킨 표
    cfg.write_text("[features]\ncode_mode = true\nother_flag = false\n", encoding="utf-8")
    write_cfg(home, direct="case")
    data = loads(cfg.read_text())
    assert data["features"] == {"other_flag": False, "code_mode": {"enabled": True, "direct_only_tool_namespaces": ["mcp__pweh_case"]}}
    # 사용자 이름공간은 두고 예전 pweh 항목만 맞춘다
    cfg.write_text('[features.code_mode]\nenabled = true\ndirect_only_tool_namespaces = [\n  "mcp__notes",  # 내 것\n'
                   '  "mcp__pweh_jtagulator",\n]\n', encoding="utf-8")
    write_cfg(home, direct="case")
    text = cfg.read_text()
    assert loads(text)["features"]["code_mode"] == {"enabled": True, "direct_only_tool_namespaces": ["mcp__notes", "mcp__pweh_case"]}
    assert "# 내 것" in text
    write_cfg(home, direct="all")
    assert loads(cfg.read_text())["features"]["code_mode"]["direct_only_tool_namespaces"] == ["mcp__notes", "mcp__pweh_case", *ALL_NS[1:]]
    write_cfg(home, direct="none")
    assert loads(cfg.read_text())["features"]["code_mode"]["direct_only_tool_namespaces"] == ["mcp__notes"]
    # pweh 항목만 있던 목록은 none 이면 키를 지운다
    cfg.write_text('[features.code_mode]\ndirect_only_tool_namespaces = ["mcp__pweh_case"]\n', encoding="utf-8")
    write_cfg(home, direct="none")
    assert loads(cfg.read_text())["features"] == {"code_mode": {}}


def test_global_merge_rea_ownership(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    user_rea = '[mcp_servers.rea]\ncommand = "/my/rea"\nargs = ["--mcp", "--custom"]\n'
    cfg.write_text(user_rea, encoding="utf-8")
    rc, out = write_cfg(home)
    assert rc == 0 and loads(cfg.read_text())["mcp_servers"]["rea"] == {"command": "/my/rea", "args": ["--mcp", "--custom"]}
    assert any("사용자 설정" in line for line in out)
    write_cfg(home, include_rea=False)
    assert loads(cfg.read_text())["mcp_servers"]["rea"] == {"command": "/my/rea", "args": ["--mcp", "--custom"]}
    # pweh 가 넣은 rea(표식)는 바꾸고, --no-rea 면 지운다
    cfg.write_text("", encoding="utf-8")
    write_cfg(home)
    text = cfg.read_text()
    assert "[mcp_servers.rea] # pweh-managed" in text
    import tomlkit

    assert clientcfg.rea_state(tomlkit.parse(text)) == "managed"
    write_cfg(home, servers={**fake_servers(), "rea": {**fake_servers()["rea"], "command": "/new/rea"}})
    assert loads(cfg.read_text())["mcp_servers"]["rea"]["command"] == "/new/rea" and cfg.read_text().count("[mcp_servers.rea]") == 1
    rc, out = write_cfg(home, include_rea=False)
    assert rc == 0 and "rea" not in loads(cfg.read_text())["mcp_servers"] and any("rea] 제거" in line for line in out)


def test_global_dry_run_shows_diff_and_writes_nothing(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(USER_CFG, encoding="utf-8")
    rc, out = write_cfg(home, dry_run=True)
    assert rc == 0 and cfg.read_text() == USER_CFG and backups(home) == []
    text = "\n".join(out)
    assert f"--- {cfg} (현재)" in text and "-command = \"/old/path/pweh-case-mcp\"" in text and "+mcp_optional_startup_grace_ms = 15000" in text
    new_home = tmp_path / "new" / ".codex"  # 없는 홈은 이름이 .codex 일 때만 받는다
    rc, out = write_cfg(new_home, dry_run=True, repo=tmp_path / "repo")
    assert rc == 0 and not new_home.exists() and not new_home.parent.exists()


def test_user_config_diff_masks_unrelated_values(tmp_path):
    """사용자 설정의 dry-run diff: 바뀌지 않는 줄(문맥)의 값과 지워지는 env 줄의 값은 가리고, 표 머리와 pweh 가 더하는 줄은 보여 준다."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text('model = "gpt-5.5"  # 내 모델\n\n[mcp_servers.other]\ncommand = "other-mcp"\n\n[mcp_servers.other.env]\n'
                   'API_TOKEN = "s3cret-token-value"\n\n[mcp_servers.pweh-case]\ncommand = "/old/pweh-case-mcp"\n'
                   'env = { PWEH_SECRET = "pasted-token" }\n', encoding="utf-8")
    rc, out = write_cfg(home, dry_run=True)
    text = "\n".join(out)
    assert rc == 0 and "s3cret-token-value" not in text and "pasted-token" not in text and '"gpt-5.5"' not in text
    assert " API_TOKEN = …" in text and " [mcp_servers.other.env]" in text and "-command = \"/old/pweh-case-mcp\"" in text
    assert "+[mcp_servers.pweh-uart] # pweh-managed" in text and f"+++ {cfg} (pweh)" in text
    rc, out = trust(tmp_path, [home], dry_run=True)
    assert rc == 0 and "s3cret-token-value" not in "\n".join(out) and '+trust_level = "trusted"' in "\n".join(out)
    # 프로젝트 설정(pweh 가 만드는 파일)은 가리지 않는다
    lines = clientcfg.masked_diff(["a = 1", 'b = "x"', "c = 3"], ["a = 1", 'b = "y"', "c = 3"], "f", "t").splitlines()
    assert lines[:3] == ["--- f", "+++ t", "@@ -1,3 +1,3 @@"] and " a = …" in lines and '-b = "x"' in lines and '+b = "y"' in lines
    assert clientcfg.masked_diff(["x = 1"], ["x = 1"], "f", "t") == ""


def test_invalid_toml_is_refused_and_nothing_is_written(tmp_path):
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.mkdir()
    bad.mkdir()
    (good / "config.toml").write_text(USER_CFG, encoding="utf-8")
    dup = '[mcp_servers.pweh-case]\ncommand = "a"\n\n[mcp_servers.pweh-case]\ncommand = "b"\n'
    (bad / "config.toml").write_text(dup, encoding="utf-8")
    rc, out = write_cfg(good, homes=[str(good), str(bad)])
    assert rc == 1 and any(line.startswith("거부:") and "올바른 TOML" in line for line in out)
    assert (good / "config.toml").read_text() == USER_CFG and (bad / "config.toml").read_text() == dup
    assert backups(good) == [] and backups(bad) == []
    (bad / "config.toml").write_bytes(b"model = \"\xff\xfe\"\n")  # UTF-8 아님
    rc, out = write_cfg(bad)
    assert rc == 1 and any("UTF-8" in line for line in out)
    rc = clientcfg.codex_trust(repo=tmp_path, codex_homes=[str(bad)], yes=True, dry_run=False, check=False, interactive=False,
                               say=out.append)
    assert rc == 1 and (bad / "config.toml").read_bytes() == b"model = \"\xff\xfe\"\n"


def test_symlinked_user_config_is_updated_through_the_link(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    real = tmp_path / "dotfiles" / "codex.toml"
    real.parent.mkdir()
    real.write_text(USER_CFG, encoding="utf-8")
    (home / "config.toml").symlink_to(real)
    rc, _ = write_cfg(home)
    assert rc == 0 and (home / "config.toml").is_symlink() and "pweh-case" in loads(real.read_text())["mcp_servers"]
    assert len(list(real.parent.glob("codex.toml.bak-pweh-*"))) == 1


def test_merge_rejects_structures_it_cannot_edit_safely():
    specs = clientcfg.codex_server_specs(fake_servers(), Path("/r"), rea_tools=None)
    with pytest.raises(clientcfg.ClientConfigError):
        clientcfg.merge_user_config('mcp_servers = { notes = { command = "n" } }\n', specs, ALL_NS, include_rea=True, where="x")
    with pytest.raises(clientcfg.ClientConfigError):
        clientcfg.merge_user_config("features = 3\n", specs, ALL_NS, include_rea=True, where="x")


def test_rea_enabled_tools_rules(tmp_path):
    tools, warn = clientcfg.rea_enabled_tools(SETTINGS)
    assert tools == rea_tools_from_settings() and warn is None
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"permissions": {"allow": ["mcp__rea__a", "mcp__rea__b", "mcp__pweh-case__*"], "ask": ["mcp__rea__a", "mcp__rea__c"],
                                             "deny": ["mcp__rea__c"]}}))
    assert clientcfg.rea_enabled_tools(p) == (["a", "b"], None)
    p.write_text(json.dumps({"permissions": {"allow": ["mcp__rea__*"]}}))
    tools, warn = clientcfg.rea_enabled_tools(p)
    assert tools is None and "mcp__rea__*" in warn
    p.write_text(json.dumps({"permissions": {"allow": ["mcp__pweh-case__*"]}}))
    assert clientcfg.rea_enabled_tools(p)[0] is None  # 빈 enabled_tools 는 만들지 않는다
    assert clientcfg.rea_enabled_tools(tmp_path / "missing.json")[0] is None
    specs = clientcfg.codex_server_specs(fake_servers(), Path("/r"), rea_tools=None)
    assert "enabled_tools" not in specs["rea"]
    assert clientcfg.direct_namespaces(specs, "all") == ALL_NS and "mcp__rea" not in clientcfg.direct_namespaces(specs, "all")


# ---------------------------------------------------------------------------
# codex-trust
# ---------------------------------------------------------------------------


def trust(repo, homes, **kw):
    out: list[str] = []
    args = {"yes": False, "dry_run": False, "check": False, "interactive": False}
    args.update(kw)
    rc = clientcfg.codex_trust(repo=repo, codex_homes=[str(h) for h in homes], say=out.append, **args)
    return rc, out


def test_codex_trust_add_check_dry_run_and_non_tty(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    key = os.path.realpath(repo)
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(USER_CFG, encoding="utf-8")
    cfg.chmod(0o600)
    rc, out = trust(repo, [home], check=True)
    assert rc == 1 and any("신뢰 항목 없음" in line for line in out)
    rc, out = trust(repo, [home])  # TTY 가 아니고 --yes 도 없으면 아무것도 하지 않는다
    assert rc == 0 and cfg.read_text() == USER_CFG and any("--yes" in line for line in out)
    rc, out = trust(repo, [home], dry_run=True)
    assert rc == 0 and cfg.read_text() == USER_CFG and any(f'+[projects."{key}"]' in line for line in out)
    rc, out = trust(repo, [home], interactive=True, ask=lambda prompt: "n")
    assert rc == 0 and cfg.read_text() == USER_CFG
    rc, out = trust(repo, [home], interactive=True, ask=lambda prompt: "y")
    assert rc == 0 and loads(cfg.read_text())["projects"][key] == {"trust_level": "trusted"}
    assert loads(cfg.read_text())["projects"]["/srv/elsewhere"] == {"trust_level": "trusted"} and "# 모델" in cfg.read_text()
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600 and len(backups(home)) == 1
    rc, out = trust(repo, [home], check=True)
    assert rc == 0 and any("신뢰됨" in line for line in out)
    rc, out = trust(repo, [home], yes=True)  # 이미 신뢰됨 → 쓰지 않는다
    assert rc == 0 and any("이미 신뢰됨" in line for line in out) and len(backups(home)) == 1
    # 두 번째 홈(아직 없는 .codex)은 --check 가 1, --yes 로 새 파일(0600)을 만든다
    home2 = tmp_path / "h2" / ".codex"
    rc, _ = trust(repo, [home, home2], check=True)
    assert rc == 1
    rc, out = trust(repo, [home, home2], yes=True)
    assert rc == 0 and loads((home2 / "config.toml").read_text()) == {"projects": {key: {"trust_level": "trusted"}}}
    assert stat.S_IMODE((home2 / "config.toml").stat().st_mode) == 0o600 and stat.S_IMODE(home2.stat().st_mode) == 0o700
    # untrusted 는 신뢰 없음으로 보고 --yes 면 trusted 로 바꾼다
    cfg.write_text(f'[projects."{key}"]\ntrust_level = "untrusted"\n', encoding="utf-8")
    assert trust(repo, [home], check=True)[0] == 1
    rc, out = trust(repo, [home], yes=True)
    assert rc == 0 and loads(cfg.read_text())["projects"][key]["trust_level"] == "trusted"


def test_codex_trust_without_homes_is_a_no_op(tmp_path, monkeypatch):
    monkeypatch.setattr(clientcfg.shutil, "which", lambda name, *a, **k: None if name == "codex" else _REAL_WHICH(name, *a, **k))
    out: list[str] = []
    rc = clientcfg.codex_trust(repo=tmp_path, codex_homes=None, yes=True, dry_run=False, check=True, interactive=False, say=out.append)
    assert rc == 0 and any("찾지 못했다" in line for line in out)


# ---------------------------------------------------------------------------
# Codex 홈 찾기 (가짜 Windows 프로필)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_profile(tmp_path, monkeypatch):
    profile = tmp_path / "c" / "Users" / "tester"
    (profile / ".codex").mkdir(parents=True)
    monkeypatch.setattr(clientcfg, "windows_profile", lambda report=None: (profile, "시험 프로필"))
    return profile


def test_scan_homes_cli_and_desktop_wsl_mode(fake_profile, _isolated, monkeypatch):
    (_isolated / ".codex").mkdir()
    dcfg = fake_profile / ".codex" / "config.toml"
    dcfg.write_text("[desktop]\nrunCodexInWindowsSubsystemForLinux = true\n", encoding="utf-8")
    homes, notes = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.path, h.skipped) for h in homes] == [("cli", _isolated / ".codex", None), ("desktop-wsl", fake_profile / ".codex", None)]
    assert notes == []
    dcfg.write_text("[desktop]\nrunCodexInWindowsSubsystemForLinux = false\n", encoding="utf-8")
    homes, _ = clientcfg.scan_codex_homes(None)
    desk = homes[-1]
    assert desk.label == "desktop-wsl" and desk.skipped and "WSL 모드가 아님" in desk.skipped
    dcfg.write_text('model = "x"\n', encoding="utf-8")
    assert "WSL 모드가 아님" in clientcfg.scan_codex_homes(None)[0][-1].skipped
    dcfg.write_text("[desktop\n", encoding="utf-8")
    assert "읽지 못함" in clientcfg.scan_codex_homes(None)[0][-1].skipped
    # 건너뛴 홈에는 쓰지 않는다
    rc, out = write_cfg(fake_profile, homes=None)
    assert rc == 0 and dcfg.read_text() == "[desktop\n" and any(line.startswith("건너뜀:") for line in out)


def test_scan_homes_codex_home_pointing_at_desktop_home(fake_profile, _isolated, monkeypatch):
    """데스크톱 에이전트 안(WSLENV 로 CODEX_HOME = Windows 홈): 데스크톱 홈은 desktop-wsl 하나로, WSL CLI 의 ~/.codex 도 함께 찾는다."""
    (fake_profile / ".codex" / "config.toml").write_text("[desktop]\nrunCodexInWindowsSubsystemForLinux = true\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(fake_profile / ".codex"))
    monkeypatch.setattr(clientcfg.shutil, "which", lambda name, *a, **k: None if name == "codex" else _REAL_WHICH(name, *a, **k))
    homes, _ = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.path) for h in homes] == [("desktop-wsl", fake_profile / ".codex")] and "$CODEX_HOME" in homes[0].source
    (_isolated / ".codex").mkdir()
    homes, _ = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.path) for h in homes] == [("cli", _isolated / ".codex"), ("desktop-wsl", fake_profile / ".codex")]
    # 사용자가 셸에서 CODEX_HOME 을 따로 정했으면 그 홈과 ~/.codex 를 둘 다 본다 (doctor 줄 이름은 겹치지 않게)
    custom = _isolated / "custom-codex"
    custom.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(custom))
    homes, _ = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.source) for h in homes][:2] == [("cli", "$CODEX_HOME"), ("cli", "~/.codex")]
    names = [c["check"] for c in clientcfg.codex_checks(_isolated, project={"state": "missing", "path": "x"}, homes=homes)]
    assert "codex:trust[cli]" in names and "codex:trust[cli-2]" in names and "codex:trust[desktop-wsl]" in names


def test_scan_homes_does_not_invent_unused_default_home(fake_profile, _isolated, monkeypatch):
    """CODEX_HOME 을 따로 정한 사용자에게 없는 ~/.codex 를 만들어 넣지 않는다 (CLI 가 읽지 않는 홈). 데스크톱 에이전트 안이면 찾는다."""
    monkeypatch.setattr(clientcfg.shutil, "which", lambda name, *a, **k: "/usr/local/bin/codex" if name == "codex" else _REAL_WHICH(name, *a, **k))
    custom = _isolated / "custom-codex"
    custom.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(custom))
    homes, _ = clientcfg.scan_codex_homes(None)
    # ~/.codex 는 없고 CLI 는 $CODEX_HOME 을 쓴다. 데스크톱 홈은 config.toml 이 없어 건너뜀으로만 보인다
    assert [(h.label, h.path, bool(h.skipped)) for h in homes] == [("cli", custom, False), ("desktop-wsl", fake_profile / ".codex", True)]
    (fake_profile / ".codex" / "config.toml").write_text("[desktop]\nrunCodexInWindowsSubsystemForLinux = true\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(fake_profile / ".codex"))
    homes, _ = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.path) for h in homes] == [("cli", _isolated / ".codex"), ("desktop-wsl", fake_profile / ".codex")]
    assert not (_isolated / ".codex").exists() and "아직 없음" in homes[0].source


def test_scan_homes_without_codex_and_explicit_override(tmp_path, monkeypatch):
    monkeypatch.setattr(clientcfg.shutil, "which", lambda name, *a, **k: None if name == "codex" else _REAL_WHICH(name, *a, **k))
    assert clientcfg.scan_codex_homes(None) == ([], [])
    monkeypatch.setattr(clientcfg.shutil, "which", lambda name, *a, **k: "/usr/local/bin/codex" if name == "codex" else None)
    homes, _ = clientcfg.scan_codex_homes(None)
    assert [h.label for h in homes] == ["cli"] and not homes[0].path.exists()
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    homes, notes = clientcfg.scan_codex_homes([str(a), str(a), str(b)])
    assert [(h.label, h.path) for h in homes] == [("explicit", a), ("explicit", b)] and notes == []


def test_explicit_codex_home_must_exist_or_be_named_dot_codex(tmp_path, monkeypatch):
    """--codex-home '' 는 지금 디렉터리를 홈으로 쓰지 않고 거부한다. 오타(없는 디렉터리)도 거부하고, 이름이 .codex 인 새 홈만 받는다."""
    monkeypatch.chdir(tmp_path)
    for bad in ("", "   "):
        with pytest.raises(clientcfg.ClientConfigError, match="비어 있다"):
            clientcfg.scan_codex_homes([bad])
    with pytest.raises(clientcfg.ClientConfigError, match="없다"):
        clientcfg.scan_codex_homes([str(tmp_path / ".codx")])
    (tmp_path / "file").write_text("x")
    with pytest.raises(clientcfg.ClientConfigError, match="디렉터리가 아니다"):
        clientcfg.scan_codex_homes([str(tmp_path / "file")])
    homes, _ = clientcfg.scan_codex_homes([str(tmp_path / "new" / ".codex")])
    assert homes[0].path == tmp_path / "new" / ".codex"
    out: list[str] = []
    with pytest.raises(clientcfg.ClientConfigError):
        clientcfg.codex_trust(repo=tmp_path, codex_homes=[""], yes=True, dry_run=False, check=False, interactive=False, say=out.append)
    assert not (tmp_path / "config.toml").exists()
    # CLI: 같은 거부를 한 줄로 (--check 는 '확인하지 못함' = 종료 코드 2)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    assert cli.main(["codex-trust", "--codex-home", "", "--yes"]) == 1
    assert cli.main(["codex-trust", "--codex-home", "", "--check"]) == 2
    assert not (tmp_path / "config.toml").exists()


def test_shared_home_with_native_windows_desktop_is_reported_and_not_written(fake_profile, _isolated, monkeypatch):
    """~/.codex 가 WSL 모드가 아닌 Windows 데스크톱 앱 홈을 가리키는 링크면: 건너뛴 이유를 알리고 --scope global 은 자동으로 쓰지 않는다.
    trust 는 무해하므로 더한다. --codex-home 으로 직접 주면 쓴다."""
    dcfg = fake_profile / ".codex" / "config.toml"
    dcfg.write_text('model = "x"\n', encoding="utf-8")
    (_isolated / ".codex").symlink_to(fake_profile / ".codex", target_is_directory=True)
    homes, notes = clientcfg.scan_codex_homes(None)
    assert [(h.label, h.native_windows is not None) for h in homes] == [("cli", True)]
    assert any("같은 디렉터리" in n and "WSL 모드가 아님" in n for n in notes)
    rc, out = write_cfg(_isolated / ".codex", homes=None)
    assert rc == 1 and dcfg.read_text(encoding="utf-8") == 'model = "x"\n' and any("데스크톱 앱 홈과 같은 디렉터리" in ln for ln in out)
    out2: list[str] = []
    assert clientcfg.codex_trust(repo=_isolated, codex_homes=None, yes=True, dry_run=False, check=False, interactive=False, say=out2.append) == 0
    assert "trust_level" in dcfg.read_text(encoding="utf-8")
    rc, _ = write_cfg(_isolated / ".codex", homes=[str(_isolated / ".codex")])
    assert rc == 0 and "pweh-case" in loads(dcfg.read_text(encoding="utf-8"))["mcp_servers"]


def test_windows_profile_override_and_userprofile(tmp_path, monkeypatch):
    profile = tmp_path / "c" / "Users" / "tester"
    profile.mkdir(parents=True)
    monkeypatch.setenv(clientcfg.WINDOWS_PROFILE_ENV, str(profile))
    assert _REAL_WINDOWS_PROFILE() == (profile, clientcfg.WINDOWS_PROFILE_ENV)
    monkeypatch.setenv(clientcfg.WINDOWS_PROFILE_ENV, str(tmp_path / "missing"))
    p, why = _REAL_WINDOWS_PROFILE()
    assert p is None and "없음" in why
    monkeypatch.delenv(clientcfg.WINDOWS_PROFILE_ENV)
    monkeypatch.setenv("USERPROFILE", str(profile))
    assert _REAL_WINDOWS_PROFILE() == (profile, "USERPROFILE")


def test_interop_profile_uses_fixed_powershell_script_not_cmd(tmp_path, monkeypatch):
    """interop 경로: hostenv 가 확인한 powershell.exe + 고정 스크립트, cwd=C: 마운트. cmd.exe 는 쓰지 않는다 (실제로 실행하지 않음)."""
    from pweh import hostenv

    c_root = tmp_path / "c"
    profile = c_root / "Users" / "tester"
    profile.mkdir(parents=True)
    report = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}}
    monkeypatch.setattr(hostenv, "powershell_path", lambda probe=None: "/fake/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setattr(hostenv, "drvfs_root", lambda drive="C", probe=None: str(c_root))
    monkeypatch.setattr(hostenv, "windows_path_to_wsl", lambda p, probe=None: str(profile) if p == "C:\\Users\\tester" else None)
    calls = []

    def fake_run(argv, **kw):
        calls.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, 0, stdout="C:\\Users\\tester\r\n".encode("utf-8"), stderr=b"")

    monkeypatch.setattr(clientcfg.subprocess, "run", fake_run)
    assert clientcfg._interop_profile(report) == (profile, "interop (powershell.exe)")
    (argv, kw), = calls
    assert argv[0].endswith("powershell.exe") and argv[1:4] == ["-NoProfile", "-NonInteractive", "-Command"] and argv[4] == clientcfg.PS_USER_PROFILE
    assert kw["cwd"] == str(c_root) and kw["timeout"] == clientcfg.PS_TIMEOUT_S and kw["stdin"] == subprocess.DEVNULL
    assert "cmd.exe" not in " ".join(argv)
    calls.clear()
    p, why = clientcfg._interop_profile({"kind": "WSL2_NO_INTEROP", "wsl": {"interop": {"usable": False, "reason": "꺼짐"}}})
    assert p is None and "interop" in why and calls == []
    assert clientcfg._interop_profile({"kind": "NATIVE_LINUX"}) == (None, "WSL 이 아님") and calls == []


# ---------------------------------------------------------------------------
# mcp-check (실제 pweh-case 서버 + 가짜 서버)
# ---------------------------------------------------------------------------

FAKE_MCP = r'''#!{python}
import json, os, sys
dump = os.environ.get("FAKE_DUMP")
if dump:
    with open(dump, "w") as fh:
        json.dump({{"env": dict(os.environ), "cwd": os.getcwd()}}, fh)
if os.environ.get("FAKE_BANNER"):
    print("hello from a server that prints to stdout", flush=True)
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        res = {{"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "fake-mcp", "version": "0.0.1"}}}}
    elif msg["method"] == "tools/list":
        res = {{"tools": [{{"name": "t1", "inputSchema": {{"type": "object"}}}}, {{"name": "t2", "inputSchema": {{"type": "object"}}}}]}}
    else:
        res = {{}}
    sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": res}}) + "\n")
    sys.stdout.flush()
'''


def fake_mcp(tmp_path: Path) -> Path:
    p = tmp_path / "fake-mcp"
    p.write_text(FAKE_MCP.format(python=sys.executable), encoding="utf-8")
    p.chmod(0o755)
    return p


def failing_mcp(tmp_path: Path) -> Path:
    p = tmp_path / "failing-mcp"
    p.write_text("#!/bin/sh\necho 'boom: 시작 실패' >&2\nexit 3\n", encoding="utf-8")
    p.chmod(0o755)
    return p


def real_case_spec(workspace) -> dict:
    exe = REPO / ".venv" / "bin" / "pweh-case-mcp"
    if not exe.exists():
        found = shutil.which("pweh-case-mcp")
        if not found:
            pytest.skip("pweh-case-mcp 가 설치되어 있지 않다")
        exe = Path(found)
    # 설정 env 가 주변 환경보다 이긴다 → 격리된 작업공간을 spec env 로 준다 (실제 저장소 .pweh/ cases/ 를 쓰지 않게)
    return {"command": str(exe), "args": [], "cwd": str(REPO), "env_vars": ["WSL_DISTRO_NAME"], "startup_timeout_sec": 60,
            "tool_timeout_sec": 600, "env": {"PWEH_CONFIG": str(workspace["config"]), "PWEH_CASES_DIR": str(workspace["cases_dir"]),
                                             "PWEH_STATE_DIR": str(workspace["state_dir"])}}


def test_check_servers_real_pweh_case_and_failing_command(workspace, tmp_path):
    rows = clientcfg.check_servers({"pweh-case": real_case_spec(workspace), "pweh-uart": {"command": str(failing_mcp(tmp_path)), "args": []},
                                    "pweh-esp": {"command": str(tmp_path / "missing-mcp"), "args": []}}, client="codex", timeout=60)
    case, uart, esp = rows
    assert case["ok"] is True and case["tools"] > 10 and case["server_info"].startswith("case-mcp") and case["error"] is None, case
    assert case["protocol"] and case["t_total"] < 60
    assert uart["ok"] is False and "boom" in " ".join(uart["stderr_tail"]) and uart["error"]
    assert esp["ok"] is False and "실행 파일 없음" in esp["error"]


def test_check_server_collects_stderr_after_child_exit(tmp_path, monkeypatch):
    """자식 종료 뒤에도 수신 스레드가 보류되면 join을 거쳐 stderr를 수집한다."""
    import threading

    release = threading.Event()
    entered = threading.Event()
    joined = threading.Event()
    readers = []
    read_err = clientcfg._StdioClient._read_err
    close = clientcfg._StdioClient.close
    join = threading.Thread.join

    def delayed_err(self):
        readers.append(threading.current_thread())
        entered.set()
        if release.wait(10):
            read_err(self)

    def release_on_join(thread, timeout=None):
        if readers and thread is readers[0]:
            joined.set()
            release.set()
        return join(thread, timeout)

    def close_after_reader_started(self, grace=3.0):
        assert entered.wait(10)
        return close(self, grace=grace)

    monkeypatch.setattr(clientcfg._StdioClient, "_read_err", delayed_err)
    monkeypatch.setattr(clientcfg._StdioClient, "close", close_after_reader_started)
    monkeypatch.setattr(threading.Thread, "join", release_on_join)
    try:
        result = clientcfg.check_server(
            "pweh-failing", {"command": str(failing_mcp(tmp_path)), "args": []},
            env=clientcfg.codex_like_env(), timeout=10,
        )
        assert entered.wait(1)
        assert result["ok"] is False
        assert "boom: 시작 실패" in " ".join(result["stderr_tail"])
        assert joined.is_set()
        assert not readers[0].is_alive()
    finally:
        release.set()
        for reader in readers:
            join(reader, 2)


def test_stdio_close_reader_joins_share_a_bounded_deadline(monkeypatch):
    """첫 reader가 예산을 써도 두 번째에 새 예산을 주거나 stream을 직접 닫지 않는다."""
    from types import SimpleNamespace

    now = [10.0]
    waits = []

    class PendingReader:
        ident = 1

        def join(self, timeout):
            waits.append(timeout)
            now[0] += timeout

    class PendingStream:
        def close(self):
            pytest.fail("수신 중인 stream은 그 reader만 닫아야 한다")

    cli = clientcfg._StdioClient.__new__(clientcfg._StdioClient)
    cli.p = SimpleNamespace(stdin=None, stdout=PendingStream(), stderr=PendingStream(), wait=lambda **kwargs: 0)
    cli._readers = (PendingReader(), PendingReader())
    monkeypatch.setattr(cli, "_group_alive", lambda: False)
    monkeypatch.setattr(clientcfg.time, "monotonic", lambda: now[0])
    cli.close()
    assert waits == [2.0, 0.0]


def test_stdio_close_skips_reader_that_did_not_start(monkeypatch):
    """reader 시작 실패 뒤 남은 객체도 미시작 Thread.join 없이 정리한다."""
    import threading
    from types import SimpleNamespace

    reader = threading.Thread(target=lambda: None, daemon=True)
    cli = clientcfg._StdioClient.__new__(clientcfg._StdioClient)
    cli.p = SimpleNamespace(stdin=None, wait=lambda **kwargs: 0)
    cli._readers = (reader,)
    monkeypatch.setattr(cli, "_group_alive", lambda: False)
    with clientcfg._LIVE_LOCK:
        clientcfg._LIVE.add(cli)
    try:
        cli.close()
        assert reader.ident is None
        with clientcfg._LIVE_LOCK:
            assert cli not in clientcfg._LIVE
    finally:
        with clientcfg._LIVE_LOCK:
            clientcfg._LIVE.discard(cli)


def test_check_server_uses_codex_like_environment_and_flags_stdout_noise(tmp_path, monkeypatch):
    srv = fake_mcp(tmp_path)
    dump = tmp_path / "env.json"
    monkeypatch.setenv("PWEH_SECRET_AMBIENT", "x")
    monkeypatch.setenv("WSL_DISTRO_NAME", "TestDistro")
    rows = clientcfg.check_servers({"pweh-fake": {"command": str(srv), "args": [], "cwd": str(tmp_path), "env_vars": ["WSL_DISTRO_NAME"],
                                                  "env": {"FAKE_DUMP": str(dump)}}}, client="codex", timeout=30)
    assert rows[0]["ok"] is True and rows[0]["tools"] == 2 and rows[0]["server_info"] == "fake-mcp 0.0.1"
    seen = json.loads(dump.read_text())
    assert set(seen["env"]) - {"FAKE_DUMP", "WSL_DISTRO_NAME", "PWD", "SHLVL", "_", "LC_CTYPE"} <= set(clientcfg.CODEX_LIKE_ENV)
    assert seen["env"]["WSL_DISTRO_NAME"] == "TestDistro" and "PWEH_SECRET_AMBIENT" not in seen["env"] and seen["cwd"] == str(tmp_path)
    rows = clientcfg.check_servers({"pweh-fake": {"command": str(srv), "args": [], "env": {"FAKE_BANNER": "1"}}}, client="codex", timeout=30)
    assert rows[0]["ok"] is False and "JSON 이 아닌 줄" in rows[0]["error"]


def test_mcp_check_claude_uses_mcp_json_with_project_dir(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    srv = fake_mcp(repo)
    dump = tmp_path / "claude-env.json"
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "pweh-case": {"type": "stdio", "command": "bash", "args": ["-c", f'FAKE_DUMP={dump} exec "$CLAUDE_PROJECT_DIR/fake-mcp"']},
        "other": {"type": "stdio", "command": "/bin/false"}}}), encoding="utf-8")
    out: list[str] = []
    rc = clientcfg.mcp_check(repo=repo, client="claude", deep=False, timeout=30, generated=dict, server_names=["pweh-case", "pweh-uart"],
                             as_json=True, say=out.append)
    rep = json.loads(out[0])
    rows = {r["server"]: r for r in rep["clients"]["claude"]["servers"]}
    assert rc == 0 and rows["pweh-case"]["ok"] is True and rows["pweh-uart"]["ok"] is None and "other" not in rows
    seen = json.loads(dump.read_text())
    assert seen["env"]["CLAUDE_PROJECT_DIR"] == str(repo) and seen["cwd"] == str(repo)
    rc = clientcfg.mcp_check(repo=tmp_path / "nowhere", client="claude", deep=False, timeout=5, generated=dict, server_names=[],
                             as_json=True, say=out.append)
    assert rc == 1 and ".mcp.json" in json.loads(out[-1])["clients"]["claude"]["error"]


def test_mcp_check_codex_reads_project_config(workspace, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".codex").mkdir(parents=True)
    specs = {"pweh-case": real_case_spec(workspace), "pweh-uart": {"command": str(failing_mcp(tmp_path)), "args": []}}
    (repo / ".codex" / "config.toml").write_text(clientcfg.render_project_config(specs, [], ["# 시험"]), encoding="utf-8")
    out: list[str] = []
    rc = clientcfg.mcp_check(repo=repo, client="codex", deep=False, timeout=60, generated=dict, server_names=list(cli.SERVERS), as_json=False,
                             say=out.append)
    text = "\n".join(out)
    assert rc == 1 and f"codex: {repo}/.codex/config.toml" in text
    assert "[OK ] codex:pweh-case" in text and "[!! ] codex:pweh-uart" in text and "[-- ] codex:pweh-esp" in text and "결과: 1/2 정상" in text


@pytest.mark.external
def test_deep_check_with_real_codex(workspace, tmp_path, monkeypatch, _isolated):
    if not shutil.which("codex"):
        pytest.skip("codex 가 없다")
    # 사용자의 Codex 홈 대역: --deep 은 여기에 아무것도 만들지 않는다. codex 는 임시 디렉터리(TMPDIR) 아래의 홈에는 도우미를
    # 만들지 않으므로, 실제 ~/.codex 처럼 TMPDIR 밖에 두도록 TMPDIR 을 따로 준다
    user_codex_home = tmp_path / "user-codex-home"
    user_codex_home.mkdir()
    fake_tmp = tmp_path / "tmpdir"
    fake_tmp.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(user_codex_home))
    monkeypatch.setenv("TMPDIR", str(fake_tmp))
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", None)  # mkdtemp 가 바꾼 TMPDIR 을 쓰게
    d = clientcfg.deep_check({"pweh-case": real_case_spec(workspace), "pweh-uart": {"command": str(failing_mcp(tmp_path)), "args": [],
                                                                                    "startup_timeout_sec": 10}}, timeout=30)
    rows = {r["server"]: r for r in d["servers"]}
    assert d["error"] is None, d
    assert rows["pweh-case"]["ok"] is True and rows["pweh-case"]["tools"] > 10 and rows["pweh-case"]["server_info"].startswith("case-mcp")
    assert rows["pweh-uart"]["ok"] is False and rows["pweh-uart"]["error"]
    assert d["ok"] is False and d["version"]
    # codex 는 --version 에도 $CODEX_HOME/tmp 를 만든다 — 버전 확인도 임시 홈에서 한다
    assert list(user_codex_home.iterdir()) == [] and not (_isolated / ".codex").exists()


@pytest.mark.external
def test_generated_project_config_is_accepted_by_real_codex(tmp_path):
    """실제 codex 로 확인 (오프라인): 임시 CODEX_HOME 에 신뢰 항목 → codex mcp list 가 PWEH 서버를 보여 준다. 신뢰가 없으면 안 보인다."""
    codex = shutil.which("codex")
    if not codex:
        pytest.skip("codex 가 없다")
    proj = tmp_path / "proj"
    (proj / ".git").mkdir(parents=True)
    servers = cli.build_mcp_servers(include_rea=True, tools_env=str(tmp_path / "missing-env.sh"))
    trusted, untrusted, fake_home = tmp_path / "codex-home", tmp_path / "codex-home-untrusted", tmp_path / "fake-home"
    for d in (trusted, untrusted, fake_home):
        d.mkdir()
    rc, _ = write_cfg(trusted, servers=servers, scope="project", repo=proj, homes=[str(trusted)])
    assert rc == 0
    rc, _ = trust(proj, [trusted], yes=True)
    assert rc == 0

    def run(home: Path, *args: str):
        env = {"HOME": str(fake_home), "CODEX_HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "dumb"}
        argv = [codex, *args]
        unshare = shutil.which("unshare")
        if unshare and subprocess.run([unshare, "-c", "-n", "--", "true"], capture_output=True).returncode == 0:
            argv = [unshare, "-c", "-n", "--", *argv]
        r = subprocess.run(argv, cwd=proj, env=env, capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr[-2000:]
        return json.loads(r.stdout)

    listed = {s["name"]: s for s in run(trusted, "mcp", "list", "--json")}
    assert set(listed) == set(cli.SERVERS) | {"rea"}
    case = listed["pweh-case"]
    assert case["transport"]["command"] == servers["pweh-case"]["command"] and case["transport"]["cwd"] == str(proj)
    assert case["transport"]["env_vars"] == ["WSL_DISTRO_NAME"] and case["tool_timeout_sec"] == 600 and case["startup_timeout_sec"] == 60
    assert listed["rea"]["tool_timeout_sec"] == 900
    # REA 는 런처로 (실행할 때 env.sh 를 불러온다) — 설정에 셸의 PATH 를 적지 않는다
    rea_t = listed["rea"]["transport"]
    assert rea_t["command"] == str(cli.REPO_ROOT / "scripts" / "mcp-launch.sh") and rea_t["args"] == ["rea"]
    assert "PATH" not in (rea_t.get("env") or {})
    rea = run(trusted, "mcp", "get", "rea", "--json")
    assert rea["enabled_tools"] == rea_tools_from_settings()
    assert run(untrusted, "mcp", "list", "--json") == []  # 신뢰하지 않으면 프로젝트 설정을 읽지 않는다


# ---------------------------------------------------------------------------
# doctor 의 Codex 줄
# ---------------------------------------------------------------------------


def test_codex_checks_lines(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    h1, h2 = tmp_path / "h1", tmp_path / "h2"
    h1.mkdir()
    homes = [clientcfg.CodexHome(h1, "cli", "~/.codex"),
             clientcfg.CodexHome(h2, "desktop-wsl", "Windows 프로필 (시험)", skipped="데스크톱 앱이 WSL 모드가 아님 (시험)")]
    names = list(cli.SERVERS)
    by = {c["check"]: c for c in clientcfg.codex_checks(repo, project=clientcfg.project_status(repo, None, names), homes=homes)}
    assert by["codex:project-config"]["ok"] is False and by["codex:project-config"]["hint"] == "pweh mcp-config --client codex --write"
    assert by["codex:trust[cli]"]["ok"] is False and by["codex:trust[cli]"]["hint"] == "pweh codex-trust"
    assert by["codex:trust[desktop-wsl]"]["ok"] is None and "WSL 모드가 아님" in by["codex:trust[desktop-wsl]"]["detail"]
    assert by["codex:mcp-check"]["ok"] is None and "pweh mcp-check" in by["codex:mcp-check"]["hint"]
    # 쓰고 신뢰하면 최신·신뢰됨
    root = make_exes(tmp_path / "fakeroot")
    text, _ = clientcfg.project_text(fake_servers(root), repo, settings_path=SETTINGS, include_rea=True, direct="all", tools_env=None)
    (repo / ".codex").mkdir()
    (repo / ".codex" / "config.toml").write_text(text, encoding="utf-8")
    trust(repo, [h1], yes=True)
    by = {c["check"]: c for c in clientcfg.codex_checks(repo, project=clientcfg.project_status(repo, text, names), homes=homes,
                                                         home_notes=["WSL interop 을 쓸 수 없어 (시험)"])}
    assert by["codex:project-config"]["ok"] is True and "최신" in by["codex:project-config"]["detail"]
    assert by["codex:trust[cli]"]["ok"] is True and by["codex:desktop"]["ok"] is None
    assert clientcfg.project_status(repo, text + "# 주석만 다름\n", names)["state"] == "current"
    other_path = text.replace('REA_GHIDRA_STARTUP_TIMEOUT_MS = "600000"', 'REA_GHIDRA_STARTUP_TIMEOUT_MS = "600000"\nPATH = "/other/shell/path"')
    (repo / ".codex" / "config.toml").write_text(other_path, encoding="utf-8")
    assert clientcfg.project_status(repo, text, names)["state"] == "current"  # env PATH 는 셸마다 달라 비교하지 않는다
    assert clientcfg.project_status(repo, text.replace("tool_timeout_sec = 600", "tool_timeout_sec = 9", 1), names)["state"] == "stale"
    shutil.rmtree(root / "bin")
    st = clientcfg.project_status(repo, text, names)
    assert st["state"] == "broken" and "rea" in st["detail"]
    assert clientcfg.project_status(repo, text, [*names, "pweh-new"])["state"] == "broken"
    (repo / ".codex" / "config.toml").write_text('model = "mine"\n', encoding="utf-8")
    assert clientcfg.project_status(repo, text, names)["state"] == "user"
    assert clientcfg.codex_checks(repo, project={"state": "missing", "path": "x"}, homes=[])[0]["ok"] is None  # Codex 를 안 쓰면 '--'


def test_codex_checks_global_scope_needs_no_trust(tmp_path):
    """전역 범위로 등록한 홈은 신뢰가 없어도 PWEH 도구가 뜬다 → doctor 가 '!!' 로 보지 않는다 (설치 스크립트 --codex-global 과 같은 판단)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    h1, h2 = tmp_path / "h1", tmp_path / "h2"
    h1.mkdir()
    h2.mkdir()
    root = make_exes(tmp_path / "fakeroot")  # 등록한 실행 파일이 있어야 전역 등록으로 본다
    assert write_cfg(h1, servers=fake_servers(root), repo=repo)[0] == 0  # h1: --scope global 로 등록, 신뢰 없음
    (h2 / "config.toml").write_text('model = "m"\n', encoding="utf-8")  # h2: 등록도 신뢰도 없음
    g1 = clientcfg.CodexHome(h1, "cli", "~/.codex")
    bare = clientcfg.CodexHome(h2, "explicit", "--codex-home")
    skipped = clientcfg.CodexHome(tmp_path / "h3", "desktop-wsl", "Windows 프로필 (시험)", skipped="데스크톱 앱이 WSL 모드가 아님 (시험)")
    names = list(cli.SERVERS)

    def checks(homes):
        return {c["check"]: c for c in clientcfg.codex_checks(repo, project=clientcfg.project_status(repo, None, names), homes=homes)}

    # 섞인 경우: 전역 등록 홈은 신뢰가 없어도 '--', 등록이 없는 홈에는 프로젝트 설정과 신뢰가 필요하다
    by = checks([g1, bare])
    assert by["codex:project-config"]["ok"] is False and by["codex:project-config"]["hint"] == "pweh mcp-config --client codex --write"
    assert by["codex:trust[cli]"]["ok"] is None and f"PWEH 서버 {len(names)}개가 직접 등록" in by["codex:trust[cli]"]["detail"]
    assert by["codex:trust[explicit]"]["ok"] is False and by["codex:trust[explicit]"]["hint"] == "pweh codex-trust"
    # 감지한(건너뛰지 않은) 모든 홈이 전역 등록이면 프로젝트 설정이 없어도 '--'
    by = checks([g1, skipped])
    assert by["codex:project-config"]["ok"] is None and "직접 등록" in by["codex:project-config"]["detail"]
    assert by["codex:trust[cli]"]["ok"] is None and by["codex:trust[desktop-wsl]"]["ok"] is None
    # 전역 등록이 없으면 예전처럼 프로젝트 설정이 없는 것이 문제다
    assert checks([bare])["codex:project-config"]["ok"] is False
    assert checks([skipped])["codex:project-config"]["ok"] is None  # Codex 를 쓰지 않는 것으로 본다 ('--')
    # 등록한 실행 파일이 사라지면(저장소·가상환경을 옮김) 전역 등록이 아니라 문제다
    shutil.rmtree(root / ".venv")
    by = checks([g1])
    assert by["codex:trust[cli]"]["ok"] is False and "실행 파일 없음" in by["codex:trust[cli]"]["detail"]
    assert "--scope global --codex-home" in by["codex:trust[cli]"]["hint"] and by["codex:project-config"]["ok"] is False


def test_old_pasted_snippet_without_trust_is_a_failure_not_info(tmp_path, workspace):
    """예전 '>>' 붙여 넣기(표식 없음, 낡은 실행 파일 경로)가 남은 홈: doctor 는 신뢰가 없는 것을 '!!' 로 보고(옮기는 방법 안내),
    mcp-check 는 Codex 가 실제로 띄울 그 표를 점검해 실패로 드러낸다 (프로젝트 설정만 보고 통과시키지 않는다)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    home = tmp_path / "old-home"
    home.mkdir()
    (home / "config.toml").write_text(OLD_SNIPPET, encoding="utf-8")  # /opt/old/... 는 없다
    h = clientcfg.CodexHome(home, "cli", "~/.codex")
    names = list(cli.SERVERS)
    for state in ("current", "missing"):
        by = {c["check"]: c for c in clientcfg.codex_checks(repo, project={"state": state, "path": "p"}, homes=[h], codex_bin="/x/codex")}
        assert by["codex:trust[cli]"]["ok"] is False and "pweh-managed 표식 없음" in by["codex:trust[cli]"]["detail"]
        assert "실행 파일 없음: pweh-case" in by["codex:trust[cli]"]["detail"]
    by = {c["check"]: c for c in clientcfg.codex_checks(repo, project={"state": "missing", "path": "p"}, homes=[h], codex_bin="/x/codex")}
    assert by["codex:project-config"]["ok"] is False
    reg = clientcfg.home_registration(OLD_SNIPPET, "x")
    assert reg == {"names": ["pweh-case"], "unmarked": ["pweh-case"], "missing_cmd": ["pweh-case"]}
    # 신뢰했으면 이 저장소에서는 프로젝트 설정이 이기지만 남은 표는 경고로 알린다
    trust(repo, [home], yes=True)
    by = {c["check"]: c for c in clientcfg.codex_checks(repo, project={"state": "current", "path": "p"}, homes=[h])}
    assert by["codex:trust[cli]"]["ok"] is True and by["codex:home-servers[cli]"]["ok"] is None
    # mcp-check: 프로젝트 설정은 점검하되, 신뢰하지 않는 홈의 표도 Codex 가 띄우는 그대로 점검한다
    (home / "config.toml").write_text(OLD_SNIPPET, encoding="utf-8")  # 신뢰 없음으로 되돌림
    specs = {"pweh-case": real_case_spec(workspace)}
    (repo / ".codex").mkdir()
    (repo / ".codex" / "config.toml").write_text(clientcfg.render_project_config(specs, [], ["# 시험"]), encoding="utf-8")
    out: list[str] = []
    rc = clientcfg.mcp_check(repo=repo, client="codex", deep=False, timeout=60, generated=dict, server_names=["pweh-case"], as_json=True,
                             codex_homes=[h], say=out.append)
    rep = json.loads(out[0])
    assert rc == 1 and set(rep["clients"]) == {"codex", "codex[cli]"}
    assert rep["clients"]["codex"]["servers"][0]["ok"] is True and any("신뢰한 Codex 홈이 없어" in n for n in rep["clients"]["codex"]["notes"])
    stale = {r["server"]: r for r in rep["clients"]["codex[cli]"]["servers"]}
    assert stale["pweh-case"]["ok"] is False and "/opt/old" in stale["pweh-case"]["error"]
    # 신뢰하면 프로젝트 설정이 이겨 그 홈의 표는 점검 대상이 아니다
    trust(repo, [home], yes=True)
    out.clear()
    rc = clientcfg.mcp_check(repo=repo, client="codex", deep=False, timeout=60, generated=dict, server_names=["pweh-case"], as_json=True,
                             codex_homes=[h], say=out.append)
    rep = json.loads(out[0])
    assert rc == 0 and list(rep["clients"]) == ["codex"] and rep["clients"]["codex"]["notes"] == []
    assert names  # 서버 목록은 cli.SERVERS 그대로


# ---------------------------------------------------------------------------
# 경계 사례: 예전 붙여 넣기 형식, 인라인 표, 표 안에 들어간 최상위 키, 중복 표 안내, env_vars 표 형식, 없는 cwd
# ---------------------------------------------------------------------------

OLD_SNIPPET = """model = "m"

# ~/.codex/config.toml 에 추가 (pweh mcp-config --client codex 로 생성)

[mcp_servers.pweh-case]
command = "/opt/old/.venv/bin/pweh-case-mcp"
args = []
cwd = "/opt/old"
startup_timeout_sec = 60
tool_timeout_sec = 600
env = { "PWEH_CONFIG" = "/opt/old/orchestrator/pipeline-config.yaml" }

[mcp_servers.rea]
command = "/opt/old/rea"
args = ["--mcp"]
cwd = "/opt/old"
startup_timeout_sec = 60
tool_timeout_sec = 900
env = { "REA_GHIDRA_STARTUP_TIMEOUT_MS" = "600000" }
"""


def test_global_merge_migrates_old_pasted_snippet(tmp_path):
    """예전 안내(출력을 config.toml 에 덧붙이기)로 한 번 붙인 표는 바꾸고, 표식 없는 rea 는 계약대로 두되 이유를 알린다."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(OLD_SNIPPET, encoding="utf-8")
    rc, out = write_cfg(home)
    text = cfg.read_text(encoding="utf-8")
    data = loads(text)
    assert rc == 0 and text.count("[mcp_servers.pweh-case]") == 1
    assert data["mcp_servers"]["pweh-case"]["command"] == "/opt/pweh-fake/.venv/bin/pweh-case-mcp"
    assert data["mcp_servers"]["rea"]["command"] == "/opt/old/rea" and "enabled_tools" not in data["mcp_servers"]["rea"]
    assert any("enabled_tools 가 없어" in line for line in out)
    lines = text.splitlines()
    assert lines.index("mcp_optional_startup_grace_ms = 15000") < next(i for i, ln in enumerate(lines) if ln.startswith("["))


def test_doubly_pasted_snippet_is_refused_with_repair_hint(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(OLD_SNIPPET + OLD_SNIPPET.split("\n", 2)[2], encoding="utf-8")  # 같은 표를 두 번 붙인 상태 (Codex 도 시작하지 않는다)
    before = cfg.read_bytes()
    rc, out = write_cfg(home)
    assert rc == 1 and cfg.read_bytes() == before and backups(home) == []
    assert any("두 번" in line and "한 벌을 지운 뒤" in line for line in out)


def test_global_merge_inline_features_and_misplaced_grace_note(tmp_path):
    specs = clientcfg.codex_server_specs(fake_servers(rea=False), Path("/r"), rea_tools=None)
    new, _ = clientcfg.merge_user_config("features = { code_mode = true, x = 1 }\n", specs, ["mcp__pweh_case"], include_rea=False, where="t")
    assert loads(new)["features"] == {"x": 1, "code_mode": {"enabled": True, "direct_only_tool_namespaces": ["mcp__pweh_case"]}}
    new, _ = clientcfg.merge_user_config("features = { code_mode = { enabled = false } }\n", specs, ["mcp__pweh_case"], include_rea=False,
                                         where="t")
    assert loads(new)["features"]["code_mode"] == {"enabled": False, "direct_only_tool_namespaces": ["mcp__pweh_case"]}
    src = '[projects."/x"]\ntrust_level = "trusted"\nmcp_optional_startup_grace_ms = 5000\n'  # 표 뒤에 덧붙여 표 안에 들어간 키
    new, notes = clientcfg.merge_user_config(src, specs, [], include_rea=False, where="t")
    data = loads(new)
    assert data["mcp_optional_startup_grace_ms"] == 15000 and data["projects"]["/x"]["mcp_optional_startup_grace_ms"] == 5000
    assert any("표 안에 들어간" in n and "projects./x" in n for n in notes)


def test_codex_like_env_accepts_env_var_tables_and_missing_cwd_is_reported(tmp_path):
    base = {"HOME": "/h", "PATH": "/bin", "SECRET": "s", "A": "1", "B": "2", "C": "3"}
    env = clientcfg.codex_like_env({"X": "9"}, ["A", {"name": "B"}, {"name": "C", "source": "remote"}], base)
    assert env == {"HOME": "/h", "PATH": "/bin", "A": "1", "B": "2", "X": "9"}
    r = clientcfg.check_server("pweh-x", {"command": "/bin/true", "args": [], "cwd": str(tmp_path / "gone")}, env=env, timeout=5)
    assert r["ok"] is False and "cwd" in r["error"]


# ---------------------------------------------------------------------------
# 리뷰 반영: 사용자 키 유지, 백업 권한, 동시 쓰기, --check 종료 코드, 선택 서버, 중단 정리
# ---------------------------------------------------------------------------

USER_KEYS_CFG = """[mcp_servers.pweh-uart] # pweh-managed
command = "/old"
enabled = false
required = false
disabled_tools = ["uart_write"]
startup_timeout_ms = 5

[mcp_servers.pweh-uart.tools.uart_send]
approval_mode = "approve"
"""


def test_global_merge_keeps_user_keys_inside_pweh_tables(tmp_path):
    """리뷰 s3 §2: pweh 표 안의 사용자 키(enabled·required·disabled_tools·tools.<도구>)는 다시 써도 남는다. 그 밖의 빠지는 키는 이름만 알린다."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text(USER_KEYS_CFG, encoding="utf-8")
    rc, out = write_cfg(home)
    data = loads(cfg.read_text(encoding="utf-8"))
    uart = data["mcp_servers"]["pweh-uart"]
    assert rc == 0 and uart["command"] == "/opt/pweh-fake/.venv/bin/pweh-uart-mcp"
    assert uart["enabled"] is False and uart["required"] is False and uart["disabled_tools"] == ["uart_write"]
    assert uart["tools"] == {"uart_send": {"approval_mode": "approve"}} and "startup_timeout_ms" not in uart
    assert any("사용자 키 유지: enabled, required, disabled_tools, tools" in ln for ln in out)
    assert any("빠지는 키: startup_timeout_ms" in ln for ln in out)
    first = cfg.read_bytes()
    baks = backups(home)
    rc, out = write_cfg(home)  # 다시 실행: 같은 바이트 (사용자 키가 있어도 'same')
    assert rc == 0 and cfg.read_bytes() == first and backups(home) == baks and any(ln.startswith("변경 없음") for ln in out)
    # REA 의 enabled_tools 는 pweh 것이라 옮기지 않는다 (사용자의 disabled_tools 는 옮긴다)
    cfg.write_text('[mcp_servers.rea] # pweh-managed\ncommand = "/r"\nenabled_tools = ["old_tool"]\ndisabled_tools = ["x"]\n', encoding="utf-8")
    write_cfg(home)
    rea = loads(cfg.read_text(encoding="utf-8"))["mcp_servers"]["rea"]
    assert rea["enabled_tools"] == rea_tools_from_settings() and rea["disabled_tools"] == ["x"]


def test_unmarked_tables_with_current_content_get_the_managed_mark(tmp_path):
    """내용이 지금 생성값과 같아도 표식 없는 표(붙여 넣은 표)는 표식을 단다 — doctor 의 '옮기기' 안내가 되풀이되지 않게."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    write_cfg(home)
    cfg.write_text(cfg.read_text(encoding="utf-8").replace(" # pweh-managed", ""), encoding="utf-8")
    assert clientcfg.home_registration(cfg.read_text(encoding="utf-8"), "x")["unmarked"]
    rc, out = write_cfg(home)
    assert rc == 0 and any("표식을 단다" in ln for ln in out)
    assert clientcfg.home_registration(cfg.read_text(encoding="utf-8"), "x")["unmarked"] == []
    rc, out = write_cfg(home)
    assert rc == 0 and any(ln.startswith("변경 없음") for ln in out)


def test_backup_is_created_owner_only_before_copying_mode(tmp_path, monkeypatch):
    """0600 설정(비밀값)의 백업이 잠깐이라도 0644 로 보이지 않는다. 권한 복사가 실패해도 0600 그대로다."""
    home = tmp_path / "h"
    home.mkdir()
    home.chmod(0o755)
    cfg = home / "config.toml"
    cfg.write_text('[mcp_servers.gh]\ncommand = "gh"\nenv = { GITHUB_TOKEN = "ghp_secret" }\n', encoding="utf-8")
    cfg.chmod(0o600)
    seen: list[int] = []
    real_copystat = shutil.copystat

    def spy(src, dst, *a, **k):
        seen.append(stat.S_IMODE(os.stat(dst).st_mode))
        return real_copystat(src, dst, *a, **k)

    monkeypatch.setattr(clientcfg.shutil, "copystat", spy)
    assert trust(tmp_path, [home], yes=True)[0] == 0
    (bak,) = backups(home)
    assert seen == [0o600] and stat.S_IMODE(bak.stat().st_mode) == 0o600

    def broken(src, dst, *a, **k):
        raise OSError("chmod 이 안 되는 파일 시스템")

    monkeypatch.setattr(clientcfg.shutil, "copystat", broken)
    cfg.chmod(0o644)
    assert write_cfg(home)[0] == 0
    newest = backups(home)[-1]
    assert newest != bak and stat.S_IMODE(newest.stat().st_mode) == 0o600
    # 백업을 만들 수 없으면(읽기 전용 디렉터리) Traceback 대신 ClientConfigError, 아무것도 바꾸지 않는다
    if os.geteuid() != 0:
        before = cfg.read_bytes()
        home.chmod(0o555)
        try:
            with pytest.raises(clientcfg.ClientConfigError, match="백업을 만들지 못함"):
                trust(tmp_path / "other-repo", [home], yes=True)
        finally:
            home.chmod(0o755)
        assert cfg.read_bytes() == before


def test_concurrent_change_before_replace_is_refused_and_backup_removed(tmp_path, monkeypatch):
    """백업을 만든 뒤·바꾸기 전에 다른 프로그램이 파일을 고치면 쓰지 않고(그 사람의 변경을 덮지 않음) 방금 만든 백업도 지운다."""
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text('model = "m"\n', encoding="utf-8")
    real_backup = clientcfg.backup_file

    def racing_backup(path):
        b = real_backup(path)
        Path(path).write_text('model = "m"\n[projects."/other"]\ntrust_level = "trusted"\n', encoding="utf-8")  # 동시에 쓴 사람
        return b

    monkeypatch.setattr(clientcfg, "backup_file", racing_backup)
    with pytest.raises(clientcfg.ClientConfigError, match="읽은 뒤에 바뀌었다"):
        trust(tmp_path, [home], yes=True)
    assert 'projects."/other"' in cfg.read_text(encoding="utf-8") and backups(home) == []
    monkeypatch.setattr(clientcfg, "backup_file", real_backup)
    # 바꾼 직후 다른 프로그램이 썼으면(확인 시점) 종료 코드가 0 이 아니게 오류로 알린다 (백업 위치 포함)
    real_replace = os.replace

    def replace_then_clobber(src, dst):
        real_replace(src, dst)
        if str(dst).endswith("config.toml"):
            Path(dst).write_text('model = "someone else"\n', encoding="utf-8")

    monkeypatch.setattr(clientcfg.os, "replace", replace_then_clobber)
    with pytest.raises(clientcfg.ClientConfigError, match="쓴 내용과 다르다") as ei:
        trust(tmp_path, [home], yes=True)
    assert "bak-pweh-" in str(ei.value)


def test_held_lock_makes_a_second_writer_wait_and_refuse(tmp_path, monkeypatch):
    """같은 홈을 다른 pweh 가 고치는 중이면(디렉터리 flock) 기다리다 쓰지 않는다. dry-run·--check 는 잠그지 않는다."""
    import fcntl

    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "config.toml"
    cfg.write_text('model = "m"\n', encoding="utf-8")
    monkeypatch.setattr(clientcfg, "LOCK_TIMEOUT_S", 0.3)
    fd = os.open(str(home), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(clientcfg.ClientConfigError, match="고치고 있다"):
            trust(tmp_path, [home], yes=True)
        assert cfg.read_text(encoding="utf-8") == 'model = "m"\n'
        assert trust(tmp_path, [home], dry_run=True)[0] == 0 and trust(tmp_path, [home], check=True)[0] == 1
        rc, _ = write_cfg(home, dry_run=True)
        assert rc == 0
    finally:
        os.close(fd)
    assert trust(tmp_path, [home], yes=True)[0] == 0 and "trust_level" in cfg.read_text(encoding="utf-8")
    assert sorted(p.name for p in home.iterdir() if not p.name.startswith("config.toml.bak-pweh-")) == ["config.toml"]  # 잠금 파일이 남지 않는다


def test_codex_trust_check_exit_code_two_when_a_home_cannot_be_read(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.mkdir()
    bad.mkdir()
    (good / "config.toml").write_text('model = "m"\n', encoding="utf-8")
    (bad / "config.toml").write_text("[a]\nx = 1\n[a]\ny = 2\n", encoding="utf-8")
    assert trust(repo, [good], check=True)[0] == 1
    rc, out = trust(repo, [good, bad], check=True)
    assert rc == 2 and any("읽지 못함" in ln for ln in out)
    trust(repo, [good], yes=True)
    assert trust(repo, [good], check=True)[0] == 0 and trust(repo, [good, bad], check=True)[0] == 2


def test_cli_codex_commands_without_tomlkit_give_one_line(tmp_path, monkeypatch, capsys):
    """이 변경 전에 만든 가상환경(tomlkit 없음): Traceback 대신 다시 설치하라는 한 줄. codex-trust --check 는 '확인하지 못함'(2)."""
    monkeypatch.setitem(sys.modules, "tomlkit", None)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    assert cli.main(["codex-trust", "--check", "--codex-home", str(tmp_path)]) == 2
    assert cli.main(["mcp-config", "--client", "codex"]) == 1
    assert cli.main(["mcp-check", "--client", "codex"]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.count("tomlkit 이 없다") == 3 and "./scripts/install.sh --only python --force" in err


def test_mcp_check_optional_servers_do_not_fail_the_exit_code(tmp_path):
    """--optional rea: rea 실패만이면 종료 코드 0 (보고는 함). PWEH 서버가 실패하면 rea 와 상관없이 1."""
    srv = fake_mcp(tmp_path)
    bad = failing_mcp(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".codex").mkdir(parents=True)
    proj = repo / ".codex" / "config.toml"

    def run(specs, optional):
        proj.write_text(clientcfg.render_project_config(specs, [], ["# 시험"]), encoding="utf-8")
        out: list[str] = []
        rc = clientcfg.mcp_check(repo=repo, client="codex", deep=False, timeout=30, generated=dict, server_names=["pweh-case"],
                                 as_json=False, codex_homes=[], optional=optional, say=out.append)
        return rc, "\n".join(out)

    ok, rea_bad, case_bad = {"command": str(srv), "args": []}, {"command": str(bad), "args": []}, {"command": str(bad), "args": []}
    rc, text = run({"pweh-case": ok, "rea": rea_bad}, ["rea"])
    assert rc == 0 and "선택 서버 실패 1개 (종료 코드에 넣지 않음: rea)" in text and "[!! ] codex:rea" in text
    rc, text = run({"pweh-case": ok, "rea": rea_bad}, [])
    assert rc == 1 and "선택 서버" not in text
    rc, text = run({"pweh-case": case_bad, "rea": rea_bad}, ["rea"])
    assert rc == 1 and "실패가 있다" in text


def test_server_that_exits_immediately_reports_its_exit_code(tmp_path):
    exits = tmp_path / "exits"
    exits.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
    exits.chmod(0o755)
    for _ in range(3):  # 경쟁(쓰기 전에 끝남 / 읽는 중에 끝남) 어느 쪽이든 같은 문구
        r = clientcfg.check_server("pweh-x", {"command": str(exits), "args": []}, env=clientcfg.codex_like_env(), timeout=10)
        assert r["ok"] is False and "서버가 끝남 (종료 코드 3)" in r["error"] and "Broken pipe" not in r["error"], r


@pytest.mark.parametrize("sig", ["SIGINT", "SIGTERM"])
def test_interrupted_mcp_check_cleans_up_starting_servers(tmp_path, sig):
    """Ctrl-C(SIGINT)·시간 제한(SIGTERM)으로 mcp-check 가 중단돼도 아직 stdin 을 읽지 않는 서버를 남기지 않는다."""
    import signal as _signal

    pidfile = tmp_path / "server.pid"
    hang = tmp_path / "hang-mcp"
    hang.write_text(f"#!/bin/sh\necho $$ > '{pidfile}'\nexec sleep 300\n", encoding="utf-8")
    hang.chmod(0o755)
    repo = tmp_path / "repo"
    (repo / ".codex").mkdir(parents=True)
    (repo / ".codex" / "config.toml").write_text(clientcfg.render_project_config({"pweh-case": {"command": str(hang), "args": []}}, [], ["# 시험"]),
                                                 encoding="utf-8")
    code = ("import sys\nfrom pathlib import Path\nfrom pweh import cli, clientcfg\ncli.REPO_ROOT = Path(sys.argv[1])\n"
            "clientcfg.windows_profile = lambda report=None: (None, 'x')\nsys.exit(cli.main(['mcp-check', '--client', 'codex', '--timeout', '120']))\n")
    env = {**os.environ, "HOME": str(tmp_path), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.pop("CODEX_HOME", None)
    p = subprocess.Popen([sys.executable, "-c", code, str(repo)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 30
    while not pidfile.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pidfile.exists(), p.communicate(timeout=10)
    pid = int(pidfile.read_text().strip())
    p.send_signal(getattr(_signal, sig))
    _out, err = p.communicate(timeout=30)
    assert p.returncode == 130 and b"Traceback" not in err, err.decode(errors="replace")
    gone = time.monotonic() + 10
    while time.monotonic() < gone:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        os.kill(pid, _signal.SIGKILL)
        pytest.fail("중단 뒤에도 서버 프로세스가 남았다")
