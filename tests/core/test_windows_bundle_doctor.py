"""합성 번들로 명시 선택과 무실행 doctor 경계를 검증한다."""
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from pweh import cli, toolsdir
from pweh.config import DEFAULTS, load_config
from pweh.errors import PwehError, ValidationFailed

PRIVATE = "PRIVATE_SYNTHETIC_BUNDLE_PATH_973"


@pytest.fixture
def clean_env(tmp_path, monkeypatch):
    monkeypatch.delenv("PWEH_OPENOCD_WIN_BUNDLE", raising=False)
    monkeypatch.delenv("PWEH_SIGROK_WIN_BUNDLE", raising=False)
    monkeypatch.setenv("PWEH_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(toolsdir, "POINTER", tmp_path / "missing-pointer")
    return tmp_path


def cfg(**tools):
    return SimpleNamespace(tools=tools)


def verified(tool="openocd", release_id="synthetic-1"):
    return SimpleNamespace(tool=tool, release_id=release_id, manifest_sha256="a"*64,
        digest_basis="supplier-checksum" if tool == "openocd" else "first-acquisition",
        known_limitations=(() if tool == "openocd" else ("python34_signature_decoder_unsupported",)))


def test_candidates_choose_exactly_one_without_filesystem_or_environment(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("순수 후보 함수가 외부 상태를 조회함")
    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(toolsdir, "tools_dir", forbidden)
    managed = Path("/fixed/managed")
    select = toolsdir.windows_bundle_candidates
    assert select("openocd", "/explicit/config", "/explicit/env", managed) == [("/explicit/config", "config")]
    assert select("sigrok", "", "/explicit/env", managed) == [("/explicit/env", "env")]
    assert select("sigrok", None, None, managed) == [(str(managed), "pweh-tools")]
    assert select("openocd", "", "", None) == []


@pytest.mark.parametrize("value", [" ", " /tmp/root", "/tmp/root ", "relative", "~/root", "C:\\root",
    "//server/root", "/tmp/../root", "/tmp/a\\b", "/tmp/a\x00b", "/tmp/a\nb", "/tmp/a\x7fb", 1, True])
@pytest.mark.parametrize("source", ["config", "env"])
def test_invalid_explicit_candidate_never_falls_back(value, source):
    arguments = (value, "/env/valid") if source == "config" else (None, value)
    with pytest.raises(ValidationFailed) as caught:
        toolsdir.windows_bundle_candidates("openocd", *arguments, Path("/managed/valid"))
    assert caught.value.code == "bundle_invalid_argument"
    assert PRIVATE not in str(caught.value)


def test_valid_high_priority_ignores_invalid_lower_candidate():
    assert toolsdir.windows_bundle_candidates("openocd", "/config", "bad-env", Path("relative")) == [("/config", "config")]
    with pytest.raises(ValidationFailed):
        toolsdir.windows_bundle_candidates("unknown", "/config", None, None)


def test_new_config_defaults_leave_env_to_locator(clean_env, monkeypatch):
    path = clean_env / "config.yaml"
    path.write_text("{}\n")
    monkeypatch.setenv("PWEH_OPENOCD_WIN_BUNDLE", "/env/bundle")
    loaded = load_config(path)
    assert DEFAULTS["tools"]["openocd_win_bundle"] == DEFAULTS["tools"]["sigrok_win_bundle"] == ""
    assert loaded.tools["openocd_win_bundle"] == ""
    path.write_text("tools:\n  openocd_win_bundle: /config/bundle\n")
    assert load_config(path).tools["openocd_win_bundle"] == "/config/bundle"


def test_explicit_selection_skips_preferred_metadata_and_preserves_rollback(clean_env, monkeypatch):
    from pweh import windows_bundle as W
    def forbidden(*args, **kwargs):
        pytest.fail("명시 경로에서 preferred fallback을 조회함")
    monkeypatch.setattr(W, "load_registered_manifest", forbidden)
    seen = []
    def verify(path, tool, *, deadline):
        seen.append((path, tool, deadline))
        return verified(tool, "synthetic-old")
    monkeypatch.setenv("PWEH_OPENOCD_WIN_BUNDLE", "/bad/env")
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle="/registered/old-openocd",
        sigrok_win_bundle="/registered/old-sigrok"), verifier=verify)
    assert [str(item[0]) for item in seen] == ["/registered/old-openocd", "/registered/old-sigrok"]
    assert all(row["ok"] is True and row["source"] == "config" and row["release_id"] == "synthetic-old" for row in rows)
    assert rows[1]["digest_basis"] == "first-acquisition"
    assert rows[1]["known_limitations"] == ["python34_signature_decoder_unsupported"]
    assert all(not row["execution_verified"] and not row["backend_enabled"] and not row["hardware_verified"] for row in rows)
    assert "available" not in rows[0] and "path" not in rows[0]


def test_managed_metadata_and_verifier_share_one_deadline_per_tool(clean_env, monkeypatch):
    from pweh import windows_bundle as W
    calls = []
    def manifest(tool, *, deadline):
        calls.append(("manifest", tool, deadline))
        return SimpleNamespace(tool=tool)
    def managed(root, registered):
        assert root == clean_env / "tools"
        return root / registered.tool
    def verify(path, tool, *, deadline):
        calls.append(("verify", tool, deadline))
        raise PwehError("private", code="bundle_missing")
    monkeypatch.setattr(W, "load_registered_manifest", manifest)
    monkeypatch.setattr(W, "managed_release_root", managed)
    rows = cli.windows_bundle_checks(cfg(), verifier=verify)
    assert calls[0][1:] == calls[1][1:] and calls[2][1:] == calls[3][1:]
    assert all(row["ok"] is None and row["tree_verified"] is None for row in rows)
    assert all(row["source"] == "pweh-tools" for row in rows)


@pytest.mark.parametrize("code", ["bundle_missing", "bundle_receipt_invalid", "bundle_tree_invalid", "bundle_changed",
    "bundle_timeout", "bundle_io_failed", "bundle_release_unregistered", "foreign_private_code"])
def test_explicit_errors_are_fixed_failure_without_fallback(clean_env, code):
    calls = []
    def verify(path, tool, *, deadline):
        calls.append(path)
        raise PwehError(PRIVATE, code=code, data={"path": PRIVATE})
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle="/explicit/"+PRIVATE,
        sigrok_win_bundle="/explicit/sigrok"), verifier=verify)
    assert len(calls) == 2 and all(row["ok"] is False for row in rows)
    assert PRIVATE not in json.dumps(rows)
    expected = code if code in cli._BUNDLE_ERRORS else "bundle_io_failed"
    assert all(row["problem"] == expected for row in rows)


def test_env_source_is_retained_and_bad_config_never_uses_env(clean_env, monkeypatch):
    seen = []
    def verify(path, tool, *, deadline):
        seen.append((path, tool))
        return verified(tool)
    monkeypatch.setenv("PWEH_OPENOCD_WIN_BUNDLE", "/env/openocd")
    monkeypatch.setenv("PWEH_SIGROK_WIN_BUNDLE", "/env/sigrok")
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle="invalid"), verifier=verify)
    assert rows[0]["ok"] is False and rows[0]["source"] == "config"
    assert rows[0]["problem"] == "bundle_invalid_argument"
    assert rows[1]["ok"] is True and rows[1]["source"] == "env"
    assert seen == [(Path("/env/sigrok"), "sigrok")]


def forbid_nonstatic(monkeypatch):
    from pweh import hostenv
    def forbidden(*args, **kwargs):
        pytest.fail("정적 doctor가 실행/장치/쓰기 경계로 진입함")
    for name in ("_load_tools_env", "_local_serial_ports", "_tool_version", "_runtime", "codex_doctor_checks"):
        monkeypatch.setattr(cli, name, forbidden)
    for name in ("detect", "windows_com_ports", "wildcard_listeners", "recommend_routes"):
        monkeypatch.setattr(hostenv, name, forbidden)
    for name in ("Popen", "run", "check_output", "check_call"):
        monkeypatch.setattr(subprocess, name, forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(os, "mkdir", forbidden)


@pytest.mark.parametrize("outcome,expected_rc", [("valid", 0), ("missing", 0), ("invalid", 1)])
def test_real_cli_first_branch_is_static_in_all_outcomes(clean_env, monkeypatch, capsys, outcome, expected_rc):
    from pweh import windows_bundle as W
    config_path = clean_env / "config.yaml"
    config_path.write_text("{}\n")
    monkeypatch.setenv("PWEH_CONFIG", str(config_path))
    monkeypatch.setattr(W, "load_registered_manifest", lambda tool, **kw: SimpleNamespace(tool=tool))
    monkeypatch.setattr(W, "managed_release_root", lambda root, manifest: root / manifest.tool)
    def verify(path, tool, *, deadline):
        if outcome != "valid":
            raise PwehError(PRIVATE, code="bundle_missing" if outcome == "missing" else "bundle_receipt_invalid")
        return verified(tool)
    monkeypatch.setattr(W, "verify_release", verify)
    forbid_nonstatic(monkeypatch)
    assert cli.main(["doctor", "--windows-bundles-only", "--json"]) == expected_rc
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "windows-bundles-only" and "environment" not in report
    assert len(report["checks"]) == 2 and PRIVATE not in json.dumps(report)


def test_cli_config_failure_has_no_fallback_or_raw_error(clean_env, monkeypatch, capsys):
    monkeypatch.setenv("PWEH_CONFIG", str(clean_env / PRIVATE))
    def forbidden(*args, **kwargs):
        pytest.fail("설정 오류 뒤 번들 기본값을 사용함")
    monkeypatch.setattr(cli, "windows_bundle_checks", forbidden)
    forbid_nonstatic(monkeypatch)
    assert cli.main(["doctor", "--windows-bundles-only", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["checks"][0]["problem"] == "config_invalid"
    assert PRIVATE not in json.dumps(report)


def test_static_text_output_preserves_known_limitations(clean_env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda: cfg())
    monkeypatch.setattr(cli, "windows_bundle_checks", lambda config: [{"check": "bundle:sigrok-win", "ok": True,
        "detail": "등록 tree 일치 · Windows 실행 미확인 · backend 미연결", "hint": "",
        "known_limitations": ["python34_signature_decoder_unsupported"]}])
    forbid_nonstatic(monkeypatch)
    assert cli.main(["doctor", "--windows-bundles-only"]) == 0
    assert "python34_signature_decoder_unsupported" in capsys.readouterr().out


@pytest.fixture
def installed_bundles(clean_env, monkeypatch):
    """실제 등록 parser/verifier를 통과하는 작은 비실행 합성 tree다."""
    from pweh import windows_bundle as W
    def encode(value):
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))+"\n").encode()
    documents, payloads, roots = {}, {}, {}
    index = {"schema_version": 1, "tools": {}}
    for tool in ("openocd", "sigrok"):
        releases = []
        for release in ("synthetic-old", "synthetic-new"):
            executable = "bin/openocd.exe" if tool == "openocd" else "sigrok-cli.exe"
            files = {executable: b"SYNTHETIC_NOT_EXECUTABLE", "scripts/one.cfg": release.encode()}
            source = {"artifact_url": "https://example.invalid/synthetic.zip", "artifact_name": "synthetic.zip",
                "artifact_size": 1, "artifact_sha256": "a"*64,
                "digest_basis": "supplier-checksum" if tool == "openocd" else "first-acquisition",
                "checksum_metadata": {"repository": "https://example.invalid/repo", "ref": "synthetic", "path": "pin.json"}
                    if tool == "openocd" else None,
                "extractor": None if tool == "openocd" else {"version": "synthetic", "artifact_url": "https://example.invalid/extractor",
                    "artifact_size": 1, "artifact_sha256": "b"*64, "executable_sha256": "c"*64}}
            document = {"schema_version": 1, "tool": tool, "release_id": release, "platform": "windows-amd64",
                "source": source, "payload": {"archive_root": "synthetic/" if tool == "openocd" else "",
                    "recipe": "zip-strip-fixed-root-v1" if tool == "openocd" else "nsis-selected-v1",
                    "entrypoint": executable, "search_dirs": ["scripts"], "python_zip": None,
                    "file_count": len(files), "total_bytes": sum(map(len, files.values())),
                    "excluded": dict.fromkeys(("installer_plugins", "usb_driver_installers", "example_captures", "uninstaller"), 0)},
                "files": [{"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for path, data in sorted(files.items())],
                "known_limitations": [] if tool == "openocd" else ["python34_signature_decoder_unsupported"]}
            raw = encode(document)
            name = f"windows-bundles/{tool}-{release}.json"
            documents[name] = raw
            payloads[tool, release] = files
            releases.append({"release_id": release, "manifest": name, "sha256": hashlib.sha256(raw).hexdigest()})
        index["tools"][tool] = {"preferred_release_id": "synthetic-new", "releases": releases}
    monkeypatch.setattr(W, "_read_registry_bytes", lambda: encode(index))
    monkeypatch.setattr(W, "_read_registered_manifest_bytes", lambda name: documents[name])
    for (tool, release), files in payloads.items():
        manifest = W.load_registered_manifest(tool, release, deadline=time.monotonic()+30)
        root = W.managed_release_root(clean_env / "tools", manifest)
        payload = root / "payload"
        for name, data in files.items():
            path = payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o555 if name == manifest.entrypoint else 0o444)
        (root / "release.json").write_bytes(manifest.receipt_bytes)
        (root / "release.json").chmod(0o444)
        for path in sorted(payload.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        payload.chmod(0o555)
        root.chmod(0o555)
        roots[tool, release] = root
    yield roots
    # pytest 임시 tree의 정리 권한만 복원한다. 실행 fixture나 운영 설치는 만지지 않는다.
    for root in roots.values():
        root.chmod(0o755)
        for path in root.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)


def test_real_registry_receipt_and_tree_through_static_cli(installed_bundles, clean_env, monkeypatch, capsys):
    config_path = clean_env / "config.yaml"
    config_path.write_text("{}\n")
    monkeypatch.setenv("PWEH_CONFIG", str(config_path))
    with monkeypatch.context() as bounded:
        forbid_nonstatic(bounded)
        assert cli.main(["doctor", "--windows-bundles-only", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert all(row["ok"] is True and row["tree_verified"] is True for row in report["checks"])
    assert all(row["release_id"] == "synthetic-new" for row in report["checks"])
    assert "python34_signature_decoder_unsupported" in report["checks"][1]["known_limitations"]


@pytest.mark.parametrize("damage", ["receipt", "payload"])
def test_real_tamper_is_failure_without_fallback(installed_bundles, clean_env, damage):
    root = installed_bundles["openocd", "synthetic-new"]
    path = root / ("release.json" if damage == "receipt" else "payload/scripts/one.cfg")
    path.chmod(0o644)
    path.write_text(PRIVATE)
    path.chmod(0o444)
    rows = cli.windows_bundle_checks(cfg(), tools_root=clean_env / "tools")
    assert rows[0]["ok"] is False and rows[0]["tree_verified"] is False
    assert rows[1]["ok"] is True
    assert rows[0]["problem"] in {"bundle_receipt_invalid", "bundle_tree_invalid"}
    assert PRIVATE not in json.dumps(rows)


@pytest.mark.parametrize("selection", ["payload", "payload/bin/openocd.exe"])
def test_real_payload_or_bare_exe_is_not_a_release_root(installed_bundles, clean_env, selection):
    root = installed_bundles["openocd", "synthetic-new"]
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle=str(root / selection)), tools_root=clean_env / "tools")
    assert rows[0]["ok"] is False and rows[0]["source"] == "config"
    assert rows[1]["ok"] is True


def test_explicit_older_registered_release_is_reverified(installed_bundles, clean_env):
    root = installed_bundles["openocd", "synthetic-old"]
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle=str(root)), tools_root=clean_env / "tools")
    assert rows[0]["ok"] is True and rows[0]["release_id"] == "synthetic-old" and rows[0]["source"] == "config"
    assert rows[1]["ok"] is True and rows[1]["release_id"] == "synthetic-new"


def test_real_managed_absence_differs_from_explicit_absence(installed_bundles, clean_env):
    rows = cli.windows_bundle_checks(cfg(), tools_root=clean_env / "not-installed")
    assert all(row["ok"] is None and row["problem"] == "bundle_missing" for row in rows)
    rows = cli.windows_bundle_checks(cfg(openocd_win_bundle=str(clean_env / "not-installed")),
                                     tools_root=clean_env / "tools")
    assert rows[0]["ok"] is False and rows[0]["source"] == "config" and rows[0]["problem"] == "bundle_missing"
    assert rows[1]["ok"] is True
