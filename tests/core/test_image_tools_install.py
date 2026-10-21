"""이미지 도구 설치 계약: 고정 자료·지원 플랫폼·모델 해시·경로 우선순위. 네트워크를 쓰지 않는다."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "scripts/image-tools-lock.json"
HELPER = REPO / "scripts/image_tools_lock.py"
spec = importlib.util.spec_from_file_location("image_tools_lock", HELPER)
lock_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock_module)


def test_image_candidates_and_config(monkeypatch, tmp_path):
    from pweh.config import DEFAULTS
    from pweh.toolsdir import image_tool_candidates
    from pweh.cli import PWEH_ENV_KEYS
    import yaml

    for name, env, rel in (("tesseract", "PWEH_TESSERACT", "bin/tesseract"),
                           ("zbarimg", "PWEH_ZBARIMG", "bin/zbarimg"),
                           ("tessdata_dir", "PWEH_TESSDATA_DIR", "tesseract/tessdata")):
        assert image_tool_candidates(name, " /cfg/value ", "/env/value", tmp_path) == [
            ("/cfg/value", "config"), ("/env/value", "env"), (str(tmp_path / rel), "pweh-tools")]
        assert image_tool_candidates(name, "name", "name", None) == [("name", "config")]
        assert image_tool_candidates(name, "", None, None) == []
        assert DEFAULTS["tools"][name] == f"${{{env}:-}}"
        assert yaml.safe_load((REPO / "orchestrator/pipeline-config.yaml").read_text())["tools"][name] == DEFAULTS["tools"][name]
        assert env in PWEH_ENV_KEYS
    with pytest.raises(ValueError):
        image_tool_candidates("zbarcam", None, None, tmp_path)


def test_official_lock_is_complete_and_has_no_floating_downloads():
    profile = json.loads(LOCK.read_text())["profiles"]["ubuntu-22.04-x86_64"]
    for source in profile["sources"]:
        assert source["url"].startswith("https://archive.ubuntu.com/ubuntu/dists/")
        assert source["signing_key"] == "F6ECB3762474EDA9D21B7022871920D1991BC93C"
        assert len(source["sha256"]) == len(source["release_sha256"]) == 64
    for component in profile["components"].values():
        assert set(component["always_extract"]) <= set(component["packages"]) <= set(profile["packages"])
    for row in profile["packages"].values():
        assert row["url"].startswith("https://archive.ubuntu.com/ubuntu/pool/") and row["url"].endswith(".deb")
        assert len(bytes.fromhex(row["sha256"])) == 32 and row["version"]
    assert set(profile["models"]) == {f"{lang}.traineddata" for lang in ("eng", "kor", "osd")}
    assert all(row["license"] == "Apache-2.0" for row in profile["models"].values())


def test_unsupported_platform_has_no_fallback(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=debian\nVERSION_ID="12"\n')
    with pytest.raises(ValueError, match="임의 버전으로 대체하지 않습니다"):
        lock_module.load_profile(LOCK, os_release, "x86_64")
    os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
    with pytest.raises(ValueError):
        lock_module.load_profile(LOCK, os_release, "aarch64")


def test_primary_engine_and_models_never_reuse_system_package(monkeypatch):
    profile = json.loads(LOCK.read_text())["profiles"]["ubuntu-22.04-x86_64"]
    monkeypatch.setattr(lock_module, "installed_version", lambda _: "system-newer")
    for name in ("tesseract", "zbar"):
        selected, reused = lock_module.plan(profile, name)
        assert {row["package"] for row in selected} == set(profile["components"][name]["always_extract"])
        assert reused and all(row["source"] == "system-runtime" for row in reused)
    monkeypatch.setattr(lock_module, "installed_version", lambda _: None)
    selected, reused = lock_module.plan(profile, "tesseract")
    assert len(selected) == len(profile["components"]["tesseract"]["packages"]) and reused == []


def test_model_fingerprint_mismatch_and_missing_fail(tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    model = models / "eng.traineddata"
    model.write_bytes(b"PWEH SYNTHETIC MODEL")
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"profiles": {"ubuntu-22.04-x86_64": {
        "models": {model.name: {"sha256": hashlib.sha256(model.read_bytes()).hexdigest()}}}}}))
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
    argv = [sys.executable, str(HELPER), "verify-models", "tesseract", "--lock", str(lock),
            "--models", str(models), "--os-release", str(os_release), "--arch", "x86_64"]
    assert subprocess.run(argv, capture_output=True, timeout=10).returncode == 0
    model.write_bytes(b"PWEH CHANGED MODEL")
    result = subprocess.run(argv, capture_output=True, timeout=10)
    assert result.returncode == 1 and "SHA256 불일치" in result.stderr.decode()
    model.unlink()
    assert subprocess.run(argv, capture_output=True, timeout=10).returncode == 1


def test_locked_deb_hash_mismatch_stops_before_extract(tmp_path):
    """실제 fetch 해시 검사와 locked 분기를 함께 시험한다. 다운로드는 임시 file:// 뿐이다."""
    text = (REPO / "scripts/install.sh").read_text()
    functions = text[text.index("hash_ok() {"):text.index("SAFE_EXTRACT=")]
    functions += text[text.index("deb_fetch_extract() {"):text.index("make_wrapper() {")]
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    deb = tmp_path / "synthetic.deb"
    deb.write_bytes(b"PWEH SYNTHETIC DEB")
    helper = repo / "scripts/image_tools_lock.py"
    helper.write_text(f"print('synthetic\\t1\\t{deb.as_uri()}\\t' + '0' * 64)\n")
    marker = tmp_path / "extracted"
    env = dict(os.environ, REPO=str(repo), PY=sys.executable, CACHE=str(tmp_path / "cache"), SEED="", MARKER=str(marker))
    script = "set -e\ninfo() { :; }\ndpkg-deb() { touch \"$MARKER\"; }\n" + functions
    script += '\ndeb_fetch_extract cache "$CACHE/root" --locked unused tesseract\n'
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode != 0 and "체크섬 불일치" in result.stderr
    assert not marker.exists() and not list((tmp_path / "cache").rglob("*.part"))
    helper.write_text(f"print('synthetic\\t1\\t{deb.as_uri()}\\t{hashlib.sha256(deb.read_bytes()).hexdigest()}')\n")
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode == 0 and marker.exists(), result.stderr


def test_zbar_check_requires_lock_and_version(tmp_path):
    prefix = tmp_path / "tools with spaces"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "zbar").mkdir()
    tool = prefix / "bin/zbarimg"
    tool.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo 0.23.92; else cat >/dev/null; exit 4; fi\n')
    tool.chmod(0o755)
    argv = ["bash", str(REPO / "scripts/install.sh"), "--check", "--only", "zbar", "--prefix", str(prefix), "--no-link"]
    def run():
        return subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert "✗ zbar" in run().stdout
    (prefix / "zbar/lock.sha256").write_text(hashlib.sha256(LOCK.read_bytes()).hexdigest())
    # 지원 플랫폼이 아닌 CI 에서는 설치물을 복사해 놓아도 지원한 것으로 표시하지 않는다.
    try:
        lock_module.load_profile(LOCK, Path("/etc/os-release"), lock_module.platform.machine())
        supported = True
    except ValueError:
        supported = False
    assert ("✓ zbar" if supported else "✗ zbar") in run().stdout
    tool.write_text("#!/bin/sh\necho 99.99\n")
    assert "✗ zbar" in run().stdout


def test_image_doctor_missing_broken_and_models(monkeypatch, tmp_path):
    from pweh import cli, imagehints
    settings = SimpleNamespace(tesseract=None, zbarimg=None, tessdata_dir=None)
    monkeypatch.setattr(imagehints, "resolve_image_tools", lambda _: settings)
    assert all(row["ok"] is None for row in cli.image_doctor_checks(None))
    settings.tesseract = "/synthetic/tesseract"
    settings.zbarimg = "/synthetic/zbarimg"
    settings.tessdata_dir = str(tmp_path)
    monkeypatch.setattr(cli, "_tool_version", lambda *args: (True, "합성 버전"))
    assert cli.image_doctor_checks(None)[2]["ok"] is False
    for lang in ("eng", "kor"):
        (tmp_path / f"{lang}.traineddata").write_bytes(b"PWEH SYNTHETIC")
    assert all(row["ok"] is True for row in cli.image_doctor_checks(None))
    monkeypatch.setattr(cli, "_tool_version", lambda *args: (False, "실행 실패"))
    assert not cli.image_doctor_checks(None)[0]["ok"]
