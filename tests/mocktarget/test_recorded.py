"""tests/mock-targets/recorded/*-boot.log 이 현재 시뮬레이터 출력과 같은지 (결정적 부팅 로그 회귀 테스트)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from pweh.formats import parse_mtdparts

MOCK_TARGETS = Path(__file__).resolve().parents[1] / "mock-targets"


def _recorder():
    spec = importlib.util.spec_from_file_location("pweh_record_logs", MOCK_TARGETS / "record_logs.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
def test_recorded_boot_log_matches_simulator(profile):
    path = MOCK_TARGETS / "recorded" / f"{profile}-boot.log"
    assert path.is_file(), f"{path} 없음 — tests/mock-targets/record_logs.py 로 생성"
    recorded = path.read_bytes()
    fresh = _recorder().record_boot(profile, full=False)
    assert fresh == recorded, "부팅 로그 형식이 바뀌었으면 record_logs.py 로 다시 생성하세요"
    text = recorded.decode("utf-8", "replace")
    assert "\r\n" in text and "Hit any key to stop autoboot:" in text
    m = re.search(r"Kernel command line: (.*)\r\n", text)
    assert m and parse_mtdparts(m.group(1), total_size=16 << 20)
    assert text.endswith("Please press Enter to activate this console. ")


def test_recorded_sessions_exist():
    for profile in ("hisilicon-like", "ingenic-like"):
        for kind in ("uboot-session", "shell-session"):
            data = (MOCK_TARGETS / "recorded" / f"{profile}-{kind}.log").read_bytes()
            assert len(data) > 1000
    sess = (MOCK_TARGETS / "recorded" / "ingenic-like-uboot-session.log").read_text("utf-8", "replace")
    assert "CRC32 for 80600000 ... 8060ffff ==> " in sess and "<INTERRUPT>" in sess
