"""pweh.mcpkit: 네이티브 Windows·Cygwin·MSYS 에서는 MCP 서버를 시작하지 않는다 (port-routing 설계 §12, D6, G9)."""

from __future__ import annotations

import sys

import pytest

from pweh import mcpkit


@pytest.mark.parametrize("plat", ["win32", "cygwin", "msys"])
def test_unsupported_platform_message(plat):
    msg = mcpkit.unsupported_platform(plat)
    assert msg is not None
    assert repr(plat) in msg and "WSL" in msg and "wsl.exe -d <배포판> -e" in msg and "-u root" in msg


@pytest.mark.parametrize("plat", ["linux", "darwin", "freebsd13"])
def test_supported_platforms(plat):
    assert mcpkit.unsupported_platform(plat) is None


def test_unsupported_platform_reads_sys_platform_at_call_time(monkeypatch):
    monkeypatch.setattr(sys, "platform", "msys")
    assert mcpkit.unsupported_platform() is not None
    monkeypatch.setattr(sys, "platform", "linux")
    assert mcpkit.unsupported_platform() is None


@pytest.mark.parametrize("plat", ["win32", "cygwin", "msys"])
def test_create_server_refuses_to_start(plat, monkeypatch):
    def no_server(*a, **kw):
        raise AssertionError("서버를 만들면 안 된다")

    monkeypatch.setattr(mcpkit, "MCPServer", no_server)
    monkeypatch.setattr(sys, "platform", plat)
    with pytest.raises(SystemExit) as ei:
        mcpkit.create_server("uart-mcp", instructions="시험")
    text = str(ei.value.code)
    assert text.startswith("[uart-mcp] ") and "WSL" in text
    assert "/.venv/bin/pweh-uart-mcp" in text  # pyproject 의 콘솔 스크립트 이름


@pytest.mark.parametrize("plat", ["linux", "darwin"])
def test_create_server_starts_elsewhere(plat, monkeypatch):
    monkeypatch.setattr(sys, "platform", plat)
    server = mcpkit.create_server("platform-test", instructions="시험")
    assert isinstance(server, mcpkit.MCPServer)
