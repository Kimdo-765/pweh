"""고정 Zig로 C 파서 및 실제 coordinator의 Win32 fake를 검사한다."""
from pathlib import Path
import os
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.external
@pytest.mark.parametrize("name", ["test-native", "test-win32"])
def test_native_host_harness(tmp_path, name):
    zig = os.environ.get("PWEH_ZIG")
    if not zig or not Path(zig).is_file():
        pytest.skip("명시한 고정 PWEH_ZIG가 없음")
    assert subprocess.check_output([zig, "version"], timeout=10).strip() == b"0.17.0"
    header = tmp_path / "pweh-build-id.h"
    header.write_text("static volatile const unsigned char PWEH_BUILD_ID[40] = {0};\n")
    env = {**os.environ, "ZIG_GLOBAL_CACHE_DIR": str(tmp_path / "global"), "ZIG_LOCAL_CACHE_DIR": str(tmp_path / "local")}
    binary = tmp_path / name
    result = subprocess.run([zig, "cc", "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
                             "-I" + str(tmp_path), str(ROOT / "tools/winserial" / (name + ".c")), "-o", str(binary)],
                            env=env, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    result = subprocess.run([str(binary)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.rstrip().endswith(b": ok")
