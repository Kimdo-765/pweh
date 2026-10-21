"""espfmt 를 코어(pweh.espfmt)로 옮긴 뒤에도 fwtriage_mcp.espfmt 가 같은 객체를 모두 다시 내보내는지 (결정 D1).

fwtriage 서버·시험·tests/fwtriage/esp_builders.py 는 ``fwtriage_mcp.espfmt`` 를 그대로 쓴다. 코어에 공개 이름을 더하고 shim 에
빠뜨리면 여기서 드러난다.
"""

from __future__ import annotations

import ast
import inspect

import pweh.espfmt as core


def _public_names() -> list[str]:
    """코어 모듈이 최상위에서 정의한 공개 이름(함수·클래스·상수 — __all__ 에 없는 것도)."""
    tree = ast.parse(inspect.getsource(core))
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            names += [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return [n for n in names if not n.startswith("_")]


def test_core_espfmt_is_pure_stdlib_and_exports_its_public_names():
    names = _public_names()
    assert {"parse_nvs", "parse_partition_table", "parse_app_image", "image_to_elf", "nvs_set_primitives", "nvs_item_diff",
            "find_partition", "nvs_crc32", "secret_hint", "classify_address", "chip_info", "EspFormatError", "NvsError",
            "NVS_PAGE_SIZE", "PARTITION_TABLE_DEFAULT_OFFSET", "PARTITION_TABLE_MAX_LEN", "NVS_DEFAULT_MAX_ITEMS"} <= set(names)
    assert set(core.__all__) == set(names)
    tree = ast.parse(inspect.getsource(core))
    imported = {a.name.split(".")[0] for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
    assert imported <= {"__future__", "hashlib", "re", "struct", "zlib", "typing"}, imported


def test_fwtriage_shim_reexports_the_same_objects():
    import fwtriage_mcp.espfmt as shim

    names = _public_names()
    assert set(shim.__all__) == set(names)
    for name in names:
        assert getattr(shim, name) is getattr(core, name), name
    # 서버의 예외 처리(except espfmt.EspFormatError)와 시험 빌더가 같은 객체를 본다
    import fwtriage_mcp.server  # noqa: F401
    from fwtriage.esp_builders import nvs_crc32

    assert nvs_crc32 is core.nvs_crc32
    assert issubclass(shim.EspFormatError, ValueError) and shim.NvsError is core.NvsError
