"""ESP32 계열 펌웨어 형식 라이브러리 — 코어 ``pweh.espfmt`` 의 재수출 shim.

구현은 코어 ``src/pweh/espfmt.py`` 로 옮겼다. pweh-emu 도 NVS 비밀값 수집에 쓰는데 서버끼리는 import 하지 않으므로
공통 코어에 둔다(설계 docs/design/emulation.md 결정 D1). 이 모듈은 fwtriage 모듈과 시험(tests/fwtriage/esp_builders.py 등)이
쓰던 ``fwtriage_mcp.espfmt`` 이름을 그대로 둔다. 같은 객체를 다시 내보내므로 ``except espfmt.EspFormatError`` 같은 코드도
그대로 동작한다. 새 코드는 ``pweh.espfmt`` 를 직접 import 한다.
"""

from __future__ import annotations

from pweh.espfmt import (
    NVS_DEFAULT_MAX_ITEMS,
    NVS_PAGE_SIZE,
    PARTITION_TABLE_DEFAULT_OFFSET,
    PARTITION_TABLE_MAX_LEN,
    EspFormatError,
    NvsError,
    chip_info,
    classify_address,
    find_partition,
    image_to_elf,
    nvs_crc32,
    nvs_item_diff,
    nvs_set_primitives,
    parse_app_image,
    parse_nvs,
    parse_partition_table,
    secret_hint,
)

__all__ = [
    "EspFormatError",
    "NvsError",
    "chip_info",
    "classify_address",
    "PARTITION_TABLE_DEFAULT_OFFSET",
    "PARTITION_TABLE_MAX_LEN",
    "parse_partition_table",
    "find_partition",
    "parse_app_image",
    "image_to_elf",
    "NVS_PAGE_SIZE",
    "NVS_DEFAULT_MAX_ITEMS",
    "nvs_crc32",
    "parse_nvs",
    "secret_hint",
    "nvs_item_diff",
    "nvs_set_primitives",
]
