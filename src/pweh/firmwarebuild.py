"""espprobe 고정 빌드·정적 검사·사전 빌드 설치의 공통 계약.

기기를 열거나 펌웨어를 실행하지 않는다. Docker는 로컬 daemon과 고정 image만 사용한다.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import time
from typing import Any

IMAGE = "espressif/idf@sha256:f81b6e077e6af93c312181cd7d4e7936cfbafc5c7f77cbacba8fdd34994f218a"
PROFILE = "probe-hello"
BOARD = "esp32s3-devkitc1-hello"
COMPONENTS = {"espressif/esp_tinyusb": "2.4.0", "espressif/tinyusb": "0.21.0~2"}
DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
MAX_FILE = 32 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024


class BuildError(ValueError):
    """불완전한 빌드·검사·배포 입력을 거부한다."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_tar(data: bytes, destination: Path, *, limit: int = 256 * 1024 * 1024) -> None:
    """Docker/git archive의 regular 파일만 새 경로에 복사한다. tar extract 기능은 쓰지 않는다."""
    if len(data) > limit + 32 * 1024 * 1024:
        raise BuildError("archive 크기 상한 초과")
    total = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for item in archive:
            name = item.name.removeprefix("./").rstrip("/")
            if not name or name == ".":
                continue
            path = Path(name)
            if (path.is_absolute() or ".." in path.parts or len(name) > 256 or name in seen
                    or len(seen) >= 20000 or not (item.isfile() or item.isdir())):
                raise BuildError("archive 경로/링크/파일 상한 오류")
            seen.add(name)
            total += item.size
            if item.size > 64 * 1024 * 1024 or total > limit:
                raise BuildError("archive 해제 크기 상한 초과")
            target = destination / path
            if target.exists() or target.is_symlink():
                if item.isdir() and target.is_dir() and not target.is_symlink():
                    continue
                raise BuildError("archive 기존 파일/링크 덮어쓰기 거부")
            if item.isdir():
                target.mkdir(parents=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(item)
                if stream is None:
                    raise BuildError("archive 파일 내용 누락")
                blob = stream.read(item.size + 1)
                if len(blob) != item.size:
                    raise BuildError("archive 파일 길이 불일치")
                target.write_bytes(blob)


def bounded_run(argv: list[str], *, timeout: float = 30, limit: int = MAX_OUTPUT,
                cwd: Path | None = None, log: Path | None = None,
                check: bool = True, env: dict[str, str] | None = None) -> bytes:
    """고정 argv를 wall/출력 상한 안에서 실행하고 실패·취소 때 process group을 회수한다."""
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    result = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    assert proc.stdout is not None
    selector.register(proc.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise BuildError(f"명령 시간 상한 초과: {Path(argv[0]).name}")
            for key, _ in selector.select(min(.2, max(.001, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(result) + len(chunk) > limit:
                    raise BuildError(f"명령 출력 상한 초과: {Path(argv[0]).name}")
                result.extend(chunk)
                if log is not None:
                    with log.open("ab") as target:
                        target.write(chunk)
        rc = proc.wait(timeout=max(.001, deadline - time.monotonic()))
        if check and rc:
            raise BuildError(f"명령 실패({rc}): {Path(argv[0]).name}: " + result[-2000:].decode("utf-8", "replace"))
        return bytes(result)
    finally:
        selector.close()
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        # leader가 먼저 끝나도 stdout을 붙잡은 자식 또는 SIGTERM을 무시한 같은 group을 회수한다.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        proc.stdout.close()


def inspect_image() -> dict[str, Any]:
    """정확한 image가 로컬에 있고 OS/architecture/digest가 맞는지 확인한다."""
    raw = bounded_run([*DOCKER, "image", "inspect", IMAGE], limit=1024 * 1024)
    try:
        info = json.loads(raw)[0]
        if info["Os"] != "linux" or info["Architecture"] != "amd64" or IMAGE not in info["RepoDigests"]:
            raise BuildError("Docker image platform 또는 RepoDigest 불일치")
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise BuildError("Docker image inspect 검증 실패") from exc
    return {"image": IMAGE, "id": info["Id"], "os": info["Os"], "architecture": info["Architecture"],
            "size": info.get("Size")}


def prepare_image(output: Path) -> dict[str, Any]:
    """승인된 준비 단계: 고정 image만 내려받는다. 설치/daemon 설정은 바꾸지 않는다."""
    output.mkdir(parents=True, exist_ok=True)
    try:
        return inspect_image()
    except BuildError:
        bounded_run([*DOCKER, "pull", "--platform", "linux/amd64", IMAGE], timeout=5400,
                    log=output / "docker-pull.log")
    result = inspect_image()
    (output / "docker-image.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def read_regular(path: Path, *, limit: int = MAX_FILE) -> bytes:
    """링크·특수 파일·크기 상한을 확인한 뒤 열린 fd 하나에서 읽는다."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise BuildError(f"일반 파일/크기 상한 위반: {path.name}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit or len(data) != info.st_size:
            raise BuildError(f"파일 크기 변경 또는 상한 초과: {path.name}")
        return data
    finally:
        os.close(fd)


def inside(root: Path, value: str | Path) -> Path:
    """존재하는 입력 경로가 root의 regular file이고 링크를 거치지 않는지 확인한다."""
    root = root.resolve(strict=True)
    path = Path(value)
    path = path if path.is_absolute() else root / path
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise BuildError("입력 경로가 빌드 디렉터리 밖임") from exc
    if ".." in relative.parts:
        raise BuildError("상위 경로 참조 거부")
    cursor = root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise BuildError("입력 symlink 거부")
    if not path.is_file():
        raise BuildError(f"입력 파일 없음: {path.name}")
    return path


def safe_name(name: Any) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) or ".." in name:
        raise BuildError("파일 이름/식별자 형식 오류")
    return name


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def elf_symbols(data: bytes) -> tuple[dict[str, dict[str, Any]], dict[int, tuple[int, int, int]]]:
    """ELF32 little-endian symtab과 section 범위를 해석한다. 실행·동적 로드는 하지 않는다."""
    if len(data) > MAX_FILE or len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise BuildError("ELF32 little-endian 입력 필요")
    header = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    if header[1] != 94:
        raise BuildError("ESP32-S3 Xtensa ELF가 아님")
    shoff, shsize, shnum = header[5], header[10], header[11]
    if shsize != 40 or not 0 < shnum < 8192 or shoff + shsize * shnum > len(data):
        raise BuildError("ELF section 범위 오류")
    sections = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * 40) for i in range(shnum)]
    ranges: dict[int, tuple[int, int, int]] = {}
    for i, row in enumerate(sections):
        if row[1] != 8 and row[4] + row[5] > len(data):
            raise BuildError("ELF section이 파일 밖임")
        if row[1] != 8:
            ranges[i] = (row[3], row[4], row[5])
    symbols: dict[str, dict[str, Any]] = {}
    found = False
    symbol_count = 0
    symbol_spans = []
    for row in sections:
        if row[1] != 2:
            continue
        found = True
        symbol_count += row[5] // 16
        if symbol_count > 200000 or len(symbol_spans) >= 8:
            raise BuildError("ELF 전체 symbol table 상한 초과")
        if any(row[4] < end and start < row[4] + row[5] for start, end in symbol_spans):
            raise BuildError("ELF symbol table 범위 중복")
        symbol_spans.append((row[4], row[4] + row[5]))
        if row[9] != 16 or row[5] % 16 or row[5] // 16 > 200000 or row[6] >= shnum:
            raise BuildError("ELF symbol table 상한/형식 오류")
        strings = sections[row[6]]
        if strings[1] != 3:
            raise BuildError("ELF symbol string table 누락")
        raw = data[strings[4]:strings[4] + strings[5]]
        for pos in range(row[4], row[4] + row[5], 16):
            name, value, size, info, other, section = struct.unpack_from("<IIIBBH", data, pos)
            if name >= len(raw):
                raise BuildError("ELF symbol 이름 범위 오류")
            end = raw.find(b"\0", name, min(len(raw), name + 1025))
            if end < 0:
                raise BuildError("ELF symbol 이름 상한 오류")
            text = raw[name:end].decode("utf-8", "strict")
            if text:
                entry = {"value": value, "size": size, "bind": info >> 4, "type": info & 15, "section": section}
                if text in symbols:
                    if info >> 4 != 0 or symbols[text]["bind"] != 0 or text.startswith("pweh_"):
                        raise BuildError(f"중복 global/필수 symbol: {text}")
                    # 로컬 compiler symbol은 파일마다 반복될 수 있으며 정책 추출 대상이 아니다.
                    continue
                symbols[text] = entry
    if not found or not symbols:
        raise BuildError("ELF .symtab 누락/비어 있음")
    return symbols, ranges


def symbol_bytes(data: bytes, symbols: dict, ranges: dict, name: str, *, limit: int = 4096) -> bytes:
    row = symbols.get(name)
    if not row or not 0 < row["size"] <= limit or row["section"] not in ranges:
        raise BuildError(f"필수 symbol 누락/크기 오류: {name}")
    addr, off, length = ranges[row["section"]]
    start = row["value"] - addr
    if start < 0 or start + row["size"] > length:
        raise BuildError(f"symbol section 경계 오류: {name}")
    return data[off + start:off + start + row["size"]]


FORBIDDEN_APP = (
    r"esp_wifi_.*", r"ieee80211_.*", r"esp_bt_.*", r"esp_ble_gap_.*(?:adv|advert).*", r"esp_ble_gatts_.*", r"esp_ble_.*(?:security|bond|encrypt).*",
    r"ble_gap_adv_.*", r"ble_gatts_.*", r"ble_sm_.*", r"esp_hidd_.*", r"esp_flash_init", r"esp_flash_write.*",
    r"esp_flash_erase.*", r"spi_bus_add_flash_device", r"esp_efuse_write.*", r"rmt_new_tx_channel",
    r"tud_hid_.*", r"tud_msc_.*", r"httpd_start", r"lwip_listen.*", r"mdns_.*",
)


def check_symbols(app_objects: dict[str, bytes], final_elf: bytes, *, rom_symbols: dict[str, int] | None = None) -> dict[str, Any]:
    if not app_objects or len(app_objects) > 4096 or sum(map(len, app_objects.values())) > 128 * 1024 * 1024:
        raise BuildError("응용 object 집합 누락/상한 초과")
    for name, blob in app_objects.items():
        symbols, _ = elf_symbols(blob)
        for symbol, row in symbols.items():
            if row["section"] == 0 and any(re.fullmatch(pattern, symbol) for pattern in FORBIDDEN_APP):
                raise BuildError(f"응용 object 금지 참조: {name}: {symbol}")
            if symbol == "ieee80211_raw_frame_sanity_check" and row["bind"] == 1 and row["section"] != 0:
                raise BuildError("strong ieee80211_raw_frame_sanity_check 거부")
    symbols, _ = elf_symbols(final_elf)
    rom_aliases = []
    for symbol in symbols:
        if symbol in ("esp_wifi_init", "esp_bt_controller_init") or symbol.startswith("ieee80211_"):
            row = symbols[symbol]
            if (row["section"] == 0xFFF1 and (rom_symbols or {}).get(symbol) == row["value"]
                    and 0x40000000 <= row["value"] < 0x40080000):
                rom_aliases.append({"name": symbol, "address": row["value"]})
                continue
            raise BuildError(f"유선 profile final ELF에 무선 symbol 존재: {symbol}: {symbols[symbol]}")
    return {"app_objects": len(app_objects), "final_symbols": len(symbols), "sdk_rom_aliases": rom_aliases}


def expand_flags(argv: list[str], root: Path, *, _seen: set[Path] | None = None, _depth: int = 0) -> list[str]:
    """response file을 경로·깊이·크기 상한 아래 펼친다."""
    seen = set() if _seen is None else _seen
    if _depth > 8 or len(seen) > 1024:
        raise BuildError("response file 상한 초과")
    result = []
    for arg in argv:
        if arg.startswith("-Wl,"):
            result.append("-Wl," + ",".join(expand_flags(arg[4:].split(","), root, _seen=seen, _depth=_depth + 1)))
        elif arg.startswith("@"):
            path = inside(root, arg[1:])
            if path in seen:
                raise BuildError("response file 순환/중복")
            seen.add(path)
            nested = shlex.split(read_regular(path, limit=64 * 1024).decode("utf-8"))
            result.extend(expand_flags(nested, root, _seen=seen, _depth=_depth + 1))
        else:
            result.append(arg)
        if len(result) > 100000:
            raise BuildError("명령 인자 상한 초과")
    return result


def check_flags(argv: list[str]) -> None:
    """동등한 GCC/linker spelling과 objcopy 약화 옵션을 모두 거부한다."""
    flat = []
    objcopy = any(Path(arg).name.endswith("objcopy") for arg in argv)
    for arg in argv:
        flat.extend(arg[4:].split(",") if arg.startswith("-Wl,") else [arg])
    flat = [part for part in flat if part != "-Xlinker"]
    for index, arg in enumerate(flat):
        if (arg in ("--allow-multiple-definition", "-zmuldefs") or arg.startswith("--allow-multiple-definition=")
                or "--weaken" in arg or arg == "-W" or (objcopy and arg.startswith("-W")) or arg.startswith("-flto")
                or (arg == "-z" and index + 1 < len(flat) and flat[index + 1] == "muldefs")):
            raise BuildError(f"금지 build flag: {arg}")


def parse_config(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if key in result:
                raise BuildError("중복 sdkconfig key")
            result[key] = value
    return result


def check_config(config: dict[str, str]) -> None:
    expected = {"CONFIG_IDF_TARGET": '"esp32s3"', "CONFIG_APP_REPRODUCIBLE_BUILD": "y",
                "CONFIG_TINYUSB_CDC_ENABLED": "y", "CONFIG_TINYUSB_CDC_COUNT": "2",
                "CONFIG_TINYUSB_DESC_SERIAL_STRING": '""', "CONFIG_TINYUSB_DESC_PRODUCT_STRING": '"PWEH espprobe"',
                "CONFIG_TINYUSB_HID_COUNT": "0", "CONFIG_TINYUSB_MIDI_COUNT": "0", "CONFIG_TINYUSB_VENDOR_COUNT": "0",
                "CONFIG_TINYUSB_DFU_MODE_NONE": "y", "CONFIG_TINYUSB_NET_MODE_NONE": "y",
                "CONFIG_TINYUSB_SUSPEND_CALLBACK": "y", "CONFIG_TINYUSB_RESUME_CALLBACK": "y",
                "CONFIG_ESP_CONSOLE_NONE": "y", "CONFIG_ESP_CONSOLE_SECONDARY_NONE": "y",
                "CONFIG_ESP_TASK_WDT_EN": "y", "CONFIG_ESP_TASK_WDT_INIT": "y", "CONFIG_ESP_TASK_WDT_PANIC": "y",
                "CONFIG_ESP_TASK_WDT_TIMEOUT_S": "2",
                "CONFIG_ESPTOOLPY_FLASHSIZE_4MB": "y", "CONFIG_PARTITION_TABLE_CUSTOM": "y",
                "CONFIG_PARTITION_TABLE_CUSTOM_FILENAME": '"partitions.csv"', "CONFIG_PARTITION_TABLE_OFFSET": "0x8000"}
    for key, value in expected.items():
        if config.get(key) != value:
            raise BuildError(f"필수 sdkconfig 불일치: {key}")
    for key in ("CONFIG_TINYUSB_MSC_ENABLED", "CONFIG_TINYUSB_MTP_ENABLED", "CONFIG_TINYUSB_BTH_ENABLED",
                "CONFIG_COMPILER_LTO", "CONFIG_SPIRAM", "CONFIG_SECURE_BOOT", "CONFIG_SECURE_FLASH_ENC_ENABLED",
                "CONFIG_APP_COMPILE_TIME_DATE", "CONFIG_ESP_WIFI_ENABLED", "CONFIG_BT_ENABLED"):
        if config.get(key) == "y":
            raise BuildError(f"금지 sdkconfig: {key}")


def expected_usb() -> tuple[bytes, bytes]:
    """승인된 hello-only CDC 2개 descriptor의 독립 canonical bytes."""
    device = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xEF, 2, 1, 64, 0x303A, 0x4002, 0x0100, 1, 2, 3, 1)
    config = bytearray((9, 2, 141, 0, 4, 1, 0, 0x80, 50))
    for interface, notify, output, incoming in ((0, 0x81, 2, 0x82), (2, 0x83, 4, 0x84)):
        config.extend((8, 11, interface, 2, 2, 2, 0, 0,
                       9, 4, interface, 0, 1, 2, 2, 0, 4,
                       5, 0x24, 0, 0x20, 1,
                       5, 0x24, 1, 0, interface + 1,
                       4, 0x24, 2, 6,
                       5, 0x24, 6, interface, interface + 1,
                       7, 5, notify, 3, 8, 0, 1,
                       9, 4, interface + 1, 0, 2, 10, 0, 0, 0,
                       7, 5, output, 2, 64, 0, 0,
                       7, 5, incoming, 2, 64, 0, 0))
    return device, bytes(config)


def check_usb(device: bytes, configuration: bytes) -> dict[str, Any]:
    if (device, configuration) != expected_usb():
        raise BuildError("고정 USB CDC descriptor와 다름 (class/endpoint/functional/serial 포함)")
    if len(device) != 18 or device[:2] != b"\x12\x01" or device[16] == 0 or device[17] != 1:
        raise BuildError("USB device descriptor/serial/configuration 오류")
    vid, pid = struct.unpack_from("<HH", device, 8)
    if (vid, pid) != (0x303A, 0x4002):
        raise BuildError("USB VID/PID 불일치")
    if len(configuration) < 9 or configuration[:2] != b"\x09\x02" or struct.unpack_from("<H", configuration, 2)[0] != len(configuration):
        raise BuildError("USB configuration 길이 오류")
    classes = []
    endpoints = []
    associations = []
    current_class = None
    interface_endpoints = []
    pos = 0
    while pos < len(configuration):
        if pos + 2 > len(configuration) or configuration[pos] < 2 or pos + configuration[pos] > len(configuration):
            raise BuildError("USB descriptor 경계 오류")
        size, kind = configuration[pos:pos + 2]
        if kind == 4:
            if size != 9 or configuration[pos + 3] != 0:
                raise BuildError("USB interface/alternate 오류")
            classes.append((configuration[pos + 2], configuration[pos + 5]))
            current_class = configuration[pos + 5]
            interface_endpoints.append(configuration[pos + 4])
        elif kind == 5:
            if size != 7 or current_class not in (2, 10):
                raise BuildError("USB endpoint descriptor 오류")
            address, attributes = configuration[pos + 2:pos + 4]
            if not address & 15 or attributes & 3 != (3 if current_class == 2 else 2):
                raise BuildError("USB CDC endpoint 전송 종류 오류")
            endpoints.append(address)
        elif kind == 11:
            if size != 8 or configuration[pos + 3:pos + 6] != bytes((2, 2, 2)):
                raise BuildError("USB CDC IAD 오류")
            associations.append(configuration[pos + 2])
        elif kind == 0x24:
            if current_class != 2 or size < 3:
                raise BuildError("USB CDC functional descriptor 오류")
        elif kind != 2 or pos != 0:
            raise BuildError("예상하지 않은 USB descriptor 종류")
        pos += size
    if classes != [(0, 2), (1, 10), (2, 2), (3, 10)] or configuration[4] != 4:
        raise BuildError("USB CDC 2개 외 interface 거부")
    if (associations != [0, 2] or interface_endpoints != [1, 2, 1, 2]
            or len(endpoints) != 6 or len(set(endpoints)) != 6):
        raise BuildError("USB CDC interface/endpoint 누락·중복")
    return {"vid": vid, "pid": pid, "product": "PWEH espprobe", "serial_rule": "base-mac-12hex", "cdc_count": 2}


def check_app(data: bytes, elf: bytes) -> dict[str, Any]:
    from pweh.espfmt import parse_app_image
    result = parse_app_image(data)
    if (not result["ok"] or result["chip_id"] != 9 or not result["sha256"]["ok"]
            or result["image_size"] != len(data) or not result["app_desc"] or not result["app_desc"]["magic_ok"]):
        raise BuildError("ESP32-S3 app checksum/hash/크기/appdesc 검증 실패")
    if result["app_desc"]["app_elf_sha256"] != sha256(elf):
        raise BuildError("appdesc ELF SHA256 불일치")
    return {"image_sha256": result["sha256"]["stored"], "app_file_sha256": sha256(data),
            "app_elf_sha256": sha256(elf), "app_desc": result["app_desc"]}


def policy_blob() -> bytes:
    """hello 전용 profile의 canonical TLV(tags 19..26)."""
    values = {19: bytes(4), 20: struct.pack("<HHH", 4096, 1000, 0), 21: bytes(24),
              22: b"\xff", 23: b"\0", 24: b"", 25: b"\0", 26: bytes(4)}
    return b"".join(struct.pack("<HH", tag, len(value)) + value for tag, value in values.items())


def check_identity(elf: bytes, commit: str, version: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise BuildError("source commit/version 형식 오류")
    symbols, ranges = elf_symbols(elf)
    blobs = {}
    for name in ("pweh_usb_device_descriptor", "pweh_usb_configuration_descriptor", "pweh_probe_policy_blob"):
        value = symbol_bytes(elf, symbols, ranges, name)
        declared = symbol_bytes(elf, symbols, ranges, name + "_size", limit=4)
        if len(declared) != 4 or struct.unpack("<I", declared)[0] != len(value):
            raise BuildError(f"descriptor/policy size symbol 불일치: {name}")
        blobs[name] = value
    if blobs["pweh_probe_policy_blob"] != policy_blob():
        raise BuildError("ELF policy TLV가 hello-only 계약과 다름")
    for value in (commit, version, PROFILE, BOARD):
        if value.encode() + b"\0" not in elf:
            raise BuildError(f"ELF build identity 누락: {value}")
    usb = check_usb(blobs["pweh_usb_device_descriptor"], blobs["pweh_usb_configuration_descriptor"])
    return {"usb": usb, "policy_sha256": sha256(policy_blob()), "git_commit": commit, "fw_version": version}


RELEASE_NAMES = ("pweh_espprobe.bin", "bootloader.bin", "partition-table.bin", "merged.bin", "pweh_espprobe.elf",
                 "pweh_espprobe.map", "build-check.json", "dependencies-lock.json")


def compare_builds(first: dict[str, bytes], second: dict[str, bytes], first_meta: dict, second_meta: dict) -> dict:
    """서로 새로 수행한 build의 source·도구·모든 release bytes를 비교한다."""
    if (first_meta != second_meta or first_meta.get("status") != "built" or first_meta.get("mode") != "build"
            or first_meta.get("git_commit") == "0" * 40 or first_meta.get("image", {}).get("image") != IMAGE):
        raise BuildError("재현 build source/도구/완료 상태 불일치")
    if set(first) != set(RELEASE_NAMES) or set(second) != set(RELEASE_NAMES):
        raise BuildError("재현 build 출력 집합 불일치")
    for name in RELEASE_NAMES:
        if first[name] != second[name]:
            raise BuildError(f"재현 build bytes 불일치: {name}")
    return {"status": "matched", "runs": 2, "git_commit": first_meta["git_commit"],
            "source_archive_sha256": first_meta["source_archive_sha256"],
            "files": {name: sha256(first[name]) for name in RELEASE_NAMES}}


def manifest_entry(*, commit: str, version: str, files: dict[str, bytes], report: dict,
                   source_sha256: str, dependencies: dict, reproducibility: dict) -> dict[str, Any]:
    """실제 검사 완료 bytes만 release 후보로 묶는다. 자기 manifest/report hash 순환은 없다."""
    if report.get("status") != "passed":
        raise BuildError("통과한 검사 보고서가 필요함")
    if (reproducibility.get("status") != "matched" or reproducibility.get("runs") != 2
            or reproducibility.get("git_commit") != commit or reproducibility.get("source_archive_sha256") != source_sha256
            or reproducibility.get("files") != {name: sha256(blob) for name, blob in files.items()}):
        raise BuildError("두 clean build의 byte 일치 증거가 필요함")
    roles = {"pweh_espprobe.bin": ("app", 0x10000), "bootloader.bin": ("bootloader", 0),
             "partition-table.bin": ("partition-table", 0x8000), "merged.bin": ("merged", 0),
             "pweh_espprobe.elf": ("elf", None), "pweh_espprobe.map": ("map", None),
             "build-check.json": ("build-check", None), "dependencies-lock.json": ("dependencies-lock", None)}
    if set(files) != set(roles):
        raise BuildError("release 출력 파일 집합 불일치")
    rows = []
    for name, (role, offset) in roles.items():
        row = {"name": name, "role": role, "size": len(files[name]), "sha256": sha256(files[name])}
        if offset is not None:
            row["offset"] = offset
        rows.append(row)
    image = check_app(files["pweh_espprobe.bin"], files["pweh_espprobe.elf"])
    identity = check_identity(files["pweh_espprobe.elf"], commit, version)
    return {"status": "released", "git_commit": commit, "fw_name": "PWEH espprobe", "fw_version": version,
            "build_profile": PROFILE, "board": BOARD, "chip": "esp32s3", "source_archive_sha256": source_sha256,
            "docker_image": IMAGE, "idf_version": "v6.1", "dependencies": dependencies,
            "protocol_version": 1, "image_sha256": image["image_sha256"], "app_elf_sha256": image["app_elf_sha256"],
            "policy_sha256": identity["policy_sha256"], "usb": identity["usb"], "caps": [],
            "limits": {"max_payload": 4096, "hb_ms": 1000, "max_credit": 0},
            "pins_allowed": {"H0": [], "H1": [], "H1a": []}, "pclk_pad": None, "pin_drive": None,
            "spi_read_opcodes": [], "radio": "none", "tx_caps": [], "files": rows,
            "verification": {"reproducible": True, "runs": 2, "hardware_verified": False,
                             "build_check_sha256": sha256(files["build-check.json"])}}


def validate_release(entry: dict[str, Any], payloads: dict[str, bytes] | None = None) -> dict[str, Any]:
    """패키지 manifest의 고정 profile과 선택 payload 무결성을 검증한다."""
    if not isinstance(entry, dict) or entry.get("status") != "released":
        raise BuildError("released 항목이 아님")
    for key, expected in (("build_profile", PROFILE), ("board", BOARD), ("chip", "esp32s3"),
                          ("docker_image", IMAGE), ("radio", "none"), ("caps", []), ("tx_caps", []),
                          ("spi_read_opcodes", []), ("pins_allowed", {"H0": [], "H1": [], "H1a": []})):
        if entry.get(key) != expected:
            raise BuildError(f"release profile 불일치: {key}")
    for key, expected in (("fw_name", "PWEH espprobe"), ("idf_version", "v6.1"), ("protocol_version", 1),
                          ("limits", {"max_payload": 4096, "hb_ms": 1000, "max_credit": 0}),
                          ("pclk_pad", None), ("pin_drive", None), ("policy_sha256", sha256(policy_blob()))):
        if key not in entry or entry[key] != expected:
            raise BuildError(f"release hello 계약 불일치: {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", str(entry.get("git_commit", ""))):
        raise BuildError("release source commit 오류")
    safe_name(entry.get("fw_version"))
    for key in ("image_sha256", "app_elf_sha256", "source_archive_sha256", "policy_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get(key, ""))):
            raise BuildError(f"release hash 오류: {key}")
    verification = entry.get("verification", {})
    if verification.get("reproducible") is not True or verification.get("runs") != 2 or verification.get("hardware_verified") is not False:
        raise BuildError("release 재현/하드웨어 검증 상태 오류")
    expected_roles = {"app", "bootloader", "partition-table", "merged", "elf", "map", "build-check", "dependencies-lock"}
    rows = entry.get("files", [])
    if not isinstance(rows, list) or len(rows) != len(expected_roles):
        raise BuildError("release 파일 목록 오류")
    by_role, by_name = {}, {}
    for row in rows:
        name = safe_name(row.get("name"))
        role = row.get("role")
        if name in by_name or role in by_role or role not in expected_roles:
            raise BuildError("release 파일/역할 중복")
        if type(row.get("size")) is not int or not 0 < row["size"] <= MAX_FILE:
            raise BuildError("release 파일 크기 상한 오류")
        if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))):
            raise BuildError("release 파일 hash 오류")
        by_name[name] = row
        by_role[role] = row
    for role, offset in (("app", 0x10000), ("bootloader", 0), ("partition-table", 0x8000), ("merged", 0)):
        if by_role[role].get("offset") != offset:
            raise BuildError("release flash offset 불일치")
    if by_role["bootloader"]["size"] > 0x8000 or by_role["partition-table"]["size"] > 0x8000 or by_role["app"]["size"] > 1024 * 1024:
        raise BuildError("release flash 구간 겹침/초과")
    if verification.get("build_check_sha256") != by_role["build-check"]["sha256"]:
        raise BuildError("release 검사 보고서 hash 불일치")
    if payloads is not None:
        if set(payloads) != set(by_name):
            raise BuildError("release payload 집합 불일치")
        for name, row in by_name.items():
            data = payloads[name]
            if len(data) != row["size"] or sha256(data) != row["sha256"]:
                raise BuildError(f"release payload hash 불일치: {name}")
        get = lambda role: payloads[by_role[role]["name"]]
        image = check_app(get("app"), get("elf"))
        identity = check_identity(get("elf"), entry["git_commit"], entry["fw_version"])
        if (image["image_sha256"] != entry["image_sha256"] or image["app_elf_sha256"] != entry["app_elf_sha256"]
                or identity["usb"] != entry.get("usb") or identity["policy_sha256"] != entry["policy_sha256"]):
            raise BuildError("release image/identity 계약 불일치")
        merged = get("merged")
        for role in ("bootloader", "partition-table", "app"):
            row = by_role[role]
            if merged[row["offset"]:row["offset"] + row["size"]] != get(role):
                raise BuildError("merged image와 개별 flash payload 불일치")
        check_flash_layout(get("bootloader"), get("partition-table"), get("app"), merged)
        report = json.loads(get("build-check"))
        if report.get("status") != "passed" or report.get("git_commit") != entry["git_commit"]:
            raise BuildError("release 검사 보고서 실패/출처 불일치")
    return entry


def check_flash_layout(bootloader: bytes, partitions: bytes, app: bytes, merged: bytes) -> None:
    from pweh.espfmt import parse_app_image, parse_partition_table
    boot = parse_app_image(bootloader)
    if not boot["ok"] or not boot["sha256"]["ok"] or boot["chip_id"] != 9 or boot["image_size"] != len(bootloader):
        raise BuildError("bootloader image 검증 실패")
    table = parse_partition_table(partitions, 0)
    rows = table.get("entries", [])
    if (not table.get("found") or table.get("errors") or not table["md5"]["ok"] or len(rows) != 1 or rows[0].get("label") != "factory"
            or rows[0].get("offset") != 0x10000 or rows[0].get("size") != 1024 * 1024
            or rows[0].get("type") != 0 or rows[0].get("subtype") != 0 or rows[0].get("flags") != 0):
        raise BuildError("factory-only partition table 검증 실패")
    end = 0
    for offset, blob in ((0, bootloader), (0x8000, partitions), (0x10000, app)):
        if offset < end or merged[end:offset] != b"\xff" * (offset - end) or merged[offset:offset + len(blob)] != blob:
            raise BuildError("merged flash payload/채움/경계 불일치")
        end = offset + len(blob)
    if len(merged) != end:
        raise BuildError("merged image 뒤 추가 데이터 거부")


def load_releases(path: Path) -> list[dict[str, Any]]:
    document = json.loads(read_regular(path, limit=1024 * 1024))
    if document.get("schema") != "pweh.espprobe-releases/v1" or not isinstance(document.get("releases"), list):
        raise BuildError("espprobe release catalog 형식 오류")
    entries = document["releases"]
    if len(entries) > 100:
        raise BuildError("release 항목 상한 초과")
    seen = set()
    for entry in entries:
        validate_release(entry)
        key = (entry["fw_version"], entry["build_profile"], entry["board"])
        if key in seen:
            raise BuildError("release version/profile/board 중복")
        seen.add(key)
    return entries


def load_payloads(entry: dict, directory: Path) -> dict[str, bytes]:
    return {row["name"]: read_regular(inside(directory, row["name"])) for row in entry["files"]}


def installed_directory(tools: Path, entry: dict) -> Path:
    from pweh.toolsdir import espprobe_firmware_dir
    return espprobe_firmware_dir(tools, entry["fw_version"], entry["build_profile"], entry["board"])


def install_releases(catalog: Path, source: Path, tools: Path, *, check: bool = False, force: bool = False) -> int:
    """검증된 repository 사전 빌드만 복사한다. network/build/flash를 수행하지 않는다."""
    entries = load_releases(catalog)
    if not entries:
        return 99
    for entry in entries:
        destination = installed_directory(tools, entry)
        cursor = tools
        if cursor.is_symlink():
            raise BuildError("설치 root symlink 거부")
        for part in destination.relative_to(tools).parts:
            cursor /= part
            if cursor.is_symlink():
                raise BuildError("설치 경로 symlink 거부")
        try:
            validate_release(entry, load_payloads(entry, destination))
            installed = json.loads(read_regular(destination / "release.json", limit=1024 * 1024))
            if installed != entry:
                raise BuildError("설치 release metadata 불일치")
            continue
        except (BuildError, OSError, ValueError):
            if check:
                raise BuildError("설치된 사전 빌드의 검증 실패")
        payloads = load_payloads(entry, inside_directory(source, entry["fw_version"]))
        validate_release(entry, payloads)
        # tools 자체는 사용자가 지정한 설치 root, 그 아래에는 symlink 경유를 허용하지 않는다.
        cursor = tools.resolve()
        for part in destination.relative_to(tools).parts:
            cursor /= part
            if cursor.is_symlink():
                raise BuildError("설치 경로 symlink 거부")
        if destination.exists() and not force:
            raise BuildError("기존 사전 빌드가 손상됨; 검증된 교체에는 --force 필요")
        destination.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        stage = Path(tempfile.mkdtemp(prefix=".espprobe-stage-", dir=destination.parent))
        backup = None
        try:
            for name, data in payloads.items():
                (stage / name).write_bytes(data)
                (stage / name).chmod(0o444)
            (stage / "release.json").write_bytes(json_bytes(entry))
            validate_release(entry, load_payloads(entry, stage))
            if json.loads(read_regular(stage / "release.json", limit=1024 * 1024)) != entry:
                raise BuildError("staging release metadata 불일치")
            if destination.exists():
                backup = destination.with_name(destination.name + ".old-" + str(time.time_ns()))
                destination.rename(backup)
            try:
                stage.rename(destination)
            except BaseException:
                if backup is not None:
                    backup.rename(destination)
                raise
            if backup is not None:
                shutil.rmtree(backup)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    return 0


def inside_directory(root: Path, name: str) -> Path:
    safe_name(name)
    path = root / name
    if path.is_symlink() or not path.is_dir():
        raise BuildError("사전 빌드 디렉터리 누락/링크 거부")
    return path
