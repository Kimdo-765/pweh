"""완성한 고정 IDF build tree를 빠짐없이 검사하고 공개 가능한 보고서만 쓴다."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shlex
import re
import sys

SOURCE = Path("/work/src")
BUILD = Path("/work/build")
sys.path.insert(0, str(SOURCE / "src"))
from pweh import firmwarebuild as F


def compiler_argv(row):
    argv = row.get("arguments") or shlex.split(row["command"])
    return F.expand_flags(argv, BUILD)


def macros(argv, cwd):
    """같은 compiler·source·defines로 실제 전처리 결과를 확인한다."""
    cleaned = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg in ("-o", "-MF", "-MT", "-MQ"):
            skip = True
        elif arg not in ("-c", "-MD", "-MMD", "-MP"):
            cleaned.append(arg)
    result = F.bounded_run([*cleaned, "-E", "-dM"], timeout=30, cwd=cwd)
    values = [line.split(maxsplit=2)[2] for line in result.decode().splitlines()
              if line.startswith("#define CFG_TUD_CDC_TX_OVERWRITABLE_IF_NOT_CONNECTED ")]
    if values != ["0"]:
        raise F.BuildError("실제 TinyUSB TX overwrite macro가 0이 아님")
    return F.sha256(result)


def main():
    rows = json.loads(F.read_regular(BUILD / "compile_commands.json", limit=64 * 1024 * 1024))
    if not isinstance(rows, list) or not 0 < len(rows) <= 4096:
        raise F.BuildError("compile_commands 누락/상한 초과")
    objects = {}
    macro_reports = []
    component_names = set()
    for row in rows:
        argv = compiler_argv(row)
        F.check_flags(argv)
        origin = Path(row["file"]).resolve()
        app = origin.is_relative_to(SOURCE / "firmware/common") or origin.is_relative_to(SOURCE / "firmware/espprobe/main")
        usb = "tinyusb" in str(origin)
        if not (app or usb):
            continue
        if "-o" not in argv:
            raise F.BuildError("compile object 경로 누락")
        output = Path(argv[argv.index("-o") + 1])
        directory = Path(row["directory"])
        output = F.inside(BUILD, output if output.is_absolute() else directory / output)
        relative = output.relative_to(BUILD).as_posix()
        if app:
            if relative in objects:
                raise F.BuildError("응용 object 중복")
            objects[relative] = F.read_regular(output, limit=16 * 1024 * 1024)
            if "esp-idf/main/" in relative:
                component_names.add("main")
            if "esp-idf/pweh_common/" in relative:
                component_names.add("pweh_common")
        macro_reports.append({"object": relative, "sha256": macros(argv, directory)})
    if component_names != {"main", "pweh_common"} or not any("tinyusb" in x["object"] for x in macro_reports):
        raise F.BuildError("필수 main/pweh_common/tinyusb object 검사 누락")
    commands = F.bounded_run(["ninja", "-C", str(BUILD), "-t", "commands"], timeout=30, limit=64 * 1024 * 1024)
    for line in commands.decode().splitlines():
        F.check_flags(F.expand_flags(shlex.split(line), BUILD))
    elf = F.read_regular(BUILD / "pweh_espprobe.elf")
    rom_file = Path(os.environ["IDF_PATH"]) / "components/esp_rom/esp32s3/ld/esp32s3.rom.ld"
    rom_text = F.read_regular(rom_file, limit=1024 * 1024).decode()
    rom_symbols = {name: int(address, 16) for name, address in re.findall(r"^(ieee80211_\w+)\s*=\s*(0x[0-9a-fA-F]+);", rom_text, re.M)}
    symbol_report = F.check_symbols(objects, elf, rom_symbols=rom_symbols)
    symbol_report["sdk_rom_linker_sha256"] = F.sha256(rom_text.encode())
    config = F.parse_config(F.read_regular(SOURCE / "firmware/espprobe/sdkconfig").decode())
    F.check_config(config)
    version = F.read_regular(SOURCE / "firmware/espprobe/VERSION", limit=128).decode().strip()
    identity = F.check_identity(elf, os.environ["PWEH_SOURCE_COMMIT"], version)
    app = F.check_app(F.read_regular(BUILD / "pweh_espprobe.bin"), elf)
    mapping = F.read_regular(BUILD / "pweh_espprobe.map").decode("utf-8")
    for component in ("main", "pweh_common"):
        if f"lib{component}.a" not in mapping:
            raise F.BuildError("응용 archive가 최종 map에 없음")
    for relative in objects:
        if Path(relative).name not in mapping:
            raise F.BuildError("응용 object가 최종 map에 없음")
    report = {"schema": "pweh.firmware-build-check/v1", "status": "passed", **identity,
              "build_profile": F.PROFILE, "board": F.BOARD, "image_sha256": app["image_sha256"],
              "app_file_sha256": app["app_file_sha256"], "app_elf_sha256": app["app_elf_sha256"],
              "symbols": symbol_report, "app_objects": [{"path": key, "sha256": F.sha256(value)} for key, value in sorted(objects.items())],
              "macro_checks": macro_reports, "sdkconfig_sha256": F.sha256(F.read_regular(SOURCE / "firmware/espprobe/sdkconfig")),
              "command_sha256": F.sha256(commands), "checker_sha256": F.sha256(F.read_regular(Path(__file__))),
              "hardware_verified": False}
    Path("/out/build-check.json").write_bytes(F.json_bytes(report))


if __name__ == "__main__":
    main()
