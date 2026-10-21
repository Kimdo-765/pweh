"""network none container 안의 고정 reconfigure/build 실행. 기기 action은 없다."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import sys

SOURCE = Path("/work/src")
shutil.copytree("/input/source", SOURCE)
sys.path.insert(0, str(SOURCE / "src"))
from pweh import firmwarebuild as F

PROJECT = SOURCE / "firmware/espprobe"
BUILD = Path("/work/build")
BUILD.mkdir()
generated = BUILD / "generated"
generated.mkdir()
version = F.read_regular(PROJECT / "VERSION", limit=128).decode().strip()
commit = os.environ["PWEH_SOURCE_COMMIT"]
import re
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise F.BuildError("build identity 형식 오류")
fields = {"PWEH_FW_NAME": "PWEH espprobe", "PWEH_FW_VERSION": version, "PWEH_BUILD_PROFILE": F.PROFILE,
          "PWEH_BUILD_BOARD": F.BOARD, "PWEH_SOURCE_COMMIT": commit, "PWEH_POLICY_SHA256": F.sha256(F.policy_blob())}
(generated / "pweh_build_identity.h").write_text("#pragma once\n" + "".join(f'#define {key} "{value}"\n' for key, value in fields.items()))
mode = os.environ["PWEH_BUILD_ACTION"]
if mode == "lock":
    # registry fallback는 network none 때문에 불가능하다. 사용자 HOME 설정을 상속하지 않는다.
    os.environ["IDF_COMPONENT_MANAGER"] = "1"
    os.environ["IDF_COMPONENT_LOCAL_STORAGE_URL"] = "file:///input/deps/mirror"
    os.environ["IDF_COMPONENT_STORAGE_URL"] = "file:///input/deps/mirror"
    action = "reconfigure"
elif mode == "build":
    os.environ["IDF_COMPONENT_MANAGER"] = "0"
    action = "build"
    for namespace_name, version_pin in F.COMPONENTS.items():
        dirname = namespace_name.replace("/", "__")
        shutil.copytree(Path("/input/deps/vendor") / dirname, PROJECT / "components" / namespace_name.split("/")[1])
else:
    raise F.BuildError("지원하지 않는 고정 build action")
F.bounded_run(["idf.py", "-C", str(PROJECT), "-B", str(BUILD), "-D", "IDF_TARGET=esp32s3", action],
              timeout=1600, limit=16 * 1024 * 1024, log=Path("/out/idf.log"))
if mode == "lock":
    lock = PROJECT / "dependencies.lock"
    shutil.copyfile(lock, "/out/dependencies.lock")
    shutil.copytree(PROJECT / "managed_components", "/out/vendor")
    print("고정 component offline lock 생성 완료")
else:
    shutil.copyfile(PROJECT / "sdkconfig", "/out/sdkconfig.txt")
    files = {"pweh_espprobe.bin": BUILD / "pweh_espprobe.bin", "pweh_espprobe.elf": BUILD / "pweh_espprobe.elf",
             "pweh_espprobe.map": BUILD / "pweh_espprobe.map", "bootloader.bin": BUILD / "bootloader/bootloader.bin",
             "partition-table.bin": BUILD / "partition_table/partition-table.bin"}
    payloads = {name: F.read_regular(path) for name, path in files.items()}
    merged = bytearray(b"\xff" * (0x10000 + len(payloads["pweh_espprobe.bin"])))
    for name, offset in (("bootloader.bin", 0), ("partition-table.bin", 0x8000), ("pweh_espprobe.bin", 0x10000)):
        merged[offset:offset + len(payloads[name])] = payloads[name]
    # 입력 header를 다시 쓰지 않고 검증된 flash offsets에 byte를 그대로 병합한다.
    F.check_flash_layout(payloads["bootloader.bin"], payloads["partition-table.bin"], payloads["pweh_espprobe.bin"], bytes(merged))
    for name, data in payloads.items():
        Path("/out", name).write_bytes(data)
    Path("/out/merged.bin").write_bytes(merged)
    shutil.copyfile("/input/deps/dependencies-lock.json", "/out/dependencies-lock.json")
    F.bounded_run([sys.executable, "-B", str(SOURCE / "scripts/firmware/check_build.py")], timeout=600, limit=16 * 1024 * 1024)
    print("고정 offline firmware build/check 완료")
