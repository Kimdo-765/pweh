"""합성 ELF/ESP image·가짜 실행기로 빌드 경계와 해시 구분을 검사한다."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import os
import subprocess
import tarfile
import io

import pytest
from pweh import firmwarebuild as F


def elf(entries=(), payload=b"PWEH SYNTHETIC ELF", extra=b""):
    """entries=(name,value,size,bind,section)인 최소 Xtensa ELF32."""
    names = b"\0"
    symbols = bytearray(16)
    for name, value, size, bind, section in entries:
        index = len(names)
        names += name.encode() + b"\0"
        symbols += struct.pack("<IIIBBH", index, value, size, bind << 4 | 1, 0, section)
    if not entries:
        names += b"synthetic\0"
        symbols += struct.pack("<IIIBBH", 1, 0, 1, 1 << 4 | 1, 0, 3)
    offsets = (52, 52 + len(names), 52 + len(names) + len(symbols))
    shoff = offsets[2] + len(payload) + len(extra)
    header = b"\x7fELF\x01\x01\x01" + bytes(9)
    header += struct.pack("<HHIIIIIHHHHHH", 2, 94, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 4, 0)
    sections = bytes(40)
    sections += struct.pack("<10I", 0, 3, 0, 0, offsets[0], len(names), 0, 0, 1, 0)
    sections += struct.pack("<10I", 0, 2, 0, 0, offsets[1], len(symbols), 1, 0, 4, 16)
    sections += struct.pack("<10I", 0, 1, 2, 0, offsets[2], len(payload), 0, 0, 4, 0)
    return header + names + symbols + payload + extra + sections


def image(payload=b"PWEH SYNTHETIC APP", elf_data=None):
    if elf_data is not None:
        desc = bytearray(256)
        struct.pack_into("<I", desc, 0, 0xABCD5432)
        desc[16:21] = b"0.1.0"
        desc[48:61] = b"pweh_espprobe"
        desc[112:117] = b"v6.1\0"
        desc[144:176] = hashlib.sha256(elf_data).digest()
        payload = bytes(desc) + payload
    header = bytearray(24)
    header[:4] = bytes((0xE9, 1, 2, 0x20))
    struct.pack_into("<H", header, 12, 9)
    header[23] = 1
    data = header + struct.pack("<II", 0x3C000020, len(payload)) + payload
    data += bytes(15 - len(data) % 16)
    checksum = 0xEF
    for value in payload:
        checksum ^= value
    data.append(checksum)
    return bytes(data) + hashlib.sha256(data).digest()


@pytest.mark.parametrize("symbol", ["esp_flash_write", "esp_flash_erase_region", "tud_hid_report", "mdns_init", "esp_ble_gatts_register_callback"])
def test_forbidden_application_reference(symbol):
    with pytest.raises(F.BuildError, match="금지 참조"):
        F.check_symbols({"app.o": elf([(symbol, 0, 0, 1, 0)])}, elf())


def test_sdk_flash_reference_allowed_but_final_radio_rejected():
    F.check_symbols({"app.o": elf()}, elf([("esp_flash_write", 0, 1, 1, 3)]))
    with pytest.raises(F.BuildError, match="무선"):
        F.check_symbols({"app.o": elf()}, elf([("esp_wifi_init", 0, 1, 1, 3)]))


@pytest.mark.parametrize("flags", [["-Wl,-z,muldefs"], ["-Xlinker", "-z", "-Xlinker", "muldefs"],
                                   ["--allow-multiple-definition"], ["--weaken-symbol=x"], ["--weaken-symbols=names"], ["-flto=auto"]])
def test_linker_bypass_flags_fail(flags):
    with pytest.raises(F.BuildError):
        F.check_flags(flags)


def test_response_file_escape_cycle_and_flag(tmp_path):
    (tmp_path / "a.rsp").write_text("@a.rsp")
    with pytest.raises(F.BuildError, match="순환"):
        F.expand_flags(["@a.rsp"], tmp_path)
    (tmp_path / "a.rsp").write_text("-Wl,--allow-multiple-definition")
    with pytest.raises(F.BuildError):
        F.check_flags(F.expand_flags(["@a.rsp"], tmp_path))
    with pytest.raises(F.BuildError):
        F.expand_flags(["@../outside.rsp"], tmp_path)


def test_elf_symbol_section_bounds_and_empty_table():
    data = elf([("bad", 999, 10, 1, 3)])
    symbols, ranges = F.elf_symbols(data)
    with pytest.raises(F.BuildError, match="경계"):
        F.symbol_bytes(data, symbols, ranges, "bad")
    with pytest.raises(F.BuildError):
        F.elf_symbols(bytes(100))
    with pytest.raises(F.BuildError):
        F.check_symbols({}, elf())


def test_image_digest_is_not_whole_file_or_elf_hash():
    executable = elf()
    data = image(elf_data=executable)
    facts = F.check_app(data, executable)
    assert facts["image_sha256"] == data[-32:].hex()
    assert len({facts["image_sha256"], facts["app_file_sha256"], facts["app_elf_sha256"]}) == 3
    with pytest.raises(F.BuildError):
        F.check_app(data[:-1] + bytes((data[-1] ^ 1,)), executable)
    with pytest.raises(F.BuildError):
        F.check_app(data, executable + b"changed")


def test_bounded_runner_timeout_output_and_nonzero(tmp_path):
    with pytest.raises(F.BuildError, match="시간"):
        F.bounded_run([sys.executable, "-c", "import time;time.sleep(3)"], timeout=.05)
    with pytest.raises(F.BuildError, match="출력"):
        F.bounded_run([sys.executable, "-c", "print('x'*10000)"], limit=100)
    with pytest.raises(F.BuildError, match="실패"):
        F.bounded_run([sys.executable, "-c", "raise SystemExit(7)"])


def test_prepare_fixed_dry_run_no_subprocess(tmp_path, monkeypatch, capsys):
    script = Path(__file__).resolve().parents[2] / "scripts/firmware/build.py"
    spec = importlib.util.spec_from_file_location("firmware_cli_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [str(script), "prepare", "--output", str(tmp_path / "new"), "--dry-run"])
    monkeypatch.setattr(module, "prepare", lambda _: pytest.fail("prepare가 실행됨"))
    assert module.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["components"] == F.COMPONENTS and plan["devices"] == []
    assert not (tmp_path / "new").exists()
    argv = module.container_argv("synthetic", tmp_path)
    assert "--network=none" in argv and "--pull=never" in argv and "--read-only" in argv
    assert not any(x.startswith("--device") or (x.startswith("type=bind") and "docker.sock" in x) for x in argv)


def test_empty_releases_never_reports_installed(tmp_path):
    catalog = tmp_path / "releases.json"
    catalog.write_text(json.dumps({"schema": "pweh.espprobe-releases/v1", "releases": []}))
    assert F.install_releases(catalog, tmp_path / "source", tmp_path / "tools") == 99
    assert not (tmp_path / "tools").exists()


def test_regular_input_symlink_and_size_limit(tmp_path):
    path = tmp_path / "synthetic"
    path.write_bytes(b"1234")
    with pytest.raises(F.BuildError):
        F.read_regular(path, limit=3)
    (tmp_path / "link").symlink_to(path)
    with pytest.raises((OSError, F.BuildError)):
        F.read_regular(tmp_path / "link")


def test_duplicate_symtab_and_local_shadow_cannot_hide_reference():
    with pytest.raises(F.BuildError, match="중복"):
        F.elf_symbols(elf([("esp_flash_write", 0, 0, 1, 0), ("esp_flash_write", 0, 1, 0, 3)]))
    raw = bytearray(elf())
    shoff = struct.unpack_from("<I", raw, 32)[0]
    struct.pack_into("<H", raw, 48, 5)
    raw += raw[shoff + 80:shoff + 120]
    with pytest.raises(F.BuildError, match="중복"):
        F.elf_symbols(bytes(raw))


def test_rom_alias_requires_exact_sdk_name_address_and_abs():
    name, address = "ieee80211_crypto_encap", 0x40005B20
    sdk = {name: address}
    result = F.check_symbols({"app.o": elf()}, elf([(name, address, 0, 1, 0xFFF1)]), rom_symbols=sdk)
    assert result["sdk_rom_aliases"] == [{"name": name, "address": address}]
    for value, section in ((address + 4, 0xFFF1), (address, 3), (address, 0)):
        with pytest.raises(F.BuildError):
            F.check_symbols({"app.o": elf()}, elf([(name, value, 0, 1, section)]), rom_symbols=sdk)
    with pytest.raises(F.BuildError):
        F.check_symbols({"app.o": elf([(name, 0, 0, 1, 0)])}, elf(), rom_symbols=sdk)


def test_objcopy_attached_weaken_and_linker_response(tmp_path):
    with pytest.raises(F.BuildError):
        F.check_flags(["xtensa-esp32s3-elf-objcopy", "-Wieee80211_raw_frame_sanity_check", "in.o", "out.o"])
    F.check_flags(["cc", "-Wall", "-Wextra"])
    (tmp_path / "ld.rsp").write_text("--allow-multiple-definition")
    with pytest.raises(F.BuildError):
        F.check_flags(F.expand_flags(["cc", "-Wl,@ld.rsp"], tmp_path))


def test_every_usb_descriptor_byte_is_fixed():
    device, config = F.expected_usb()
    assert F.check_usb(device, config)["cdc_count"] == 2
    for target in (0, 1):
        original = device if target == 0 else config
        for index in range(len(original)):
            changed = bytearray(original)
            changed[index] ^= 1
            with pytest.raises(F.BuildError):
                F.check_usb(bytes(changed) if target == 0 else device, bytes(changed) if target == 1 else config)


def test_archive_rejects_escape_links_duplicates_and_size(tmp_path):
    for kind in ("escape", "symlink", "duplicate"):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            info = tarfile.TarInfo("../escape" if kind == "escape" else "file")
            if kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, "/outside"
            archive.addfile(info)
            if kind == "duplicate":
                archive.addfile(info)
        with pytest.raises(F.BuildError):
            F.extract_tar(output.getvalue(), tmp_path / kind)


def test_bounded_runner_kills_child_after_leader_exits(tmp_path):
    child_pid = tmp_path / "child.pid"
    code = ("import subprocess,os; p=subprocess.Popen(['sleep','20']); "
            f"open({str(child_pid)!r},'w').write(str(p.pid)); os._exit(0)")
    with pytest.raises(F.BuildError, match="시간"):
        F.bounded_run([sys.executable, "-c", code], timeout=.15)
    pid = int(child_pid.read_text())
    # orphan의 짧은 zombie 상태는 실행이 끝난 상태다. 실제 살아 있는 sleep이면 실패한다.
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        assert stat_path.read_text().split()[2] in {"Z", "X"}
    except (FileNotFoundError, ProcessLookupError):
        pass


def cli_module():
    script = Path(__file__).resolve().parents[2] / "scripts/firmware/build.py"
    spec = importlib.util.spec_from_file_location("firmware_cli_boundary_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cleanup_continues_after_stop_failure(monkeypatch):
    cli = cli_module()
    seen = []
    def fake(argv, **kwargs):
        seen.append(argv)
        if "stop" in argv:
            raise F.BuildError("합성 stop timeout")
        return b""
    monkeypatch.setattr(cli, "bounded_run", fake)
    errors = cli.cleanup([[*F.DOCKER, "stop", "own"], [*F.DOCKER, "rm", "--force", "own"], [*F.DOCKER, "volume", "rm", "own"]])
    assert len(errors) == 1 and len(seen) == 3


def test_volume_cleanup_attempts_all_and_removes_success_record(tmp_path, monkeypatch):
    cli = cli_module()
    seen = []
    (tmp_path / "build.json").write_text('{"status":"built"}')
    def fake(argv, **kwargs):
        seen.append(argv[-1])
        if argv[-1] == "own-one":
            raise F.BuildError("합성 volume rm 실패")
        return b""
    monkeypatch.setattr(cli, "bounded_run", fake)
    with pytest.raises(F.BuildError, match="cleanup"):
        cli.cleanup_volumes(["own-one", "own-two"], tmp_path)
    assert seen == ["own-one", "own-two"]
    assert not (tmp_path / "build.json").exists()
    assert (tmp_path / "volume-cleanup-errors.json").exists()


def test_source_commit_ignores_git_replace_and_export_attributes(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
    git("init")
    git("config", "user.name", "PWEH Synthetic")
    git("config", "user.email", "synthetic@example.invalid")
    (repo / "firmware/common").mkdir(parents=True)
    code = repo / "firmware/common/code.c"
    code.write_text("PWEH SYNTHETIC ORIGINAL")
    git("add", ".")
    git("commit", "-m", "synthetic old")
    old = git("rev-parse", "HEAD")
    code.write_text("PWEH SYNTHETIC REPLACEMENT")
    git("add", ".")
    git("commit", "-m", "synthetic new")
    new = git("rev-parse", "HEAD")
    git("replace", old, new)
    (repo / ".git/info/attributes").write_text("firmware/common/code.c export-ignore\n")
    cli = cli_module()
    monkeypatch.setattr(cli, "REPO", repo)
    raw, identity, _ = cli.source_archive(old)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert archive.extractfile("firmware/common/code.c").read() == b"PWEH SYNTHETIC ORIGINAL"
    assert identity == old


@pytest.mark.parametrize("key", ["CONFIG_ESP_TASK_WDT_EN", "CONFIG_ESP_TASK_WDT_INIT", "CONFIG_ESP_TASK_WDT_PANIC",
                                  "CONFIG_ESP_TASK_WDT_TIMEOUT_S", "CONFIG_ESP_CONSOLE_NONE", "CONFIG_ESP_CONSOLE_SECONDARY_NONE"])
def test_required_watchdog_and_console_are_checked(key):
    defaults = Path(__file__).resolve().parents[2] / "firmware/espprobe/sdkconfig.defaults"
    values = F.parse_config(defaults.read_text())
    F.check_config(values)
    values.pop(key)
    with pytest.raises(F.BuildError):
        F.check_config(values)
