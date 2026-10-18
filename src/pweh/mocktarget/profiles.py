"""시뮬레이터 프로필 로더.

프로필은 ``src/pweh/mocktarget/profiles/*.yaml`` (패키지 데이터) 또는 임의 경로의 YAML 이며,
가상 카메라 한 대의 하드웨어/부트로더/커널/BusyBox 설정을 담는다.

- ``load_profile("hisilicon-like")`` / ``load_profile("/path/x.yaml")`` / ``load_profile(dict)``
- ``aliases`` 로 pipeline-config.yaml 의 프로필 이름(``mock-hisilicon`` 등)으로도 찾을 수 있다.
- ``overrides`` 는 깊은 병합된다 (테스트에서 ``{"uboot": {"crc32_style": "lower"}}`` 처럼 일부만 바꿀 때).
- U-Boot 동작 차이는 ``uboot.dialect`` 의 기본값(``DIALECTS``) 위에 프로필 값이 덮어쓰는 방식이다.
  각 기본값은 실제 소스(벤더 포크의 베이스 버전)에서 확인한 동작이다. 근거는 주석 참고.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..errors import ConfigError
from ..formats import parse_mtdparts
from ..fsutil import parse_size

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"

SYNTHETIC_MARKER = "PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE"

# ---------------------------------------------------------------------------
# U-Boot 방언 기본값
#
# hisilicon-2010 : HiSilicon V1~V3 SDK (U-Boot 2010.06 포크). common/main.c (simple 파서),
#                  lib/display_options.c (마지막 줄 패딩 없음), common/cmd_sf.c (HiSilicon: probe 는
#                  "%u KiB %s at %u:%u is now current device", read 성공 시 빈 줄만 출력),
#                  CONFIG_SYS_LONGHELP 미정의(CFG_LONGHELP 오타) → cmd_usage 는 한 줄만.
# ingenic-2013   : Ingenic T 시리즈 SDK (U-Boot 2013.07). common/main.c builtin_run_command (simple),
#                  해시테이블 env(정렬 출력, hexport_r 크기 계산), common/cmd_sf.c 에 PRINT_TIME
#                  ("---> %s spend %d ms"), "SF: %zu bytes @ %#x Read: OK".
# hisilicon-2016 : HiSilicon V4 SDK (U-Boot 2016.11 포크). CONFIG_HUSH_PARSER=y, LONGHELP,
#                  "SF: Detected %s with page size ..., erase size ..., total ...",
#                  sf read 는 "\n" 다음 "SF: %zu bytes @ %#x Read: OK".
# 세 방언 모두 SHA256/CMD_HASH 가 꺼져 있어 crc32 는 대문자 "CRC32 for ..." 를 출력한다
# (common/hash.c 의 multi_hash()==0 경로). 소문자는 crc32_style: lower 로 바꿀 수 있다.
# ---------------------------------------------------------------------------
DIALECTS: dict[str, dict[str, Any]] = {
    "hisilicon-2010": {
        "parser": "simple",
        "longhelp": False,
        "md_pad_last_line": False,
        "printenv_order": "insertion",
        "env_size_calc": "legacy",
        "sf_style": "hisilicon-2010",
        "sf_probe_requires_cs": True,
        "sf_update": False,
        "bdinfo_style": "arm-2010",
        "version_extra": False,
        "crc32_style": "upper",
        "repeat_empty_line": True,
        "setenv_force_flag": False,
        "env_command": False,
        "cmd_failure_rc": -1,
    },
    "ingenic-2013": {
        "parser": "simple",
        "longhelp": True,
        "md_pad_last_line": True,
        "printenv_order": "sorted",
        "env_size_calc": "hashtable-2013",
        "sf_style": "ingenic-2013",
        "sf_probe_requires_cs": False,
        "sf_update": True,
        "bdinfo_style": "mips-2013",
        "version_extra": True,
        "crc32_style": "upper",
        "repeat_empty_line": True,
        "setenv_force_flag": True,
        "env_command": True,
        "cmd_failure_rc": 1,
    },
    "hisilicon-2016": {
        "parser": "hush",
        "longhelp": True,
        "md_pad_last_line": True,
        "printenv_order": "sorted",
        "env_size_calc": "hashtable-2013",
        "sf_style": "generic-2016",
        "sf_probe_requires_cs": False,
        "sf_update": True,
        "bdinfo_style": "arm-2016",
        "version_extra": True,
        "crc32_style": "upper",
        "repeat_empty_line": True,
        "setenv_force_flag": True,
        "env_command": True,
        "cmd_failure_rc": 1,
    },
}

# 모든 프로필에 적용되는 기본값 (YAML 에서 생략 가능)
BASE_DEFAULTS: dict[str, Any] = {
    "arch": "arm",
    "endianness": "little",
    "baud": 115200,
    "marker": SYNTHETIC_MARKER,
    "aliases": [],
    "flash": {
        "type": "spi-nor",
        "size": "16MiB",
        "page_size": 256,
        "erase_size": "64KiB",
        "model": "W25Q128",
        "jedec_id": [0xEF, 0x40, 0x18],
    },
    "dram": {"base": 0x80000000, "size": "64MiB"},
    "uart": {"rx_fifo": 64, "linux_rx_buffer": 4096},
    "uboot": {
        "dialect": "ingenic-2013",
        "prompt": "=> ",
        "hush_ps2": "> ",
        "maxargs": 32,
        "cbsize": 1024,
        "help_width": 8,
        "autoboot": {"delay": 1, "keys": None, "zero_check": True, "mode": "any-key", "stop_str": None,
                     "prompt": "Hit any key to stop autoboot: %2d "},
        "env_offset": None,
        "env_size": None,
        "env_redundant": False,
        "default_env": {},
        "env": {},
        "runtime_env": {"stdin": "serial", "stdout": "serial", "stderr": "serial"},
        "commands": [],
        "banner": "",
        "net": {"link_down": [], "eth_name": "eth0"},
        "timings": {},
        "bdinfo": {},
        "cc_version": "",
        "ld_version": "",
    },
    "kernel": {
        "version": "3.10.14",
        "image_name": "Linux-3.10.14",
        "load_addr": 0x80008000,
        "entry": 0x80008000,
        "compression": "none",
        "zimage_banner": False,
        "boot_log": "",
        "cpuinfo": "",
        "meminfo": {},
        "rootdev_major": 31,
    },
    "linux": {
        "hostname": "(none)",
        "busybox_banner": "BusyBox v1.24.1 (2020-01-01 00:00:00 CST)",
        "applets": [],
        "login": {"username": "root", "password": "", "motd": ""},
        "shell_prompt": "# ",
        "askfirst": True,
        "issue": "",
        "rcs_output": "",
        "processes": [],
        "mounts": [],
        "interfaces": {},
        "listening": [],
        "dd_third_status_line": True,
    },
    "firmware": {},
}


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in (override or {}).items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _as_int(value: Any, what: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"프로필 값 {what} 가 정수가 아닙니다: {value!r}")
    if isinstance(value, int):
        return value
    try:
        return parse_size(str(value))
    except Exception:
        raise ConfigError(f"프로필 값 {what} 를 정수/크기로 해석할 수 없습니다: {value!r}") from None


def _yaml_word(value: Any) -> str:
    """YAML 1.1 이 true/false 를 bool 로 바꾸는 문제 보정 (명령/애플릿 이름은 항상 문자열)."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _profile_files() -> list[Path]:
    if not PROFILE_DIR.is_dir():
        return []
    return sorted(p for p in PROFILE_DIR.glob("*.yaml") if p.is_file())


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"프로필 YAML 을 읽을 수 없습니다: {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"프로필 최상위는 매핑이어야 합니다: {path}")
    return data


def list_profiles() -> list[dict[str, Any]]:
    """내장 프로필 목록: [{name, description, arch, uboot, kernel, aliases, path}]."""
    out = []
    for path in _profile_files():
        data = _read_yaml(path)
        out.append(
            {
                "name": data.get("name", path.stem),
                "description": data.get("description", ""),
                "arch": data.get("arch"),
                "uboot": (data.get("uboot") or {}).get("version"),
                "dialect": (data.get("uboot") or {}).get("dialect"),
                "kernel": (data.get("kernel") or {}).get("version"),
                "aliases": list(data.get("aliases") or []),
                "path": str(path),
            }
        )
    return out


def _find_profile_file(name: str) -> Path | None:
    cand = PROFILE_DIR / f"{name}.yaml"
    if cand.is_file():
        return cand
    for path in _profile_files():
        data = _read_yaml(path)
        if name == data.get("name") or name in (data.get("aliases") or []):
            return path
    return None


def load_profile(profile: str | os.PathLike[str] | Mapping[str, Any] = "hisilicon-like",
                 overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """이름/경로/딕셔너리로 프로필을 읽어 정규화한 사본을 반환한다."""
    if isinstance(profile, Mapping):
        if profile.get("_normalized"):
            data = copy.deepcopy(dict(profile))
            data.pop("_normalized", None)
            data.pop("partitions", None)
        else:
            data = copy.deepcopy(dict(profile))
        source = "<dict>"
    else:
        text = os.fspath(profile)
        path = Path(os.path.expanduser(text))
        if path.suffix in (".yaml", ".yml") or os.sep in text or path.is_file():
            if not path.is_file():
                raise ConfigError(f"프로필 파일이 없습니다: {path}")
            data = _read_yaml(path)
            data.setdefault("name", path.stem)
            source = str(path)
        else:
            found = _find_profile_file(text)
            if found is None:
                names = ", ".join(p["name"] for p in list_profiles())
                raise ConfigError(f"알 수 없는 시뮬레이터 프로필: {text!r}", hint=f"사용 가능: {names}")
            data = _read_yaml(found)
            data.setdefault("name", found.stem)
            source = str(found)
    if overrides:
        data = _deep_merge(data, overrides)
    return _normalize(data, source)


def _normalize(data: dict[str, Any], source: str) -> dict[str, Any]:
    prof = _deep_merge(BASE_DEFAULTS, data)
    ub = prof["uboot"]
    dialect = ub.get("dialect") or "ingenic-2013"
    if dialect not in DIALECTS:
        raise ConfigError(f"알 수 없는 U-Boot 방언: {dialect!r} ({source})", hint=f"허용: {sorted(DIALECTS)}")
    # 방언 기본값 → 프로필에 명시한 값이 우선
    for key, value in DIALECTS[dialect].items():
        if key not in (data.get("uboot") or {}):
            ub[key] = copy.deepcopy(value)
    prof["name"] = str(prof.get("name") or "custom")
    prof["source"] = source
    prof["arch"] = str(prof["arch"]).lower()
    if prof["arch"] not in ("arm", "mips"):
        raise ConfigError(f"지원하지 않는 아키텍처: {prof['arch']!r} (arm|mips)")
    prof["baud"] = _as_int(prof["baud"], "baud")

    fl = prof["flash"]
    fl["size"] = _as_int(fl["size"], "flash.size")
    fl["erase_size"] = _as_int(fl["erase_size"], "flash.erase_size")
    fl["page_size"] = _as_int(fl["page_size"], "flash.page_size")
    if fl["size"] <= 0 or fl["size"] % fl["erase_size"]:
        raise ConfigError("flash.size 는 erase_size 의 배수여야 합니다.")
    if fl.get("memory_window") is not None:
        fl["memory_window"] = _as_int(fl["memory_window"], "flash.memory_window")
    mtdparts = fl.get("mtdparts")
    if not mtdparts:
        raise ConfigError(f"flash.mtdparts 가 필요합니다 ({source})")
    parts = parse_mtdparts(str(mtdparts), total_size=fl["size"])
    for p in parts:
        if p["size"] is None or p["offset"] + p["size"] > fl["size"]:
            raise ConfigError(f"mtdparts 파티션이 플래시 크기를 벗어납니다: {p}")
    fl["mtd_id"] = str(mtdparts).split(":", 1)[0].replace("mtdparts=", "")
    prof["partitions"] = parts

    dr = prof["dram"]
    dr["base"] = _as_int(dr["base"], "dram.base")
    dr["size"] = _as_int(dr["size"], "dram.size")

    for key in ("env_offset", "env_size"):
        if ub.get(key) is not None:
            ub[key] = _as_int(ub[key], f"uboot.{key}")
    env_part = next((p for p in parts if p["name"] == "env"), None)
    if ub.get("env_offset") is None:
        if env_part is None:
            raise ConfigError("env 파티션이 없으면 uboot.env_offset 을 지정해야 합니다.")
        ub["env_offset"] = env_part["offset"]
    if ub.get("env_size") is None:
        ub["env_size"] = env_part["size"] if env_part else 0x10000
    for key in ("loadaddr",):
        if ub.get(key) is not None:
            ub[key] = _as_int(ub[key], f"uboot.{key}")
    bd = ub.get("bdinfo") or {}
    for key, value in list(bd.items()):
        if isinstance(value, str) and value.lower().startswith("0x"):
            bd[key] = int(value, 16)
    ub["maxargs"] = _as_int(ub.get("maxargs", 32), "uboot.maxargs")
    ub["cbsize"] = _as_int(ub.get("cbsize", 1024), "uboot.cbsize")
    ab = ub["autoboot"]
    ab["delay"] = int(ab.get("delay", 1))
    if ab.get("keys") is not None:
        ab["keys"] = [str(k) for k in ab["keys"]]
    ub["env"] = {str(k): str(v) for k, v in (ub.get("env") or {}).items()}
    ub["default_env"] = {str(k): str(v) for k, v in (ub.get("default_env") or {}).items()} or dict(ub["env"])
    ub["runtime_env"] = {str(k): str(v) for k, v in (ub.get("runtime_env") or {}).items()}
    if ub["crc32_style"] not in ("upper", "lower"):
        raise ConfigError("uboot.crc32_style 은 upper|lower 입니다.")
    if ub["parser"] not in ("simple", "hush"):
        raise ConfigError("uboot.parser 는 simple|hush 입니다.")

    kn = prof["kernel"]
    kn["load_addr"] = _as_int(kn["load_addr"], "kernel.load_addr")
    kn["entry"] = _as_int(kn["entry"], "kernel.entry")
    if kn["compression"] not in ("none", "gzip", "lzma"):
        raise ConfigError("kernel.compression 은 none|gzip|lzma 입니다.")

    lx = prof["linux"]
    lx["applets"] = [_yaml_word(a) for a in (lx.get("applets") or [])]
    ub["commands"] = [_yaml_word(c) for c in (ub.get("commands") or [])]
    lg = lx.get("login") or {}
    lg.setdefault("username", "root")
    lg.setdefault("password", "")
    lx["login"] = lg
    prof["_normalized"] = True
    return prof


def partition(profile: Mapping[str, Any], name: str) -> dict[str, Any] | None:
    for p in profile.get("partitions") or []:
        if p["name"] == name:
            return p
    return None


__all__ = ["DIALECTS", "PROFILE_DIR", "SYNTHETIC_MARKER", "list_profiles", "load_profile", "partition"]
