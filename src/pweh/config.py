"""pipeline-config.yaml 로더.

설정 파일 탐색 순서:
  1. load_config(path=...) 인자
  2. 환경변수 PWEH_CONFIG
  3. 현재 디렉터리에서 위로 올라가며 ``orchestrator/pipeline-config.yaml`` 탐색
  4. 내장 기본값 (root = 현재 디렉터리)

문자열 값의 ``${VAR}`` / ``${VAR:-기본값}`` 은 환경변수로 확장되고, 경로 값의 ``~`` 는 홈으로 확장된다.
프로필은 ``extends`` 로 다른 프로필을 상속할 수 있다 (깊은 병합).
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

CONFIG_RELPATH = Path("orchestrator") / "pipeline-config.yaml"

VALID_DESTRUCTIVE = {"deny", "approve"}
VALID_MODIFY = {"allow", "approve", "deny"}
VALID_UNKNOWN_RISK = {"interact", "modify", "destructive"}
VALID_APPROVAL_METHODS = {"elicitation", "cli"}

# 설정 파일이 없을 때도 동작하도록 최소 기본값을 내장한다.
DEFAULTS: dict[str, Any] = {
    "version": 1,
    "workspace": {
        "cases_dir": "cases",
        "state_dir": ".pweh/state",
    },
    "safety": {
        # 영구 변경/하드웨어 손상 가능 작업(플래시 쓰기·삭제, saveenv, 전압 설정 등)
        "destructive_policy": "deny",
        # 휘발성 상태 변경(setenv, boot, reset, halt 등)
        "modify_policy": "allow",
        # 분류 규칙에 없는 명령의 위험도
        "unknown_command_risk": "modify",
        # 사람 승인 방식: elicitation(클라이언트 UI 확인창) / cli(별도 터미널에서 `pweh approve <id>`)
        "approval_methods": ["elicitation", "cli"],
        "approval_ttl_seconds": 900,
        # 하드웨어 도구 사용 전 케이스에 소유/허가 증명이 있어야 함
        "require_authorization": True,
        # 리눅스 셸에서 쓰기가 '영구 변경'으로 간주되는 경로 접두어
        "persistent_paths": [
            "/mnt/mtd",
            "/mnt/flash",
            "/mnt/config",
            "/config",
            "/data",
            "/etc/config",
            "/home",
            "/opt",
            "/usr/local",
            "/var/lib",
        ],
    },
    "tools": {
        "sigrok_cli": "${PWEH_SIGROK_CLI:-sigrok-cli}",
        "openocd": "${PWEH_OPENOCD:-openocd}",
        "rea": "${PWEH_REA:-rea}",
        "mksquashfs": "${PWEH_MKSQUASHFS:-mksquashfs}",
        "unsquashfs": "${PWEH_UNSQUASHFS:-unsquashfs}",
        "mkimage": "${PWEH_MKIMAGE:-mkimage}",
        "mkenvimage": "${PWEH_MKENVIMAGE:-mkenvimage}",
        "zig": "${PWEH_ZIG:-zig}",
        "binwalk": "${PWEH_BINWALK:-binwalk}",
        "unblob": "${PWEH_UNBLOB:-unblob}",
        "openocd_scripts": "${PWEH_OPENOCD_SCRIPTS:-}",
    },
    "uart": {
        "default_baud_candidates": [115200, 57600, 38400, 19200, 9600, 230400, 460800, 921600, 1500000],
        "read_buffer_bytes": 4 * 1024 * 1024,
        "default_command_timeout": 10.0,
    },
    "profiles": {
        "generic-ipcam": {
            "description": "벤더 미상 IP 카메라/DVR 기본 프로필",
            "vendor": "unknown",
            "arch": "unknown",
            "uart": {},
        }
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: Any) -> Any:
    """문자열/리스트/딕셔너리 안의 ${VAR} / ${VAR:-default} 를 재귀적으로 확장."""
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            env = os.environ.get(name)
            if env is None or env == "":
                return default if default is not None else ""
            return env

        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


@dataclass
class SafetyConfig:
    destructive_policy: str = "deny"
    modify_policy: str = "allow"
    unknown_command_risk: str = "modify"
    approval_methods: list[str] = field(default_factory=lambda: ["cli"])
    approval_ttl_seconds: int = 900
    require_authorization: bool = True
    persistent_paths: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SafetyConfig":
        cfg = cls(
            destructive_policy=str(d.get("destructive_policy", "deny")).lower(),
            modify_policy=str(d.get("modify_policy", "allow")).lower(),
            unknown_command_risk=str(d.get("unknown_command_risk", "modify")).lower(),
            approval_methods=[str(m).lower() for m in d.get("approval_methods", ["cli"])],
            approval_ttl_seconds=int(d.get("approval_ttl_seconds", 900)),
            require_authorization=bool(d.get("require_authorization", True)),
            persistent_paths=[str(p) for p in d.get("persistent_paths", [])],
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.destructive_policy not in VALID_DESTRUCTIVE:
            raise ConfigError(
                f"safety.destructive_policy 값이 잘못되었습니다: {self.destructive_policy!r}",
                hint=f"허용 값: {sorted(VALID_DESTRUCTIVE)}",
            )
        if self.modify_policy not in VALID_MODIFY:
            raise ConfigError(
                f"safety.modify_policy 값이 잘못되었습니다: {self.modify_policy!r}",
                hint=f"허용 값: {sorted(VALID_MODIFY)}",
            )
        if self.unknown_command_risk not in VALID_UNKNOWN_RISK:
            raise ConfigError(
                f"safety.unknown_command_risk 값이 잘못되었습니다: {self.unknown_command_risk!r}",
                hint=f"허용 값: {sorted(VALID_UNKNOWN_RISK)}",
            )
        bad = [m for m in self.approval_methods if m not in VALID_APPROVAL_METHODS]
        if bad or not self.approval_methods:
            raise ConfigError(
                f"safety.approval_methods 값이 잘못되었습니다: {self.approval_methods!r}",
                hint=f"허용 값: {sorted(VALID_APPROVAL_METHODS)} 중 하나 이상",
            )
        if self.approval_ttl_seconds < 30:
            raise ConfigError("safety.approval_ttl_seconds 는 30초 이상이어야 합니다.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "destructive_policy": self.destructive_policy,
            "modify_policy": self.modify_policy,
            "unknown_command_risk": self.unknown_command_risk,
            "approval_methods": list(self.approval_methods),
            "approval_ttl_seconds": self.approval_ttl_seconds,
            "require_authorization": self.require_authorization,
            "persistent_paths": list(self.persistent_paths),
        }


@dataclass
class PwehConfig:
    path: Path | None
    root: Path
    cases_dir: Path
    state_dir: Path
    safety: SafetyConfig
    tools: dict[str, str]
    uart: dict[str, Any]
    profiles: dict[str, dict[str, Any]]
    raw: dict[str, Any]

    def profile(self, name: str | None) -> dict[str, Any]:
        """``extends`` 를 해석한 프로필을 반환. name 이 None 이면 generic-ipcam."""
        name = name or "generic-ipcam"
        if name not in self.profiles:
            raise ConfigError(
                f"알 수 없는 프로필: {name!r}",
                hint=f"사용 가능한 프로필: {', '.join(sorted(self.profiles))}",
            )
        seen: list[str] = []
        return self._resolve_profile(name, seen)

    def _resolve_profile(self, name: str, seen: list[str]) -> dict[str, Any]:
        if name in seen:
            raise ConfigError(f"프로필 상속(extends)에 순환이 있습니다: {' -> '.join(seen + [name])}")
        seen.append(name)
        prof = self.profiles.get(name)
        if prof is None:
            raise ConfigError(f"extends 대상 프로필이 없습니다: {name!r}")
        parent = prof.get("extends")
        if parent:
            base = self._resolve_profile(str(parent), seen)
            merged = _deep_merge(base, {k: v for k, v in prof.items() if k != "extends"})
        else:
            merged = copy.deepcopy(prof)
        merged["name"] = name
        return merged

    def list_profiles(self) -> list[dict[str, Any]]:
        out = []
        for name in sorted(self.profiles):
            prof = self.profiles[name]
            out.append(
                {
                    "name": name,
                    "description": prof.get("description", ""),
                    "extends": prof.get("extends"),
                    "vendor": prof.get("vendor"),
                }
            )
        return out

    def tool_path(self, name: str) -> str:
        value = self.tools.get(name)
        if not value:
            return name
        return os.path.expanduser(value)

    def baud_candidates(self, profile: str | None = None) -> list[int]:
        prof = self.profile(profile) if profile else {}
        cands = (prof.get("uart") or {}).get("baud_candidates")
        if cands:
            # 프로필 후보를 앞에, 나머지 기본 후보를 뒤에 (중복 제거)
            rest = [b for b in self.uart.get("default_baud_candidates", []) if b not in cands]
            return [int(b) for b in list(cands) + rest]
        return [int(b) for b in self.uart.get("default_baud_candidates", [])]


def find_config_file(start: Path | None = None) -> Path | None:
    env = os.environ.get("PWEH_CONFIG")
    if env:
        p = Path(os.path.expanduser(env))
        if not p.exists():
            raise ConfigError(f"PWEH_CONFIG 가 가리키는 파일이 없습니다: {p}")
        return p.resolve()
    cur = (start or Path.cwd()).resolve()
    for d in [cur, *cur.parents]:
        cand = d / CONFIG_RELPATH
        if cand.exists():
            return cand
    return None


def load_config(path: str | os.PathLike[str] | None = None) -> PwehConfig:
    cfg_path: Path | None
    if path is not None:
        cfg_path = Path(os.path.expanduser(str(path))).resolve()
        if not cfg_path.exists():
            raise ConfigError(f"설정 파일이 없습니다: {cfg_path}")
    else:
        cfg_path = find_config_file()

    data: dict[str, Any] = {}
    if cfg_path is not None:
        try:
            with cfg_path.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"설정 파일 YAML 파싱 실패: {cfg_path}: {exc}")
        if not isinstance(loaded, dict):
            raise ConfigError(f"설정 파일 최상위는 매핑이어야 합니다: {cfg_path}")
        data = loaded

    merged = _deep_merge(DEFAULTS, data)
    # 프로필은 사용자 정의가 있으면 기본 generic 위에 덮어쓰되, generic-ipcam 은 항상 존재
    merged = expand_env(merged)

    if cfg_path is not None:
        explicit_root = (merged.get("workspace") or {}).get("root")
        if explicit_root:
            root = (cfg_path.parent / os.path.expanduser(str(explicit_root))).resolve()
        elif cfg_path.parent.name == "orchestrator":
            root = cfg_path.parent.parent.resolve()
        else:
            root = cfg_path.parent.resolve()
    else:
        root = Path.cwd().resolve()

    ws = merged.get("workspace") or {}
    cases_dir = Path(os.path.expanduser(str(ws.get("cases_dir", "cases"))))
    state_dir = Path(os.path.expanduser(str(ws.get("state_dir", ".pweh/state"))))
    if not cases_dir.is_absolute():
        cases_dir = root / cases_dir
    if not state_dir.is_absolute():
        state_dir = root / state_dir
    # 환경변수로 케이스/상태 디렉터리를 덮어쓸 수 있다 (테스트·격리 실행용)
    if os.environ.get("PWEH_CASES_DIR"):
        cases_dir = Path(os.path.expanduser(os.environ["PWEH_CASES_DIR"]))
    if os.environ.get("PWEH_STATE_DIR"):
        state_dir = Path(os.path.expanduser(os.environ["PWEH_STATE_DIR"]))

    safety = SafetyConfig.from_dict(merged.get("safety") or {})
    profiles = merged.get("profiles") or {}
    if not isinstance(profiles, dict):
        raise ConfigError("profiles 는 매핑이어야 합니다.")

    return PwehConfig(
        path=cfg_path,
        root=root,
        cases_dir=cases_dir.resolve(),
        state_dir=state_dir.resolve(),
        safety=safety,
        tools={k: str(v) for k, v in (merged.get("tools") or {}).items()},
        uart=dict(merged.get("uart") or {}),
        profiles=profiles,
        raw=merged,
    )
