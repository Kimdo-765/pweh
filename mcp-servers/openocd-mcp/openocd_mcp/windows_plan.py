"""Windows OpenOCD의 입력 관찰과 실행 계획. 승인·번들 신뢰·실행을 수행하지 않는다.

local 파일과 Windows 경로를 구분하며 converter는 필수 주입한다. 파일 관찰은
그 시점의 동일성만 확인한다. 실제 실행자는 승인 뒤 파일·번들·route를 다시 확인해야 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Literal

from pweh.errors import ValidationFailed
from pweh.wininterop import OwnedWindowsLaunch, validate_windows_path

from . import process

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CFG_BYTES = 1024 * 1024
MAX_CFGS = 64
MAX_SEARCH_DIRS = 8
MAX_PLAN_BYTES = 256 * 1024
MAX_ARGV_BYTES = 32768
MAX_SECONDS = 30.0
MAX_ENV_ITEMS = 256
MAX_COMMANDS = 64
MAX_PATH_BYTES = 8192
OWNER_CONTENT = b"# PWEH OpenOCD process ownership marker.\n"
OWNER_SHA256 = hashlib.sha256(OWNER_CONTENT).hexdigest()
WSLENV = "OPENOCD_SCRIPTS/w:HOME/w:XDG_CONFIG_HOME/w:APPDATA/w:USERPROFILE/w"
_CONTROLS = frozenset({"home", "userprofile", "xdg_config_home", "appdata", "openocd_scripts", "wslenv"})
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_OWNER = re.compile(r"owner-[0-9a-f]{32}\.cfg\Z")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class WindowsPlanError(ValidationFailed):
    """입력 원문·경로를 담지 않는 계획 실패."""

    code = "openocd_plan_invalid"


def _fail(reason: str = "invalid") -> WindowsPlanError:
    messages = {
        "invalid": "Windows OpenOCD 계획 입력이 올바르지 않습니다.",
        "limit": "Windows OpenOCD 계획의 크기·개수 상한을 넘었습니다.",
        "timeout": "Windows OpenOCD 계획 시간 상한을 넘었습니다.",
        "input": "Windows OpenOCD 계획 입력 파일·디렉터리를 확인하지 못했습니다.",
        "changed": "Windows OpenOCD 계획 입력이 관찰 이후 바뀌었습니다.",
        "converter": "Windows OpenOCD 경로 변환 결과를 확인하지 못했습니다.",
    }
    return WindowsPlanError(messages[reason], code="openocd_plan_" + reason)


@dataclass(frozen=True)
class FileSnapshot:
    """한 번 관찰한 일반 파일의 지문. 배포 출처나 승인 증명이 아니다."""

    path: Path
    size: int
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class CfgInput:
    """CfgRef의 frozen 복사. kind는 기존 해석 표식만 보존한다."""

    kind: Literal["standard", "custom"]
    file: FileSnapshot


@dataclass(frozen=True)
class PipeStartInputs:
    """순서와 bytes 지문을 고정한 요청. cfg 위험 분류는 호출자의 책임이다."""

    executable: FileSnapshot
    search_dirs: tuple[Path, ...]
    interface: CfgInput
    targets: tuple[CfgInput, ...]
    extras: tuple[CfgInput, ...]
    transport: str | None
    adapter_speed_khz: int | None
    extra_commands: tuple[str, ...]


@dataclass(frozen=True)
class RunLayout:
    """호출자가 만든 전용 root와 비어 있는 네 하위 디렉터리."""

    root: Path
    cwd: Path
    home: Path
    config_home: Path
    appdata: Path
    owner_cfg: FileSnapshot


@dataclass(frozen=True)
class OpenOcdWindowsPlan:
    """파일 관찰 후 만든 argv·환경·프로세스 식별 계획. 실행 권한을 뜻하지 않는다."""

    inputs: PipeStartInputs
    layout: RunLayout
    argv: tuple[str, ...]
    env_items: tuple[tuple[str, str], ...]
    launch: OwnedWindowsLaunch

    @property
    def executable(self) -> str:
        """WSL Popen에 넘길 local 실행파일 경로."""
        return str(self.inputs.executable.path)

    @property
    def cwd(self) -> Path:
        """WSL Popen에 넘길 local 작업 디렉터리."""
        return self.layout.cwd


def _tick(deadline: float) -> None:
    if (type(deadline) not in (int, float)
            or (type(deadline) is int and abs(deadline) > 2**53) or not math.isfinite(deadline)):
        raise _fail()
    now = time.monotonic()
    if deadline - now > MAX_SECONDS:
        raise _fail()
    if now >= deadline:
        raise _fail("timeout")


def _text(value: str, limit: int) -> int:
    if type(value) is not str:
        raise _fail()
    if len(value) > limit:
        raise _fail("limit")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError:
        raise _fail() from None
    if size > limit:
        raise _fail("limit")
    return size


def _path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise _fail()
    raw = str(path)
    _text(raw, MAX_PATH_BYTES)
    if len(path.parts) > 128 or any(c in raw for c in "\x00\r\n\x1a"):
        raise _fail()
    return path


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open_dir(path: Path, deadline: float) -> int:
    """중간 링크를 따라가지 않고 경로를 bounded fd 순회한다."""
    _path(path)
    _tick(deadline)
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            _tick(deadline)
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _fail("input")
            new = os.open(part, _DIR_FLAGS, dir_fd=fd)
            try:
                if _identity(before) != _identity(os.fstat(new)):
                    raise _fail("changed")
            except BaseException:
                os.close(new)
                raise
            os.close(fd)
            fd = new
        _tick(deadline)
        return fd
    except BaseException:
        os.close(fd)
        raise


def observe_file(path: Path, *, max_bytes: int, deadline: float) -> FileSnapshot:
    """일반 파일을 상한 안에서 읽고 fd·이름·부모 신원을 전후 대조한다."""
    _path(path)
    _tick(deadline)
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_FILE_BYTES:
        raise _fail()
    pfd = fd = fresh = None
    try:
        pfd = _open_dir(path.parent, deadline)
        parent = os.fstat(pfd)
        initial = os.stat(path.name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISREG(initial.st_mode):
            raise _fail("input")
        if initial.st_size > max_bytes:
            raise _fail("limit")
        fd = os.open(path.name, _READ_FLAGS, dir_fd=pfd)
        if _identity(initial) != _identity(os.fstat(fd)):
            raise _fail("changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            _tick(deadline)
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _fail("limit")
            digest.update(chunk)
        fresh = _open_dir(path.parent, deadline)
        current_parent = os.fstat(fresh)
        if (parent.st_dev, parent.st_ino) != (current_parent.st_dev, current_parent.st_ino):
            raise _fail("changed")
        if (total != initial.st_size or _identity(initial) != _identity(os.fstat(fd))
                or _identity(initial) != _identity(os.stat(path.name, dir_fd=fresh, follow_symlinks=False))):
            raise _fail("changed")
        _tick(deadline)
        return FileSnapshot(path, total, digest.hexdigest(), _identity(initial))
    except OSError:
        raise _fail("input") from None
    finally:
        for opened in (fresh, fd, pfd):
            if opened is not None:
                os.close(opened)


def _snapshot(value: FileSnapshot, max_bytes: int) -> None:
    if type(value) is not FileSnapshot:
        raise _fail()
    _path(value.path)
    if (type(value.size) is not int or not 0 <= value.size <= max_bytes
            or type(value.sha256) is not str or len(value.sha256) != 64 or _SHA.fullmatch(value.sha256) is None
            or type(value.identity) is not tuple or len(value.identity) != 6
            or any(type(x) is not int for x in value.identity)
            or value.identity[3] != value.size or not stat.S_ISREG(value.identity[2])):
        raise _fail()


def freeze_cfg(ref: process.CfgRef, observed: FileSnapshot, *, classified_sha256: str | None = None) -> CfgInput:
    """해석한 cfg를 복사한다. custom은 실제 분류한 전체 bytes 지문과 같아야 한다."""
    _snapshot(observed, MAX_CFG_BYTES)
    if (type(ref) is not process.CfgRef or ref.kind not in ("standard", "custom")
            or ref.path != observed.path or ref.arg != str(observed.path)):
        raise _fail()
    if ref.kind == "custom" and classified_sha256 != observed.sha256:
        raise _fail("changed")
    if classified_sha256 is not None and classified_sha256 != observed.sha256:
        raise _fail("changed")
    return CfgInput(ref.kind, observed)


def _inputs(value: PipeStartInputs) -> tuple[CfgInput, ...]:
    if type(value) is not PipeStartInputs:
        raise _fail()
    _snapshot(value.executable, MAX_FILE_BYTES)
    if value.executable.path.name != "openocd.exe":
        raise _fail()
    if (type(value.search_dirs) is not tuple or not 1 <= len(value.search_dirs) <= MAX_SEARCH_DIRS
            or type(value.targets) is not tuple or type(value.extras) is not tuple
            or len(value.targets) + len(value.extras) + 1 > MAX_CFGS
            or type(value.extra_commands) is not tuple or len(value.extra_commands) > MAX_COMMANDS):
        raise _fail("limit")
    for directory in value.search_dirs:
        _path(directory)
    if len(set(value.search_dirs)) != len(value.search_dirs):
        raise _fail()
    cfgs = (value.interface, *value.targets, *value.extras)
    for cfg in cfgs:
        if type(cfg) is not CfgInput or cfg.kind not in ("standard", "custom"):
            raise _fail()
        _snapshot(cfg.file, MAX_CFG_BYTES)
    if sum(c.file.size for c in cfgs) > MAX_FILE_BYTES:
        raise _fail("limit")
    if value.transport is not None and (type(value.transport) is not str or value.transport not in process.TRANSPORTS):
        raise _fail()
    speed = value.adapter_speed_khz
    if speed is not None and (type(speed) is not int or not 0 <= speed <= 1_000_000):
        raise _fail()
    for command in value.extra_commands:
        _text(command, 8192)
        if not command.strip() or any(c in command for c in "\x00\x1a"):
            raise _fail()
    return cfgs


def _directory(path: Path, deadline: float, *, expected: set[str] | None = None) -> tuple[int, ...]:
    fd = _open_dir(path, deadline)
    try:
        before = _identity(os.fstat(fd))
        if expected is not None:
            names = set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    _tick(deadline)
                    if entry.name not in expected or entry.name in names:
                        raise _fail("input")
                    names.add(entry.name)
            if names != expected:
                raise _fail("input")
        if before != _identity(os.fstat(fd)):
            raise _fail("changed")
        _tick(deadline)
        return before
    finally:
        os.close(fd)


def _layout(value: RunLayout, deadline: float) -> tuple[tuple[Path, tuple[int, ...]], ...]:
    if type(value) is not RunLayout:
        raise _fail()
    _path(value.root)
    _snapshot(value.owner_cfg, len(OWNER_CONTENT))
    dirs = (("cwd", value.cwd), ("home", value.home), ("config", value.config_home), ("appdata", value.appdata))
    for name, path in dirs:
        if _path(path) != value.root / name:
            raise _fail()
    owner = value.owner_cfg
    if (owner.path.parent != value.root or _OWNER.fullmatch(owner.path.name) is None
            or owner.sha256 != OWNER_SHA256 or owner.size != len(OWNER_CONTENT)):
        raise _fail()
    result = [(value.root, _directory(value.root, deadline, expected={*(n for n, _ in dirs), owner.path.name}))]
    result.extend((path, _directory(path, deadline, expected=set())) for _, path in dirs)
    return tuple(result)


def _ambient(values: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if type(values) is not tuple or len(values) > MAX_ENV_ITEMS:
        raise _fail("limit")
    result: dict[str, str] = {}
    seen: set[str] = set()
    size = 0
    for pair in values:
        if type(pair) is not tuple or len(pair) != 2:
            raise _fail()
        key, value = pair
        size += _text(key, 256) + _text(value, MAX_PATH_BYTES) + 2
        if size > MAX_PLAN_BYTES:
            raise _fail("limit")
        if _ENV_NAME.fullmatch(key) is None or "\x00" in value:
            raise _fail()
        folded = key.lower()
        if folded in _CONTROLS:
            continue
        if folded in seen:
            raise _fail()
        seen.add(folded)
        result[key] = value
    return result


def build_plan(inputs: PipeStartInputs, layout: RunLayout, *, ambient_env: tuple[tuple[str, str], ...],
               path_converter: Callable[[Path, float], str | bytes], deadline: float) -> OpenOcdWindowsPlan:
    """합성 가능한 주입 converter로 계획한다. 승인·PE/tree pin·프로세스 실행은 하지 않는다.

    converter 자체를 강제로 중단하지는 못하므로 호출 전후 deadline을 검사한다.
    반환 직후 경로 교체를 봉쇄하는 잠금도 아니며 실행자는 같은 입력을 다시 검증해야 한다.
    """
    return _build_plan(inputs, layout, ambient_env=ambient_env, path_converter=path_converter,
                       deadline=deadline, dummy=False)


def build_dummy_plan(inputs: PipeStartInputs, layout: RunLayout, *, ambient_env: tuple[tuple[str, str], ...],
                     path_converter: Callable[[Path, float], str | bytes], deadline: float) -> OpenOcdWindowsPlan:
    """고정 dummy cfg와 상수 명령만 허용하는 noinit 계획. 공개 guard 해제 옵션이 아니다."""
    return _build_plan(inputs, layout, ambient_env=ambient_env, path_converter=path_converter,
                       deadline=deadline, dummy=True)


def _dummy_inputs(inputs: PipeStartInputs) -> None:
    """기존 타입 검사 뒤 고정 profile의 입력을 대조한다. bundle 결속은 실행자의 책임이다."""
    from .dummy_profile import DUMMY_PROFILE as profile

    cfg = inputs.interface
    if (len(inputs.search_dirs) != 1 or cfg.kind != "standard"
            or cfg.file.path != inputs.search_dirs[0] / profile.interface_ref
            or cfg.file.sha256 != profile.interface_sha256 or cfg.file.size != profile.interface_size
            or inputs.targets or inputs.extras or inputs.extra_commands
            or inputs.transport != profile.transport or inputs.adapter_speed_khz != profile.adapter_speed_khz):
        raise _fail()


def _build_plan(inputs: PipeStartInputs, layout: RunLayout, *, ambient_env: tuple[tuple[str, str], ...],
                path_converter: Callable[[Path, float], str | bytes], deadline: float,
                dummy: bool) -> OpenOcdWindowsPlan:
    """두 고정 builder의 관찰·변환을 공유한다. 외부 argv factory/skip_init 입력은 없다."""
    _tick(deadline)
    cfgs = _inputs(inputs)
    if dummy:
        _dummy_inputs(inputs)
    env = _ambient(ambient_env)
    if not callable(path_converter):
        raise _fail()
    cache: dict[Path, str] = {}
    projections: dict[str, Path] = {}

    def convert(path: Path) -> str:
        if path not in cache:
            _tick(deadline)
            try:
                raw = path_converter(path, deadline)
            except Exception:
                raise _fail("converter") from None
            _tick(deadline)
            if type(raw) is bytes:
                if len(raw) > MAX_PATH_BYTES:
                    raise _fail("limit")
                try:
                    raw = raw.decode("utf-8", "strict")
                except UnicodeError:
                    raise _fail("converter") from None
            _text(raw, MAX_PATH_BYTES)
            if raw.endswith("\r\n"):
                raw = raw[:-2]
            elif raw.endswith("\n"):
                raw = raw[:-1]
            try:
                projected = validate_windows_path(raw)
            except Exception:
                raise _fail("converter") from None
            key = projected.replace("\\", "/")
            if len(key) >= 2 and key[1] == ":":
                key = key[0].upper() + key[1:]
            if key in projections and projections[key] != path:
                raise _fail("converter")
            projections[key] = path
            cache[path] = projected
        return cache[path]

    try:
        directories = _layout(layout, deadline)
        directories += tuple((d, _directory(d, deadline)) for d in inputs.search_dirs)
        all_files = (inputs.executable, *(c.file for c in cfgs), layout.owner_cfg)
        if any(c.file.path == layout.owner_cfg.path for c in cfgs):
            raise _fail()
        for observed in all_files:
            if observe_file(observed.path, max_bytes=observed.size, deadline=deadline) != observed:
                raise _fail("changed")
        windows_image = convert(inputs.executable.path)
        searches = [convert(d) for d in inputs.search_dirs]

        def cfg_ref(cfg: CfgInput) -> process.CfgRef:
            return process.CfgRef(convert(cfg.file.path), cfg.kind, cfg.file.path)

        marker = convert(layout.owner_cfg.path)
        owner = process.CfgRef(marker, "custom", layout.owner_cfg.path)
        if dummy:
            argv = process.build_dummy_pipe_argv(str(inputs.executable.path), scripts_dir=searches[0],
                                                 interface=cfg_ref(inputs.interface), owner=owner)
            # 고정 -s 한 개와 dummy/owner -f만이다. -c 안의 문장을 옵션으로 다시 해석하지 않는다.
            path_indices = (2, 10, 20)
        else:
            argv = process.build_pipe_argv(
                str(inputs.executable.path), scripts_dir=searches[0], search_dirs=searches,  # type: ignore[arg-type]
                interface=cfg_ref(inputs.interface), targets=[cfg_ref(c) for c in inputs.targets],
                extra_cfgs=[*(cfg_ref(c) for c in inputs.extras), owner],
                transport=inputs.transport, adapter_speed_khz=inputs.adapter_speed_khz,
                extra_commands=list(inputs.extra_commands), debug_level=3, semihosting_guard=True,
            )
            # 생성 위치를 고정한다. Tcl 문자열의 '-f' 같은 내용을 다시 파싱하지 않는다.
            path_indices = tuple([2 + i * 2 for i in range(len(searches))]
                                 + [len(searches) * 2 + 8]
                                 + [len(searches) * 2 + 12 + (2 if inputs.transport else 0) + i * 4
                                    for i in range(len(inputs.targets) + len(inputs.extras) + 1)])
        env.update({"OPENOCD_SCRIPTS": searches[0], "HOME": convert(layout.home),
                    "XDG_CONFIG_HOME": convert(layout.config_home), "APPDATA": convert(layout.appdata),
                    "USERPROFILE": convert(layout.home), "WSLENV": WSLENV})
        if (sum(_text(a, MAX_ARGV_BYTES) + 1 for a in argv) > MAX_ARGV_BYTES
                or sum(_text(k, 256) + _text(v, MAX_PATH_BYTES) + 2 for k, v in env.items()) > MAX_PLAN_BYTES):
            raise _fail("limit")
        # converter가 파일을 바꾸거나 오래 실행됐어도 성공 계획으로 반환하지 않는다.
        for observed in all_files:
            if observe_file(observed.path, max_bytes=observed.size, deadline=deadline) != observed:
                raise _fail("changed")
        if _layout(layout, deadline) != directories[:5]:
            raise _fail("changed")
        for path, identity in directories[5:]:
            if _directory(path, deadline) != identity:
                raise _fail("changed")
        _tick(deadline)
        return OpenOcdWindowsPlan(inputs, layout, tuple(argv), tuple(env.items()),
                                 OwnedWindowsLaunch(windows_image, tuple(argv[1:]), marker, path_indices))
    except OSError:
        raise _fail("input") from None
