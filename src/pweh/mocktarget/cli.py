"""``pweh-mock-device``: 시뮬레이터 실행 / 합성 펌웨어 빌드 CLI.

사용 예::

    pweh-mock-device --profile hisilicon-like --pty            # {"ok": true, "pty": "/dev/pts/5", ...}
    pweh-mock-device --profile ingenic-like --tcp --port 4321   # {"ok": true, "url": "socket://127.0.0.1:4321", ...}
    pweh-mock-device --profile hisilicon-like --build-firmware fw.bin   # 이미지 + fw.bin.manifest.json 만 만들고 종료

시작 후 stdout 에 **JSON 한 줄**(접속 정보)을 출력하고, stdin 에서 제어 명령을 한 줄씩 읽어 JSON 한 줄로 답한다:
``power-cycle`` ``power-off`` ``power-on`` ``status`` ``events [N]`` ``destructive`` ``console [N]`` ``wait STATE [SEC]``
``quit``. stdin 이 닫히면(EOF) 종료한다. 로그는 stderr 로만 나간다.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path
from typing import Any

import yaml

from ..errors import PwehError
from .device import STATES, MockDevice
from .firmware import build_image
from .profiles import list_profiles

log = logging.getLogger("pweh.mocktarget")


def _parse_set(items: list[str]) -> dict[str, Any]:
    """``--set uboot.crc32_style=lower`` → 중첩 딕셔너리 (값은 YAML 로 해석)."""
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--set 형식 오류: {item!r} (key.sub=value)")
        key, raw = item.split("=", 1)
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError:
            value = raw
        cur = out
        parts = key.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value
    return out


def _emit(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pweh-mock-device",
        description="PWEH 카메라 UART 콘솔 시뮬레이터 (U-Boot + BusyBox 흉내, PTY/TCP) 및 합성 펌웨어 빌더",
    )
    ap.add_argument("--profile", default="hisilicon-like", help="프로필 이름 또는 YAML 경로 (기본 hisilicon-like)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--pty", action="store_true", help="원시 모드 PTY 를 연다 (기본)")
    mode.add_argument("--tcp", action="store_true", help="TCP 서버를 연다 (pyserial socket://host:port)")
    ap.add_argument("--host", default="127.0.0.1", help="--tcp 바인드 주소 (기본 127.0.0.1)")
    ap.add_argument("--port", type=int, default=0, help="--tcp 포트 (0=임의)")
    ap.add_argument("--link", default=None, help="--pty 슬레이브 경로에 만들 심볼릭 링크 (예: /tmp/ttyMOCK0)")
    ap.add_argument("--baud", type=int, default=None, help="기기 보드레이트 (기본: 프로필 값, 보통 115200)")
    ap.add_argument("--firmware", default=None,
                    help="플래시 이미지 경로. 생략하면 캐시된 전체 합성 이미지(zig/mksquashfs 가 없으면 빠른 이미지)")
    ap.add_argument("--fast-firmware", action="store_true", help="외부 도구 없이 즉석 생성한 빠른 이미지를 쓴다")
    ap.add_argument("--build-firmware", metavar="OUT", default=None, help="이미지를 OUT 에 만들고 종료 (+ OUT.manifest.json)")
    ap.add_argument("--time-scale", type=float, default=1.0, help="지연 배율 (데모 1.0, 테스트 0.02 등)")
    ap.add_argument("--seed", type=int, default=0, help="초기화되지 않은 RAM 의사난수 시드")
    ap.add_argument("--no-autostart", action="store_true", help="전원을 켜지 않고 대기 (stdin 에 power-on)")
    ap.add_argument("--pace-output", action="store_true", help="출력을 실제 보드레이트 속도로 제한")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="프로필 덮어쓰기 (예: --set uboot.crc32_style=lower)")
    ap.add_argument("--log-file", default=None, help="콘솔 출력 사본을 저장할 파일 (종료 시 기록)")
    ap.add_argument("--list-profiles", action="store_true", help="내장 프로필 목록을 JSON 으로 출력하고 종료")
    ap.add_argument("-v", "--verbose", action="store_true", help="stderr 로그 자세히")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        overrides = _parse_set(args.set)
        if args.list_profiles:
            _emit({"ok": True, "profiles": list_profiles()})
            return 0
        if args.build_firmware:
            manifest = build_image(args.profile, args.build_firmware, fast=args.fast_firmware, overrides=overrides or None)
            _emit({"ok": True, "image": manifest["image"], "manifest": str(Path(manifest["image"]["path"]).with_name(
                Path(manifest["image"]["path"]).name + ".manifest.json")), "fallbacks": manifest["fallbacks"],
                "planted_issues": [p["id"] for p in manifest["planted_issues"]]})
            return 0
        flash: Any = args.firmware
        if flash is None and not args.fast_firmware:
            from .firmware import build_image_bytes

            data, manifest = build_image_bytes(args.profile, fast=False, overrides=overrides or None)
            flash = data
        dev = MockDevice(args.profile, flash_image=flash, time_scale=args.time_scale, seed=args.seed,
                         baud=args.baud, overrides=overrides or None, autostart=not args.no_autostart,
                         pace_output=args.pace_output)
        if flash is not None and not isinstance(flash, str) and dev.firmware_manifest is None:
            dev.firmware_manifest = manifest  # type: ignore[possibly-undefined]
        if args.tcp:
            host, port = dev.start_tcp(args.host, args.port)
            info: dict[str, Any] = {"ok": True, "url": f"socket://{host}:{port}", "host": host, "port": port}
        else:
            path = dev.start_pty(link=args.link)
            info = {"ok": True, "pty": path}
            if args.link:
                info["link"] = args.link
        info.update({"profile": dev.profile["name"], "baud": dev.baud, "time_scale": dev.time_scale,
                     "powered": dev.powered, "credentials": dev.profile["linux"]["login"],
                     "uboot_prompt": dev.profile["uboot"]["prompt"]})
        _emit(info)
    except PwehError as exc:
        _emit({"ok": False, "error": exc.to_dict()})
        return 2
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "error": {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"}})
        return 2

    stop = threading.Event()

    def _sig(*_a: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    try:
        _control_loop(dev, stop)
    finally:
        if args.log_file:
            try:
                Path(args.log_file).write_bytes(dev.console_output)
            except OSError as exc:
                log.warning("log file write failed: %s", exc)
        dev.stop()
    return 0


def _control_loop(dev: MockDevice, stop: threading.Event) -> None:
    lines: list[str] = []
    done = threading.Event()

    def reader() -> None:
        try:
            for line in sys.stdin:
                lines.append(line)
                handled.set()
        finally:
            done.set()
            handled.set()

    handled = threading.Event()
    threading.Thread(target=reader, name="pweh-mock-stdin", daemon=True).start()
    while not stop.is_set():
        handled.wait(0.2)
        handled.clear()
        while lines:
            line = lines.pop(0).strip()
            if not line:
                continue
            resp = _handle(dev, line)
            _emit(resp)
            if resp.get("quit"):
                return
        if done.is_set() and not lines:
            return


def _handle(dev: MockDevice, line: str) -> dict[str, Any]:
    parts = line.split()
    cmd = parts[0].lower()
    try:
        if cmd in ("power-cycle", "cycle", "reset-power"):
            dev.power_cycle()
            return {"ok": True, "cmd": cmd, "state": dev.state}
        if cmd in ("power-off", "off"):
            dev.power_off()
            dev.wait_for_state("off", 5.0)
            return {"ok": True, "cmd": cmd, "state": dev.state}
        if cmd in ("power-on", "on"):
            dev.power_on()
            return {"ok": True, "cmd": cmd, "state": dev.state}
        if cmd == "status":
            return {"ok": True, "cmd": cmd, **dev.status()}
        if cmd == "events":
            n = int(parts[1]) if len(parts) > 1 else 50
            return {"ok": True, "cmd": cmd, "events": dev.events[-n:]}
        if cmd in ("destructive", "destructive-events"):
            return {"ok": True, "cmd": cmd, "destructive_events": list(dev.destructive_events)}
        if cmd == "console":
            n = int(parts[1]) if len(parts) > 1 else 4096
            return {"ok": True, "cmd": cmd, "text": dev.console_text()[-n:]}
        if cmd == "wait":
            state = parts[1] if len(parts) > 1 else "uboot"
            if state not in STATES:
                return {"ok": False, "cmd": cmd, "error": f"unknown state {state!r}", "states": list(STATES)}
            secs = float(parts[2]) if len(parts) > 2 else 30.0
            ok = dev.wait_for_state(state, secs)
            return {"ok": ok, "cmd": cmd, "state": dev.state}
        if cmd in ("quit", "exit", "stop"):
            return {"ok": True, "cmd": cmd, "quit": True}
        return {"ok": False, "cmd": cmd, "error": "unknown command",
                "commands": ["power-cycle", "power-off", "power-on", "status", "events [N]", "destructive",
                             "console [N]", "wait STATE [SEC]", "quit"]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "cmd": cmd, "error": f"{type(exc).__name__}: {exc}"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
