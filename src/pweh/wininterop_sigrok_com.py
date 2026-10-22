"""OLS COM scan/show에만 쓰는 고유 image·실행 세대 검증.

정보용 SigrokLaunch와 runner의 허용 범위는 바꾸지 않는다. Windows 실행은
필수 주입 runner가 맡으며 이 모듈은 조회 실패를 부재로 해석하지 않는다.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

from . import wininterop as W
from .sigrok_com import ComCommand
from .wininterop_sigrok import (SigrokIdentity, parse_process_snapshot,
                                QUERY_SCRIPT, TERMINATE_SCRIPT_TEMPLATE)

_fail = W._fail
_deadline = W._deadline
_check = W._check
_json = W._json
split_command_line = W.split_command_line


@dataclass(frozen=True)
class SigrokComLaunch:
    """고정 profile의 명령만 받는다. 임의 argv나 다른 driver를 받지 않는다."""
    image: str
    command: ComCommand

    def __post_init__(self):
        W.validate_windows_path(self.image)
        if self.image.replace('/', '\\').rsplit('\\', 1)[-1] != 'sigrok-cli.exe':
            _fail()
        if type(self.command) is not ComCommand:
            _fail()

    @property
    def argv_tail(self):
        return self.command.argv_tail


def matches_launch(identity: SigrokIdentity, launch: SigrokComLaunch, *, deadline=None) -> bool:
    """고유 image와 고정 tail만 비교하고 argv0의 WSL 철자는 제외한다."""
    if type(identity) is not SigrokIdentity or type(launch) is not SigrokComLaunch:
        _fail()
    args = split_command_line(identity.command_line, deadline=deadline)[1:]
    return W._path_key(identity.image) == W._path_key(launch.image) and args == launch.argv_tail


class SigrokComProcessProbe:
    """필수 runner에 고정 script와 deadline만 전달한다. 기본 실행 fallback은 없다."""

    def __init__(self, *, runner):
        if not callable(runner):
            _fail()
        self._runner = runner

    def _run(self, script: str, end: float) -> bytes:
        _check(end)
        try:
            raw = self._runner(script, end)
        except Exception:
            _fail()
        _check(end)
        return raw

    def observe(self, launch: SigrokComLaunch, *, deadline: float) -> tuple[SigrokIdentity, ...]:
        end = _deadline(deadline)
        if type(launch) is not SigrokComLaunch:
            _fail()
        rows = parse_process_snapshot(self._run(QUERY_SCRIPT, end), deadline=end)
        matches = []
        for row in rows:
            _check(end)
            # 같은 고유 image의 다른 argv/세대는 다른 작업으로 무시하지 않는다.
            if W._path_key(row.image).casefold() == W._path_key(launch.image).casefold():
                if not matches_launch(row, launch, deadline=end):
                    _fail()
                matches.append(row)
        if len(matches) > 1:
            _fail()
        _check(end)
        return tuple(matches)

    def terminate_and_confirm(self, launch: SigrokComLaunch, observed: tuple[SigrokIdentity, ...], *, deadline: float) -> bool:
        """관찰 세대 재대조 뒤 같은 핸들만 종료한다. 미확인/변경/실패는 False다."""
        try:
            end = _deadline(deadline)
            if (type(observed) is not tuple or len(observed) > 1
                    or any(type(row) is not SigrokIdentity or not matches_launch(row, launch, deadline=end) for row in observed)):
                return False
            fresh = self.observe(launch, deadline=end)
            if fresh != observed:
                return False
            for row in fresh:
                _check(end)
                remaining = end - time.monotonic()
                request = {"pid": row.pid, "image": row.image, "creation": row.creation_filetime,
                           "cmd": row.command_line, "wait_ms": max(1, min(2000, int(remaining * 1000)))}
                data = base64.b64encode(json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("ascii")).decode("ascii")
                result = _json(self._run(TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", data), end), end, cap=1024)
                if type(result) is not dict or set(result) != {"terminated"} or result["terminated"] is not True:
                    return False
            return not self.observe(launch, deadline=end)
        except Exception:
            return False
