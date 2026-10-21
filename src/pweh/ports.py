"""포트 참조·불변 route·읽기 전용 식별·scope — port-routing P0/P1/P2.

지금 들어 있는 것:
- Windows COM 이름 문법(:func:`parse_win_com`): ``COM1``–``COM4096``, 대소문자 무관, 앞자리 0 금지.
  4096 은 Windows COM 이름 DB 의 최대 크기(``COMDB_MAX_PORTS_ARBITRATED``)다.
- 원격 시리얼 URL(``socket://``, ``rfc2217://``)의 호스트 검사(:func:`validate_net_url`, 설계 결정 D4).
  루프백(127.0.0.0/8, ``[::1]``, 모든 주소가 루프백으로 풀리는 ``localhost``)만 받는다.
  LAN 의 ser2net·RFC2217 서버는 지금 받지 않는다. 설계의 운영자 허용 목록(``safety.ports.remote_serial_hosts``)은
  아직 구현하지 않았다(설정 키도 없다).
- 루프백 호스트 판정(:func:`is_loopback_host`)과 시뮬레이터 리스너(IPv4 전용)의 바인드 주소 검사(:func:`check_listen_host`, G13).
- 같은 끝점을 가리키는 표기를 한 키로(:func:`endpoint_key`) — 루프백 원격 URL 은 포트만(``net-loopback:<port>``) 본다.

resolve/list/scope는 장치를 열지 않는다. open_serial만 별도 serialtransport에 위임한다.
WSL의 Windows COM 세션은 검증한 helper에 위임한다. Windows sigrok는 후속 P3이다.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import stat
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping, TYPE_CHECKING

from .errors import ValidationFailed

if TYPE_CHECKING:
    from .portidentity import PortIdentity

# ---------------------------------------------------------------------------
# Windows COM 이름
# ---------------------------------------------------------------------------

WIN_COM_MAX = 4096
_WIN_COM_RE = re.compile(r"COM([1-9][0-9]{0,3})", re.IGNORECASE | re.ASCII)
_COM_LIKE_RE = re.compile(r"COM[0-9]+", re.IGNORECASE | re.ASCII)


def parse_win_com(name: str) -> int | None:
    """``COM<n>`` 이면 n(1–4096), 아니면 None. 대소문자는 무관하고, 공백·앞자리 0(``COM01``)·``COM0`` 은 받지 않는다."""
    if not isinstance(name, str):
        return None
    m = _WIN_COM_RE.fullmatch(name)
    if m is None:
        return None
    n = int(m.group(1))
    return n if n <= WIN_COM_MAX else None


def looks_like_win_com(name: str) -> bool:
    """``COM`` + ASCII 숫자 모양인가(범위·앞자리 0 은 보지 않음). 범위 밖 COM 이름에 맞는 오류 문구를 고르는 데 쓴다."""
    return isinstance(name, str) and _COM_LIKE_RE.fullmatch(name) is not None


# ---------------------------------------------------------------------------
# 루프백 판정
# ---------------------------------------------------------------------------

#: ``resolve(host, port)`` → getaddrinfo 형식 결과(각 항목의 [4][0] 이 주소 문자열). 시험은 이 인자로 주입한다.
Resolver = Callable[[str, "int | None"], Iterable[Any]]

_IPV4_TEXT_RE = re.compile(r"[0-9.]+", re.ASCII)


def _getaddrinfo(host: str, port: int | None) -> list[Any]:
    """기본 이름 풀이. pyserial 의 ``socket.create_connection`` 과 같은 조건(SOCK_STREAM)으로 푼다."""
    return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)


def _resolve_loopback(host: str, port: int | None, resolve: Resolver | None) -> list[str] | None:
    """host 를 풀어 나온 주소가 하나 이상이고 **모두** 루프백이면 그 주소들(정규형 문자열, 풀이 순서), 아니면 None (fail closed)."""
    fn = resolve if resolve is not None else _getaddrinfo
    try:
        infos = list(fn(host, port))
    except (OSError, UnicodeError, ValueError):  # socket.gaierror 는 OSError
        return None
    out: list[str] = []
    for info in infos:
        try:
            addr = info[4][0]
        except (IndexError, KeyError, TypeError):
            return None
        if not isinstance(addr, str) or "%" in addr:  # zone 이 붙은 주소(링크 로컬 등)는 루프백이 아니다
            return None
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        if not ip.is_loopback:  # Python 3.10 은 ::ffff:127.0.0.1 을 루프백으로 보지 않는다 → 거부(fail closed)
            return None
        if str(ip) not in out:
            out.append(str(ip))
    return out or None


def is_loopback_host(host: str, *, port: int | None = None, resolve: Resolver | None = None) -> bool:
    """host 가 루프백인가 — 확인할 수 있는 정규형만 인정한다(fail closed).

    - IPv4: 엄격한 점 네 개 십진 표기(앞자리 0 불허)이고 127.0.0.0/8. ``127.1``·``2130706433``·``0x7f.1``·
      ``0177.0.0.1`` 같은 inet_aton 별칭은 받지 않는다(``0127.0.0.1`` 은 8진수로 87.0.0.1 이 될 수 있다).
    - IPv6: 괄호 없는 ``::1`` 만. zone(``%``)·확장형(``0:0:0:0:0:0:0:1``)·IPv4-mapped(``::ffff:127.0.0.1``)는 거부.
    - ``localhost``(대소문자 무관, 끝 점 없음): 이름 풀이 결과가 하나 이상이고 모두 루프백일 때만. 풀이 실패는 False.
    - 그 밖(빈 문자열 = 모든 주소, ``0.0.0.0``, ``::``, 이 호스트의 이름, ``localhost.``)은 False.
    """
    if not isinstance(host, str) or not host or not host.isascii():
        return False
    if host == "::1":
        return True
    if _IPV4_TEXT_RE.fullmatch(host):
        try:
            addr = ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return str(addr) == host and addr.is_loopback
    if host.lower() == "localhost":
        return _resolve_loopback("localhost", port, resolve) is not None
    return False


# ---------------------------------------------------------------------------
# 원격 시리얼 URL (socket://, rfc2217://)
# ---------------------------------------------------------------------------

#: 네트워크로 접속하는 pyserial URL 스킴. ``loop://`` 는 네트워크를 쓰지 않으므로 여기서 다루지 않는다.
NET_URL_SCHEMES = ("socket", "rfc2217")
_NET_URL_PREFIXES = tuple(f"{scheme}://" for scheme in NET_URL_SCHEMES)

# <scheme>://<host>:<port> 전체 일치만. host = [IPv6 문자] 또는 영숫자·점·하이픈.
# 사용자 정보('@'), zone·퍼센트 인코딩('%'), 경로·질의·조각('/', '?', '#'), 공백은 어느 자리에도 올 수 없다.
_NET_URL_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9]*)://(?:\[(?P<v6>[0-9A-Za-z:.]*)\]|(?P<name>[A-Za-z0-9.\-]*)):(?P<port>[0-9]*)",
    re.ASCII,
)
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}", re.ASCII)

NET_URL_FORM_HINT = (
    "형식: socket://127.0.0.1:<포트> 또는 rfc2217://127.0.0.1:<포트> — 루프백 호스트(127.0.0.0/8, [::1], localhost), "
    "포트 1–65535(앞자리 0 없이) 필수, 사용자 정보(@)·경로·질의(?)·공백 없이."
)
NET_URL_LOOPBACK_HINT = (
    "원격 시리얼 URL(socket://, rfc2217://)은 이 호스트의 루프백(127.0.0.0/8, [::1], localhost)만 받습니다. "
    "LAN 의 ser2net·RFC2217 서버는 이 버전에서 지원하지 않습니다(인증 없는 시리얼을 LAN 에 여는 일이고, 뒤에 어떤 장치가 "
    "있는지 식별할 수 없음). 어댑터를 이 호스트에 USB 로 연결해 장치 경로(/dev/ttyUSB0 등 — WSL2 는 usbipd attach 뒤)를 쓰세요."
)


def validate_net_url(url: str, *, resolve: Resolver | None = None) -> str:
    """원격 시리얼 URL 검사 → 정규형 ``<scheme>://<host>:<port>``(스킴·호스트 소문자). 어긋나면 ValidationFailed.

    받는 것:
    - 스킴 ``socket``·``rfc2217``(대소문자 무관).
    - 호스트: 정규형 IPv4 루프백(127.0.0.0/8, 예 ``127.0.0.1``), ``[::1]``, ``localhost``(모든 주소가 루프백으로 풀릴 때).
      ``localhost`` 는 확인한 루프백 주소로 **바꿔** 돌려준다(IPv4 가 있으면 첫 IPv4, 없으면 ``[::1]``) — 연결할 때 이름을
      다시 풀지 않으므로 검사와 연결 사이에 다른 주소로 바뀌지 않는다.
    - 포트: 반드시 있고 1–65535, 앞자리 0 없음.

    받지 않는 것(모두 ValidationFailed): LAN·와일드카드 주소, 사용자 정보(``user@``), zone(``%lo``)·퍼센트 인코딩,
    경로·질의(pyserial 옵션 ``?logging=``·``?ign_set_control``·``?timeout=`` 포함)·조각, 공백·제어 문자·ASCII 밖 문자,
    inet_aton 별칭(``127.1``, ``2130706433``, ``0x7f.1``), 확장형·IPv4-mapped IPv6, 끝 점(``localhost.``), 빈 호스트.

    pyserial 은 ``urllib.parse.urlsplit(url)`` 의 hostname·port 로 접속하므로, 직접 해석한 값과 urlsplit 의 해석이
    같을 때만 통과시킨다(두 해석기가 다른 호스트를 보는 URL 을 막는다).
    """
    if not isinstance(url, str) or not url.isascii() or any(c.isspace() or not c.isprintable() for c in url):
        raise ValidationFailed(
            f"원격 시리얼 URL 에 쓸 수 없는 문자(공백·제어 문자·ASCII 밖 문자)가 있습니다: {url!r}", hint=NET_URL_FORM_HINT
        )
    m = _NET_URL_RE.fullmatch(url)
    if m is None:
        raise ValidationFailed(f"원격 시리얼 URL 형식이 아닙니다: {url!r}", hint=NET_URL_FORM_HINT)
    scheme = m.group("scheme").lower()
    if scheme not in NET_URL_SCHEMES:
        raise ValidationFailed(f"원격 시리얼 URL 스킴이 아닙니다: {url!r}", hint=NET_URL_FORM_HINT)
    port_text = m.group("port")
    if not _PORT_RE.fullmatch(port_text) or int(port_text) > 65535:
        raise ValidationFailed(f"원격 시리얼 URL 의 포트는 1–65535(앞자리 0 없이)여야 합니다: {url!r}", hint=NET_URL_FORM_HINT)
    port = int(port_text)
    v6, name = m.group("v6"), m.group("name")
    if v6 is not None:
        if v6 != "::1":
            raise ValidationFailed(
                f"원격 시리얼 URL 의 호스트가 루프백이 아닙니다(IPv6 는 [::1] 만): {url!r}", hint=NET_URL_LOOPBACK_HINT
            )
        host, url_host = "::1", "[::1]"
    else:
        if not name:
            raise ValidationFailed(f"원격 시리얼 URL 에 호스트가 없습니다: {url!r}", hint=NET_URL_FORM_HINT)
        host = name.lower()  # urlsplit 과의 교차 확인은 적힌 그대로의 호스트로 한다
        if host == "localhost":
            addrs = _resolve_loopback(host, port, resolve)
            if addrs is None:
                raise ValidationFailed(f"원격 시리얼 URL 의 호스트가 루프백이 아닙니다: {url!r}", hint=NET_URL_LOOPBACK_HINT)
            v4 = [a for a in addrs if ":" not in a]
            url_host = v4[0] if v4 else "[::1]"  # 확인한 주소로 바꾼다 (루프백 IPv6 는 ::1 하나뿐)
        elif is_loopback_host(host, port=port, resolve=resolve):
            url_host = host
        else:
            raise ValidationFailed(f"원격 시리얼 URL 의 호스트가 루프백이 아닙니다: {url!r}", hint=NET_URL_LOOPBACK_HINT)
    # pyserial(protocol_socket·rfc2217 의 from_url)과 같은 해석인지 교차 확인
    try:
        parts = urllib.parse.urlsplit(url)
        same = (
            parts.scheme == scheme
            and parts.hostname == host
            and parts.port == port
            and parts.username is None
            and parts.password is None
            and not parts.path
            and not parts.query
            and not parts.fragment
        )
    except ValueError:
        same = False
    if not same:
        raise ValidationFailed(f"원격 시리얼 URL 을 모호하지 않게 해석할 수 없습니다: {url!r}", hint=NET_URL_FORM_HINT)
    return f"{scheme}://{url_host}:{port}"


def endpoint_key(port: str, *, resolve: Resolver | None = None) -> str:
    """같은 끝점을 가리키는 다른 표기를 한 키로 — 서버 프로세스 안의 '사용 중' 비교용(P1 의 OS 객체 키 ``lock_key`` 전까지).

    - 원격 시리얼 URL(``socket://``·``rfc2217://`` — 받는 것은 루프백뿐): **포트만** 본다 → ``net-loopback:<port>``.
      ``127.0.0.1``·다른 ``127.x``·``[::1]``·``localhost`` 와 두 스킴은 리스너가 모든 루프백 주소(또는 모든 주소)에 바인드하면
      같은 콘솔이다. 표기가 다르다고 다른 포트로 보면 세션 두 개가 한 콘솔에 붙어 줄 조립기가 둘로 나뉘고
      (``sa`` + ``veenv\\r`` → ``saveenv``) 재동기화 키가 남의 콘솔로 간다. 정말 다른 리스너(127.0.0.2:P 와 127.0.0.3:P)도 같은
      키가 되지만 지나치게 막을 뿐이다(fail closed). 정규형이 아니면 :func:`validate_net_url` 로 검사한다(어긋나면 ValidationFailed).
    - ``loop://``: 문자열 그대로(네트워크·장치 없음).
    - Windows ``COM<n>``: 정규형 ``COM<n>``.
    - 장치 경로: realpath(``/dev/serial/by-id/…`` 링크 → ``/dev/ttyUSB0``).

    프로세스 사이(예: uart 서버와 jtagulator 서버)의 배타는 이 키로 하지 않는다. 장치 경로는 열 때 flock 이 막지만,
    socket://·rfc2217:// 는 pyserial 이 ``exclusive`` 를 무시하므로 프로세스 사이 배타가 없다(P1 의 portlock).
    """
    p = (port or "").strip()
    low = p.lower()
    if low.startswith(_NET_URL_PREFIXES):
        canon = validate_net_url(p, resolve=resolve)
        return f"net-loopback:{int(canon.rsplit(':', 1)[1])}"
    if "://" in p:
        return p
    com = parse_win_com(p)
    if com is not None:
        return f"COM{com}"
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return p


# ---------------------------------------------------------------------------
# 시뮬레이터 리스너 (G13)
# ---------------------------------------------------------------------------


def check_listen_host(host: str, *, allow_lan: bool = False, resolve: Resolver | None = None) -> bool:
    """시뮬레이터 TCP 리스너(IPv4 전용 — ``AF_INET``)의 바인드 주소 검사(설계 §5.5·§11 규칙 5, G13).

    - IPv6 주소(``::1``, ``::``, ``[::1]`` 처럼 ':' 가 든 값)는 ``allow_lan`` 과 무관하게 ValidationFailed — 리스너가 IPv4 만
      열기 때문이다(그대로 두면 bind 에서 gaierror).
    - 루프백(127.0.0.0/8, ``localhost``)이면 False(LAN 노출 없음).
    - 루프백이 아니면(빈 문자열 = 모든 주소, ``0.0.0.0``, LAN 주소, 이 호스트의 이름) ``allow_lan`` 일 때 True
      (LAN 노출 — 호출자가 :func:`lan_listen_warning` 을 stderr 로 알린다), 아니면 ValidationFailed.
    """
    if isinstance(host, str) and ":" in host:
        raise ValidationFailed(
            f"시뮬레이터 리스너는 IPv4 루프백 주소(127.0.0.0/8, localhost)만 받습니다 — IPv6 주소는 쓸 수 없습니다: {host!r}",
            hint="127.0.0.1 을 쓰세요(접속 URL 은 socket://127.0.0.1:<포트>).",
        )
    if is_loopback_host(host, resolve=resolve):
        return False
    if allow_lan:
        return True
    raise ValidationFailed(
        f"시뮬레이터는 루프백 주소에만 바인드합니다: {host!r}",
        hint="기본값(127.0.0.1)을 쓰세요. LAN 에서 접속해야 하면 --allow-lan 을 명시하세요"
             "(인증 없는 시리얼 콘솔이 LAN 에 열린다 — 브리지 모드 WSL 이면 LAN 전체).",
    )


def lan_listen_warning(host: str, port: int | str) -> str:
    """``--allow-lan`` 으로 루프백이 아닌 주소에 바인드했을 때 stderr 로 내는 경고 문구."""
    return (
        f"경고: 시뮬레이터가 루프백이 아닌 주소 {host or '0.0.0.0'}:{port} 에서 접속을 받습니다. "
        "같은 LAN 의 다른 호스트가 인증 없이 접속할 수 있습니다(브리지 모드 WSL 이면 LAN 전체). "
        f"PWEH 서버(uart·jtagulator)는 루프백 URL 만 받으므로 이 호스트에서는 socket://127.0.0.1:{port} 로 접속하세요"
        "(0.0.0.0·LAN 주소 URL 은 validation_failed)."
    )


__all__ = [
    "NET_URL_FORM_HINT",
    "NET_URL_LOOPBACK_HINT",
    "NET_URL_SCHEMES",
    "WIN_COM_MAX",
    "Resolver",
    "check_listen_host",
    "endpoint_key",
    "is_loopback_host",
    "lan_listen_warning",
    "looks_like_win_com",
    "parse_win_com",
    "validate_net_url",
]


@dataclass(frozen=True)
class PortProbe:
    """읽기 전용 route 의존성. None은 호출 때 모듈 기본 함수를 선택한다."""
    stat: Callable | None = None
    realpath: Callable[[str], str] | None = None
    identity: Callable[[str], PortIdentity] | None = None
    resolve_host: Resolver | None = None


@dataclass(frozen=True)
class PortRoute:
    """OS route snapshot. 가변 dict·환경·fd를 저장하지 않는다."""
    ref: str
    purpose: str
    backend: str
    side: str
    device_path: str
    lock_key: str | None
    device_id: str | None
    identity: PortIdentity
    identity_strength: str
    reset_risk: str
    warnings: tuple[str, ...] = ()
    node_identity: tuple[int, int, int] | None = None

    def __post_init__(self) -> None:
        from .portidentity import PortIdentity
        if not isinstance(self.identity, PortIdentity):
            raise ValidationFailed("PortRoute identity는 불변 PortIdentity여야 합니다.")
        for name in ("ref", "purpose", "backend", "side", "device_path", "lock_key", "device_id", "identity_strength", "reset_risk"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or len(value) > 16384):
                raise ValidationFailed("PortRoute는 bounded scalar 필드만 보관합니다.")
        warnings = tuple(self.warnings)
        if len(warnings) > 64 or any(not isinstance(v, str) or len(v) > 4096 for v in warnings):
            raise ValidationFailed("PortRoute warnings 형식 오류")
        object.__setattr__(self, "warnings", warnings)
        if self.node_identity is not None:
            node = tuple(self.node_identity)
            if len(node) != 3 or any(type(v) is not int or v < 0 for v in node):
                raise ValidationFailed("PortRoute node identity 형식 오류")
            object.__setattr__(self, "node_identity", node)

    def to_dict(self) -> dict[str, Any]:
        identity = self.identity.to_dict()
        identity["strength"] = self.identity_strength
        return {"ref": self.ref, "backend": self.backend, "side": self.side, "device_path": self.device_path,
                "lock_key": self.lock_key, "device_id": self.device_id, "identity": identity,
                "reset_risk": self.reset_risk, "warnings": list(self.warnings)}

    def approval_identity(self) -> dict[str, str | None]:
        return {"backend": self.backend, "lock_key": self.lock_key, "device_id": self.device_id}

    def _binding(self) -> tuple[Any, ...]:
        i = self.identity
        return (self.backend, self.lock_key, self.device_id, self.device_path, self.node_identity,
                i.device_instance, i.parent_instance, i.usb_ancestor, i.interface_number, i.serial)

    def continuity_key(self) -> tuple[Any, ...] | None:
        if self.backend in ("loop", "net-url") or (self.side == "windows" and self.identity.status != "known"):
            return None
        return self._binding() if self.node_identity is not None or self.device_id is not None else None


@dataclass(frozen=True)
class SiblingScope:
    """동일 USB 부모의 현재 OS 형제 전체 관찰 결과."""
    keys: tuple[str, ...]
    parent_id: str | None
    complete: bool
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", tuple(self.keys))
        object.__setattr__(self, "reasons", tuple(self.reasons))


def validate_ref(ref: str, *, purpose: str, resolve_host: Resolver | None = None) -> str:
    """factory를 부르기 전 포트 참조 문법만 검사한다."""
    if purpose not in ("serial-session", "esptool", "sigrok-serial"):
        raise ValidationFailed("지원하지 않는 포트 용도입니다.")
    if not isinstance(ref, str) or not ref or len(ref) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in ref):
        raise ValidationFailed("포트 참조 형식/길이 오류")
    p = ref.strip()
    if ".." in Path(p).parts:
        raise ValidationFailed("포트 경로에 ..를 쓸 수 없습니다.")
    if "://" in p:
        if purpose != "serial-session":
            raise ValidationFailed("이 도구는 네트워크/URL 포트를 지원하지 않습니다.")
        if p == "loop://":
            return p
        return validate_net_url(p, resolve=resolve_host)
    com = parse_win_com(p)
    if com is not None:
        return f"COM{com}"
    if looks_like_win_com(p):
        raise ValidationFailed(f"COM1–COM{WIN_COM_MAX}만 받으며 앞자리 0은 허용하지 않습니다.")
    if not p.startswith("/dev/"):
        raise ValidationFailed("포트는 /dev 아래 문자장치 절대 경로여야 합니다.")
    return p


def identity_projection(identity: PortIdentity) -> tuple[str | None, str]:
    """OS 원문 device_id와 표시 강도를 분리한다. 하드웨어 인증이 아니다."""
    i = identity
    device_id = None
    if i.backend == "windows" and i.usb_ancestor:
        device_id = "win-pnp:" + i.usb_ancestor + "/" + ("MI_" + i.interface_number.upper() if i.interface_number else "-")
    elif i.backend == "linux" and i.vid and i.pid and i.usb_ancestor:
        loc = i.serial or (i.location_paths[0] if i.location_paths else i.usb_ancestor)
        device_id = f"usb:{i.vid}:{i.pid}:{loc}/if{i.interface_number or '-'}"
    generic = {"0001", "00000001", "0123456789abcdef", "00000000", "000000000000"}
    strength = "serial" if (i.serial and i.serial.lower() not in generic and i.status == "known") else ("location" if device_id else "none")
    return device_id, strength


@lru_cache(maxsize=1)
def _usb_table() -> dict[str, Any]:
    import yaml
    with (Path(__file__).parent / "data" / "usb-ids.yaml").open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def usb_device_info(vid: int | str | None, pid: int | str | None) -> dict[str, Any]:
    """합본 표의 새 dict를 반환한다. 범용 ID는 reset 배선/역할의 증거가 아니다."""
    def part(value: Any) -> str:
        return f"{value:04x}" if isinstance(value, int) else str(value or "").lower().removeprefix("0x")
    import copy
    return copy.deepcopy(_usb_table()["devices"].get(part(vid) + ":" + part(pid), {}))


def usb_uart_vendors() -> dict[int, str]:
    """기존 UART vendor 힌트를 공유하되 caller의 수정을 캐시에 반영하지 않는다."""
    return {int(k, 16): v for k, v in _usb_table()["uart_vendors"].items()}


def _probe_identity(ref: str, *, config: Any = None, stat_port: Callable | None = None) -> PortIdentity:
    """route 기본 관찰의 얇은 late seam. guard의 독립 provider를 바꾸지 않는다."""
    from . import portidentity
    return portidentity.probe_identity(ref, config=config, stat_port=stat_port or os.stat)


def resolve(env: Mapping[str, Any], ref: str, purpose: str, *, probe: PortProbe | None = None,
            config: Any = None) -> PortRoute:
    """포트를 열지 않고 환경·문자장치·OS 식별로 경로를 결정한다."""
    from . import hostenv, portidentity
    p = probe or PortProbe()
    ref = validate_ref(ref, purpose=purpose, resolve_host=p.resolve_host)
    kind = env.get("kind")
    if kind in ("NATIVE_WINDOWS", "CYGWIN", "MSYS"):
        raise ValidationFailed("이 버전은 네이티브 Windows/Cygwin/MSYS 실행을 지원하지 않습니다.")
    node = None
    backend, side, path, key, identity_ref = "posix-tty", "local", ref, None, ref
    com = parse_win_com(ref)
    if com is not None:
        side = "windows"
        key = f"win:COM{com}"
        if purpose == "sigrok-serial":
            raise ValidationFailed("Windows COM sigrok 경로는 P3에서 지원 예정입니다. local tty를 쓰세요.")
        if purpose == "serial-session":
            if kind == "WSL1" and com <= 191:
                path = f"/dev/ttyS{com}"
            else:
                disabled = hostenv.disabled_keys(config)
                if (disabled & {"interop", "serial_helper", "windows_tools"}
                        or ((env.get("windows") or {}).get("serial_helper") or {}).get("disabled")):
                    raise ValidationFailed("hostenv.disable 설정으로 Windows COM helper 경로가 꺼져 있습니다.")
                if kind not in {"WSL1", "WSL2_INTEROP", "WSL_UNKNOWN"} or not hostenv.interop_usable(env):
                    raise ValidationFailed("Windows COM 직렬 세션은 사용 가능한 WSL interop이 필요합니다.")
                backend = "win-helper"
        else:
            if not hostenv.interop_usable(env):
                raise ValidationFailed("Windows esptool COM 경로는 사용 가능한 WSL interop이 필요합니다.")
            backend = "win-exe"
    elif ref == "loop://":
        backend, side = "loop", "local"
    elif "://" in ref:
        backend, side, key = "net-url", "remote", endpoint_key(ref)
    if backend == "posix-tty":
        path = (p.realpath or os.path.realpath)(path)
        if not isinstance(path, str) or not path.startswith("/dev/") or ".." in Path(path).parts:
            raise ValidationFailed("포트 링크가 /dev 밖을 가리킵니다.")
        if kind == "MACOS" and Path(path).name.startswith("tty."):
            raise ValidationFailed("macOS에서는 대응하는 /dev/cu.* call-out 장치를 쓰세요.")
        try:
            st = (p.stat or os.stat)(path)
        except OSError as exc:
            raise ValidationFailed("시리얼 문자장치를 확인할 수 없습니다.", data={"path": path}) from exc
        if not stat.S_ISCHR(st.st_mode):
            raise ValidationFailed("시리얼 포트가 문자장치가 아닙니다.")
        node = (st.st_dev, st.st_ino, st.st_rdev)
        match = re.fullmatch(r"/dev/ttyS([1-9][0-9]*)", path)
        if kind == "WSL1" and match:
            n = int(match.group(1))
            if n > 191:
                raise ValidationFailed("WSL1 ttyS↔COM 대응은 1–191만 지원합니다.")
            side, key, identity_ref = "windows", f"win:COM{n}", f"COM{n}"
        key = key or f"tty:{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        if side != "windows":
            identity_ref = path
    identity = p.identity(identity_ref) if p.identity else _probe_identity(identity_ref, config=config,
                                                                          stat_port=p.stat or os.stat)
    device_id, strength = identity_projection(identity)
    risk = "none" if backend in ("loop", "net-url") or path.startswith("/dev/pts/") else "possible"
    if usb_device_info(identity.vid, identity.pid).get("reset_wiring") in ("chip-reset-on-lines", "auto-reset"):
        risk = "wired"
    return PortRoute(ref, purpose, backend, side, path, key, device_id, identity, strength, risk,
                     identity.reasons if identity.status != "known" else (), node)


def revalidate(route: PortRoute, *, env: Mapping[str, Any], probe: PortProbe | None = None,
               config: Any = None) -> PortRoute:
    """승인된 route의 경로/OS 식별을 새 관찰과 비교한다. 자동 승인/재연결은 하지 않는다."""
    from .errors import PwehError
    try:
        fresh = resolve(env, route.ref, route.purpose, probe=probe, config=config)
    except (OSError, ValidationFailed) as exc:
        raise PwehError("포트 경로를 다시 확인하지 못했습니다.", code="route_changed") from exc
    if route._binding() != fresh._binding():
        raise PwehError("승인/연결 이후 포트 경로 또는 장치 식별이 바뀌었습니다.", code="route_changed",
                        data={"expected": route.approval_identity(), "observed": fresh.approval_identity()})
    return fresh


def probe_siblings(route: PortRoute, *, config: Any = None, windows_runner: Callable | None = None,
                   sysfs_root: Path | None = None, stat_port: Callable | None = None) -> SiblingScope:
    """장치 전체 reset에 필요한 OS sibling을 bounded provider로 읽는다."""
    from . import portidentity
    return portidentity.probe_siblings(route, config=config, windows_runner=windows_runner,
                                       sysfs_root=sysfs_root, stat_port=stat_port)


def reset_scope(route: PortRoute, *, whole_device: bool = False,
                siblings_provider: Callable[[PortRoute], SiblingScope] | None = None,
                config: Any = None) -> tuple[str, ...]:
    """부분 sibling 관찰을 단일 포트 성공으로 낮추지 않는다."""
    from .errors import PwehError
    from .portlock import _keys
    if not whole_device:
        return (route.lock_key,) if route.lock_key else ()
    result = siblings_provider(route) if siblings_provider else probe_siblings(route, config=config)
    if (not result.complete or not route.identity.usb_ancestor or result.parent_id != route.identity.usb_ancestor
            or route.lock_key not in result.keys):
        raise PwehError("USB 장치의 모든 형제 인터페이스를 확인하지 못했습니다.", code="port_scope_unknown",
                        data={"reasons": list(result.reasons)})
    try:
        return _keys(result.keys)
    except ValidationFailed as exc:
        raise PwehError("USB scope key 상한/형식 오류", code="port_scope_unknown") from exc


def open_serial(*args: Any, **kwargs: Any) -> Any:
    """공통 transport의 지연 import. P2 helper를 자동 선택하지 않는다."""
    from .serialtransport import open_serial as impl
    return impl(*args, **kwargs)


def check_holders(route: PortRoute, *, env: Mapping[str, Any], proc_root: Path | None = None) -> dict[str, Any]:
    """같은 uid의 /proc fd를 rdev로 대조한다. 불완전 조회를 빈 목록으로 숨기지 않는다."""
    from .errors import Busy, PwehError
    if route.backend != "posix-tty":
        return {"busy_check": "not-applicable", "warnings": []}
    if env.get("kind") == "MACOS":
        return {"busy_check": "portlock-only", "warnings": ["macOS에서는 외부 프로세스 fd를 조회하지 않음"]}
    root = Path(proc_root) if proc_root is not None else Path("/proc")
    deadline = time.monotonic() + 2.0
    pid_count = fd_count = 0
    holders = set()
    def budget() -> None:
        if time.monotonic() > deadline or pid_count > 20000 or fd_count > 100000:
            raise ValueError("holder_scan_limit")
    try:
        if route.node_identity is None:
            raise ValueError("holder_route_node_missing")
        with os.scandir(root) as pids:
            for entry in pids:
                pid_count += 1
                budget()
                if not entry.name.isascii() or not entry.name.isdecimal() or int(entry.name) == os.getpid():
                    continue
                try:
                    before = entry.stat(follow_symlinks=False)
                    if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid():
                        continue
                    with os.scandir(Path(entry.path) / "fd") as descriptors:
                        for fd in descriptors:
                            fd_count += 1
                            budget()
                            if not fd.name.isascii() or not fd.name.isdecimal():
                                continue
                            try:
                                info = fd.stat(follow_symlinks=True)
                            except FileNotFoundError:
                                continue  # 닫힌 fd/종료된 프로세스
                            if stat.S_ISCHR(info.st_mode) and info.st_rdev == route.node_identity[2]:
                                holders.add(int(entry.name))
                    after = os.stat(entry.path, follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_uid) != (after.st_dev, after.st_ino, after.st_uid):
                        raise ValueError("holder_process_changed")
                except FileNotFoundError:
                    continue
        if holders:
            raise Busy("다른 프로세스가 이 tty를 보유하고 있습니다.",
                       data={"lock_key": route.lock_key, "pids": sorted(holders)[:100], "busy_check": "proc-fd"})
        return {"busy_check": "proc-fd", "warnings": ["동일 uid에서 보이는 fd만 검사함; 이후 외부 open 경합은 남음"]}
    except (OSError, ValueError) as exc:
        raise PwehError("외부 tty 보유자를 완전히 확인하지 못했습니다.", code="port_holders_unknown",
                        data={"reason": type(exc).__name__}) from exc


def list_serial(env: Mapping[str, Any], *, purpose: str = "serial-session", include_links: bool = False,
                probe: PortProbe | None = None, config: Any = None, local_provider: Callable | None = None,
                windows_provider: Callable | None = None, locks: Any = None) -> dict[str, Any]:
    """기존 목록 사실을 보존하고 사용 가능한 route/점유 상태를 덧붙인다."""
    from . import hostenv, portidentity
    from .errors import PwehError
    from .portlock import get_manager
    locks = locks or get_manager()
    deadline = time.monotonic() + 10.0
    def check_time() -> None:
        if time.monotonic() > deadline:
            raise PwehError("포트 목록 관찰 시간 상한 초과", code="port_list_incomplete")
    if local_provider is None:
        from serial.tools import list_ports
        local_provider = list_ports.comports
    entries = []
    hidden = 0
    for index, row in enumerate(local_provider(include_links=include_links)):
        check_time()
        if index >= 512:
            raise ValidationFailed("포트 목록 상한 초과")
        data = dict(row) if isinstance(row, dict) else {k: getattr(row, k, None) for k in (
            "device", "description", "hwid", "vid", "pid", "serial_number", "manufacturer", "product", "interface", "location")}
        if not data.get("vid") and data.get("hwid") in (None, "", "n/a"):
            hidden += 1
            continue
        data["device"] = data.get("device") or data.get("port")
        entries.append(data)
    win = {"available": False, "ports": [], "note": None}
    if hostenv.interop_usable(env):
        try:
            if windows_provider is not None:
                supplied = windows_provider()
                win = dict(supplied) if isinstance(supplied, dict) else {"available": True, "ports": list(supplied), "note": None}
            else:
                import json
                raw = portidentity._windows_output(config)
                parsed = json.loads(raw)
                win = {"available": True, "ports": [{"device": r["port"]} for r in parsed], "note": None}
                original_probe = probe or PortProbe()
                probe = PortProbe(original_probe.stat, original_probe.realpath,
                                  original_probe.identity or (lambda ref: portidentity.parse_windows(ref, raw)
                                                             if parse_win_com(ref) else _probe_identity(ref, config=config)),
                                  original_probe.resolve_host)
        except (OSError, ValueError, PwehError) as exc:
            win["note"] = str(exc)[:300]
    def enrich(rows: Iterable[dict], side: str) -> list[dict]:
        result = []
        for index, row in enumerate(rows):
            check_time()
            if index >= 512:
                raise ValidationFailed("포트 목록 상한 초과")
            rec = dict(row)
            ref = rec.get("device") or rec.get("port")
            rec.update(owner_side=side, route=None, device_id=None, held_by=None)
            try:
                route = resolve(env, ref, purpose, probe=probe, config=config)
                rec.update(route=route.to_dict(), device_id=route.device_id,
                           held_by=locks.held_by(route.lock_key) if route.lock_key else None)
            except PwehError as exc:
                rec["routing_error"] = exc.to_dict()
                # P2 미지원 COM도 관찰 사실은 보여 준다. flat CIM에서 부모를 지어내거나
                # 경로 미지원 때문에 추가 PnP 프로세스를 포트마다 실행하지 않는다.
                if parse_win_com(ref):
                    rec["held_by"] = locks.held_by(f"win:COM{parse_win_com(ref)}")
                    if probe is not None and probe.identity is not None:
                        observed = probe.identity(ref)
                        rec["device_id"], strength = identity_projection(observed)
                        rec["identity"] = {**observed.to_dict(), "strength": strength}
            result.append(rec)
            check_time()
        return result
    win["ports"] = enrich(win.get("ports", []), "windows")
    return {"env_kind": env.get("kind"), "local": {"ports": enrich(entries, "local"), "hidden_legacy_ports": hidden}, "windows": win}


__all__ += ["PortProbe", "PortRoute", "SiblingScope", "validate_ref", "resolve", "revalidate", "reset_scope",
            "probe_siblings", "open_serial", "list_serial", "identity_projection", "usb_device_info", "usb_uart_vendors", "check_holders"]
