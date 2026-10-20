"""포트 참조 문법 — port-routing 설계(docs/design/port-routing.md) §4.1 의 P0 부분.

지금 들어 있는 것:
- Windows COM 이름 문법(:func:`parse_win_com`): ``COM1``–``COM4096``, 대소문자 무관, 앞자리 0 금지.
  4096 은 Windows COM 이름 DB 의 최대 크기(``COMDB_MAX_PORTS_ARBITRATED``)다.
- 원격 시리얼 URL(``socket://``, ``rfc2217://``)의 호스트 검사(:func:`validate_net_url`, 설계 결정 D4).
  루프백(127.0.0.0/8, ``[::1]``, 모든 주소가 루프백으로 풀리는 ``localhost``)만 받는다.
  LAN 의 ser2net·RFC2217 서버는 지금 받지 않는다. 설계의 운영자 허용 목록(``safety.ports.remote_serial_hosts``)은
  아직 구현하지 않았다(설정 키도 없다).
- 루프백 호스트 판정(:func:`is_loopback_host`)과 시뮬레이터 리스너(IPv4 전용)의 바인드 주소 검사(:func:`check_listen_host`, G13).
- 같은 끝점을 가리키는 표기를 한 키로(:func:`endpoint_key`) — 루프백 원격 URL 은 포트만(``net-loopback:<port>``) 본다.

해석기(resolve)·열거·장치 식별·portlock 은 P1 에서 이 모듈에 더한다.
이 모듈은 포트를 열지 않는다. ``localhost`` 판정만 이름 풀이(getaddrinfo — 보통 /etc/hosts)를 한다.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import urllib.parse
from typing import Any, Callable, Iterable

from .errors import ValidationFailed

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
