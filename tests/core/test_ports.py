"""pweh.ports: COM 이름 문법, 원격 시리얼 URL 의 루프백 검사(D4), 리스너 바인드 주소 검사(G13).

호스트 이름 풀이는 주입한 resolver 로만 한다(이 호스트의 /etc/hosts 에 기대지 않는다).
LAN 주소는 문서용 대역(RFC 5737 192.0.2.0/24·198.51.100.0/24, RFC 3849 2001:db8::/32)과 사설 대역 예시만 쓴다.
"""

from __future__ import annotations

import socket
import urllib.parse

import pytest

from pweh import ports
from pweh.errors import ValidationFailed


def _resolver(*addrs: str, calls: list | None = None):
    def resolve(host, port):
        if calls is not None:
            calls.append((host, port))
        out = []
        for a in addrs:
            if ":" in a:
                out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (a, port or 0, 0, 0)))
            else:
                out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0)))
        return out

    return resolve


LOOPBACK_ONLY = _resolver("127.0.0.1", "::1")


def _raises_gaierror(host, port):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


# ---------------------------------------------------------------------------
# COM 이름
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,n", [("COM1", 1), ("com12", 12), ("Com256", 256), ("COM999", 999), ("COM4096", 4096)])
def test_parse_win_com_accepts(name, n):
    assert ports.parse_win_com(name) == n
    assert ports.looks_like_win_com(name)


@pytest.mark.parametrize("name", ["COM0", "COM01", "COM007", "COM4097", "COM9999", "COM99999", "COM", "COM-1", " COM1", "COM1 ",
                                  "COM1:", "\\\\.\\COM1", "LPT1", "ＣＯＭ1", "COM１", "COM٣", "", None])
def test_parse_win_com_rejects(name):
    assert ports.parse_win_com(name) is None


def test_looks_like_win_com_only_ascii_digits():
    assert ports.looks_like_win_com("COM0") and ports.looks_like_win_com("com4097") and ports.looks_like_win_com("COM007")
    for name in ("COM", "COM1x", "COM١", "COM１", "xCOM1", "", None):
        assert not ports.looks_like_win_com(name)


# ---------------------------------------------------------------------------
# 원격 시리얼 URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,canonical", [
    ("socket://127.0.0.1:7777", "socket://127.0.0.1:7777"),
    ("SOCKET://127.0.0.1:7777", "socket://127.0.0.1:7777"),
    ("rfc2217://127.0.0.1:2217", "rfc2217://127.0.0.1:2217"),
    ("Rfc2217://127.0.0.53:1", "rfc2217://127.0.0.53:1"),
    ("socket://127.255.255.254:65535", "socket://127.255.255.254:65535"),
    ("rfc2217://[::1]:2217", "rfc2217://[::1]:2217"),
    ("socket://localhost:4000", "socket://127.0.0.1:4000"),   # localhost 는 확인한 루프백 주소로 바뀐다(IPv4 우선)
    ("socket://LocalHost:4000", "socket://127.0.0.1:4000"),
])
def test_validate_net_url_accepts_loopback(url, canonical):
    out = ports.validate_net_url(url, resolve=LOOPBACK_ONLY)
    assert out == canonical
    # pyserial(from_url)이 보는 호스트·포트도 같다
    parts = urllib.parse.urlsplit(out)
    assert parts.hostname in ("127.0.0.1", "127.0.0.53", "127.255.255.254", "::1") and parts.port == int(out.rsplit(":", 1)[1])
    assert "localhost" not in out  # 연결할 때 이름을 다시 풀지 않는다


REJECTED = [
    # LAN·와일드카드 (LAN 의 ser2net 은 지금 지원하지 않는다)
    "socket://192.0.2.10:4000", "rfc2217://198.51.100.7:2217", "socket://10.0.0.2:4000", "socket://[2001:db8::1]:7777",
    "socket://0.0.0.0:7777", "socket://[::]:7777", "socket://255.255.255.255:7777",
    # inet_aton 별칭·앞자리 0 (0127.0.0.1 은 8진수로 87.0.0.1 이 될 수 있다)
    "socket://127.1:7777", "socket://2130706433:7777", "socket://0x7f.1:7777", "socket://0x7f000001:7777",
    "socket://0177.0.0.1:7777", "socket://0127.0.0.1:7777", "socket://127.0.0.01:7777", "socket://127.000.000.001:7777",
    # 끝 점·다른 이름
    "socket://127.0.0.1.:7777", "socket://localhost.:7777", "socket://localhost.localdomain:7777", "socket://ip6-localhost:7777",
    "socket://foo.localhost:7777", "socket://example.test:7777",
    # 사용자 정보 — urlsplit 은 '@' 뒤를 호스트로 본다
    "socket://user@127.0.0.1:7777", "socket://127.0.0.1@192.0.2.1:7777", "socket://192.0.2.1@127.0.0.1:7777",
    "socket://:pw@127.0.0.1:7777",
    # IPv6 변형
    "socket://[::1%25lo]:7777", "socket://[::1%lo]:7777", "socket://[0:0:0:0:0:0:0:1]:7777", "socket://[::ffff:127.0.0.1]:7777",
    "socket://[::ffff:7f00:1]:7777", "socket://::1:7777", "socket://[::1]junk:7777", "socket://x[::1]:7777", "socket://[::1]",
    # 퍼센트 인코딩
    "socket://127.0.0.1%2e:7777", "socket://%31%32%37.0.0.1:7777",
    # 포트
    "socket://127.0.0.1", "socket://127.0.0.1:", "socket://127.0.0.1:0", "socket://127.0.0.1:65536", "socket://127.0.0.1:99999",
    "socket://127.0.0.1:07777", "socket://127.0.0.1:+7777", "socket://127.0.0.1:7_777", "socket://127.0.0.1:７７７７",
    "socket://127.0.0.1:7777:8888", "socket://127.0.0.1:-1",
    # 경로·질의·조각 (pyserial 옵션 포함)
    "socket://127.0.0.1:7777/", "socket://127.0.0.1:7777/x", "socket://127.0.0.1:7777?logging=debug",
    "rfc2217://127.0.0.1:2217?ign_set_control", "rfc2217://127.0.0.1:2217?poll_modem&timeout=3", "socket://127.0.0.1:7777#f",
    # 빈 호스트·공백·제어 문자·ASCII 밖 문자 (urlsplit 은 \t 를 지우고, 소켓은 전각 글자를 정규화한다)
    "socket://:7777", "socket://", "socket:// 127.0.0.1:7777", "socket://127.0.0.1 :7777", "socket://127.0.0.1:77\t77",
    "socket://loc\talhost:7777", "socket://ｌｏｃａｌｈｏｓｔ:7777", "socket://127。0。0。1:7777", "socket://127.0.0.1:7777\x00",
    # 스킴
    "loop://127.0.0.1:1", "spy://127.0.0.1:1", "socket:/127.0.0.1:7777", "socket:127.0.0.1:7777", "tcp://127.0.0.1:7777",
]


@pytest.mark.parametrize("url", REJECTED)
def test_validate_net_url_rejects(url):
    # resolver 는 무엇이든 루프백으로 푼다 — 거부가 이름 풀이가 아니라 문법·정규형 검사에서 나온다는 뜻
    with pytest.raises(ValidationFailed):
        ports.validate_net_url(url, resolve=LOOPBACK_ONLY)


def test_validate_net_url_lan_hint_says_not_supported():
    with pytest.raises(ValidationFailed) as ei:
        ports.validate_net_url("rfc2217://192.0.2.10:2217")
    text = str(ei.value)
    assert "루프백" in text and "LAN" in text and "지원하지 않" in text
    assert "remote_serial_hosts" not in text  # 아직 없는 설정 키를 에이전트에게 알리지 않는다


def test_validate_net_url_localhost_resolution():
    calls: list = []
    assert ports.validate_net_url("socket://localhost:7777", resolve=_resolver("127.0.0.1", "::1", calls=calls)) \
        == "socket://127.0.0.1:7777"
    assert calls == [("localhost", 7777)]
    # 확인한 주소로 바꾼다: IPv4 가 있으면 첫 IPv4(풀이 순서가 ::1 먼저여도), IPv6 뿐이면 [::1]
    assert ports.validate_net_url("socket://localhost:7777", resolve=_resolver("::1", "127.0.0.1")) == "socket://127.0.0.1:7777"
    assert ports.validate_net_url("rfc2217://localhost:2217", resolve=_resolver("::1")) == "rfc2217://[::1]:2217"
    assert ports.validate_net_url("socket://localhost:7777", resolve=_resolver("127.0.1.1")) == "socket://127.0.1.1:7777"
    for resolve in (_resolver("127.0.0.1", "192.0.2.5"),       # 하나라도 루프백이 아니면 거부
                    _resolver("::ffff:127.0.0.1"),              # IPv4-mapped 는 루프백으로 보지 않는다(fail closed)
                    _resolver("fe80::1%lo"),                     # zone 이 붙은 주소
                    _resolver(),                                  # 결과 없음
                    _raises_gaierror):                            # 풀이 실패
        with pytest.raises(ValidationFailed):
            ports.validate_net_url("socket://localhost:7777", resolve=resolve)


def test_validate_net_url_numeric_hosts_do_not_resolve():
    calls: list = []
    ports.validate_net_url("socket://127.0.0.1:7777", resolve=_resolver("192.0.2.5", calls=calls))
    ports.validate_net_url("socket://[::1]:7777", resolve=_resolver("192.0.2.5", calls=calls))
    with pytest.raises(ValidationFailed):
        ports.validate_net_url("socket://192.0.2.5:7777", resolve=LOOPBACK_ONLY)
    assert calls == []


def test_default_resolver_is_used_lazily(monkeypatch):
    """resolve 를 주지 않으면 모듈의 _getaddrinfo 를 호출 시점에 찾는다 (시험이 바꿔 끼울 수 있다)."""
    calls: list = []
    monkeypatch.setattr(ports, "_getaddrinfo", _resolver("127.0.0.1", calls=calls))
    assert ports.validate_net_url("rfc2217://localhost:2217") == "rfc2217://127.0.0.1:2217"
    monkeypatch.setattr(ports, "_getaddrinfo", _raises_gaierror)
    with pytest.raises(ValidationFailed):
        ports.validate_net_url("rfc2217://localhost:2217")
    assert calls == [("localhost", 2217)]


# ---------------------------------------------------------------------------
# 루프백 호스트 · 리스너
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "localhost", "LOCALHOST"])
def test_is_loopback_host_true(host):
    assert ports.is_loopback_host(host, resolve=LOOPBACK_ONLY)


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "[::1]", "0:0:0:0:0:0:0:1", "::1%lo", "192.0.2.1", "10.0.0.2", "127.1",
                                  "2130706433", "0x7f.1", "localhost.", "example.test", "<broadcast>", None, 2130706433])
def test_is_loopback_host_false(host):
    assert not ports.is_loopback_host(host, resolve=LOOPBACK_ONLY)


def test_check_listen_host():
    assert ports.check_listen_host("127.0.0.1") is False
    assert ports.check_listen_host("localhost", resolve=LOOPBACK_ONLY) is False
    for host in ("0.0.0.0", "", "192.0.2.10"):
        with pytest.raises(ValidationFailed) as ei:
            ports.check_listen_host(host)
        assert "--allow-lan" in (ei.value.hint or "")
        assert ports.check_listen_host(host, allow_lan=True) is True
    assert ports.check_listen_host("127.0.0.1", allow_lan=True) is False  # 루프백이면 노출 없음


@pytest.mark.parametrize("host", ["::1", "[::1]", "::", "::ffff:127.0.0.1", "fe80::1%lo"])
def test_check_listen_host_refuses_ipv6_even_with_allow_lan(host):
    """시뮬레이터 리스너는 AF_INET 전용 — IPv6 주소는 bind 의 gaierror 대신 분명한 ValidationFailed (allow_lan 과 무관)."""
    for allow in (False, True):
        with pytest.raises(ValidationFailed, match="IPv4") as ei:
            ports.check_listen_host(host, allow_lan=allow)
        assert "127.0.0.1" in (ei.value.hint or "")
    assert ports.is_loopback_host("::1")  # URL 쪽 판정(rfc2217://[::1]:P)은 그대로 루프백


# ---------------------------------------------------------------------------
# 끝점 키 (같은 콘솔의 다른 표기를 한 포트로)
# ---------------------------------------------------------------------------


def test_endpoint_key_collapses_loopback_url_aliases():
    aliases = ["socket://127.0.0.1:7777", "SOCKET://127.0.0.1:7777", "socket://127.0.0.2:7777", "socket://127.255.255.254:7777",
               "socket://[::1]:7777", "rfc2217://127.0.0.1:7777", "rfc2217://[::1]:7777", "socket://localhost:7777",
               " socket://LOCALHOST:7777 "]
    assert {ports.endpoint_key(a, resolve=LOOPBACK_ONLY) for a in aliases} == {"net-loopback:7777"}
    assert ports.endpoint_key("socket://127.0.0.1:7778") == "net-loopback:7778"


def test_endpoint_key_other_forms(tmp_path):
    assert ports.endpoint_key("loop://") == "loop://"
    assert ports.endpoint_key("com12") == ports.endpoint_key("COM12") == "COM12"
    target = tmp_path / "ttyFAKE0"
    target.write_text("")
    link = tmp_path / "by-id-link"
    link.symlink_to(target)
    assert ports.endpoint_key(str(link)) == ports.endpoint_key(str(target)) == str(target.resolve())


@pytest.mark.parametrize("url", ["socket://192.0.2.10:7777", "socket://127.0.0.1", "socket://user@127.0.0.1:7777"])
def test_endpoint_key_refuses_unvalidated_remote_urls(url):
    with pytest.raises(ValidationFailed):
        ports.endpoint_key(url, resolve=LOOPBACK_ONLY)


def test_lan_listen_warning_text():
    msg = ports.lan_listen_warning("0.0.0.0", 4321)
    assert "0.0.0.0:4321" in msg and "LAN" in msg and "socket://127.0.0.1:4321" in msg
    assert "0.0.0.0:4321" in ports.lan_listen_warning("", 4321)  # 빈 문자열 = 모든 주소
