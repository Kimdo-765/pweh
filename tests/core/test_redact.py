"""pweh.safety.redact: 옮긴 자격증명 패턴(fwtriage 와 같은 정의), 콘솔 키 규칙·값 토큰 끝까지 가림, 알려진 비밀값,
열린 줄(open_tail), 정규화 사본(쪼갠 키), 이스케이프, ESP 스택 블록, PEM 블록, 적대적 16 KiB 줄의 처리 시간."""

from __future__ import annotations

import logging
import random
import string
import struct
import time

import pytest

from pweh.console import escape_controls
from pweh.safety import redact as R
from pweh.safety.masking import mask_secret
from pweh.safety.redact import (
    CONSOLE_CRED_RX,
    CONSOLE_KEY_RX,
    CRED_RX,
    NON_VALUES,
    PEM_LINE_TOKEN,
    PEM_MAX_LINES,
    QUOTED_CRED_RX,
    STACK_PENDING_TOKEN,
    ConsoleRedactor,
    KnownSecrets,
    redact_line,
)


def red(text: str, known: KnownSecrets | None = None, **kw) -> str:
    return redact_line(text, known, **kw)[0]


def distinct_value(n: int, *, spaces: bool = False) -> str:
    """앞뒤 2글자가 마스킹 표시에 보여도 다른 부분과 겹치지 않는 결정적 값."""
    alphabet = string.ascii_letters + string.digits
    rnd = random.Random(n * 7 + (1 if spaces else 0))
    chars = [rnd.choice(alphabet) for _ in range(n)]
    if spaces:
        for i in range(5, n - 5, 9):
            chars[i] = " "
    return "".join(chars)


# ---------------------------------------------------------------------------
# fwtriage 에서 옮긴 정의
# ---------------------------------------------------------------------------


def test_fwtriage_uses_the_core_definitions():
    from fwtriage_mcp import rootfs

    assert rootfs.CRED_RX is CRED_RX
    assert rootfs._QUOTED_CRED_RX is QUOTED_CRED_RX
    assert rootfs._NON_VALUES is NON_VALUES
    # fwtriage 자체 표시 함수(자기 mask_secret)는 그대로 — 출력이 바뀌지 않는다
    assert rootfs.mask_credentials("mount -t cifs -o username=admin,password=admin //nas/rec /mnt/sd") == \
        "mount -t cifs -o username=admin,password=ad*** //nas/rec /mnt/sd"
    assert rootfs.mask_credentials("wget http://cam/admin/cfg.cgi?password=admin -O /x") == \
        "wget http://cam/admin/cfg.cgi?password=ad*** -O /x"
    assert "horse" not in rootfs.mask_credentials('PASSWORD="correct horse battery" ./x')


def test_moved_patterns_keep_their_positions():
    names = [n for n, _ in CRED_RX]
    assert names == ["builtin-config-password", "builtin-xml-password", "builtin-url-credential"]
    cfg = dict(CRED_RX)
    m = cfg["builtin-config-password"].search("wifi_password = hunter2;x")
    assert m and m.group("key") == "wifi_password" and m.group("val") == "hunter2"
    m = cfg["builtin-config-password"].search("x" + "a" * 70)  # 키 없음
    assert m is None
    m = cfg["builtin-xml-password"].search("<psk>abc</psk>")
    assert m and m.group("val") == "abc"
    m = cfg["builtin-url-credential"].search("rtsp://admin:12345@10.0.0.2/live")
    assert m and (m.group("key"), m.group("val")) == ("admin", "12345")
    m = QUOTED_CRED_RX.search('passwd = "a b c"')
    assert m and m.group("val") == "a b c"
    assert {"none", "true", "disabled", "value"} <= NON_VALUES and isinstance(NON_VALUES, frozenset)


# ---------------------------------------------------------------------------
# 콘솔 키 규칙과 리뷰에서 나온 줄
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("line, expected", [
    ("password:my secret phrase", "password:<가림 16자>"),
    ("psk=ab;cdefghijklmnopq", "psk=<가림 18자>"),
    ("pass: hi there friend", "pass: <가림 15자>"),
    ("password=Abc,defghijklmnop1234", "password=<가림 21자>"),
    ("token=eyAbc123.zz", "token=<가림 11자>"),
    ("api_key=XyZ-123_abc", "api_key=<가림 11자>"),
    ("API-KEY: abcdef", "API-KEY: <가림 6자>"),
    ("access_key = AKIA1234 rest", "access_key = <가림 13자>"),
    ("auth_key:k", "auth_key:<가림 1자>"),
    ("private-key=xyz", "private-key=<가림 3자>"),
    ("auth: user:pw", "auth: <가림 7자>"),
    ("secret 0123456789", "secret <가림 10자>"),  # 공백 구분
    ("wifi password hunter2 ok", "wifi password <가림 10자>"),
    ("wifi_password=hunter2", "wifi_password=<가림 7자>"),  # 식별자 접두
    ("mqttpass:abc", "mqttpass:<가림 3자>"),
    ('{"password": "hunter2", "n": 1}', '{"password": <가림 18자>'),  # JSON 키 뒤 닫는 따옴표
    ("PASSPHRASE = long one", "PASSPHRASE = <가림 8자>"),
    ("Password: wrong password", "Password: <가림 14자>"),
    ("password incorrect", "password <가림 9자>"),  # 과잉 마스킹은 받아들인다
    ("BLE passkey: 123456", "BLE passkey: <가림 6자>"),
    ("Passcode = 9876 ok", "Passcode = <가림 7자>"),
])
def test_console_key_rule_masks_to_end_of_line(line, expected):
    assert red(line) == expected


@pytest.mark.parametrize("line", ["Password:", "Password: ", "Password ", "login: ", "esp32> ", "passwords: 3 stored",
                                  "authenticated", "tokens left", "I (123) boot: ESP-IDF v5.1.2"])
def test_key_without_value_or_no_key_stays_visible(line):
    assert red(line) == line
    assert red(line, open_tail=True) == line


def test_zero_width_split_key_is_masked_and_escaped():
    out = red("pass​word=hunter2pass")
    assert out == "pass\\u200bword=<가림 11자>"
    assert "hunter2" not in out
    # 다른 보이지 않는 글자로 쪼개도 같다(태그 문자, 이체 선택자, 사용자 정의 영역, bidi)
    for ch in ("\U000e0041", "️", "", "‮", "⁠", "﻿", "\x7f", "\x9b"):
        out = red(f"pass{ch}word=hunter2pass")
        assert "hunter2" not in out and out.endswith("=<가림 11자>"), (ch, out)


def test_ansi_split_key_is_masked():
    assert red("\x1b[1mpass\x1b[0mword=hunter2\x1b[0m") == "password=<가림 7자>"


def test_key_rule_is_leftmost_and_linear():
    rx = CONSOLE_KEY_RX
    m = rx.search("user=admin password=x token=y")
    assert m and m.group(0) == "password="
    assert red("user=admin password=x token=y") == "user=admin password=<가림 9자>"


# ---------------------------------------------------------------------------
# 값 토큰 끝까지 가림 (64·256 상한을 넘는 값)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [65, 257, 300])
def test_unquoted_value_extends_to_token_end(n):
    v = distinct_value(n)
    # rootpw 는 키 규칙에 없는 CRED_RX 키 — 값 토큰 확장만으로 가려져야 한다
    assert red(f"rootpw={v} tail") == f"rootpw={mask_secret(v)} tail"
    assert red(f"rootpw={v};next") == f"rootpw={mask_secret(v)};next"
    # 키 규칙 키는 줄 끝까지
    assert red(f"wifi_password={v} tail") == f"wifi_password=<가림 {n + 5}자>"
    assert red(f"psk={v}") == f"psk=<가림 {n}자>"


@pytest.mark.parametrize("n", [65, 257, 300])
def test_quoted_value_extends_to_closing_quote_or_eol(n):
    v = distinct_value(n, spaces=True)
    assert red(f'rootpw="{v}" tail') == f'rootpw="{mask_secret(v)}" tail'
    assert red(f"rootpw='{v}' tail") == f"rootpw='{mask_secret(v)}' tail"
    assert red(f'rootpw="{v}') == f'rootpw="{mask_secret(v)}'  # 닫히지 않으면 줄 끝까지
    assert red(f'psk="{v}" tail') == f"psk=<가림 {n + 7}자>"  # 키 규칙
    out = red(f'rootpw="{v}" tail')
    assert v[2:-2] not in out and v[:20] not in out


@pytest.mark.parametrize("n", [65, 257, 300])
def test_open_tail_values_touching_the_end_are_length_only(n):
    v = distinct_value(n)
    assert red(f"rootpw={v}", open_tail=True) == f"rootpw=<가림 {n}자>"
    vq = distinct_value(n, spaces=True)
    assert red(f'rootpw="{vq}', open_tail=True) == f'rootpw="<가림 {n}자>'
    # 끝에 닿지 않은(닫힌) 값은 보통 표시
    assert red(f'rootpw="{vq}" x', open_tail=True) == f'rootpw="{mask_secret(vq)}" x'
    assert red(f"password={v}", open_tail=True) == f"password=<가림 {n}자>"


def test_open_tail_short_values():
    assert red("password=ab", open_tail=True) == "password=<가림 2자>"
    assert red("rootpw=abcdefghijklmnop", open_tail=True) == "rootpw=<가림 16자>"
    assert red("rootpw=abcdefghijklmnop") == f"rootpw={mask_secret('abcdefghijklmnop')}"


def test_non_values_and_paths_follow_fwtriage_rules():
    # 키 규칙이 없는 형태에서만 확인한다(키 규칙은 password=none 도 가린다)
    for line in ("rootpw=none", "<password>none</password>", "rootpw=/etc/shadow", "rootpw=$ROOT_PW",
                 "rootpw=******", "rootpw=xxxx", "http://user:$PASS@host"):
        assert red(line) == line, line
    assert red("password=none") == "password=<가림 4자>"


# ---------------------------------------------------------------------------
# 콘솔 추가 패턴
# ---------------------------------------------------------------------------


def test_console_patterns_individually():
    pats = dict(CONSOLE_CRED_RX)
    m = pats["console-space-password"].search("rootpw ab")
    assert m and m.group("val") == "ab"
    m = pats["console-space-password"].search("psk: x")
    assert m and m.group("val") == "x"
    m = pats["console-quoted-value"].search('rootpw="' + "Q" * 300)
    assert m and len(m.group("val")) == 256
    m = pats["console-authorization"].search("Authorization: Bearer abc.def")
    assert m and m.group("val") == "abc.def"
    m = pats["console-bearer"].search("got Bearer " + "A1b2" * 5)
    assert m and m.group("val") == "A1b2" * 5
    assert pats["console-bearer"].search("basic mode enabled") is None  # 토큰 모양이 아님
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
    m = pats["console-jwt"].search(f"tok {jwt} end")
    assert m and m.group("val") == jwt
    m = pats["console-xml-secret"].search("<token>" + "z" * 80)
    assert m and m.group("val") == "z" * 64
    m = pats["console-url-credential"].search("mqtts://dev:" + "p" * 300 + "@broker")
    assert m and m.group("val") == "p" * 300


def test_console_patterns_through_redact_line():
    tok = "abcDEF123ghiJKL456mno"
    assert red(f"Authorization: Bearer {tok}") == f"Authorization: Bearer <가림 {len(tok)}자>"
    assert red(f"Proxy-Authorization: Basic {tok}==") == f"Proxy-Authorization: Basic <가림 {len(tok) + 2}자>"
    assert red(f"hdr Bearer {tok} ok") == f"hdr Bearer {mask_secret(tok)} ok"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
    assert red(f"cookie {jwt} ok") == f"cookie {mask_secret(jwt)} ok"
    pw = distinct_value(100)
    assert red(f"connect http://admin:{pw}@cam/x") == f"connect http://admin:{mask_secret(pw)}@cam/x"
    assert red("<passphrase>" + "k" * 90 + "</passphrase>") == f"<passphrase>{mask_secret('k' * 90)}</passphrase>"


@pytest.mark.parametrize("user_size,value_size", [(8, 1500), (512, 1500), (8, 12000)])
def test_url_secret_longer_than_pattern_seed_is_masked(user_size, value_size):
    user = "u" * user_size
    value = distinct_value(value_size)
    prefix = f"https://{user}:"
    assert red(prefix + value + "@example.invalid/path") == prefix + mask_secret(value) + "@example.invalid/path"
    # @ 가 다음 수신 조각에서 올 때도 값의 앞부분을 먼저 내보내지 않는다.
    assert red(prefix + value, open_tail=True) == prefix + f"<가림 {value_size}자>"
    assert red("https://example.invalid:8080/path") == "https://example.invalid:8080/path"


@pytest.mark.parametrize("header_size,body_size", [(5000, 32), (32, 9000)])
def test_jwt_long_parts_within_line_limit_do_not_bypass_masking(header_size, body_size):
    value = "eyJ" + distinct_value(header_size) + "." + distinct_value(body_size) + ".signature"
    assert red("cookie " + value + " end") == "cookie " + mask_secret(value) + " end"


# ---------------------------------------------------------------------------
# 알려진 비밀값
# ---------------------------------------------------------------------------

SECRET = b"Zq9hunter2pass"


def test_known_secret_raw_hex_and_spaced_hex():
    k = KnownSecrets([SECRET])
    assert k.count == 1 and len(k) == 1 and "hunter" not in repr(k)
    h = SECRET.hex()
    sp = " ".join(f"{b:02x}" for b in SECRET)
    for form in (SECRET.decode(), h, h.upper(), sp, sp.upper(), h[:10].upper() + h[10:]):
        assert red(f"cfg {form}, end", k) == "cfg ⟪비밀 14바이트⟫, end", form
    # 비밀값 자체가 키 낱말(pass)로 끝나고 공백이 이어지면 키 규칙이 줄 끝까지 가린다(과잉 마스킹 — 안전한 쪽)
    assert red(f"cfg {SECRET.decode()} end", k) == "cfg ⟪비밀 14바이트⟫ <가림 3자>"
    assert k.spans(f"a {h} b {SECRET.decode()}") == [(2, 2 + len(h)), (2 + len(h) + 3, 2 + len(h) + 3 + 14)]


def test_hex_forms_only_for_long_enough_values():
    k = KnownSecrets([b"k3Yz9"])  # 5 바이트 < min_hex_len 6
    assert red("v k3Yz9 x", k) == "v ⟪비밀 5바이트⟫ x"
    assert red(f"v {b'k3Yz9'.hex()} x", k) == f"v {b'k3Yz9'.hex()} x"
    k6 = KnownSecrets([b"k3Yz9Q"])
    assert red(f"v {b'k3Yz9Q'.hex()} x", k6) == "v ⟪비밀 6바이트⟫ x"


def test_low_entropy_candidates_are_dropped():
    k = KnownSecrets([b"\xff\xff\xff\xff", b"\x00" * 16, b"aaaaaaa", b"abab", b"aab\x00", b"xyz", SECRET + b"\x00\x00"])
    assert k.count == 1  # SECRET 만 (끝 NUL 제거 뒤)
    line = "invalid header: 0xffffffff"
    assert red(line, k) == line
    assert red("pad 00000000000000000000000000000000 abab", k) == "pad 00000000000000000000000000000000 abab"
    assert red(SECRET.decode(), k) == "⟪비밀 14바이트⟫"


def test_known_secret_limits_dedupe_and_chunking():
    long_val = distinct_value(300).encode()
    k = KnownSecrets([long_val, long_val, "문자열값도됨".encode(), "str-value-ok"], max_len=256)
    assert k.count == 4  # 300 바이트 → 256 + 끝 256 조각, 중복 제거, str 도 받는다
    out = red(f"x {long_val.decode()} y", k)
    assert long_val.decode()[:8] not in out and long_val.decode()[-8:] not in out and out.startswith("x ⟪비밀")
    assert red("v=문자열값도됨!", k).startswith("v=⟪비밀 18바이트⟫")
    many = KnownSecrets([f"secret-{i:04d}-value".encode() for i in range(400)])
    assert many.count == 256
    with pytest.raises(TypeError):
        KnownSecrets([1234])


def test_many_secrets_use_the_index_path_and_find_all_occurrences():
    vals = [f"S{i:03d}-{distinct_value(10 + i % 7)}".encode() for i in range(100)]
    k = KnownSecrets(vals)
    assert k._raw.index is not None and k._hex.index is not None
    line = f"{vals[3].decode()}|{vals[3].hex()}|{vals[50].decode()}"
    out = red(line, k)
    assert out.count("⟪비밀") == 3 and vals[3].decode() not in out


def test_binary_secret_with_control_bytes():
    blob = b"\x01\x02key\x03\xfe\xfdZZ"
    k = KnownSecrets([blob])
    text = blob.decode("utf-8", "surrogateescape")
    out = red(f"dump {text} end", k)
    assert out == f"dump ⟪비밀 {len(blob)}바이트⟫ end"
    assert red(f"hex {blob.hex()}", k) == f"hex ⟪비밀 {len(blob)}바이트⟫"


def test_prefix_tail_and_hold():
    k = KnownSecrets([SECRET])
    assert k.prefix_tail("cfg dump Zq9hu") == 5
    assert k.prefix_tail("cfg dump zq9hu") == 0  # 원문은 대소문자를 가린다
    assert k.prefix_tail("x 5A713968") == 8  # hex 앞부분 (대소문자 무관)
    assert k.prefix_tail("x 5a 71 39 ") == 9  # 공백 구분 hex, 끝 공백 포함
    assert k.prefix_tail("x Zq9hunter2pass") == 0  # 온전한 비밀은 spans 가 맡는다
    assert k.prefix_tail("") == 0
    assert red("cfg dump Zq9hu", k, open_tail=True) == "cfg dump ⟪보류 5자⟫"
    assert red("cfg dump Zq9hu", k) == "cfg dump Zq9hu"  # 완성된 줄은 보류하지 않는다
    assert red("x 5A 71 3", k, open_tail=True) == "x ⟪보류 7자⟫"


# ---------------------------------------------------------------------------
# 이스케이프
# ---------------------------------------------------------------------------


def test_escape_of_invisible_and_control_characters():
    cases = {
        "\x1b": "\\x1b", "\x00": "\\x00", "\x7f": "\\x7f", "\x85": "\\x85", "​": "\\u200b", "‏": "\\u200f",
        "⁠": "\\u2060", "⁤": "\\u2064", "﻿": "\\ufeff", "‮": "\\u202e", "\U000e0041": "\\U000e0041",
        "\U000e007f": "\\U000e007f", "️": "\\ufe0f", "\U000e0100": "\\U000e0100", "͏": "\\u034f",
        "": "\\ue000", "\U000f0000": "\\U000f0000", "\udcff": "\\udcff", " ": "\\u2028", " ": "\\u2029",
        "­": "\\xad", "͸": "\\u0378",
    }
    for ch, esc in cases.items():
        assert escape_controls(f"a{ch}b") == f"a{esc}b", repr(ch)
        if ch != "\x1b":  # ESC + 글자는 2바이트 ESC 시퀀스라 redact_line 이 지운다
            assert red(f"a{ch}b") == f"a{esc}b", repr(ch)
    assert red("a\x1b") == "a\\x1b" and red("a\x1bb") == "a"
    for keep in ("한국어", "é", "é", "😀", " ", "\t", "÷", "①", "«»", "　"):
        assert red(f"a{keep}b") == f"a{keep}b" == escape_controls(f"a{keep}b"), repr(keep)


def test_output_is_always_json_safe():
    import json

    raw = b"\xff\xfe password=\x1b[31mhun\xe2\x80\x8bter\x00 \xc3"
    out = red(raw.decode("utf-8", "surrogateescape"))
    json.dumps(out)  # 서로게이트가 남지 않는다
    assert "hun" not in out and "ter" not in out


# ---------------------------------------------------------------------------
# ESP 스택 블록
# ---------------------------------------------------------------------------


def _stack_lines(payload: bytes, base: int = 0x3FC8A5D0, per_line: int = 8) -> list[str]:
    payload += b"\x00" * ((-len(payload)) % 4)
    words = [struct.unpack("<I", payload[i:i + 4])[0] for i in range(0, len(payload), 4)]
    out = []
    for i in range(0, len(words), per_line):
        out.append(f"{base + i * 4:08x}: " + " ".join(f"0x{w:08x}" for w in words[i:i + per_line]))
    return out


def test_stack_memory_block_masks_words_and_counts_embedded_secret():
    k = KnownSecrets([SECRET])
    payload = b"\x00" * 26 + SECRET + b"\x00" * 24  # 비밀이 두 줄에 걸친다
    lines = _stack_lines(payload)
    assert len(lines) >= 2
    r = ConsoleRedactor(k)
    outs = [r.redact(ln) for ln in ["Guru Meditation Error: Core  0 panic'ed (Load access fault)", "MEPC    : 0x4038e5b6  RA      : 0x4038e5a0",
                                    "Stack memory:", *lines, "ELF file SHA256: 0123456789abcdef", "Rebooting..."]]
    texts = [t for t, _c in outs]
    assert texts[0].startswith("Guru Meditation Error") and texts[1].startswith("MEPC")
    assert texts[2] == "Stack memory:"
    assert texts[3:3 + len(lines)] == [f"⟪스택 {len(ln.split()) - 1}워드⟫" for ln in lines]
    assert texts[-2] == "ELF file SHA256: 0123456789abcdef" and texts[-1] == "Rebooting..."
    assert r.stack_secret_hits == 1
    assert sum(c for _t, c in outs[3:3 + len(lines)]) == len(lines) + 1
    assert r.in_block is None
    joined = "\n".join(texts)
    assert "0x" not in "".join(texts[3:3 + len(lines)])
    assert SECRET.decode() not in joined


def test_stack_word_lines_masked_without_header_and_pending_prefix():
    r = ConsoleRedactor(None)
    assert r.redact("3fc8a5d0: 0x00000000 0x4038e5b6")[0] == "⟪스택 2워드⟫"
    assert r.in_block == "stack"
    assert r.redact("3fc8a5d8: 0x0000", open_tail=True)[0] == STACK_PENDING_TOKEN
    assert r.redact("3fc8", open_tail=True)[0] == STACK_PENDING_TOKEN  # 블록 안의 덜 온 주소
    assert r.in_block == "stack"  # 미리보기는 상태를 바꾸지 않는다
    assert r.redact("Backtrace: 0x4038e5b6:0x3fc8a5d0")[0] == "Backtrace: 0x4038e5b6:0x3fc8a5d0"
    assert r.in_block is None
    assert r.redact("1234", open_tail=True)[0] == "1234"  # 블록 밖의 숫자는 그대로
    assert redact_line("3fc8a5d0: 0x00000000", None)[0] == "⟪스택 1워드⟫"  # 상태 없는 한 줄 규칙


# ---------------------------------------------------------------------------
# PEM 블록
# ---------------------------------------------------------------------------


def test_pem_block_until_end_line():
    r = ConsoleRedactor(None)
    lines = ["-----BEGIN " + "RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEAwz3", "Proc-Type: 4,ENCRYPTED", "", "abc",
             "-----END RSA PRIVATE KEY----- token=zzz", "I (99) app: ok"]
    texts = [r.redact(ln)[0] for ln in lines]
    assert texts[0] == lines[0]
    assert texts[1:5] == [PEM_LINE_TOKEN] * 4
    assert texts[5] == "-----END RSA PRIVATE KEY----- token=<가림 3자>"
    assert texts[6] == "I (99) app: ok"
    assert r.in_block is None


def test_pem_block_ends_after_max_lines_without_end():
    r = ConsoleRedactor(None)
    r.redact("-----BEGIN PRIVATE KEY-----")
    for _ in range(PEM_MAX_LINES):
        assert r.redact("QUJDREVGR0g=")[0] == PEM_LINE_TOKEN
    assert r.in_block is None
    assert r.redact("visible again")[0] == "visible again"


def test_pem_single_line_and_open_tail_preview():
    out = red('cfg="-----BEGIN ' + 'EC PRIVATE KEY-----\\nMHcCAQEEIBase64Body\\n-----END EC PRIVATE KEY-----\\n" next')
    assert out == 'cfg="-----BEGIN EC PRIVATE KEY-----⟪개인키 23자⟫-----END EC PRIVATE KEY-----\\n" next'
    r = ConsoleRedactor(None)
    t, c = r.redact("-----BEGIN " + "OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjE", open_tail=True)
    assert t == "-----BEGIN OPENSSH PRIVATE KEY-----⟪개인키 19자⟫" and c == 1
    assert r.in_block is None  # 미리보기
    r.redact("-----BEGIN PRIVATE KEY-----")
    assert r.redact("MIIE", open_tail=True)[0] == PEM_LINE_TOKEN
    assert r.in_block == "pem"
    assert red("-----BEGIN CERTIFICATE-----") == "-----BEGIN CERTIFICATE-----"  # 인증서는 비밀이 아니다


def test_identical_line_cache_respects_block_state():
    k = KnownSecrets([SECRET])
    r = ConsoleRedactor(k)
    a = r.redact("hello Zq9hunter2pass")
    assert r.redact("hello Zq9hunter2pass") == a == ("hello ⟪비밀 14바이트⟫", 1)
    r.redact("-----BEGIN PRIVATE KEY-----")
    assert r.redact("hello Zq9hunter2pass") == (PEM_LINE_TOKEN, 1)
    r.reset()
    assert r.in_block is None and r.redact("hello Zq9hunter2pass") == a


# ---------------------------------------------------------------------------
# 처리 시간 (정규식은 펌웨어가 정한 16 KiB 줄에서도 선형)
# ---------------------------------------------------------------------------

N16K = 16 * 1024


def _fill(unit: str) -> str:
    return (unit * (N16K // len(unit) + 1))[:N16K]


ADVERSARIAL = {
    "a": "a" * N16K, "space": " " * N16K, "eq": "=" * N16K, "colon": ":" * N16K, "quote": '"' * N16K,
    "pw": _fill("password"), "pw_eq": _fill("password="), "pw_sp": _fill("password "), "pass_colon": _fill("pass:"),
    "pass_spaces": "pass=" + " " * (N16K - 6) + "x", "pass_q": _fill('pass="'), "key_tabs": "password" + "\t" * (N16K - 8),
    "prefix": _fill("a.b-c_d") + "password", "xpassword": _fill("xpassword"), "eyJ": _fill("eyJ"), "eyJdot": _fill("eyJa."),
    "url": _fill("http://a:"), "url_long": "http://" + "a" * 60 + ":" + "b" * (N16K - 70), "bearer": _fill("bearer "),
    "bearer_tok": "bearer " + "A" * (N16K - 7), "authz": _fill("authorization: "), "xml": _fill("<password>"),
    "xml_long": "<password>" + "x" * (N16K - 10), "begin": _fill("-----BEGIN "), "begin_words": _fill("-----BEGIN RSA RSA "),
    "end": _fill("-----END "), "hex": _fill("deadbeef: 0x"), "stack_tail": "3fc8a5d0:" + " 0x00000000" * 8 + " " * (N16K - 97) + "z",
    "stack_spaces": "3fc8a5d0: " + " " * (N16K - 20) + "0x1", "esc": _fill("\x1b["), "osc": _fill("\x1b]"), "dcs": _fill("\x1bP"),
    "csi_long": "\x1b[" + "1;" * (N16K // 2 - 2), "psk_sp": _fill("psk "), "tok_q": _fill("token='"),
    "unclosed": 'rootpw="' + "Q" * (N16K - 8), "unclosed_sp": 'rootpw="' + "Q " * (N16K // 2 - 4),
    "mixed": "".join(random.Random(5).choice(string.printable) for _ in range(N16K)),
    "zw": _fill("p​a​s​s="), "nonascii": _fill("비밀번호=값 "),
}


def _best(fn, reps: int = 5) -> float:
    best = float("inf")
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best


def test_every_pattern_is_bounded_on_adversarial_16k_lines():
    from pweh.console import _ANSI_RX

    search = [("CRED_RX:" + n, rx) for n, rx in CRED_RX] + [("QUOTED_CRED_RX", QUOTED_CRED_RX)] + \
             [("CONSOLE_CRED_RX:" + n, rx) for n, rx in CONSOLE_CRED_RX] + \
             [("key rule", CONSOLE_KEY_RX), ("hint", R._CRED_HINT_RX), ("PEM begin", R._PEM_BEGIN_RX),
              ("PEM end", R._PEM_END_RX), ("token stop", R._TOKEN_STOP_RX), ("URL stop", R._URL_VALUE_STOP_RX), ("ANSI", _ANSI_RX)]
    full = [("stack line", R._STACK_LINE_RX), ("stack header", R._STACK_HEADER_RX), ("stack prefix", R._STACK_PREFIX_RX)]
    slow = []
    for name, rx in search:
        for label, line in ADVERSARIAL.items():
            dt = _best(lambda: list(rx.finditer(line)))
            if dt > 0.050:
                slow.append((name, label, round(dt * 1000, 1)))
    for name, rx in full:
        for label, line in ADVERSARIAL.items():
            dt = _best(lambda: rx.fullmatch(line))
            if dt > 0.050:
                slow.append((name, label, round(dt * 1000, 1)))
    assert not slow, f"50 ms 를 넘은 패턴(목표 20 ms): {slow}"


def test_whole_line_redaction_is_bounded_on_adversarial_lines():
    rnd = random.Random(11)
    k = KnownSecrets(["".join(rnd.choice(string.ascii_letters) for _ in range(20)).encode() for _ in range(256)])
    slow = []
    for label, line in ADVERSARIAL.items():
        for open_tail in (False, True):
            dt = _best(lambda: redact_line(line, k, open_tail=open_tail), reps=3)
            if dt > 0.25:
                slow.append((label, open_tail, round(dt * 1000, 1)))
        r = ConsoleRedactor(k)
        dt = _best(lambda: r.redact(line), reps=3)
        if dt > 0.25:
            slow.append((label, "commit", round(dt * 1000, 1)))
    assert not slow, slow


def test_redaction_never_logs_values(caplog):
    caplog.set_level(logging.DEBUG)
    k = KnownSecrets([SECRET])
    r = ConsoleRedactor(k)
    for ln in ("password=SentinelPw123", SECRET.decode(), "-----BEGIN PRIVATE KEY-----", "QUJD", "-----END PRIVATE KEY-----"):
        r.redact(ln)
        r.redact(ln, open_tail=True)
    text = caplog.text
    assert "SentinelPw123" not in text and SECRET.decode() not in text
