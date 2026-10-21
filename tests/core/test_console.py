"""pweh.console: ANSI 제거·이스케이프·UTF-8 자르기와 LineTranscript(레코드 경계 커서, 중간 커서 내림, 반복 접기와 동결,
메모리 한도, 열린 줄의 조용함 규칙, 강제 끊기, close, until 리터럴, 조용한 틈에 나뉜 비밀, 홍수 처리량, 스레드 안전)."""

from __future__ import annotations

import json
import random
import string
import threading
import time

import pytest

from pweh.console import (
    COLLAPSE_SUFFIX,
    CONTINUATION_SUFFIX,
    LineTranscript,
    decode_console,
    escape_controls,
    is_printable_char,
    strip_ansi,
    utf8_safe_cut,
)
from pweh.safety.redact import PEM_LINE_TOKEN, ConsoleRedactor, KnownSecrets

Q = 0.2  # open_quiet_s


def tr(known: KnownSecrets | None = None, **kw) -> LineTranscript:
    return LineTranscript(ConsoleRedactor(known), **kw)


def rd(t: LineTranscript, since=None, max_chars=8000, now=100.0, **kw):
    return t.read(since, max_chars, open_quiet_s=Q, now=now, **kw)


# ---------------------------------------------------------------------------
# 순수 함수
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    ("\x1b[31mred\x1b[0m", "red"),
    ("a\x1b[1;32;40mb", "ab"),
    ("\x1b[?25lhide\x1b[?25h", "hide"),
    ("title\x1b]0;my title\x07after", "titleafter"),
    ("clip\x1b]52;c;c2VjcmV0\x1b\\done", "clipdone"),
    ("dcs\x1bPq#0;2;0;0;0\x1b\\x", "dcsx"),
    ("\x1b(Bascii\x1b)0", "ascii"),
    ("save\x1b7restore\x1b8", "saverestore"),
    ("\x1bcreset", "reset"),
    ("no escapes here", "no escapes here"),
    ("unterminated \x1b]0;title", "unterminated 0;title"),
    ("tail\x1b", "tail\x1b"),
])
def test_strip_ansi(raw, expected):
    assert strip_ansi(raw) == expected


def test_escape_controls_forms_and_allowlist():
    assert escape_controls("plain ASCII ~!") == "plain ASCII ~!"
    assert escape_controls("tab\tkept") == "tab\tkept"
    assert escape_controls("\x00\x1b\x7f\x9b") == "\\x00\\x1b\\x7f\\x9b"
    assert escape_controls("zw​j‍bidi‮⁦bom﻿") == "zw\\u200bj\\u200dbidi\\u202e\\u2066bom\\ufeff"
    assert escape_controls("tag\U000e0041\U000e007f") == "tag\\U000e0041\\U000e007f"
    assert escape_controls("vs︎️\U000e0100\U000e01ef cgj͏") == "vs\\ufe0e\\ufe0f\\U000e0100\\U000e01ef cgj\\u034f"
    assert escape_controls("pua\U000f0001\U00100000") == "pua\\ue000\\U000f0001\\U00100000"
    assert escape_controls("ls ps ") == "ls\\u2028ps\\u2029"
    assert escape_controls("bad\udcff") == "bad\\udcff"
    assert escape_controls("͸unassigned") == "\\u0378unassigned"
    kept = "한글 Ελληνικά é é 😀 ①½ «» ÷  　"
    assert escape_controls(kept) == kept
    assert all(is_printable_char(c) for c in kept) and not is_printable_char("​") and is_printable_char("\t")


def test_utf8_safe_cut():
    assert utf8_safe_cut(b"") == 0
    assert utf8_safe_cut(b"abc") == 3
    s = "가".encode()  # 3 바이트
    assert utf8_safe_cut(b"ab" + s) == 5
    assert utf8_safe_cut(b"ab" + s[:2]) == 2
    assert utf8_safe_cut(b"ab" + s[:1]) == 2
    e = "😀".encode()  # 4 바이트
    assert utf8_safe_cut(e[:3]) == 0 and utf8_safe_cut(e) == 4
    assert utf8_safe_cut(b"\xff\xfe") == 2  # 잘못된 바이트는 그대로 둔다
    assert decode_console(b"a\xffb") == "a\udcffb"


# ---------------------------------------------------------------------------
# 커서·레코드
# ---------------------------------------------------------------------------


def test_record_boundary_cursor_and_mid_cursor_snap():
    t = tr()
    t.feed(b"first line\r\nsecond\nthird\n", 1.0)
    assert t.raw_total == 25
    r = rd(t, 0)
    assert r["text"] == "first line\nsecond\nthird"
    assert (r["cursor_start"], r["cursor_end"], r["lines"], r["more"]) == (0, 25, 3, False)
    for since, start in ((5, 0), (11, 0), (12, 12), (15, 12), (19, 19), (24, 19), (25, 25), (999, 25)):
        assert rd(t, since)["cursor_start"] == start, since
    r = rd(t, 15)
    assert r["text"] == "second\nthird"  # 중간 커서는 레코드 시작으로 내려 맞춘다 (키 없이 값만 나가지 않게)


def test_since_none_continues_from_last_cursor_end():
    t = tr()
    t.feed(b"a\nb\n", 1.0)
    assert rd(t)["text"] == "a\nb"
    assert rd(t)["text"] == ""
    t.feed(b"c\n", 2.0)
    r = rd(t)
    assert r["text"] == "c" and r["cursor_start"] == 4 and r["cursor_end"] == 6


def test_max_chars_splits_on_records_and_more_flag():
    t = tr()
    t.feed(b"".join(f"line-{i:02d}\n".encode() for i in range(10)), 1.0)
    r = rd(t, 0, max_chars=20)
    assert r["text"] == "line-00\nline-01" and r["more"] is True and r["cursor_end"] == 16
    r2 = rd(t, r["cursor_end"], max_chars=20)
    assert r2["text"] == "line-02\nline-03"


def test_long_first_record_is_clipped_but_progress_is_made():
    t = tr()
    t.feed(b"x" * 1000 + b"\nnext\n", 1.0)
    r = rd(t, 0, max_chars=256)
    assert len(r["text"]) == 256 and r["text"].endswith("…⟪줄 잘림⟫") and r["cursor_end"] == 1001
    assert "since_cursor=0" in r["note"]
    assert rd(t, r["cursor_end"])["text"] == "next"


def test_repeat_collapse_frozen_records_and_continuations():
    t = tr()
    t.feed(b"boot\n" + b"invalid header: 0xffffffff\n" * 3, 1.0)
    r = rd(t, 0)
    assert r["text"] == "boot\ninvalid header: 0xffffffff" + COLLAPSE_SUFFIX.format(n=3)
    assert r["text"].endswith("  ⟪위 줄 ×3⟫") and r["collapsed"] == 2 and r["lines"] == 2
    end1 = r["cursor_end"]
    t.feed(b"invalid header: 0xffffffff\n" * 2, 2.0)
    r = rd(t)  # 동결된 레코드 뒤의 같은 줄은 새 '이어짐' 레코드
    assert r["cursor_start"] == end1
    assert r["text"] == "invalid header: 0xffffffff" + CONTINUATION_SUFFIX.format(n=2)
    assert r["text"].endswith("  ⟪위 줄 ×2 더⟫") and r["collapsed"] == 1
    t.feed(b"invalid header: 0xffffffff\nother\n", 3.0)
    r = rd(t)
    assert r["text"] == "invalid header: 0xffffffff  ⟪위 줄 ×1 더⟫\nother"
    # 처음부터 다시 읽어도 표시가 같다 (동결된 레코드는 바뀌지 않는다)
    full = rd(t, 0)["text"].split("\n")
    assert full == ["boot", "invalid header: 0xffffffff  ⟪위 줄 ×3⟫", "invalid header: 0xffffffff  ⟪위 줄 ×2 더⟫",
                    "invalid header: 0xffffffff  ⟪위 줄 ×1 더⟫", "other"]


def test_cursor_advances_during_a_flood():
    t = tr()
    last_end = 0
    for i in range(20):
        t.feed(b"rst:0x3 (SW_RESET)\n" * 50, float(i))
        r = rd(t, now=float(i))
        assert r["cursor_end"] > last_end and r["cursor_end"] == t.raw_total
        last_end = r["cursor_end"]
    assert len(rd(t, 0)["text"].split("\n")) == 20


def test_collapse_uses_masked_text():
    t = tr()
    t.feed(b"password=one1\npassword=two2\n", 1.0)
    r = rd(t, 0)
    assert r["text"] == "password=<가림 4자>  ⟪위 줄 ×2⟫"
    assert "one1" not in r["text"] and "two2" not in r["text"]


def test_memory_caps_drop_oldest_and_report_lost_bytes():
    t = tr(max_records=3)
    t.feed(b"".join(f"r{i}\n".encode() for i in range(6)), 1.0)  # 각 3 바이트
    assert t.dropped_bytes == 9
    r = rd(t, 0)
    assert r["text"] == "r3\nr4\nr5" and r["lost_bytes"] == 9 and r["cursor_start"] == 9 and "밀려나" in r["note"]
    t2 = tr(max_text_bytes=10)
    t2.feed(b"aaaa\nbbbb\ncccc\n", 1.0)
    r2 = rd(t2, 0)
    assert r2["text"] == "bbbb\ncccc" and r2["lost_bytes"] == 5


def test_force_split_long_lines_at_utf8_boundary():
    t = tr(max_line_bytes=16)
    t.feed("가나다라마바사아자차".encode() + b"\n", 1.0)  # 30 바이트 → 15 + 15 (16 바이트 경계는 문자 중간)
    r = rd(t, 0)
    assert r["text"].split("\n") == ["가나다라마", "바사아자차"] and r["cursor_end"] == 31
    t2 = tr(max_line_bytes=16)
    t2.feed(("가" * 10).encode() + b"\n", 1.0)  # 같은 조각은 접힌다
    assert rd(t2, 0)["text"] == "가가가가가  ⟪위 줄 ×2⟫"
    t3 = tr(max_line_bytes=16)
    t3.feed(b"x" * 40, 1.0)
    r3 = rd(t3, 0, now=1.05)
    assert r3["text"] == "x" * 16 + "  ⟪위 줄 ×2⟫" and r3["cursor_end"] == 32 and r3["pending_line"] is None
    assert rd(t3, None, now=2.0)["pending_line"] == "x" * 8


def test_open_line_quiet_rule_pending_and_cursor_stays():
    t = tr()
    t.feed(b"Welcome\nlogin: ", 10.0)
    r = rd(t, 0, now=10.1)
    assert r["text"] == "Welcome" and r["pending_line"] is None and r["pending_raw_end"] is None
    r = rd(t, 0, now=10.25)
    assert r["pending_line"] == "login: " and r["pending_raw_end"] == 15 and r["cursor_end"] == 8
    r = rd(t, None, now=10.3)  # 커서는 열린 줄 시작에 머문다 → 다시 보인다
    assert r["text"] == "" and r["cursor_start"] == 8 and r["pending_line"] == "login: "
    t.feed(b"root\r\n", 11.0)
    r = rd(t, None, now=11.5)
    assert r["text"] == "login: root" and r["pending_line"] is None


def test_pending_hidden_while_more_records_remain_and_partial_utf8_cut():
    t = tr()
    t.feed(b"one\ntwo\nprompt> ", 1.0)
    r = rd(t, 0, max_chars=3, now=5.0)
    assert r["text"] == "one" and r["more"] is True and r["pending_line"] is None
    t2 = tr()
    t2.feed(b"\xea\xb0\x80\xea\xb0", 1.0)  # '가' + 잘린 문자
    r2 = rd(t2, 0, now=2.0)
    assert r2["pending_line"] == "가" and r2["pending_raw_end"] == 3


def test_pending_line_uses_open_tail_rules():
    k = KnownSecrets([b"Zq9hunter2pass"])
    t = tr(k)
    t.feed(b"Password:", 1.0)
    assert rd(t, now=2.0)["pending_line"] == "Password:"
    t.feed(b" hun", 3.0)
    assert rd(t, now=4.0)["pending_line"] == "Password: <가림 3자>"
    t2 = tr(k)
    t2.feed(b"cfg dump Zq9hu", 1.0)
    assert rd(t2, now=2.0)["pending_line"] == "cfg dump ⟪보류 5자⟫"


def test_close_finalizes_open_line_with_open_tail_rules():
    k = KnownSecrets([b"Zq9hunter2pass"])
    t = tr(k)
    t.feed(b"ok\ncfg dump Zq9hun", 1.0)
    t.close(2.0)
    assert t.closed
    r = rd(t, 0, now=9.0)
    assert r["text"] == "ok\ncfg dump ⟪보류 6자⟫" and r["pending_line"] is None and r["cursor_end"] == t.raw_total
    t.feed(b"ignored\n", 3.0)
    assert t.raw_total == 18 and rd(t, 0, now=9.0)["text"] == "ok\ncfg dump ⟪보류 6자⟫"
    t.close(4.0)  # 두 번 불러도 된다


def test_tail_reads_from_the_end_and_moves_the_cursor():
    t = tr()
    t.feed(b"".join(f"l{i}\n".encode() for i in range(10)) + b"> ", 1.0)
    r = t.tail(8, now=5.0)
    assert r["text"] == "l7\nl8\nl9" and r["cursor_end"] == 30 and r["pending_line"] == "> "
    assert rd(t, now=5.0)["text"] == ""  # 에이전트 커서가 끝으로 옮겨졌다
    r1 = t.tail(1, now=5.0)  # 한도가 아주 작아도 max_chars 를 넘지 않고 적어도 한 레코드를 넘긴다
    assert r1["text"] == "l" and r1["lines"] == 1 and "note" in r1
    r2 = t.tail(9, now=5.0)
    assert r2["text"] == "l7\nl8\nl9" and len(r2["text"]) <= 9


def test_peek_and_find_until_do_not_change_state():
    t = tr()
    t.feed(b"a\n" * 3 + b"boot done\n", 1.0)
    r = rd(t, 0, max_chars=4, peek=True, until="done")
    assert r["matched"] is False and r["more"] is True  # 넘긴 글 안에서만 맞춘다
    assert t.find_until("done", since=0, open_quiet_s=Q, now=2.0) == "done"  # 모든 레코드를 본다
    assert rd(t)["cursor_start"] == 0  # peek 는 커서를 옮기지 않았다
    t.feed(b"a\n", 2.0)
    assert rd(t, 0)["text"].split("\n")[0] == "a  ⟪위 줄 ×3⟫"  # peek 는 동결하지 않았다 → 아직 한 레코드


# ---------------------------------------------------------------------------
# until (리터럴만)
# ---------------------------------------------------------------------------


def test_until_literals_on_masked_lines_and_quiet_pending_prompt():
    t = tr()
    t.feed(b"Booting...\nPASSWORD=hunter2\nlogin: ", 1.0)
    r = rd(t, 0, now=1.1, until=["login:", "Booting"])
    assert r["matched"] and r["match"] == "Booting" and r["pending_line"] is None
    r = rd(t, 11, now=1.1, until="login:")
    assert r["matched"] is False  # 열린 줄은 아직 조용하지 않다
    r = rd(t, 11, now=1.5, until="login:")
    assert r["matched"] and r["match"] == "login:" and r["pending_line"] == "login: "
    assert rd(t, 0, now=1.5, until="hunter2")["matched"] is False  # 마스킹한 글에서만 찾는다 — 비밀로 찾을 수 없다
    assert rd(t, 0, now=1.5, until="booting", until_ignore_case=True)["match"] == "booting"
    assert rd(t, 0, now=1.5, until="booting")["matched"] is False
    r = rd(t, 0, now=1.5, until=["zzz", "PASSWORD=", "Boot"])
    assert r["match"] == "Boot"  # 가장 앞선 줄의 가장 앞 리터럴
    r = rd(t, 0, now=1.5, until=["ing...", "Boot"])
    assert r["match"] == "Boot"
    assert rd(t, 0, now=1.5, until=[])["matched"] is False and rd(t, 0, now=1.5)["match"] is None


# ---------------------------------------------------------------------------
# 조용한 틈에 나뉜 비밀 — 어떤 읽기 순서로도 원문이 나오지 않는다
# ---------------------------------------------------------------------------

SECRET = b"Zq9hunter2pass"


def _all_outputs(t: LineTranscript, now: float) -> list[str]:
    outs = []
    for since in list(range(0, t.raw_total + 2)) + [None]:
        for mc in (256, 8000):
            r = t.read(since, mc, open_quiet_s=Q, now=now, peek=True)
            outs.append(json.dumps(r, ensure_ascii=False))
    for mc in (1, 8, 64, 8000):
        r = t.tail(mc, now=now)
        outs.append(json.dumps(r, ensure_ascii=False))
    return outs


def _assert_no_leak(outs: list[str], secret: str, minlen: int = 4) -> None:
    pieces = {secret[i:i + minlen] for i in range(len(secret) - minlen + 1)}
    for o in outs:
        for p in pieces:
            assert p not in o, (p, o)


@pytest.mark.parametrize("first, second, secret", [
    (b"cfg dump Zq9hu", b"nter2pass end\n", SECRET.decode()),  # 알려진 비밀 원문
    (b"key: " + SECRET.hex().encode()[:9], SECRET.hex().encode()[9:] + b" done\n", SECRET.hex()),  # hex
    (b"key: " + b" ".join(f"{x:02x}".encode() for x in SECRET)[:13],
     b" ".join(f"{x:02x}".encode() for x in SECRET)[13:] + b" done\n", " ".join(f"{x:02x}" for x in SECRET)),  # 공백 hex
    (b"wifi password=Mx7q", b"Lp2vRt8z\n", "Mx7qLp2vRt8z"),  # 키 패턴(알려지지 않은 값)
    (b'rootpw="Kd83', b'jf92Hs" ok\n', "Kd83jf92Hs"),
])
def test_secret_split_across_quiet_gap_never_leaks(first, second, secret):
    k = KnownSecrets([SECRET])
    t = tr(k)
    t.feed(b"boot ok\n" + first, 1.0)
    _assert_no_leak(_all_outputs(t, 1.05), secret)  # 아직 조용하지 않음
    _assert_no_leak(_all_outputs(t, 5.0), secret)  # 조용함 → 열린 줄이 보인다
    t.feed(second, 6.0)
    _assert_no_leak(_all_outputs(t, 6.01), secret)
    _assert_no_leak(_all_outputs(t, 9.0), secret)
    t.feed(b"after\n", 10.0)
    t.close(11.0)
    _assert_no_leak(_all_outputs(t, 12.0), secret)


def test_secret_cut_by_close_is_held():
    k = KnownSecrets([SECRET])
    t = tr(k)
    t.feed(b"x Zq9hunt", 1.0)
    t.close(2.0)
    _assert_no_leak(_all_outputs(t, 3.0), SECRET.decode())


# ---------------------------------------------------------------------------
# 블록·이스케이프·sink
# ---------------------------------------------------------------------------


def test_pem_block_through_transcript_and_pending_inside_block():
    t = tr()
    t.feed(b"-----BEGIN " + b"PRIVATE KEY-----\nMIIEvQIBADANBg\nkqhkiG9w0BAQEF\nAASC", 1.0)
    r = rd(t, 0, now=5.0)
    assert r["text"] == f"-----BEGIN PRIVATE KEY-----\n{PEM_LINE_TOKEN}  ⟪위 줄 ×2⟫"
    assert r["pending_line"] == PEM_LINE_TOKEN  # 블록 안의 열린 줄
    t.feed(b"BKcwggSjAgEAAoIB\n-----END PRIVATE KEY-----\nvisible\n", 6.0)
    r = rd(t, None, now=9.0)
    assert r["text"] == f"{PEM_LINE_TOKEN}  ⟪위 줄 ×1 더⟫\n-----END PRIVATE KEY-----\nvisible"


def test_invalid_utf8_and_controls_are_escaped_and_json_safe():
    t = tr()
    t.feed(b"bad \xff\xfe bytes \x1b]0;t\x07 \x07bell\r mid\x00\n\x1b[31mred\x1b[0m\n", 1.0)
    r = rd(t, 0)
    assert r["text"] == "bad \\udcff\\udcfe bytes  \\x07bell\\x0d mid\\x00\nred"
    json.dumps(r)


def test_sink_receives_final_masked_records():
    got: list[tuple] = []
    t = LineTranscript(ConsoleRedactor(None), sink=lambda *a: got.append(a))
    t.feed(b"a\na\npassword=hunter2\nb", 1.0)
    assert [g[0] for g in got] == ["a  ⟪위 줄 ×2⟫"]  # 마지막 레코드는 아직 바뀔 수 있다
    t.feed(b"\n", 2.0)
    assert [g[0] for g in got] == ["a  ⟪위 줄 ×2⟫", "password=<가림 7자>"]
    t.close(3.0)
    assert [g[0] for g in got][-1] == "b" and got[0][1:3] == (0, 4) and got[1][1:3] == (4, 21)
    assert all("hunter2" not in g[0] for g in got)

    def boom(*_a):
        raise RuntimeError("disk full")

    t2 = LineTranscript(ConsoleRedactor(None), sink=boom)
    t2.feed(b"x\ny\n", 1.0)  # sink 실패가 콘솔 처리를 멈추지 않는다
    assert rd(t2, 0)["text"] == "x\ny"


def test_counters():
    t = tr()
    t.feed(b"password=a1\nok\nok\n", 1.0)
    assert t.lines_total == 3 and t.masked_total == 1 and t.last_feed == 1.0


def test_constructor_validates_limits():
    with pytest.raises(ValueError):
        LineTranscript(ConsoleRedactor(None), max_records=0)


# ---------------------------------------------------------------------------
# 처리량·스레드
# ---------------------------------------------------------------------------


def test_flood_with_many_known_secrets_collapses_quickly():
    rnd = random.Random(3)
    secrets = ["".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(rnd.randint(8, 40))).encode()
               for _ in range(255)] + [b"\xff\xff\xff\xff"]
    k = KnownSecrets(secrets)
    assert k.count == 255  # 0xFFFFFFFF 는 흔한 값이라 버린다
    t = tr(k)
    blob = b"invalid header: 0xffffffff\n" * 50000
    t0 = time.perf_counter()
    for i in range(0, len(blob), 4096):
        t.feed(blob[i:i + 4096], 1.0)
    dt = time.perf_counter() - t0
    r = rd(t, 0)
    assert r["text"] == "invalid header: 0xffffffff  ⟪위 줄 ×50000⟫"
    assert dt < 5.0, dt
    # 서로 다른 줄의 홍수도 버틴다 (마스킹 경로를 모두 지남)
    t2 = tr(k)
    lines = b"".join(f"I ({i}) wifi:state: auth -> assoc heap={30000 + i}\n".encode() for i in range(10000))
    t0 = time.perf_counter()
    t2.feed(lines, 2.0)
    assert time.perf_counter() - t0 < 5.0


def test_concurrent_feed_and_read():
    t = tr(KnownSecrets([SECRET]))
    stop = threading.Event()
    errors: list[BaseException] = []

    def feeder():
        try:
            for i in range(3000):
                t.feed(f"line {i} Zq9hunter2pass\n".encode() if i % 7 == 0 else f"line {i}\n".encode(), float(i))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            stop.set()

    def reader():
        try:
            while not stop.is_set():
                r = t.read(None, 4000, open_quiet_s=Q, now=1e9)
                assert "hunter2" not in r["text"]
                t.tail(500, now=1e9)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = [threading.Thread(target=feeder), threading.Thread(target=reader), threading.Thread(target=reader)]
    for x in th:
        x.start()
    for x in th:
        x.join(30)
    assert not errors, errors
    assert t.lines_total == 3000


def test_carriage_returns_around_lines_are_dropped():
    t = tr()
    t.feed(b"crlf\r\nlfcr\n\rnext\n\r\r\ncrcrlf\r\r\nmid\rcr\n", 1.0)
    assert rd(t, 0)["text"] == "crlf\nlfcr\nnext\n\ncrcrlf\nmid\\x0dcr"


def test_default_force_split_at_16_kib():
    t = tr()
    t.feed(b"y" * (40 * 1024), 1.0)
    r = rd(t, 0, max_chars=65536, now=1.0)
    assert r["text"] == "y" * 16384 + "  ⟪위 줄 ×2⟫" and r["cursor_end"] == 32768
    t.feed(b"\n", 2.0)
    assert rd(t, None, max_chars=65536, now=3.0)["text"] == "y" * (8 * 1024)


def test_redaction_failure_hides_the_line():
    class Broken:
        def redact(self, line, *, open_tail=False):
            raise RuntimeError("bug")

    t = LineTranscript(Broken())  # type: ignore[arg-type]
    t.feed(b"password=hunter2\nprompt> ", 1.0)
    r = rd(t, 0, now=5.0)
    assert r["text"] == "⟪마스킹 실패로 숨긴 줄⟫" and r["pending_line"] == "⟪마스킹 실패로 숨긴 줄⟫"
    assert "hunter2" not in json.dumps(r, ensure_ascii=False)
