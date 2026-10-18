"""비밀번호 해시 식별과 오프라인 대조 (fw_crack_hashes, fw_rootfs_audit).

목적: 운영자 소유 기기의 펌웨어에 들어 있는 해시가 '공개된 기본 비밀번호'인지 확인하는 감사.
네트워크 로그인 시도는 하지 않는다 (사전 대입은 오직 펌웨어에서 뽑은 해시에 대해 오프라인으로만).

순수 Python 구현 (crypt 모듈은 Python 3.13 에서 제거되므로 의존하지 않음):
- md5crypt ($1$), apr1 ($apr1$) — PHK FreeBSD crypt-md5 알고리즘
- sha256crypt ($5$), sha512crypt ($6$) — Drepper SHA-crypt 명세 (crypt 모듈이 있으면 속도를 위해 그쪽 사용)
- 전통 DES crypt (13자, 앞 8자만 유효) — FIPS 46-3 표 + crypt(3) salt 의 E 박스 교환
- XiongMai Sofia 8자 해시 (MD5 다이제스트 2바이트씩 합 % 62 → 영숫자; 빈 비밀번호 = 'tlJwpbo6')
- 솔트 없는 md5/sha1/sha256 hex
bcrypt/yescrypt 등은 crypt 모듈이 있고 libcrypt 가 지원할 때만 확인 (아니면 not_checked).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
import warnings
from typing import Any, Iterable

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ITOA_IDX = {c: i for i, c in enumerate(ITOA64)}

try:  # crypt 는 3.11+ 에서 DeprecationWarning, 3.13 에서 제거
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import crypt as _crypt  # type: ignore
except Exception:  # pragma: no cover - 환경에 따라
    _crypt = None


def _to64(v: int, n: int) -> str:
    out = []
    for _ in range(n):
        out.append(ITOA64[v & 0x3F])
        v >>= 6
    return "".join(out)


# ---------------------------------------------------------------------------
# md5crypt / apr1
# ---------------------------------------------------------------------------


def md5_crypt(password: bytes | str, salt: bytes | str, magic: str = "$1$") -> str:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    s = salt.encode("latin-1") if isinstance(salt, str) else salt
    s = s.split(b"$", 1)[0][:8]
    mg = magic.encode("ascii")
    alt = hashlib.md5(pw + s + pw).digest()
    ctx = hashlib.md5(pw + mg + s)
    pl = len(pw)
    while pl > 0:
        ctx.update(alt[: min(16, pl)])
        pl -= 16
    i = len(pw)
    while i:
        ctx.update(b"\x00" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if i & 1 else final)
        if i % 3:
            c.update(s)
        if i % 7:
            c.update(pw)
        c.update(final if i & 1 else pw)
        final = c.digest()
    f = final
    enc = (
        _to64((f[0] << 16) | (f[6] << 8) | f[12], 4)
        + _to64((f[1] << 16) | (f[7] << 8) | f[13], 4)
        + _to64((f[2] << 16) | (f[8] << 8) | f[14], 4)
        + _to64((f[3] << 16) | (f[9] << 8) | f[15], 4)
        + _to64((f[4] << 16) | (f[10] << 8) | f[5], 4)
        + _to64(f[11], 2)
    )
    return f"{magic}{s.decode('latin-1')}${enc}"


# ---------------------------------------------------------------------------
# SHA-crypt ($5$ / $6$)
# ---------------------------------------------------------------------------

_SHA512_ORDER = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
    (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
    (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41),
]
_SHA256_ORDER = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)]


def _b64_24(b2: int, b1: int, b0: int, n: int) -> str:
    return _to64((b2 << 16) | (b1 << 8) | b0, n)


def parse_sha_crypt(h: str) -> tuple[str, int | None, str] | None:
    """'$5$[rounds=N$]salt$hash' → (variant, rounds or None, salt)."""
    m = re.match(r"^\$([56])\$(?:rounds=(\d+)\$)?([^$]{0,16})\$[./0-9A-Za-z]+$", h)
    if not m:
        return None
    return m.group(1), (int(m.group(2)) if m.group(2) else None), m.group(3)


def sha_crypt(password: bytes | str, salt: str, rounds: int | None = None, variant: str = "6") -> str:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    H = hashlib.sha512 if variant == "6" else hashlib.sha256
    hl = 64 if variant == "6" else 32
    custom = rounds is not None
    r = 5000 if rounds is None else max(1000, min(999_999_999, int(rounds)))
    s = salt.encode("latin-1")[:16]
    B = H(pw + s + pw).digest()
    a = H(pw + s)
    a.update(B * (len(pw) // hl) + B[: len(pw) % hl])
    i = len(pw)
    while i > 0:
        a.update(B if i & 1 else pw)
        i >>= 1
    A = a.digest()
    dp = H(pw * len(pw)).digest()
    P = dp * (len(pw) // hl) + dp[: len(pw) % hl]
    ds = H(s * (16 + A[0])).digest()
    S = ds * (len(s) // hl) + ds[: len(s) % hl]
    C = A
    for i in range(r):
        c = H()
        c.update(P if i & 1 else C)
        if i % 3:
            c.update(S)
        if i % 7:
            c.update(P)
        c.update(C if i & 1 else P)
        C = c.digest()
    if variant == "6":
        enc = "".join(_b64_24(C[a_], C[b_], C[c_], 4) for a_, b_, c_ in _SHA512_ORDER) + _b64_24(0, 0, C[63], 2)
    else:
        enc = "".join(_b64_24(C[a_], C[b_], C[c_], 4) for a_, b_, c_ in _SHA256_ORDER) + _b64_24(0, C[31], C[30], 3)
    rounds_part = f"rounds={r}$" if custom else ""
    return f"${variant}${rounds_part}{s.decode('latin-1')}${enc}"


# ---------------------------------------------------------------------------
# 전통 DES crypt
# ---------------------------------------------------------------------------

_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(v: int, table: list[int], nbits_in: int) -> int:
    out = 0
    for pos in table:
        out = (out << 1) | ((v >> (nbits_in - pos)) & 1)
    return out


def _build_sp() -> list[list[int]]:
    """SP[i][six]: S-box i 의 출력(4비트)을 32비트 위치에 놓고 P 순열을 적용한 값."""
    sp = []
    for i in range(8):
        tab = []
        for six in range(64):
            row = ((six >> 4) & 2) | (six & 1)
            col = (six >> 1) & 0xF
            val = _SBOX[i][row * 16 + col]
            pre = val << (28 - 4 * i)
            tab.append(_permute(pre, _P, 32))
        sp.append(tab)
    return sp


_SP = _build_sp()


def _des_subkeys(key64: int) -> list[tuple[int, ...]]:
    cd = _permute(key64, _PC1, 64)
    c, d = cd >> 28, cd & 0x0FFFFFFF
    keys = []
    for sh in _SHIFTS:
        c = ((c << sh) | (c >> (28 - sh))) & 0x0FFFFFFF
        d = ((d << sh) | (d >> (28 - sh))) & 0x0FFFFFFF
        k = _permute((c << 28) | d, _PC2, 56)
        keys.append(tuple((k >> (42 - 6 * j)) & 0x3F for j in range(8)))
    return keys


def _rev6(v: int) -> int:
    return int(f"{v & 0x3F:06b}"[::-1], 2)


def _des_rounds(L: int, R: int, keys: list[tuple[int, ...]], m0: int, m1: int, iterations: int) -> tuple[int, int]:
    sp0, sp1, sp2, sp3, sp4, sp5, sp6, sp7 = _SP
    for _ in range(iterations):
        for k in keys:
            x = ((((R & 1) << 32) | R) << 1) | (R >> 31)
            e0 = (x >> 28) & 0x3F
            e1 = (x >> 24) & 0x3F
            e2 = (x >> 20) & 0x3F
            e3 = (x >> 16) & 0x3F
            e4 = (x >> 12) & 0x3F
            e5 = (x >> 8) & 0x3F
            e6 = (x >> 4) & 0x3F
            e7 = x & 0x3F
            if m0:
                t = (e0 ^ e4) & m0
                e0 ^= t
                e4 ^= t
            if m1:
                t = (e1 ^ e5) & m1
                e1 ^= t
                e5 ^= t
            f = (sp0[e0 ^ k[0]] | sp1[e1 ^ k[1]] | sp2[e2 ^ k[2]] | sp3[e3 ^ k[3]]
                 | sp4[e4 ^ k[4]] | sp5[e5 ^ k[5]] | sp6[e6 ^ k[6]] | sp7[e7 ^ k[7]])
            L, R = R, L ^ f
        L, R = R, L
    return L, R


def des_encrypt_block(key64: int, block64: int) -> int:
    """표준 DES 한 블록 (구현 자체 검증용)."""
    keys = _des_subkeys(key64)
    ip = _permute(block64, _IP, 64)
    L, R = _des_rounds(ip >> 32, ip & 0xFFFFFFFF, keys, 0, 0, 1)
    return _permute((L << 32) | R, _FP, 64)


def _salt_val(c: str) -> int:
    o = ord(c)
    if o > ord("Z"):
        o -= 6
    if o > ord("9"):
        o -= 7
    return (o - ord(".")) & 0x3F


def des_crypt(password: bytes | str, salt: str) -> str:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    if len(salt) < 2:
        raise ValueError("DES salt 는 2자")
    key = 0
    for i in range(8):
        c = pw[i] if i < len(pw) else 0
        key = (key << 8) | ((c << 1) & 0xFF)
    keys = _des_subkeys(key)
    m0 = _rev6(_salt_val(salt[0]))
    m1 = _rev6(_salt_val(salt[1]))
    L, R = _des_rounds(0, 0, keys, m0, m1, 25)
    out = _permute((L << 32) | R, _FP, 64) << 2
    enc = "".join(ITOA64[(out >> (60 - 6 * i)) & 0x3F] for i in range(11))
    return salt[:2] + enc


# ---------------------------------------------------------------------------
# XiongMai Sofia 해시
# ---------------------------------------------------------------------------


def sofia_hash(password: bytes | str) -> str:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    d = hashlib.md5(pw).digest()
    out = []
    for i in range(8):
        n = (d[2 * i] + d[2 * i + 1]) % 0x3E
        if n > 9:
            n += 61 if n > 35 else 55
        else:
            n += 0x30
        out.append(chr(n))
    return "".join(out)


# ---------------------------------------------------------------------------
# 식별
# ---------------------------------------------------------------------------

_DES_RE = re.compile(r"^[./0-9A-Za-z]{13}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SOFIA_RE = re.compile(r"^[0-9A-Za-z]{8}$")
LOCKED_MARKERS = {"*", "!", "!!", "x", "*LK*", "NP", "!*", "LK", "*NP*"}


def identify_hash(h: str, hint: str | None = None) -> dict[str, Any]:
    """해시 문자열 → {algorithm, locked, salt?, weak, note}."""
    raw = h
    locked = False
    if h.startswith("!") and len(h) > 2 and h not in LOCKED_MARKERS:
        locked = True
        h = h.lstrip("!")
    if raw == "":
        return {"algorithm": "empty", "weak": True, "locked": False, "note": "비밀번호 없음 (빈 필드) — 무비밀번호 로그인 가능"}
    if raw in LOCKED_MARKERS or (raw.startswith("*") and len(raw) < 13):
        return {"algorithm": "locked", "weak": False, "locked": True, "note": "잠긴/비활성 계정 또는 shadow 사용 표시"}
    if hint:
        hint = hint.lower()
        if hint in ("xm-sofia", "sofia") and _SOFIA_RE.match(h):
            return {"algorithm": "xm-sofia", "weak": True, "locked": locked, "note": "XiongMai Sofia 8자 MD5 파생 해시 (솔트 없음)"}
        if hint in ("md5", "md5-hex") and len(h) == 32 and _HEX_RE.match(h):
            return {"algorithm": "md5-hex", "weak": True, "locked": locked, "note": "솔트 없는 MD5"}
    if h.startswith("$1$"):
        return {"algorithm": "md5crypt", "salt": h[3:].split("$", 1)[0][:8], "weak": True, "locked": locked, "note": "MD5-crypt (약함, GPU 로 빠르게 대입 가능)"}
    if h.startswith("$apr1$"):
        return {"algorithm": "apr1", "salt": h[6:].split("$", 1)[0][:8], "weak": True, "locked": locked, "note": "Apache MD5 (apr1)"}
    if h.startswith("$5$") or h.startswith("$6$"):
        p = parse_sha_crypt(h)
        algo = "sha256crypt" if h[1] == "5" else "sha512crypt"
        return {"algorithm": algo, "salt": p[2] if p else None, "rounds": (p[1] if p and p[1] else 5000), "weak": False, "locked": locked, "note": "SHA-crypt"}
    if re.match(r"^\$2[abxy]?\$\d\d\$", h):
        return {"algorithm": "bcrypt", "weak": False, "locked": locked, "note": "bcrypt"}
    if h.startswith("$y$"):
        return {"algorithm": "yescrypt", "weak": False, "locked": locked, "note": "yescrypt"}
    if h.startswith("$gy$"):
        return {"algorithm": "gost-yescrypt", "weak": False, "locked": locked, "note": "gost-yescrypt"}
    if h.startswith("$7$"):
        return {"algorithm": "scrypt", "weak": False, "locked": locked, "note": "scrypt"}
    if h.startswith("$md5"):
        return {"algorithm": "sun-md5", "weak": True, "locked": locked, "note": "Sun MD5"}
    if _DES_RE.match(h):
        return {"algorithm": "des", "salt": h[:2], "weak": True, "locked": locked, "note": "전통 DES crypt (비밀번호 앞 8자만 유효, 매우 약함)"}
    if h.startswith("_") and len(h) == 20:
        return {"algorithm": "bsdi-des", "weak": True, "locked": locked, "note": "BSDi 확장 DES"}
    if _HEX_RE.match(h):
        if len(h) == 32:
            return {"algorithm": "md5-hex", "weak": True, "locked": locked, "note": "솔트 없는 MD5 hex (추정)"}
        if len(h) == 40:
            return {"algorithm": "sha1-hex", "weak": True, "locked": locked, "note": "솔트 없는 SHA1 hex (추정)"}
        if len(h) == 64:
            return {"algorithm": "sha256-hex", "weak": True, "locked": locked, "note": "솔트 없는 SHA256 hex (추정)"}
    if _SOFIA_RE.match(h):
        return {"algorithm": "xm-sofia?", "weak": True, "locked": locked, "note": "8자 영숫자: XiongMai Sofia 해시일 수 있음 (hint='xm-sofia' 로 확정 대조)"}
    return {"algorithm": "unknown", "weak": None, "locked": locked, "note": "알 수 없는 형식"}


# ---------------------------------------------------------------------------
# 대조
# ---------------------------------------------------------------------------


def _crypt_module_check(h: str, pw: str) -> bool | None:
    if _crypt is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            out = _crypt.crypt(pw, h)
    except (OSError, ValueError):
        return None
    if not out or out.startswith("*"):
        return None
    return hmac.compare_digest(out, h)


def check_password(algo: str, h: str, pw: str, *, prefer_crypt_module: bool = True) -> bool | None:
    """True/False, 확인 불가면 None."""
    hh = h.lstrip("!") if h.startswith("!") and len(h) > 2 else h
    if algo == "des":
        return hmac.compare_digest(des_crypt(pw.encode("utf-8")[:8], hh[:2]), hh)
    if algo == "md5crypt":
        return hmac.compare_digest(md5_crypt(pw, hh[3:], "$1$"), hh)
    if algo == "apr1":
        return hmac.compare_digest(md5_crypt(pw, hh[6:], "$apr1$"), hh)
    if algo in ("sha256crypt", "sha512crypt"):
        if prefer_crypt_module:
            r = _crypt_module_check(hh, pw)
            if r is not None:
                return r
        p = parse_sha_crypt(hh)
        if p is None:
            return None
        return hmac.compare_digest(sha_crypt(pw, p[2], p[1], p[0]), hh)
    if algo == "xm-sofia":
        return hmac.compare_digest(sofia_hash(pw), hh)
    if algo == "md5-hex":
        return hmac.compare_digest(hashlib.md5(pw.encode("utf-8")).hexdigest(), hh.lower())
    if algo == "sha1-hex":
        return hmac.compare_digest(hashlib.sha1(pw.encode("utf-8")).hexdigest(), hh.lower())
    if algo == "sha256-hex":
        return hmac.compare_digest(hashlib.sha256(pw.encode("utf-8")).hexdigest(), hh.lower())
    if algo in ("bcrypt", "yescrypt", "gost-yescrypt", "scrypt", "sun-md5", "bsdi-des"):
        return _crypt_module_check(hh, pw)
    return None


def crypt_module_available() -> bool:
    return _crypt is not None


def parse_hash_input(item: Any) -> dict[str, Any] | None:
    """입력 항목 정규화: 'user:hash:...' 줄, 순수 해시 문자열, 또는 {user, hash, type} 딕셔너리."""
    if isinstance(item, dict):
        h = item.get("hash")
        if h is None:
            return None
        return {"user": item.get("user"), "hash": str(h).strip(), "hint": item.get("type") or item.get("hint"), "source": item.get("source")}
    if not isinstance(item, str):
        return None
    s = item.strip()
    if not s:
        return None
    if ":" in s and not s.startswith("$"):
        parts = s.split(":")
        if len(parts) >= 2 and parts[0] and not parts[0].startswith("{"):
            return {"user": parts[0], "hash": parts[1], "hint": None, "source": "passwd-line"}
    return {"user": None, "hash": s, "hint": None, "source": "raw"}


def candidate_list(words: Iterable[str], user: str | None, algo: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def add(w: str) -> None:
        key = w.encode("utf-8")[:8].decode("utf-8", "ignore") if algo == "des" else w
        if key in seen:
            return
        seen.add(key)
        out.append(w)

    add("")
    if user:
        add(user)
    for w in words:
        add(w)
    return out


def crack_entries(entries: list[dict[str, Any]], words: list[str], *, deadline: float | None, known_hashes: dict[str, dict[str, Any]] | None = None, progress: Any = None) -> list[dict[str, Any]]:
    """각 해시를 후보 사전과 대조. deadline(monotonic) 을 넘으면 남은 항목은 partial 로 표시."""
    known_hashes = known_hashes or {}
    results = []
    for idx, ent in enumerate(entries):
        h = ent["hash"]
        info = identify_hash(h, ent.get("hint"))
        algo = info["algorithm"]
        res: dict[str, Any] = {"user": ent.get("user"), "hash": h, "source": ent.get("source"), "algorithm": algo, "note": info.get("note")}
        if ent.get("file"):
            res["file"] = ent["file"]
        if ent.get("line") is not None:
            res["line"] = ent["line"]
        kh = known_hashes.get(h.lstrip("!"))
        if kh:
            res["known_hash"] = kh
        if algo == "empty":
            res.update(status="empty", password="", candidates_tried=0)
            results.append(res)
            continue
        if algo in ("locked", "unknown", "xm-sofia?"):
            res.update(status="not_checked", candidates_tried=0)
            if algo == "xm-sofia?":
                res["note"] = info["note"]
            results.append(res)
            continue
        cands = candidate_list(words, ent.get("user"), algo)
        tried = 0
        status = "not_cracked"
        found = None
        for pw in cands:
            if deadline is not None and time.monotonic() > deadline:
                status = "partial"
                break
            r = check_password(algo, h, pw)
            tried += 1
            if r is None:
                status = "not_checked"
                res["note"] = f"{algo}: 이 환경에서 확인할 수 없음 (crypt 모듈/libcrypt 미지원)"
                break
            if r:
                status = "cracked"
                found = pw
                break
        res.update(status=status, candidates_tried=tried, candidates_total=len(cands))
        if found is not None:
            res["password"] = found
            if algo == "des" and len(found.encode("utf-8")) > 8:
                res["note"] = "DES 는 앞 8자만 사용: 실제 비밀번호는 이 값으로 시작하는 더 긴 문자열일 수 있음"
        results.append(res)
        if progress:
            progress(idx + 1, len(entries), f"{idx + 1}/{len(entries)} 해시 확인")
    return results
