"""비밀값 마스킹: 케이스 솔트 다이제스트와 표시용 마스킹.

대상: 콘솔 PWD_AUTH 비밀번호, 사용자 MIFARE 키, 롤링코드·고정코드 값, 비대상 RF 기기 ID, SD·NVS 에서 찾은 Wi-Fi PSK·클라우드 토큰 등.

규칙 (모든 서버):
  - 원문은 꼭 필요한 케이스 파일에만 둔다. 도구 응답·보고서에는 ``mask_secret(값)`` 만 싣는다.
  - **게이트 ``action`` 딕셔너리와 ``Classification.matched`` 에는 원문 대신 ``secret_digest(case_id, 값)``**(또는 ``"<given>"``)만 넣는다.
    그러면 승인 지문(action_fingerprint)도 다이제스트에 묶이고, 감사 로그·승인 레코드·``approval_status`` 응답·보고서에 원문이 남지 않는다.
    같은 값은 같은 케이스에서 늘 같은 다이제스트라 재시도 지문이 맞고, 케이스가 다르면 다이제스트도 달라 케이스 사이에 연결되지 않는다.
  - 증명 subject 에 비밀이 들어가야 하면 역시 다이제스트를 쓴다.
  - 한계: 솔트는 같은 OS 계정의 에이전트가 읽을 수 있다(파일 도구, 자동 허용된 REA ``open_binary`` + ``read_bytes`` 같은 MCP 도구.
    ``case_import_file`` 은 state_dir 의 파일을 거부한다). 그래서 다이제스트는 보고서·감사 로그를 읽는 제3자에게서 원문을 가리지만,
    에이전트에게서 낮은 엔트로피 값(짧은 PIN, 32비트 PWD_AUTH, 24–32비트 ID)을 가리지는 못한다 — 솔트를 알면 전수 대입으로 되돌릴 수 있다.
    그런 값은 게이트에 넣지 말고(``"<given>"``) 비대상 정보는 개수만 남긴다. 에이전트에게서도 가리려면 MCP 서버와 ``.pweh/state`` 를
    별도 OS 계정으로 분리한다(docs/safety.md §3.4).

솔트: ``<state_dir>/salts/<case_id>.key`` — 32 바이트 난수, 처음 쓸 때 만들고 파일 권한 0600(디렉터리 0700). 한 번 만든 솔트는 바꾸지 않는다
(바꾸면 기존 다이제스트·승인 지문이 모두 달라진다). 크기가 32 바이트가 아니면 다시 만들지 않고 오류를 낸다.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
import tempfile
from pathlib import Path

from ..errors import PwehError, ValidationFailed

log = logging.getLogger("pweh.safety.masking")

SALT_BYTES = 32
DIGEST_HEX_CHARS = 16
DIGEST_PREFIX = "sha256:"


def _check_case_id(case_id: str) -> str:
    from ..case import CASE_ID_RE

    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise ValidationFailed(f"잘못된 case_id: {case_id!r}")
    return case_id


def _as_bytes(value: str | bytes | bytearray) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ValidationFailed(f"비밀값은 문자열이나 바이트여야 합니다 (받은 형식: {type(value).__name__}).")


def digest_with_salt(salt: bytes, value: str | bytes | bytearray) -> str:
    """``'sha256:' + sha256(salt || value) 의 앞 16 hex``."""
    return DIGEST_PREFIX + hashlib.sha256(bytes(salt) + _as_bytes(value)).hexdigest()[:DIGEST_HEX_CHARS]


class SecretMasker:
    """케이스별 솔트를 관리하고 다이제스트를 만든다. 디렉터리·솔트는 처음 쓸 때 만든다."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)

    def salt_path(self, case_id: str) -> Path:
        return self.dir / f"{_check_case_id(case_id)}.key"

    def _read(self, path: Path) -> bytes | None:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise PwehError(f"솔트 파일이 일반 파일이 아닙니다: {path}", code="salt_invalid")
        if st.st_mode & 0o077:
            log.warning("솔트 파일 권한을 0600 으로 고칩니다: %s (%o)", path, stat.S_IMODE(st.st_mode))
            os.chmod(path, 0o600)
        data = path.read_bytes()
        if len(data) != SALT_BYTES:
            raise PwehError(
                f"솔트 파일 크기가 {SALT_BYTES} 바이트가 아닙니다: {path} ({len(data)} 바이트)",
                code="salt_corrupt",
                hint="솔트를 다시 만들면 기존 다이제스트·승인 지문이 모두 달라지므로 자동으로 고치지 않는다. 사람이 확인해야 한다.",
            )
        return data

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:  # pragma: no cover
            pass

    def salt(self, case_id: str) -> bytes:
        """케이스 솔트(없으면 만든다). 여러 프로세스가 동시에 만들어도 한 값만 남는다(임시 파일 → 하드 링크)."""
        path = self.salt_path(case_id)
        data = self._read(path)
        if data is not None:
            return data
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(prefix=f".{case_id}.", suffix=".tmp", dir=str(self.dir))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(SALT_BYTES))
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, path)  # 원자적: 내용이 다 찬 파일만 보인다. 이미 있으면 다른 프로세스가 이겼다.
            except FileExistsError:
                pass
            except OSError:  # 하드 링크를 못 쓰는 파일시스템: O_EXCL 로 만든다
                try:
                    out = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    pass
                else:
                    with os.fdopen(out, "wb") as fh, open(tmp, "rb") as src:
                        fh.write(src.read())
                        fh.flush()
                        os.fsync(fh.fileno())
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        data = self._read(path)
        if data is None:  # pragma: no cover
            raise PwehError(f"솔트 파일을 만들지 못했습니다: {path}", code="salt_invalid")
        return data

    def digest(self, case_id: str, value: str | bytes | bytearray) -> str:
        """``secret_digest`` 와 같다 (이 저장소의 솔트 사용)."""
        return digest_with_salt(self.salt(case_id), value)


def secret_digest(case_id: str, value: str | bytes | bytearray, *, salts_dir: Path | None = None) -> str:
    """비밀값의 케이스 솔트 다이제스트: ``'sha256:<sha256(salt || value) 의 앞 16 hex>'``.

    게이트 action·``classification.matched``·감사 기록·승인 지문에는 원문 대신 이 값을 쓴다(모듈 설명 참고).
    salts_dir 를 주지 않으면 현재 설정의 ``<state_dir>/salts`` 를 쓴다(서버에서는 ``rt().secret_digest`` 를 권장).
    """
    if salts_dir is None:
        from ..config import load_config

        salts_dir = load_config().state_dir / "salts"
    return SecretMasker(Path(salts_dir)).digest(case_id, value)


def mask_secret(value: str | bytes | bytearray | None) -> str:
    """표시용 마스킹. 문자열은 길이에 따라 앞뒤 일부만 보인다(16자 이상: 앞뒤 2자, 10–15자: 앞뒤 1자, 그보다 짧으면 길이만).

    바이트(키 등 이진 비밀)는 내용을 전혀 보이지 않고 길이만 보인다. 짧은 PIN 이 통째로 드러나지 않게 한다.
    """
    if value is None:
        return "<없음>"
    if isinstance(value, (bytes, bytearray)):
        return f"<가림 {len(value)}바이트>"
    text = str(value)
    n = len(text)
    if n == 0:
        return "<빈 값>"
    keep = 2 if n >= 16 else (1 if n >= 10 else 0)
    if keep == 0:
        return f"<가림 {n}자>"
    return f"{text[:keep]}…{text[-keep:]} ({n}자)"


__all__ = [
    "DIGEST_HEX_CHARS",
    "SALT_BYTES",
    "SecretMasker",
    "digest_with_salt",
    "mask_secret",
    "secret_digest",
]
