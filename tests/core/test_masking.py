"""비밀값 마스킹(pweh.safety.masking) 테스트: 케이스 솔트 다이제스트, 솔트 파일 권한, 표시용 마스킹."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading

import pytest

from pweh.errors import PwehError, ValidationFailed
from pweh.runtime import get_runtime, reset_runtimes
from pweh.safety import Classification, Risk, mask_secret, secret_digest
from pweh.safety.masking import SALT_BYTES, SecretMasker, digest_with_salt

pytestmark = pytest.mark.anyio

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{16}$")
#: 16진수 글자가 섞이지 않은 평문이라 다이제스트에 우연히 들어갈 수 없다
PLAIN = "PwdHunterZzQ!kor"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_digest_format_stable_per_case_and_isolated(workspace):
    rt = get_runtime("test")
    d1 = rt.secret_digest("case-a", PLAIN)
    assert DIGEST_RE.match(d1)
    assert PLAIN not in d1 and PLAIN.lower() not in d1 and "Hunter" not in d1
    assert rt.secret_digest("case-a", PLAIN) == d1  # 같은 케이스·같은 값 → 같은 다이제스트 (재시도 지문이 맞는다)
    assert rt.secret_digest("case-a", PLAIN.encode()) == d1  # 바이트로 줘도 같다
    assert rt.secret_digest("case-b", PLAIN) != d1  # 케이스가 다르면 다르다 (케이스 사이에 연결되지 않음)
    assert rt.secret_digest("case-a", PLAIN + "x") != d1
    salt = (workspace["state_dir"] / "salts" / "case-a.key").read_bytes()
    assert len(salt) == SALT_BYTES == 32
    assert d1 == "sha256:" + hashlib.sha256(salt + PLAIN.encode()).hexdigest()[:16] == digest_with_salt(salt, PLAIN)
    assert secret_digest("case-a", PLAIN) == d1  # 모듈 함수도 설정의 state_dir 를 쓴다
    reset_runtimes()  # 서버 재시작 뒤에도 같은 솔트
    assert get_runtime("test").secret_digest("case-a", PLAIN) == d1


def test_salt_file_is_0600_in_0700_dir(workspace):
    rt = get_runtime("test")
    rt.secret_digest("case-perm", PLAIN)
    salts = workspace["state_dir"] / "salts"
    key = salts / "case-perm.key"
    assert (key.stat().st_mode & 0o777) == 0o600
    assert (salts.stat().st_mode & 0o777) == 0o700
    assert sorted(p.name for p in salts.iterdir()) == ["case-perm.key"]  # 임시 파일이 남지 않는다
    # 누가 권한을 넓혀 두었으면 0600 으로 되돌린다
    os.chmod(key, 0o644)
    rt.secret_digest("case-perm", PLAIN)
    assert (key.stat().st_mode & 0o777) == 0o600


def test_salt_is_created_lazily_and_concurrently_once(workspace):
    salts = workspace["state_dir"] / "salts"
    masker = SecretMasker(salts)
    assert not salts.exists()
    results: list[str] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(SecretMasker(salts).digest("case-race", PLAIN))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(set(results)) == 1
    assert masker.digest("case-race", PLAIN) == results[0]
    assert sorted(p.name for p in salts.iterdir()) == ["case-race.key"]


def test_corrupt_or_odd_salt_is_refused(workspace):
    salts = workspace["state_dir"] / "salts"
    masker = SecretMasker(salts)
    salts.mkdir(parents=True)
    (salts / "case-short.key").write_bytes(b"12345")
    with pytest.raises(PwehError) as ei:
        masker.digest("case-short", PLAIN)
    assert ei.value.code == "salt_corrupt"
    assert (salts / "case-short.key").read_bytes() == b"12345"  # 자동으로 다시 만들지 않는다
    target = salts / "elsewhere.bin"
    target.write_bytes(b"\x00" * 32)
    (salts / "case-link.key").symlink_to(target)
    with pytest.raises(PwehError) as ei:
        masker.digest("case-link", PLAIN)
    assert ei.value.code == "salt_invalid"
    for bad in ("../escape", "a/b", "", ".hidden", "x."):
        with pytest.raises(ValidationFailed):
            masker.digest(bad, PLAIN)
    with pytest.raises(ValidationFailed):
        masker.digest("case-ok", 12345)  # type: ignore[arg-type]


def test_mask_secret_reveals_little():
    assert mask_secret("abcdefghijklmnopqrst") == "ab…st (20자)"
    assert mask_secret("abcdefghijkl") == "a…l (12자)"
    assert mask_secret("1234") == "<가림 4자>"  # 짧은 PIN 은 길이만
    assert mask_secret("abcdefghi") == "<가림 9자>"
    assert mask_secret("") == "<빈 값>"
    assert mask_secret(None) == "<없음>"
    assert mask_secret(b"\xa0\xa1\xa2\xa3\xa4\xa5") == "<가림 6바이트>"  # 이진 키는 내용을 보이지 않는다
    long = "SuperSecretToken-1234567890"
    shown = mask_secret(long)
    assert "SuperSecret" not in shown and "1234567890" not in shown and shown.endswith("(27자)")


async def test_gate_action_with_digest_keeps_plaintext_out_of_audit(workspace, auth):
    """사용 규칙 시연: 게이트 action·classification.matched 에 다이제스트를 쓰면 감사 로그·승인 레코드에 원문이 없다."""
    workspace["set_safety"](modify_policy="approve", approval_methods=["cli"])
    rt = get_runtime("test")
    case = rt.cases.create(title="mask", authorization=auth, case_id="mask-case")
    digest = rt.secret_digest(case.id, PLAIN)
    cls = Classification(Risk.MODIFY, "nfc.pwd_auth", "PWD_AUTH 한 번", f"PWD_AUTH {digest}")
    d = await rt.authorize(tool="nfc_pwd_auth", action={"uid": "04A1B2", "password": digest}, classification=cls, case_id=case.id)
    assert d.status == "approval_required"
    texts = [(workspace["state_dir"] / "audit.jsonl").read_text(encoding="utf-8"), (case.dir / "audit.jsonl").read_text(encoding="utf-8"),
             json.dumps(rt.approvals.get(d.approval_id), ensure_ascii=False)]
    for text in texts:
        assert PLAIN not in text and digest in text
