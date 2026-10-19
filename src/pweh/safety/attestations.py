"""사람 증명(attestation) 저장소와 요청 도우미.

에이전트가 스스로 채울 수 없는 사실을 사람이 확인한 기록이다. 예: 콘솔 오프라인, 결제 수단 제거, 배선 = 채널 라벨과 사람이 잰 전압,
태그의 목적·소유, 쓰기 방지 장치 사용, 가져온 파일의 출처. 승인(``ApprovalStore``)은 한 번 쓰면 사라지고(consume) 짧게 만료되지만,
증명은 **소비되지 않고 재사용**되며 대상(subject)·바인딩(binding)·만료(expires_at)에 묶인다.

흐름:
  1. 서버가 필요한 증명을 ``require(kind, subject, binding)`` 로 직접 찾는다(소비하지 않음).
  2. 없으면 ``request(...)`` 로 pending 레코드를 만들고(같은 지문의 pending 이 있으면 재사용) ``attestation_required`` 를 돌려준다.
     ``Attestor.attest``(= ``rt().attest``)가 이 과정을 묶고, 클라이언트가 지원하면 MCP elicitation 폼을 먼저 띄운다.
  3. 사람이 별도 터미널에서 ``pweh attest <id>`` 를 실행해 항목마다 직접 답한다(TTY 전용, ``decided_via='cli-tty'``).
  4. 에이전트가 같은 도구를 같은 인자로 다시 호출하면 서버가 1번으로 증명을 찾는다(증명 id 를 넘길 필요도, 넘길 방법도 없다).

레코드는 ``<state_dir>/attestations/att-<hex10>.json`` 에 있다(승인 파일처럼 에이전트 수정 금지 — AGENTS.md, docs/safety.md).
케이스의 ``cases/<id>/attestations.json`` 은 보고서용 읽기 전용 사본이며 **어떤 코드도 증거로 읽지 않는다**.

신뢰 규칙 (``require``):
  - 서버는 (kind, subject, binding) 으로만 찾는다. subject 는 서버 자신의 스캔·측정 결과로 만든다.
    에이전트가 넘긴 ``attested_*`` 인자, 케이스 파일·사본, 승인 id(``ap-…``)는 증거가 아니다.
  - subject·binding 의 최상위 ``attested*`` 키(에이전트의 증명 주장)는 지문에서 빼고 무시한다(``ignored_agent_fields``).
  - 후보 레코드마다 schema·id 형식(``att-``)·파일 이름·kind(닫힌 집합)·지문(저장된 kind/subject/binding 으로 **다시 계산**)·
    상태(approved)·만료·철회·``decided_via``(cli-tty | elicitation)·답(기대값 충족)을 모두 다시 확인한다.
    그래서 소비된 승인 레코드를 복사하거나 이름을 바꿔도 통과하지 못한다.
  - 확인 항목: ``expected: 'yes'`` 가 없는 yesno 는 정보 항목이라 '아니오'여도 승인된다. 값(value) 항목은 비어 있지 않으면 충족이고
    범위·형식은 검사하지 않는다 — 서버가 ``decision.record['answers']`` 로 직접 검사한다.
  - ``valid_seconds`` 는 새로 만드는 레코드의 승인 뒤 유효 기간에만 적용된다. 같은 지문의 기존 레코드(승인·대기)는 그 레코드의 만료를 따르므로,
    더 최근의 확인이 필요하면 바인딩을 좁힌다(연결 토큰·job).
  - 한계: 같은 OS 계정의 적대적 프로세스는 레코드 전체를 위조할 수 있다(docs/safety.md §3.4 — 강한 격리는 별도 OS 계정).

증명 종류는 코드에서만 늘린다(``ATTESTATION_KINDS`` 표 또는 코어 모듈의 ``register_kind``). 설정이나 에이전트 입력으로는 늘릴 수 없다.
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

import anyio

from ..errors import NotFound, PwehError, ValidationFailed
from ..fsutil import atomic_write_json, file_lock, read_json, utcnow

log = logging.getLogger("pweh.safety.attest")

SCHEMA = "pweh.attestation/v1"
ID_RE = re.compile(r"^att-[0-9a-f]{10}$")
KIND_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
QUESTION_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: elicitation 폼의 확인 코드 필드 이름 (질문 id 로 쓸 수 없다)
RESERVED_QUESTION_IDS = frozenset({"code"})
QUESTION_TYPES = ("yesno", "value")
STATUSES = ("pending", "approved", "denied", "revoked", "expired")
#: 사람의 결정으로 인정하는 경로. 이 밖의 값(에이전트·도구 이름 등)으로는 decide 할 수 없다.
DECIDED_VIA = ("cli-tty", "elicitation")
#: 바인딩 범위 → 필수 id 키
BINDING_SCOPES: Mapping[str, str] = MappingProxyType({
    "case": "case_id",  # 케이스 전체
    "connection": "connection_id",  # 연결 토큰(재연결하면 새 토큰 → 다시 증명)
    "job": "job_id",  # 백그라운드 작업 하나
    "instrument": "instrument_id",  # 계측기 전역(사람이 철회할 때까지)
})
#: 승인 뒤 유효 기간 기본값(초). None = 사람이 철회할 때까지 — instrument 범위만 기본값으로 쓴다.
DEFAULT_VALIDITY_S: Mapping[str, int | None] = MappingProxyType({
    "case": 7 * 86400,
    "connection": 12 * 3600,
    "job": 24 * 3600,
    "instrument": None,
})
MIN_VALIDITY_S = 60
MAX_VALIDITY_S = 90 * 86400
ELICIT_CODE_ALPHABET = "ACDEFGHJKLMNPQRTUVWXY34679"  # approvals 와 같은 혼동 문자 제외 알파벳
#: 에이전트의 증명 주장으로 보고 지문에서 빼는 최상위 키 (attested, attested_by, attested_offline …)
_AGENT_CLAIM_RE = re.compile(r"^attested", re.IGNORECASE)

_KINDS: dict[str, str] = {
    "tag-purpose": "태그의 목적·소유 (이 케이스의 콘솔과 쓰는 게임·장난감 태그이며 결제·교통·출입·호텔·신분 자격증명이 아님)",
    "wiring": "배선 = 채널 라벨, 사람이 멀티미터로 잰 전압 (배선 계획 해시에 묶임)",
    "console-offline": "콘솔 네트워크 차단(오프라인)",
    "payment-locked": "결제 수단 제거 또는 구매 PIN 설정",
    "hdmi-source": "HDMI 캡처 소스 종류 (콘솔 설정으로 HDCP 끔·스트리퍼 없음, 또는 HDMI 아님)",
    "bridge-serial": "입력 브리지 USB iSerial (사람이 기록)",
    "write-blocker": "SD 카드 이미징에 하드웨어 쓰기 방지 장치 사용",
    "provenance-import": "가져온 파일(sha256)의 출처 확인",
    "instrument-pin": "계측기 고정 (이 포트·보드는 내 계측기이며 분석 대상이 아님)",
    "radio-target": "무선 분석 대상 식별자 (사람이 직접 입력)",
    "module-kc": "무선 모듈 KC 적합등록 확인",
}
#: 증명 종류(닫힌 집합). 읽기 전용 — 코드에서만 늘린다.
ATTESTATION_KINDS: Mapping[str, str] = MappingProxyType(_KINDS)


def register_kind(kind: str, description: str) -> None:
    """코드에서 증명 종류를 추가한다(설정·에이전트 입력으로는 늘릴 수 없다).

    주의: ``pweh attest``(CLI 프로세스)도 그 종류를 알아야 결정할 수 있으므로, 이 함수는 ``pweh.safety`` 가 import 하는
    코어 모듈에서만 부른다. 보통은 위 ``_KINDS`` 표에 직접 추가한다.
    """
    if not isinstance(kind, str) or not KIND_RE.match(kind):
        raise ValidationFailed(f"잘못된 증명 종류 이름: {kind!r}", hint="소문자로 시작하는 [a-z0-9-] 2~40자")
    if not isinstance(description, str) or not description.strip():
        raise ValidationFailed("증명 종류 설명이 필요합니다.")
    existing = _KINDS.get(kind)
    if existing is not None and existing != description.strip():
        raise ValidationFailed(f"이미 다른 설명으로 등록된 증명 종류입니다: {kind}")
    _KINDS[kind] = description.strip()


# ---------------------------------------------------------------------------
# 정규화·지문
# ---------------------------------------------------------------------------


def _now() -> _dt.datetime:
    """현재 시각 (테스트가 monkeypatch 로 시간을 옮길 수 있는 지점)."""
    return utcnow()


def _iso(ts: _dt.datetime) -> str:
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_ts(value: Any) -> _dt.datetime | None:
    """ISO 시각(시간대 포함)만 받는다. 시간대가 없는 값은 None — 그런 레코드는 신뢰하지 않는다(비교 오류로 저장소 전체가 멈추지 않게)."""
    if not value or not isinstance(value, str):
        return None
    try:
        ts = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def canonical_json(obj: Any) -> str:
    """정규화 JSON (키 정렬, 공백 없음, NaN 금지). JSON 값이 아니면 ValidationFailed."""
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValidationFailed(f"JSON 으로 정규화할 수 없는 값입니다: {exc}") from None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strip_claims(d: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    kept = {k: v for k, v in d.items() if not (isinstance(k, str) and _AGENT_CLAIM_RE.match(k))}
    dropped = sorted(str(k) for k in d if k not in kept)
    return kept, dropped


def normalize_subject(subject: Any) -> tuple[dict[str, Any], list[str]]:
    """subject 정규화: 객체여야 하고 JSON 값만, 최상위 ``attested*`` 키는 뺀다. 반환: (정규화한 subject, 뺀 키)."""
    if not isinstance(subject, dict):
        raise ValidationFailed("증명 subject 는 객체(dict)여야 합니다.")
    if not all(isinstance(k, str) for k in subject):
        raise ValidationFailed("증명 subject 의 키는 문자열이어야 합니다.")
    kept, dropped = _strip_claims(subject)
    return json.loads(canonical_json(kept)), dropped


def normalize_binding(binding: Any, case_id: str | None = None) -> tuple[dict[str, Any], list[str]]:
    """binding 정규화: ``{scope: case|connection|job|instrument, <범위별 id>: …}``. id 값은 비어 있지 않은 문자열(정수는 문자열로)."""
    if not isinstance(binding, dict):
        raise ValidationFailed("증명 binding 은 객체(dict)여야 합니다.", hint="예: {'scope': 'case', 'case_id': '<케이스>'}")
    kept, dropped = _strip_claims(binding)
    scope = kept.get("scope")
    if scope not in BINDING_SCOPES:
        raise ValidationFailed(f"잘못된 binding.scope: {scope!r}", hint=f"허용: {', '.join(BINDING_SCOPES)}")
    out: dict[str, Any] = {"scope": scope}
    for k, v in kept.items():
        if k == "scope":
            continue
        if not isinstance(k, str) or not re.match(r"^[a-z][a-z0-9_]{0,39}$", k):
            raise ValidationFailed(f"잘못된 binding 키: {k!r}")
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise ValidationFailed(f"binding.{k} 는 문자열 id 여야 합니다 (받은 값: {v!r}).")
        sv = str(v).strip()
        if not sv:
            raise ValidationFailed(f"binding.{k} 가 비어 있습니다.")
        out[k] = sv
    required = BINDING_SCOPES[scope]
    if required not in out:
        raise ValidationFailed(f"binding.scope={scope} 에는 {required} 가 필요합니다.")
    if case_id is not None and "case_id" in out and out["case_id"] != case_id:
        raise ValidationFailed(f"binding.case_id({out['case_id']}) 와 case_id({case_id}) 가 다릅니다.")
    return out, dropped


def normalize_questions(questions: Any) -> list[dict[str, Any]]:
    """확인 항목 정규화: ``[{id, text, type: 'yesno'|'value', expected?: 'yes'}]`` (1개 이상, id 는 식별자·중복 없음)."""
    if not isinstance(questions, (list, tuple)) or not questions:
        raise ValidationFailed("증명 questions 는 1개 이상의 목록이어야 합니다.")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for q in questions:
        if not isinstance(q, dict):
            raise ValidationFailed("증명 question 은 객체여야 합니다.")
        qid, text, qtype, expected = q.get("id"), q.get("text"), q.get("type"), q.get("expected")
        if not isinstance(qid, str) or not QUESTION_ID_RE.match(qid) or qid in RESERVED_QUESTION_IDS:
            raise ValidationFailed(f"잘못된 question id: {qid!r}", hint="소문자로 시작하는 [a-z0-9_] 1~32자 ('code' 는 예약)")
        if qid in seen:
            raise ValidationFailed(f"question id 가 중복됩니다: {qid}")
        seen.add(qid)
        if not isinstance(text, str) or not text.strip() or len(text) > 1000:
            raise ValidationFailed(f"question {qid} 의 text 가 비었거나 너무 깁니다.")
        if qtype not in QUESTION_TYPES:
            raise ValidationFailed(f"question {qid} 의 type 이 잘못되었습니다: {qtype!r}", hint="허용: yesno, value")
        if expected is not None and (expected != "yes" or qtype != "yesno"):
            raise ValidationFailed(f"question {qid} 의 expected 는 yesno 질문의 'yes' 만 허용됩니다.")
        unknown = set(q) - {"id", "text", "type", "expected"}
        if unknown:
            raise ValidationFailed(f"question {qid} 에 모르는 필드: {sorted(unknown)}")
        item: dict[str, Any] = {"id": qid, "text": text.strip(), "type": qtype}
        if expected is not None:
            item["expected"] = "yes"
        out.append(item)
    return out


def normalize_answers(questions: list[dict[str, Any]], answers: Any) -> dict[str, str]:
    """답 정규화: yesno → 'yes'/'no' (bool·y/n 허용), value → 앞뒤 공백을 뺀 문자열. 빈 값·없는 답은 빠진다."""
    if answers is None:
        answers = {}
    if not isinstance(answers, dict):
        raise ValidationFailed("answers 는 {question_id: 답} 객체여야 합니다.")
    by_id = {q["id"]: q for q in questions}
    unknown = [k for k in answers if k not in by_id]
    if unknown:
        raise ValidationFailed(f"모르는 question id 의 답: {unknown}")
    out: dict[str, str] = {}
    for qid, raw in answers.items():
        q = by_id[qid]
        if raw is None:
            continue
        if q["type"] == "yesno":
            if isinstance(raw, bool):
                out[qid] = "yes" if raw else "no"
                continue
            low = str(raw).strip().lower()
            if low in ("yes", "y"):
                out[qid] = "yes"
            elif low in ("no", "n"):
                out[qid] = "no"
            else:
                raise ValidationFailed(f"question {qid} 의 답은 yes/no 여야 합니다 (받은 값: {raw!r}).")
        else:
            if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
                raise ValidationFailed(f"question {qid} 의 값은 문자열이어야 합니다.")
            text = str(raw).strip()
            if len(text) > 1000:
                raise ValidationFailed(f"question {qid} 의 값이 너무 깁니다.")
            if text:
                out[qid] = text
    return out


def answers_satisfy(questions: list[dict[str, Any]], answers: Mapping[str, Any] | None) -> tuple[bool, list[str]]:
    """승인 조건: expected=yes 인 yesno 는 모두 'yes', value 는 모두 값이 있어야 한다. 반환: (충족 여부, 못 채운 항목 설명)."""
    if not isinstance(answers, Mapping):
        answers = {}
    problems: list[str] = []
    for q in questions:
        a = answers.get(q["id"])
        if q["type"] == "yesno":
            if q.get("expected") == "yes" and a != "yes":
                problems.append(f"{q['id']}: '예'가 아님")
            elif a not in (None, "yes", "no"):
                problems.append(f"{q['id']}: yes/no 가 아닌 답")
        elif not isinstance(a, str) or not a.strip():
            problems.append(f"{q['id']}: 값이 없음")
    return (not problems), problems


def _check_kind(kind: Any) -> str:
    if not isinstance(kind, str) or kind not in ATTESTATION_KINDS:
        raise ValidationFailed(f"알 수 없는 증명 종류: {kind!r}", hint=f"허용: {', '.join(sorted(ATTESTATION_KINDS))}")
    return kind


def attestation_fingerprint(kind: str, subject: dict[str, Any], binding: dict[str, Any]) -> str:
    """지문 = sha256(정규화 JSON {kind, subject, binding}). subject·binding 은 정규화(``attested*`` 키 제거) 후 계산한다."""
    kind = _check_kind(kind)
    subj, _ = normalize_subject(subject)
    bind, _ = normalize_binding(binding)
    return _sha256_text(canonical_json({"kind": kind, "subject": subj, "binding": bind}))


@dataclass(frozen=True)
class _Target:
    kind: str
    subject: dict[str, Any]
    binding: dict[str, Any]
    fingerprint: str
    ignored: tuple[str, ...]


def _target(kind: Any, subject: Any, binding: Any, case_id: str | None = None) -> _Target:
    kind = _check_kind(kind)
    subj, d1 = normalize_subject(subject)
    bind, d2 = normalize_binding(binding, case_id)
    fp = _sha256_text(canonical_json({"kind": kind, "subject": subj, "binding": bind}))
    ignored = tuple([f"subject.{k}" for k in d1] + [f"binding.{k}" for k in d2])
    return _Target(kind, subj, bind, fp, ignored)


def os_user() -> str:
    """결정한 사람의 OS 계정 이름(실제 uid 기준 — 환경 변수 $USER 로 바꿀 수 없다)."""
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        pass
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


def how_text(attestation_id: str | None) -> str:
    return (f"사람이 별도 터미널에서 `pweh attest {attestation_id or '<id>'}` 를 실행해 항목마다 직접 답한다 "
            "(대화형 터미널 전용 — 에이전트는 실행하지 않는다).")


# ---------------------------------------------------------------------------
# 저장소
# ---------------------------------------------------------------------------


class AttestationStore:
    """``<state_dir>/attestations/`` 의 증명 레코드. 디렉터리는 처음 쓸 때 만든다.

    on_change(case_id): 레코드가 바뀐 뒤 부르는 콜백(런타임이 케이스의 읽기 전용 사본을 다시 쓰는 데 쓴다). 실패해도 결정은 유지된다.
    """

    def __init__(
        self,
        directory: Path,
        *,
        pending_ttl_seconds: int = 900,
        on_change: Callable[[str | None], None] | None = None,
    ) -> None:
        self.dir = Path(directory)
        self.pending_ttl = int(pending_ttl_seconds)
        self._on_change = on_change

    # -- 내부 ---------------------------------------------------------------
    def _path(self, attestation_id: Any) -> Path:
        if not isinstance(attestation_id, str) or not ID_RE.match(attestation_id):
            raise PwehError(
                f"잘못된 attestation_id: {attestation_id!r}",
                code="bad_attestation_id",
                hint="증명 id 는 'att-' + 16진수 10자리다. 승인 id(ap-…)는 증명으로 쓸 수 없다.",
            )
        return self.dir / f"{attestation_id}.json"

    def _lock(self, attestation_id: str):
        return file_lock(self.dir / f".{attestation_id}.lock")

    def _store_lock(self):
        return file_lock(self.dir / ".store.lock")

    def _ensure_dir(self) -> None:
        """증명 디렉터리를 0700 으로 만든다(umask 와 무관하게 — 솔트 디렉터리와 같은 규칙)."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:  # pragma: no cover
            pass

    @staticmethod
    def _load_valid(path: Path) -> dict[str, Any] | None:
        """형식이 맞는 증명 레코드만 (schema, id 형식, 파일 이름 = id). 아니면 None."""
        try:
            rec = read_json(path)
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(rec, dict) or rec.get("schema") != SCHEMA:
            return None
        rid = rec.get("id")
        if not isinstance(rid, str) or not ID_RE.match(rid) or rid != path.stem:
            return None
        return rec

    @staticmethod
    def _expire_if_needed(rec: dict[str, Any]) -> dict[str, Any]:
        if rec.get("status") in ("pending", "approved"):
            exp = _parse_ts(rec.get("expires_at"))
            if exp is not None and _now() > exp:
                rec["status"] = "expired"
        return rec

    def _iter_records(self) -> list[dict[str, Any]]:
        if not self.dir.exists():
            return []
        out = []
        for p in sorted(self.dir.glob("att-*.json")):
            try:
                rec = self._load_valid(p)
                if rec is not None:
                    out.append(self._expire_if_needed(rec))
            except Exception:  # noqa: BLE001 - 형식이 깨진 레코드 하나가 저장소 전체를 멈추지 않게 건너뛴다(fail closed)
                log.warning("증명 레코드를 건너뜁니다(형식 오류): %s", p.name, exc_info=True)
        return out

    def _changed(self, rec: dict[str, Any]) -> None:
        if self._on_change is None:
            return
        try:
            self._on_change(rec.get("case_id"))
        except Exception:  # 사본 갱신 실패가 결정을 막지 않게
            log.warning("증명 사본 갱신 실패 (case=%s)", rec.get("case_id"), exc_info=True)

    # -- 조회 ---------------------------------------------------------------
    def get(self, attestation_id: str) -> dict[str, Any]:
        path = self._path(attestation_id)
        if not path.exists():
            raise NotFound(f"증명 요청을 찾을 수 없습니다: {attestation_id}")
        rec = self._load_valid(path)
        if rec is None:
            raise PwehError(f"증명 레코드 형식이 잘못되었습니다: {attestation_id}", code="attestation_invalid")
        return self._expire_if_needed(rec)

    def list(self, status: str | None = None, *, case_id: str | None = None) -> list[dict[str, Any]]:
        recs = [r for r in self._iter_records()
                if (status is None or r.get("status") == status) and (case_id is None or r.get("case_id") == case_id)]
        recs.sort(key=lambda r: str(r.get("created_at", "")))
        return recs

    def find(self, kind: str, subject: dict[str, Any], binding: dict[str, Any]) -> list[dict[str, Any]]:
        """같은 지문의 모든 레코드(상태 무관, 최신 먼저) — 정보 표시용. 신뢰 판단은 ``require`` 로만 한다."""
        t = _target(kind, subject, binding)
        recs = [r for r in self._iter_records() if r.get("fingerprint") == t.fingerprint and r.get("kind") == t.kind]
        recs.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
        return recs

    # -- 요청 ---------------------------------------------------------------
    def request(
        self,
        kind: str,
        subject: dict[str, Any],
        binding: dict[str, Any],
        questions: list[dict[str, Any]],
        case_id: str | None = None,
        summary: str | None = None,
        *,
        server: str | None = None,
        tool: str | None = None,
        valid_seconds: int | None = None,
    ) -> dict[str, Any]:
        """pending 증명 레코드를 만든다. 같은 지문의 (만료되지 않은) pending 이 있으면 그것을 돌려준다."""
        rec, _reused = self._request(kind, subject, binding, questions, case_id, summary, server=server, tool=tool,
                                     valid_seconds=valid_seconds)
        return rec

    def _request(
        self,
        kind: str,
        subject: dict[str, Any],
        binding: dict[str, Any],
        questions: list[dict[str, Any]],
        case_id: str | None = None,
        summary: str | None = None,
        *,
        server: str | None = None,
        tool: str | None = None,
        valid_seconds: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        from ..case import CASE_ID_RE

        if case_id is not None and not CASE_ID_RE.match(str(case_id)):
            raise ValidationFailed(f"잘못된 case_id: {case_id!r}")
        t = _target(kind, subject, binding, case_id)
        qs = normalize_questions(questions)
        scope = t.binding["scope"]
        if valid_seconds is None:
            valid = DEFAULT_VALIDITY_S[scope]
        else:
            if isinstance(valid_seconds, bool) or not isinstance(valid_seconds, int):
                raise ValidationFailed("valid_seconds 는 정수(초)여야 합니다.")
            valid = int(valid_seconds)
            if not MIN_VALIDITY_S <= valid <= MAX_VALIDITY_S:
                raise ValidationFailed(f"valid_seconds 는 {MIN_VALIDITY_S}~{MAX_VALIDITY_S} 초여야 합니다.")
        case_id = case_id or t.binding.get("case_id")
        self._ensure_dir()
        with self._store_lock():
            for rec in sorted(self._iter_records(), key=lambda r: str(r.get("created_at", "")), reverse=True):
                if (rec.get("status") == "pending" and _parse_ts(rec.get("expires_at")) is not None
                        and rec.get("fingerprint") == t.fingerprint and rec.get("kind") == t.kind and self._asks(rec, qs)):
                    return rec, True
            now = _now()
            while True:
                att_id = "att-" + secrets.token_hex(5)
                if not self._path(att_id).exists():
                    break
            rec = {
                "schema": SCHEMA,
                "id": att_id,
                "kind": t.kind,
                "kind_description": ATTESTATION_KINDS[t.kind],
                "status": "pending",
                "subject": t.subject,
                "subject_sha256": _sha256_text(canonical_json(t.subject)),
                "binding": t.binding,
                "fingerprint": t.fingerprint,
                "questions": qs,
                "answers": None,
                "case_id": case_id,
                "summary": summary or f"{t.kind}: {ATTESTATION_KINDS[t.kind]}",
                "requested_by": {"server": server, "tool": tool},
                "valid_seconds": valid,
                "created_at": _iso(now),
                "expires_at": _iso(now + _dt.timedelta(seconds=self.pending_ttl)),
                "decided_at": None,
                "decided_by": None,
                "decided_via": None,
                "revoked_at": None,
                "revoked_by": None,
            }
            if t.ignored:
                rec["ignored_agent_fields"] = list(t.ignored)
            with self._lock(att_id):
                atomic_write_json(self._path(att_id), rec)
        self._changed(rec)
        return rec, False

    # -- 확인 ---------------------------------------------------------------
    @staticmethod
    def _asks(rec: dict[str, Any], required: list[dict[str, Any]]) -> bool:
        """레코드가 required 의 질문을 모두(같은 id·type·expected) 묻는지. 질문의 뜻을 바꾸면 새 id 를 쓴다(문구만 다듬는 것은 같은 id)."""
        try:
            asked = {q["id"]: q for q in normalize_questions(rec.get("questions"))}
        except PwehError:
            return False
        for q in required:
            got = asked.get(q["id"])
            if got is None or got["type"] != q["type"] or got.get("expected") != q.get("expected"):
                return False
        return True

    @classmethod
    def _covers(cls, rec: dict[str, Any], required: list[dict[str, Any]] | None) -> bool:
        """서버가 지금 요구하는 질문(required)을 사람이 모두 받았고 답이 그 조건을 채우는지.
        서버가 항목을 늘리면 예전 증명은 충족하지 않는다."""
        if not required:
            return True
        if not cls._asks(rec, required):
            return False
        ok, _ = answers_satisfy(required, rec.get("answers"))
        return ok

    def _trusted(self, rec: dict[str, Any], t: _Target, required: list[dict[str, Any]] | None = None) -> bool:
        """승인된 유효 레코드인지 모든 필드를 다시 확인한다 (손으로 고친·복사한 레코드 방어)."""
        try:
            if rec.get("kind") != t.kind or rec.get("fingerprint") != t.fingerprint:
                return False
            again = _target(rec.get("kind"), rec.get("subject"), rec.get("binding"))
            if again.fingerprint != t.fingerprint or again.ignored:
                return False
            if rec.get("status") != "approved" or rec.get("revoked_at"):
                return False
            if rec.get("decided_via") not in DECIDED_VIA or not _parse_ts(rec.get("decided_at")):
                return False
            if rec.get("expires_at") is None:
                if again.binding["scope"] != "instrument" or rec.get("valid_seconds") is not None:
                    return False
            elif _parse_ts(rec.get("expires_at")) is None:
                return False
            if not isinstance(rec.get("answers"), dict):
                return False
            ok, _ = answers_satisfy(normalize_questions(rec.get("questions")), rec.get("answers"))
            return ok and self._covers(rec, required)
        except Exception:  # noqa: BLE001 - 형식이 깨진 레코드는 건너뛴다(require 가 죽지 않게, fail closed)
            return False

    def require(self, kind: str, subject: dict[str, Any], binding: dict[str, Any],
                questions: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        """(kind, subject, binding) 에 맞는 승인·미만료·미철회 증명 레코드(가장 최근 결정). 없으면 None. 소비하지 않는다.

        questions: 서버가 지금 요구하는 확인 항목. 주면 그 항목을 모두 받은(같은 id·type·expected) 레코드만 인정하고
        답도 그 조건으로 다시 확인한다 — 레코드가 스스로 적은 질문만 믿지 않는다(``rt().attest`` 는 늘 넘긴다).
        """
        t = _target(kind, subject, binding)
        required = normalize_questions(questions) if questions is not None else None
        best: dict[str, Any] | None = None
        for rec in self._iter_records():
            if not self._trusted(rec, t, required):
                continue
            if best is None or str(rec.get("decided_at")) > str(best.get("decided_at")):
                best = rec
        return best

    # -- 사람의 결정 ----------------------------------------------------------
    def decide(self, attestation_id: str, answers: dict[str, Any] | None, via: str, by: str | None = None) -> dict[str, Any]:
        """사람의 답을 기록한다. expected=yes 인 yesno 가 모두 'yes' 이고 value 가 모두 있으면 approved, 아니면 denied.

        via 는 ``cli-tty``(pweh attest) 또는 ``elicitation`` 만 받는다.
        """
        if via not in DECIDED_VIA:
            raise ValidationFailed(f"증명은 사람만 결정할 수 있습니다 (via={via!r}).", hint=f"허용: {', '.join(DECIDED_VIA)}")
        path = self._path(attestation_id)
        with self._lock(attestation_id):
            rec = self.get(attestation_id)
            if rec["status"] != "pending":
                raise PwehError(f"이미 처리되었거나 만료된 증명 요청입니다 (status={rec['status']}).", code="attestation_not_pending")
            _check_kind(rec.get("kind"))
            questions = normalize_questions(rec.get("questions"))
            ans = normalize_answers(questions, answers)
            ok, problems = answers_satisfy(questions, ans)
            now = _now()
            rec["answers"] = ans
            rec["decided_at"] = _iso(now)
            rec["decided_by"] = by or os_user()
            rec["decided_via"] = via
            if ok:
                rec["status"] = "approved"
                valid = rec.get("valid_seconds")
                rec["expires_at"] = _iso(now + _dt.timedelta(seconds=int(valid))) if valid else None
            else:
                rec["status"] = "denied"
                rec["denied_reasons"] = problems
            atomic_write_json(path, rec)
        self._changed(rec)
        return rec

    def deny(self, attestation_id: str, *, via: str, by: str | None = None, reason: str | None = None) -> dict[str, Any]:
        """답 없이 거부로 기록한다 (elicitation 거절·취소·확인 코드 불일치)."""
        if via not in DECIDED_VIA:
            raise ValidationFailed(f"증명은 사람만 결정할 수 있습니다 (via={via!r}).")
        path = self._path(attestation_id)
        with self._lock(attestation_id):
            rec = self.get(attestation_id)
            if rec["status"] != "pending":
                raise PwehError(f"이미 처리되었거나 만료된 증명 요청입니다 (status={rec['status']}).", code="attestation_not_pending")
            rec["status"] = "denied"
            rec["decided_at"] = _iso(_now())
            rec["decided_by"] = by or os_user()
            rec["decided_via"] = via
            rec["denied_reasons"] = [reason or "사람이 거부함"]
            atomic_write_json(path, rec)
        self._changed(rec)
        return rec

    def revoke(self, attestation_id: str, by: str | None = None, reason: str | None = None) -> dict[str, Any]:
        """사람의 철회 (pending·approved 만). 철회된 레코드는 다시 쓸 수 없다."""
        path = self._path(attestation_id)
        with self._lock(attestation_id):
            rec = self.get(attestation_id)
            if rec["status"] not in ("pending", "approved"):
                raise PwehError(f"철회할 수 없는 상태입니다 (status={rec['status']}).", code="attestation_not_revocable")
            rec["status"] = "revoked"
            rec["revoked_at"] = _iso(_now())
            rec["revoked_by"] = by or os_user()
            if reason:
                rec["revoke_reason"] = reason
            atomic_write_json(path, rec)
        self._changed(rec)
        return rec


# ---------------------------------------------------------------------------
# 서버용 도우미 (rt().attest)
# ---------------------------------------------------------------------------


@dataclass
class AttestationDecision:
    """``Attestor.attest`` 결과. satisfied 가 아니면 ``attestation_response(decision)`` 를 그대로 반환한다."""

    satisfied: bool
    status: str  # satisfied | attestation_required | denied
    kind: str
    attestation_id: str | None = None
    record: dict[str, Any] | None = None
    questions: list[dict[str, Any]] = field(default_factory=list)
    via: str | None = None  # existing | elicitation
    message: str = ""
    summary: str | None = None
    binding: dict[str, Any] | None = None
    expires_at: str | None = None
    ignored_agent_fields: list[str] = field(default_factory=list)
    previous: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"satisfied": self.satisfied, "status": self.status, "kind": self.kind}
        for key in ("attestation_id", "via", "expires_at", "summary", "binding", "message", "previous"):
            val = getattr(self, key)
            if val:
                out[key] = val
        if self.ignored_agent_fields:
            out["ignored_agent_fields"] = list(self.ignored_agent_fields)
        return out


def _form_field(question_id: str) -> str:
    """elicitation 폼의 필드 이름 (질문 id 에 'q_' 접두 — 'code' 확인 코드 필드·pydantic 이름과 겹치지 않음)."""
    return f"q_{question_id}"


def _public_questions(questions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: q[k] for k in ("id", "text", "type", "expected") if k in q} for q in questions]


def attestation_response(decision: AttestationDecision, **extra: Any) -> dict[str, Any]:
    """증명이 충족되지 않았을 때의 표준 응답 (``gate_response`` 와 같은 쓰임)."""
    out: dict[str, Any] = {
        "ok": False,
        "status": decision.status,
        "attestation_id": decision.attestation_id,
        "kind": decision.kind,
        "questions": _public_questions(decision.questions),
        "attestation": decision.to_dict(),
    }
    if decision.status == "attestation_required":
        out["how"] = how_text(decision.attestation_id)
    if decision.summary:
        out["summary"] = decision.summary
    if decision.message:
        out["message"] = decision.message
    if decision.ignored_agent_fields:
        out["ignored_agent_fields"] = list(decision.ignored_agent_fields)
    if decision.previous:
        out["previous"] = decision.previous
    out.update(extra)
    return out


class Attestor:
    """서버가 증명을 요구하는 도우미. ``require`` → (없으면) pending 요청 → elicitation → ``attestation_required``.

    사람 확인 경로는 ``safety.approval_methods`` 를 따른다(새 설정 키 없음): elicitation 은 클라이언트가 지원할 때,
    cli 는 ``pweh attest <id>``. 둘 다 쓸 수 없으면 거부한다.
    """

    def __init__(
        self,
        store: AttestationStore,
        safety: Any,
        audit: Callable[[dict[str, Any], str | None], None] | None = None,
        *,
        server: str | None = None,
    ) -> None:
        self.store = store
        self.safety = safety
        self._audit = audit
        self.server = server

    def _emit(self, event: dict[str, Any], case_id: str | None) -> None:
        if self._audit is None:
            return
        try:
            self._audit(event, case_id)
        except Exception:  # 감사 로그 실패가 작업을 막지 않도록
            log.exception("audit write failed")

    def _decision(self, rec: dict[str, Any], t: _Target, *, via: str | None = None, message: str = "",
                  previous: dict[str, Any] | None = None, required: list[dict[str, Any]] | None = None) -> AttestationDecision:
        status = rec.get("status")
        if status == "approved" and self.store._trusted(rec, t, required):
            return AttestationDecision(True, "satisfied", t.kind, rec["id"], rec, rec.get("questions") or [], via=via,
                                       summary=rec.get("summary"), binding=rec.get("binding"), expires_at=rec.get("expires_at"),
                                       ignored_agent_fields=list(t.ignored))
        if status == "pending":
            msg = message or (
                f"사람 증명이 필요합니다 (종류={t.kind}: {ATTESTATION_KINDS.get(t.kind, '')}). 요약: {rec.get('summary')}. "
                f"사용자에게 무엇을 직접 확인해야 하는지 설명하고, 사용자가 **별도 터미널**에서 `pweh attest {rec['id']}` 를 실행해 "
                "항목마다 직접 답하도록 요청하세요. 증명 뒤 같은 도구를 같은 인자로 다시 호출하면 서버가 증명을 찾아 사용합니다"
                "(attestation_id 를 넘길 필요 없음). 에이전트가 이 명령을 실행하거나 .pweh/state/attestations/ 를 고치거나, "
                f"attested_* 인자·케이스 파일로 증명을 대신해서는 안 됩니다 (요청 만료: {rec.get('expires_at')})."
            )
            return AttestationDecision(False, "attestation_required", t.kind, rec["id"], rec, rec.get("questions") or [],
                                       message=msg, summary=rec.get("summary"), binding=rec.get("binding"),
                                       expires_at=rec.get("expires_at"), ignored_agent_fields=list(t.ignored), previous=previous)
        msg = message or (f"사람이 증명하지 않았습니다 (status={status}). 작업을 진행하지 말고 우회하지 마세요. "
                          "사용자에게 결과를 보고하고, 사용자가 원하면 같은 도구를 다시 호출해 새 증명 요청을 만듭니다.")
        return AttestationDecision(False, "denied", t.kind, rec.get("id"), rec, rec.get("questions") or [], message=msg,
                                   summary=rec.get("summary"), binding=rec.get("binding"), ignored_agent_fields=list(t.ignored))

    async def attest(
        self,
        kind: str,
        subject: dict[str, Any],
        binding: dict[str, Any],
        questions: list[dict[str, Any]],
        case_id: str | None = None,
        ctx: Any = None,
        summary: str | None = None,
        *,
        tool: str | None = None,
        valid_seconds: int | None = None,
    ) -> AttestationDecision:
        from .gate import _client_supports_elicitation

        t = _target(kind, subject, binding, case_id)
        qs = normalize_questions(questions)
        case_id = case_id or t.binding.get("case_id")
        base_event = {"kind": t.kind, "fingerprint": t.fingerprint, "binding": t.binding, "tool": tool}
        if t.ignored:
            base_event["ignored_agent_fields"] = list(t.ignored)
        rec = self.store.require(t.kind, t.subject, t.binding, questions=qs)
        if rec is not None:
            self._emit({"event": "attestation_used", "attestation_id": rec["id"], **base_event}, case_id)
            return self._decision(rec, t, via="existing", required=qs)

        methods = list(getattr(self.safety, "approval_methods", None) or ["cli"])
        can_elicit = "elicitation" in methods and ctx is not None and _client_supports_elicitation(ctx)
        can_cli = "cli" in methods
        if not (can_elicit or can_cli):
            msg = "사람 증명을 받을 방법이 없어 거부되었습니다 (safety.approval_methods 확인)."
            self._emit({"event": "attestation_denied", "reason": "no_method", **base_event}, case_id)
            return AttestationDecision(False, "denied", t.kind, None, None, qs, message=msg, summary=summary,
                                       binding=t.binding, ignored_agent_fields=list(t.ignored))

        previous = None
        for old in self.store.find(t.kind, t.subject, t.binding):
            if old.get("status") in ("denied", "revoked", "expired"):
                previous = {"attestation_id": old["id"], "status": old["status"],
                            "at": old.get("revoked_at") or old.get("decided_at") or old.get("expires_at")}
                break
        rec, reused = self.store._request(t.kind, t.subject, t.binding, qs, case_id, summary, server=self.server, tool=tool,
                                          valid_seconds=valid_seconds)
        self._emit({"event": "attestation_requested", "attestation_id": rec["id"], "reused": reused,
                    "subject_sha256": rec.get("subject_sha256"), **base_event}, case_id)
        if can_elicit:
            outcome = await self._elicit(ctx, rec, t, case_id)
            if outcome is not None:
                return outcome
            # elicitation 실패(오류·시간 초과) → cli 로 폴백 (레코드는 pending 그대로)
        if can_cli:
            return self._decision(rec, t, previous=previous)
        return AttestationDecision(False, "denied", t.kind, rec["id"], rec, rec.get("questions") or [],
                                   message="elicitation 이 실패했고 cli 확인이 꺼져 있어 거부되었습니다 (safety.approval_methods 확인).",
                                   summary=rec.get("summary"), binding=t.binding, ignored_agent_fields=list(t.ignored))

    async def _elicit(self, ctx: Any, rec: dict[str, Any], t: _Target, case_id: str | None) -> AttestationDecision | None:
        from pydantic import Field, create_model

        from .gate import ELICITATION_TIMEOUT_S

        questions = normalize_questions(rec.get("questions"))
        code = "".join(secrets.choice(ELICIT_CODE_ALPHABET) for _ in range(4))
        # 폼 필드 이름은 'q_<질문 id>' — 질문 id 가 pydantic BaseModel 이름(model_config, schema, json …)과 겹쳐도 폼을 만들 수 있게
        fields: dict[str, Any] = {}
        for q in questions:
            label = q["text"] + (" (예 필요)" if q.get("expected") == "yes" else "")
            fields[_form_field(q["id"])] = ((bool, Field(description=label)) if q["type"] == "yesno"
                                            else (str, Field(description=q["text"])))
        fields["code"] = (str, Field(description="메시지에 표시된 4자리 확인 코드"))
        try:
            form = create_model("AttestationForm", **fields)
        except Exception as exc:  # 폼을 만들 수 없으면 cli 로 폴백 (레코드는 pending 그대로)
            log.warning("attestation elicitation form build failed, falling back: %r", exc)
            return None
        subject_text = canonical_json(rec.get("subject"))
        if len(subject_text) > 800:
            subject_text = subject_text[:800] + "…"
        message = (
            "🧾 사람 증명 요청 — 에이전트가 확인할 수 없는 사실입니다\n"
            f"- 종류: {t.kind} ({ATTESTATION_KINDS.get(t.kind, '')})\n"
            f"- 요약: {rec.get('summary')}\n"
            f"- 케이스: {case_id or '-'}\n"
            f"- 바인딩: {canonical_json(rec.get('binding'))}\n"
            f"- 대상: {subject_text}\n\n"
            "각 항목을 직접 확인한 경우에만 true(예)로 답하고, 값 항목에는 직접 측정·확인한 값을 입력하세요.\n"
            f"제출하려면 확인 코드 {code} 를 입력하세요. 확실하지 않으면 거부(decline)하세요."
        )
        try:
            with anyio.fail_after(ELICITATION_TIMEOUT_S):
                result = await ctx.elicit(message=message, schema=form)
        except Exception as exc:  # 클라이언트 미지원·오류·시간 초과
            log.info("attestation elicitation failed, falling back: %r", exc)
            return None
        action = getattr(result, "action", None)
        if action == "accept":
            data = getattr(result, "data", None)
            if data is None or str(getattr(data, "code", "")).strip().upper() != code:
                return self._finish_denied(rec, t, case_id, "확인 코드 불일치")
            answers: dict[str, Any] = {}
            for q in questions:
                val = getattr(data, _form_field(q["id"]), None)
                answers[q["id"]] = bool(val) if q["type"] == "yesno" else (None if val is None else str(val))
            try:
                done = self.store.decide(rec["id"], answers, via="elicitation", by="client-user")
            except PwehError as exc:  # 그사이 CLI 로 결정·만료됨 → 현재 상태로 판단
                log.info("attestation decide after elicitation failed: %s", exc)
                return self._decision(self.store.get(rec["id"]), t)
            self._emit({"event": "attestation_decided", "attestation_id": done["id"], "kind": t.kind, "status": done["status"],
                        "decided_via": "elicitation"}, case_id)
            if done["status"] == "approved":
                return self._decision(done, t, via="elicitation", required=questions)
            return self._decision(done, t, message=("사용자가 증명 항목을 '예'로 확인하지 않았습니다(또는 값이 없음). 작업을 진행하지 말고 "
                                                    "우회하지 마세요. 사용자에게 보고하세요."))
        if action in ("decline", "cancel"):
            return self._finish_denied(rec, t, case_id, f"elicitation {action}")
        return None

    def _finish_denied(self, rec: dict[str, Any], t: _Target, case_id: str | None, reason: str) -> AttestationDecision:
        try:
            done = self.store.deny(rec["id"], via="elicitation", by="client-user", reason=reason)
        except PwehError:
            done = self.store.get(rec["id"])
            return self._decision(done, t)
        self._emit({"event": "attestation_decided", "attestation_id": done["id"], "kind": t.kind, "status": "denied",
                    "decided_via": "elicitation", "reason": reason}, case_id)
        return self._decision(done, t, message=f"사용자가 증명 요청을 거부했습니다({reason}). 작업을 진행하지 말고 우회하지 마세요.")


__all__ = [
    "ATTESTATION_KINDS",
    "AttestationDecision",
    "AttestationStore",
    "Attestor",
    "BINDING_SCOPES",
    "DECIDED_VIA",
    "attestation_fingerprint",
    "answers_satisfy",
    "attestation_response",
    "canonical_json",
    "how_text",
    "normalize_answers",
    "normalize_binding",
    "normalize_questions",
    "normalize_subject",
    "os_user",
    "register_kind",
]
