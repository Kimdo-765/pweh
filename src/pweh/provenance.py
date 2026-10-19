"""출처 원장(provenance ledger): 기기에서 읽은 산출물과 기기 사실의 해시 체인 기록.

"이 케이스에서 기기로부터 읽은 것만 쓴다(에뮬레이션·올리기·패치 base·계측기 플래시 절차)"를 코드로 확인하기 위한 기록이다.
``case.json`` 아티팩트의 ``producer`` 는 에이전트가 자유롭게 넘기는 값이라 증거가 못 되므로, 출처 확인은 이 원장만 본다
(``producer`` 를 읽지 않는다).

위치: ``<state_dir>/provenance/<case_id>.jsonl`` (보호 대상 — 에이전트 수정 금지. AGENTS.md·docs/safety.md).

줄 하나 = 항목 하나(정규화 JSON: 키 정렬·공백 없음). 필드:
  ``schema, seq(1부터 연속), ts, case_id, kind, path(케이스 상대 경로 | null), sha256, size, source{server, tool, 장치 식별…},
  attestation_id, extra, prev`` (+ device-fact 는 ``fact_kind, data``)
  - ``prev`` = 바로 앞 줄 정규화 JSON 의 sha256. 첫 줄은 케이스 id 에 묶인 시작값(genesis) → 다른 케이스의 원장을 복사해도 깨진다.
  - kind:
    - ``device-read``          기기 읽기 코드 경로가 쓴 산출물 (예: esp_read_flash_start 의 이중 읽기 두 파일).
                               출처이지 무결성이 아니다 — 이중 읽기 불일치(source.match=false)도 기록하지만 verify 는 신뢰하지 않는다
    - ``device-fact``          산출물이 아닌 기기 사실 (예: esp_chip_info·esp_security_info 결과). sha256 = data 정규화 JSON 의 해시
    - ``imported-unattested``  case_import_file 등으로 밖에서 가져온 파일. ``provenance-import`` 사람 증명이 있을 때만 신뢰한다

읽을 때 체인 전체를 검증한다. 하나라도 깨지면(해석 불가 줄, 정규화가 아닌 줄, seq 불연속, prev 불일치, 잘린 마지막 줄)
**모두 신뢰하지 않는다**(fail closed: ``verify`` → ``reason='ledger-chain-broken'``, 기록·사실 조회는 ``ProvenanceError``).

한계 (docs/safety.md §3.4·§3.5): 해시 체인은 비밀 키가 없으므로 실수·단순 변조만 드러낸다. 같은 OS 계정의 프로세스가 원장 전체를
일관되게 다시 쓰거나, 올바른 prev 를 계산해 끝에 줄을 덧붙이거나, 끝 줄을 잘라 내는 것은 감지하지 못한다(잘라 내기는 신뢰를 줄일 뿐
만들지 못한다). 강한 격리는 별도 OS 계정이다.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .case import CASE_ID_RE, Case
from .errors import PwehError, ValidationFailed
from .fsutil import atomic_write_bytes, file_lock, sha256_file, utcnow_iso
from .safety.attestations import AttestationStore, canonical_json

SCHEMA = "pweh.provenance/v1"
KIND_DEVICE_READ = "device-read"
KIND_DEVICE_FACT = "device-fact"
KIND_IMPORTED = "imported-unattested"
LEDGER_KINDS = (KIND_DEVICE_READ, KIND_DEVICE_FACT, KIND_IMPORTED)
CHAIN_BROKEN = "ledger-chain-broken"
#: verify 의 reason: 기기에서 읽었지만 이중 읽기가 어긋난 덤프(source.match=false) — 신뢰하지 않는다
READ_MISMATCH = "device-read-mismatch"

#: provenance-import 증명의 확인 항목 (요청하는 쪽과 확인하는 쪽이 같은 정의를 쓴다 — provenance_import_target 참고)
PROVENANCE_IMPORT_QUESTIONS: tuple[dict[str, Any], ...] = (
    {"id": "source_known", "type": "yesno", "expected": "yes",
     "text": "이 파일(sha256 은 위 대상 참고)을 어디서 얻었는지 직접 알고 있고, 이 케이스의 소유/허가 기기에서 사람이 직접 읽은 것이다 "
             "(인터넷에서 받은 남의 덤프·남의 태그 덤프가 아니다)"},
    {"id": "how_obtained", "type": "value",
     "text": "얻은 방법을 적어 주세요 (예: SOIC 클립 + CH341A 로 읽음, Flipper 기존 폴더에서 가져옴)"},
)


class ProvenanceError(PwehError):
    code = "provenance_error"


def provenance_import_target(case_id: str, sha256: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """가져온 파일(imported-unattested)을 신뢰하게 하는 사람 증명의 (kind, subject, binding).

    요청하는 서버(``rt().attest(*provenance_import_target(...), PROVENANCE_IMPORT_QUESTIONS, ...)``)와
    ``ProvenanceLedger.verify`` 가 이 함수 하나를 써서 지문이 어긋나지 않게 한다. 대상은 내용(sha256), 범위는 케이스다.
    """
    return "provenance-import", {"sha256": str(sha256).lower()}, {"scope": "case", "case_id": case_id}


def _genesis(case_id: str) -> str:
    return hashlib.sha256(f"{SCHEMA}:genesis:{case_id}".encode("utf-8")).hexdigest()


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _case_id_of(case: Case | str) -> str:
    cid = case.id if isinstance(case, Case) else str(case)
    if not CASE_ID_RE.match(cid):
        raise ValidationFailed(f"잘못된 case_id: {cid!r}")
    return cid


def _json_value(value: Any, what: str) -> Any:
    """JSON 값으로 정규화(튜플 → 목록 등). JSON 이 아니면 ValidationFailed."""
    try:
        return json.loads(canonical_json(value))
    except ValidationFailed as exc:
        raise ValidationFailed(f"{what}: {exc.message}") from None


def _check_source(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        raise ValidationFailed("provenance source 는 객체여야 합니다 ({server, tool, 장치 식별…}).")
    for key in ("server", "tool"):
        if not isinstance(source.get(key), str) or not source[key].strip():
            raise ValidationFailed(f"provenance source.{key} 가 필요합니다.")
    return _json_value(source, "provenance source")


def _check_sha256(value: Any) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValidationFailed(f"sha256 형식이 아닙니다: {value!r}")
    return text


def parse_ledger(case_id: str, raw: bytes) -> tuple[list[dict[str, Any]], str | None]:
    """원장 바이트를 검증하며 읽는다. 반환: (항목 목록, 깨진 이유 | None). 깨졌으면 항목 목록은 비운다(fail closed)."""
    if not raw:
        return [], None
    if not raw.endswith(b"\n"):
        return [], "마지막 줄이 잘렸다(줄바꿈 없음)"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], "UTF-8 이 아닌 내용"
    entries: list[dict[str, Any]] = []
    prev = _genesis(case_id)
    for seq, line in enumerate(text.split("\n")[:-1], 1):
        try:
            entry = json.loads(line)
        except ValueError:
            return [], f"{seq}번째 줄을 해석할 수 없다"
        if not isinstance(entry, dict):
            return [], f"{seq}번째 줄이 객체가 아니다"
        try:
            canonical = canonical_json(entry)
        except ValidationFailed:
            return [], f"{seq}번째 줄을 정규화할 수 없다"
        if canonical != line:
            return [], f"{seq}번째 줄이 정규화 JSON 이 아니다(수정됨?)"
        if entry.get("schema") != SCHEMA or entry.get("case_id") != case_id:
            return [], f"{seq}번째 줄의 schema/case_id 가 다르다"
        if entry.get("seq") != seq:
            return [], f"{seq}번째 줄의 seq 가 {entry.get('seq')!r} 다(불연속)"
        if entry.get("prev") != prev:
            return [], f"{seq}번째 줄의 prev 가 앞 줄의 해시와 다르다"
        if entry.get("kind") not in LEDGER_KINDS:
            return [], f"{seq}번째 줄의 kind 가 잘못되었다: {entry.get('kind')!r}"
        entries.append(entry)
        prev = _line_hash(line)
    return entries, None


class ProvenanceLedger:
    """케이스별 출처 원장. 디렉터리·파일은 처음 기록할 때 만든다(파일 권한 0600).

    여러 서버 프로세스(esp-mcp, case-mcp …)가 같은 원장에 쓰므로 읽기 + 검증 + 덧붙이기를 파일 잠금 안에서 하고,
    새 내용(기존 바이트 + 새 줄)을 원자적으로 바꿔 쓴다(중간에 죽어도 잘린 줄이 남지 않는다).
    """

    def __init__(self, directory: Path, attestations: AttestationStore | None = None) -> None:
        self.dir = Path(directory)
        self.attestations = attestations

    def ledger_path(self, case: Case | str) -> Path:
        return self.dir / f"{_case_id_of(case)}.jsonl"

    def _lock(self, case_id: str):
        return file_lock(self.dir / f".{case_id}.lock")

    def _read(self, case_id: str) -> tuple[list[dict[str, Any]], str | None]:
        path = self.dir / f"{case_id}.jsonl"
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return [], None
        except OSError as exc:
            return [], f"원장을 읽을 수 없다: {exc}"
        return parse_ledger(case_id, raw)

    # -- 조회 ---------------------------------------------------------------
    def verify_chain(self, case: Case | str) -> dict[str, Any]:
        """체인 검증 결과: {ok, count, reason?, detail?}."""
        cid = _case_id_of(case)
        entries, broken = self._read(cid)
        if broken:
            return {"ok": False, "count": 0, "reason": CHAIN_BROKEN, "detail": broken}
        return {"ok": True, "count": len(entries)}

    def entries(self, case: Case | str, kind: str | None = None) -> list[dict[str, Any]]:
        """검증된 항목 목록. 체인이 깨졌으면 ProvenanceError(fail closed — '기록 없음'과 구별)."""
        cid = _case_id_of(case)
        entries, broken = self._read(cid)
        if broken:
            raise ProvenanceError(f"출처 원장이 깨졌습니다 ({cid}): {broken}", code="provenance_ledger_broken",
                                  hint="원장을 신뢰할 수 없어 이 케이스의 출처 확인은 모두 실패한다. 사람이 원인을 확인해야 한다.")
        return [e for e in entries if kind is None or e.get("kind") == kind]

    def facts(self, case: Case | str, fact_kind: str | None = None) -> list[dict[str, Any]]:
        """기기 사실(device-fact) 항목. fact_kind 로 거른다 (예: 'esp-security-info')."""
        return [e for e in self.entries(case, KIND_DEVICE_FACT) if fact_kind is None or e.get("fact_kind") == fact_kind]

    # -- 기록 ---------------------------------------------------------------
    def _ensure_dir(self) -> None:
        """원장 디렉터리를 0700 으로 만든다(umask 와 무관하게 — 솔트 디렉터리와 같은 규칙)."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:  # pragma: no cover
            pass

    def _append(self, case_id: str, body: dict[str, Any]) -> dict[str, Any]:
        self._ensure_dir()
        path = self.dir / f"{case_id}.jsonl"
        with self._lock(case_id):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                raw = b""
            entries, broken = parse_ledger(case_id, raw)
            if broken:
                raise ProvenanceError(f"출처 원장이 깨져 기록하지 않습니다 ({case_id}): {broken}", code="provenance_ledger_broken",
                                      hint="깨진 원장에는 덧붙이지 않는다(fail closed). 사람이 원인을 확인해야 한다.")
            prev = _line_hash(canonical_json(entries[-1])) if entries else _genesis(case_id)
            entry = {"schema": SCHEMA, "seq": len(entries) + 1, "ts": utcnow_iso(), "case_id": case_id, **body, "prev": prev}
            line = canonical_json(entry)
            atomic_write_bytes(path, raw + line.encode("utf-8") + b"\n")
            try:
                os.chmod(path, 0o600)
            except OSError:  # pragma: no cover
                pass
        return entry

    def _file_body(self, case: Case, path: str | Path, kind: str, source: Any, extra: Any, sha256: str | None,
                   attestation_id: str | None) -> dict[str, Any]:
        if not isinstance(case, Case):
            raise ValidationFailed("provenance 기록에는 Case 객체가 필요합니다.")
        p = case.resolve_path(path)
        if not p.is_file():
            raise ValidationFailed(f"출처를 기록할 파일이 없습니다: {case.rel(p)}")
        src = _check_source(source)
        actual = sha256_file(p)
        if sha256 is not None and _check_sha256(sha256) != actual:
            raise ProvenanceError(
                f"파일 내용이 읽을 때 계산한 해시와 다릅니다: {case.rel(p)} (기대 {sha256}, 지금 {actual})",
                code="provenance_sha256_mismatch", hint="읽은 뒤 파일이 바뀌었다. 출처를 기록하지 않는다.",
            )
        return {
            "kind": kind,
            "path": case.rel(p),
            "sha256": actual,
            "size": p.stat().st_size,
            "source": src,
            "attestation_id": attestation_id,
            "extra": _json_value(extra or {}, "provenance extra"),
        }

    def record_device_read(self, case: Case, path: str | Path, source: dict[str, Any], extra: dict[str, Any] | None = None, *,
                           sha256: str | None = None, attestation_id: str | None = None) -> dict[str, Any]:
        """기기 읽기 코드 경로가 만든 산출물을 기록한다(device-read).

        sha256: 서버가 읽을 때 계산한 해시. 주면 지금 파일의 해시와 같아야 기록한다(읽은 뒤 바뀐 파일을 기기 읽기로 남기지 않게).
        """
        cid = _case_id_of(case)
        return self._append(cid, self._file_body(case, path, KIND_DEVICE_READ, source, extra, sha256, attestation_id))

    def record_import(self, case: Case, path: str | Path, source: dict[str, Any], extra: dict[str, Any] | None = None, *,
                      sha256: str | None = None) -> dict[str, Any]:
        """밖에서 가져온 파일을 기록한다(imported-unattested). provenance-import 증명이 있을 때만 verify 가 신뢰한다."""
        cid = _case_id_of(case)
        return self._append(cid, self._file_body(case, path, KIND_IMPORTED, source, extra, sha256, None))

    def record_device_fact(self, case: Case | str, fact_kind: str, data: dict[str, Any], source: dict[str, Any], *,
                           attestation_id: str | None = None) -> dict[str, Any]:
        """산출물이 아닌 기기 사실을 기록한다(device-fact, 예: 칩 정보·보안 설정). data 는 원장 안에 그대로 남는다."""
        cid = _case_id_of(case)
        if not isinstance(fact_kind, str) or not fact_kind.strip() or len(fact_kind) > 64:
            raise ValidationFailed("fact_kind 가 필요합니다 (예: 'esp-security-info').")
        if not isinstance(data, dict):
            raise ValidationFailed("device-fact data 는 객체여야 합니다.")
        data_n = _json_value(data, "device-fact data")
        body = {
            "kind": KIND_DEVICE_FACT,
            "fact_kind": fact_kind.strip(),
            "path": None,
            "sha256": hashlib.sha256(canonical_json(data_n).encode("utf-8")).hexdigest(),
            "size": None,
            "source": _check_source(source),
            "attestation_id": attestation_id,
            "data": data_n,
        }
        return self._append(cid, body)

    # -- 확인 ---------------------------------------------------------------
    def verify(self, case: Case, path: str | Path) -> dict[str, Any]:
        """케이스 파일의 출처를 확인한다: {trusted, kind, record, reason, path, sha256, attestation_id?}.

        체인 전체를 검증하고(깨지면 모두 불신), 그 경로의 마지막 항목과 지금 파일의 sha256 을 맞춰 본다(다르면 불신).
        device-read 는 신뢰하되 이중 읽기 불일치(``source.match is False``)는 ``device-read-mismatch`` 로 불신한다.
        imported-unattested 는 provenance-import 증명(같은 sha256·같은 케이스)이 있을 때만 신뢰한다.
        ``case.json`` 의 producer 는 보지 않는다.

        확인과 사용 사이에 케이스 파일이 바뀔 수 있다 — 쓰는 쪽은 여기서 받은 sha256 을 승인 지문·job 인자에 묶고,
        실행 직전 다시 해시하거나 확인한 바이트를 그대로 쓴다.
        """
        if not isinstance(case, Case):
            raise ValidationFailed("provenance 확인에는 Case 객체가 필요합니다.")
        cid = _case_id_of(case)
        p = case.resolve_path(path)
        rel = case.rel(p)
        out: dict[str, Any] = {"trusted": False, "kind": None, "record": None, "reason": "", "path": rel, "sha256": None}
        entries, broken = self._read(cid)
        if broken:
            out.update(reason=CHAIN_BROKEN, detail=broken)
            return out
        if not p.is_file():
            out["reason"] = "file-missing"
            return out
        actual = sha256_file(p)
        out["sha256"] = actual
        rec = None
        for e in reversed(entries):
            if e.get("path") == rel and e.get("kind") in (KIND_DEVICE_READ, KIND_IMPORTED):
                rec = e
                break
        if rec is None:
            out["reason"] = "not-recorded"
            return out
        out["record"] = rec
        out["kind"] = rec["kind"]
        if rec.get("sha256") != actual:
            out["reason"] = "sha256-mismatch"
            return out
        if rec["kind"] == KIND_DEVICE_READ:
            # 출처(기기에서 읽음)와 무결성은 다르다: 이중 읽기가 어긋난 덤프는 기기에서 읽었어도 믿을 수 있는 내용이 아니다(fail closed)
            if (rec.get("source") or {}).get("match") is False:
                out["reason"] = READ_MISMATCH
                return out
            out.update(trusted=True, reason="device-read")
            return out
        if self.attestations is not None:
            kind, subject, binding = provenance_import_target(cid, actual)
            att = self.attestations.require(kind, subject, binding, questions=list(PROVENANCE_IMPORT_QUESTIONS))
            if att is not None:
                out.update(trusted=True, reason="imported-attested", attestation_id=att["id"])
                return out
        out["reason"] = "imported-unattested"
        return out


__all__ = [
    "CHAIN_BROKEN",
    "READ_MISMATCH",
    "KIND_DEVICE_FACT",
    "KIND_DEVICE_READ",
    "KIND_IMPORTED",
    "LEDGER_KINDS",
    "PROVENANCE_IMPORT_QUESTIONS",
    "ProvenanceError",
    "ProvenanceLedger",
    "parse_ledger",
    "provenance_import_target",
]
