"""선택한 SQLite·Android 앱 기록과 타임라인의 MCP 입구.

파서는 검증한 fd에서 선택한 바이트만 받는다. 분석 JSON의 경로도 같은 EV의 보관 기록과
해시가 맞을 때만 따라가며, 원본 DB를 SQL 엔진으로 열거나 URL·첨부물을 실행하지 않는다.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import threading
import time
from pathlib import PurePosixPath
from typing import Any

from pweh import evidence as E, fs as pfs, safeio
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

from . import fsops

MAX_FILE_BYTES = 64 << 20
MAX_ANALYSIS_BYTES = 16 << 20
PARSER_OUTPUT_BYTES = 15 << 20  # 출처·선택자·호출 인자 봉투의 공간을 남긴다.
FAMILIES = ("sms", "calls", "contacts", "browser")


class _ServerAPI:
    """서버의 현재 함수 참조를 사용한다. 순환 import 없이 테스트의 runtime 교체도 따른다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _deadline(seconds: float) -> float:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or not 0 < seconds <= 45:
        raise ValidationFailed("max_seconds 는 0 초 초과, 45 초 이하의 유한한 값이어야 합니다.")
    return time.monotonic() + seconds


def _check(cancel: threading.Event, deadline: float, *, time_limit: bool = True) -> None:
    if cancel.is_set():
        raise PwehError("분석이 취소되었습니다.", code="cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise PwehError("분석 호출의 시간 한도에 닿았습니다.", code="time_limit")


def _selector(ref: str | None, path: str | None, name: str) -> None:
    if ref is not None and path is not None:
        raise ValidationFailed(f"{name}의 ref 와 path 는 함께 지정하지 않습니다.")
    for item in (ref, path):
        if item is not None and (not isinstance(item, str) or not item.strip() or len(item) > 32768 or "\x00" in item):
            raise ValidationFailed(f"{name} 선택자는 비어 있지 않은 32768자 이하 문자열이어야 합니다.")


def _source(opened: Any, evidence_id: str, member: dict | None = None) -> dict:
    return {**(member or {}), "kind": "evidence", "evidence_id": evidence_id,
            "evidence_sha256": opened.intake["hashes"]["sha256"]}


def _selection_coverage(report: dict, sources: dict) -> None:
    """복구한 파일의 불확실성을 DB 내부 상태·앱 사건의 신뢰도에도 전달한다."""
    uncertain = [name for name, source in sources.items()
                 if source.get("deleted") or source.get("confidence") != "high" or source.get("complete") is not True]
    incomplete_containers = {name: source.get("container_truncated_reasons") or []
                             for name, source in sources.items() if source.get("container_truncated")}
    if incomplete_containers:
        # 선택한 멤버는 완전하게 검증했더라도 전체 아카이브를 다 보았다고 주장하지 않는다.
        report.setdefault("coverage", {})["container_listing_incomplete"] = incomplete_containers
        report.setdefault("warnings", []).append("container_listing_incomplete")
    if not uncertain:
        return
    report.setdefault("coverage", {})["selection_uncertain"] = uncertain
    report["coverage"]["record_state_basis"] = "selected-database-snapshot"
    report.setdefault("warnings", []).extend([
        "selection_uncertain",
        "삭제·복구 후보 입력의 바이트 출처는 확정할 수 없다. current는 선택한 DB snapshot 내부 상태이며 원래 파일·기기의 현재 기록을 뜻하지 않는다.",
    ])
    if report.get("status") == "ok":
        report["status"] = "partial"
    # SQLite 구조가 정상이어도 잘못된 복구 후보가 실제 원본 기록임을 증명하지는 않는다.
    for section in ("records", "events"):
        for item in report.get(section) or []:
            item["confidence"] = "possible"


def _load_inputs(opened: Any, *, partition: int | None, ref: str | None, path: str | None,
                 wal_ref: str | None, wal_path: str | None, journal_ref: str | None, journal_path: str | None,
                 method: str, deadline: float, cancel: threading.Event) -> tuple[dict, dict]:
    inputs, sources = {}, {}
    for kind, selected_ref, selected_path in (("database", ref, path), ("wal", wal_ref, wal_path),
                                                ("journal", journal_ref, journal_path)):
        if kind != "database" and selected_ref is None and selected_path is None:
            continue
        _check(cancel, deadline)
        data, member = fsops.read_selected_file(opened.fd, partition=partition, ref=selected_ref, path=selected_path,
                                                method=method, max_bytes=MAX_FILE_BYTES,
                                                deadline=deadline, cancel=cancel.is_set)
        inputs[kind], sources[kind] = data, member
        if kind != "database":
            # 같은 EV라고 해서 아무 DB의 WAL을 덮지 않는다. 이름 관계도 암호학적 결속은 아니다.
            db_path, side_path = sources["database"].get("path"), member.get("path")
            if not db_path or not side_path or (str(db_path) + "-" + kind).casefold() != str(side_path).casefold():
                raise ValidationFailed(f"{kind} 는 같은 EV·파티션·디렉터리에 있는 DB 이름 + '-{kind}' 파일이어야 합니다.")
            if sources["database"].get("partition") != member.get("partition"):
                raise ValidationFailed("DB 와 부속 파일의 파티션이 다릅니다.")
    return inputs, sources


async def _sqlite_run(S: Any, *, event: str, case_id: str, evidence_id: str, partition: int | None,
                      ref: str | None, path: str | None, wal_ref: str | None, wal_path: str | None,
                      journal_ref: str | None, journal_path: str | None, method: str,
                      families: list[str] | None, include_deleted: bool, max_records: int, max_seconds: float) -> dict:
    from pweh.sqliteparse import SQLiteLimits, analyze_sqlite
    from pweh.androidartifacts import project_android_artifacts

    deadline, cancelled = _deadline(max_seconds), threading.Event()
    for name, r, p in (("DB", ref, path), ("WAL", wal_ref, wal_path), ("journal", journal_ref, journal_path)):
        _selector(r, p, name)
    partition = S._partition_arg(partition)
    if ref is None and path is None and (partition is not None or method != "auto"):
        raise ValidationFailed("EV 자체 DB를 분석할 때 partition·method 를 지정하지 않습니다.")
    if not isinstance(method, str) or not 1 <= len(method) <= 32:
        raise ValidationFailed("method 는 1~32자 문자열이어야 합니다.")
    if type(max_records) is not int or not 1 <= max_records <= 10000:
        raise ValidationFailed("max_records 는 1~10000 정수여야 합니다.")
    if families is None:
        selected = FAMILIES
    elif not families or len(families) > len(FAMILIES) or any(f not in FAMILIES for f in families):
        raise ValidationFailed("families 는 sms/calls/contacts/browser 중 하나 이상이어야 합니다.")
    else:
        selected = tuple(dict.fromkeys(families))

    def work() -> dict:
        case = S.rt().case(case_id, hardware=True)
        with S._open_evidence_sync(case, evidence_id) as opened:
            try:
                inputs, sources = _load_inputs(opened, partition=partition, ref=ref, path=path,
                                               wal_ref=wal_ref, wal_path=wal_path, journal_ref=journal_ref,
                                               journal_path=journal_path, method=method, deadline=deadline, cancel=cancelled)
                limits = dataclasses.replace(SQLiteLimits(), max_records=max_records, max_output_bytes=PARSER_OUTPUT_BYTES)
                sqlite = analyze_sqlite(inputs["database"], inputs.get("wal"), inputs.get("journal"),
                                        include_records=event == "android-artifacts", include_recovery=include_deleted,
                                        limits=limits, deadline=deadline, cancel_event=cancelled)
                if event == "android-artifacts":
                    report = project_android_artifacts(sqlite, families=selected, include_deleted=include_deleted,
                                                       limits=limits, deadline=deadline, cancel_event=cancelled)
                    # 내부 raw rows를 별도로 반환하지 않고 구조·한도만 연결한다.
                    report["sqlite"] = {k: sqlite.get(k) for k in ("status", "header", "snapshot", "usage", "truncated_reasons")}
                else:
                    report = sqlite
                report["source"] = _source(opened, evidence_id, sources["database"])
                report["input_sources"] = sources
                report["params"] = {"partition": partition, "ref": ref, "path": path, "method": method,
                                    "include_deleted": include_deleted, "families": list(selected) if event == "android-artifacts" else None,
                                    "max_records": max_records, "max_seconds": max_seconds}
                _selection_coverage(report, sources)
                if inputs.get("wal") is not None:
                    report.setdefault("warnings", []).append("WAL은 같은 EV의 이름이 대응하는 제공 파일이다. checksum/salt는 WAL 내부 연속성만 확인하며 DB와의 결속을 증명하지 않는다.")
                _check(cancelled, deadline, time_limit=False)  # 시간 상한 결과도 보관하되 취소는 커밋하지 않는다.
                return E.store_analysis(case, opened, report, event=event, custody_log=S.custody(case),
                                        reference_roots=lambda: S._reference_roots(),
                                        check=lambda: _check(cancelled, deadline, time_limit=False),
                                        on_commit=lambda entry: S._audit_custody(case, entry))
            except E.IntegrityProblem as exc:
                S._record_integrity_failure(case, evidence_id, exc, found_by=event)
                raise

    return await run_blocking_cancellable(work, on_cancel=cancelled.set)


def _recorded_artifacts(case: Any, evidence_id: str, path: str, entries: list[dict], expected_sha: str) -> tuple[dict, dict]:
    """같은 EV의 기록된 앱 분석 JSON만 해시 확인 후 연다. JSON 속 경로는 따라가지 않는다."""
    prefix = "forensics/analysis/"
    if not isinstance(path, str) or not path.startswith(prefix) or str(PurePosixPath(path)) != path or "/" in path[len(prefix):] or not path.endswith(".json"):
        raise ValidationFailed("analysis_paths 는 forensics/analysis/ 바로 아래 JSON 경로여야 합니다.")
    events = [e for e in entries if e.get("event") == "android-artifacts" and e.get("evidence_id") == evidence_id
              and ((e.get("data") or {}).get("analysis") or {}).get("path") == path]
    if len(events) != 1:
        raise ValidationFailed("같은 증거의 보관 기록에 유일하게 결속된 앱 분석 JSON만 읽습니다.")
    record = events[0]["data"]["analysis"]
    if type(record.get("size")) is not int or not 0 < record["size"] <= MAX_ANALYSIS_BYTES:
        raise ValidationFailed("분석 JSON 크기가 허용 범위가 아닙니다.")
    dfd = E.open_forensics(case, "analysis")
    try:
        raw = safeio.read_regular(path[len(prefix):], dir_fd=dfd, max_bytes=MAX_ANALYSIS_BYTES, what="기록된 앱 분석", reject_hardlinks=True)
    finally:
        os.close(dfd)
    if len(raw) != record["size"] or hashlib.sha256(raw).hexdigest() != record.get("sha256"):
        raise ValidationFailed("앱 분석 JSON의 크기·해시가 보관 기록과 다릅니다.")
    try:
        report = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ValidationFailed("앱 분석 JSON을 해석할 수 없습니다.") from exc
    source = report.get("source", {}) if isinstance(report, dict) else {}
    if not isinstance(report, dict) or report.get("schema") != "pweh.android-artifacts/v1" or source.get("kind") != "evidence" or source.get("evidence_id") != evidence_id or source.get("evidence_sha256") != expected_sha:
        raise ValidationFailed("앱 분석 스키마·증거 출처가 현재 EV와 다릅니다.")
    return report, {**record, "custody_seq": events[0]["seq"]}


def _filesystem_events(S: Any, opened: Any, evidence_id: str, partition: int | None, max_events: int,
                       deadline: float, cancelled: threading.Event) -> tuple[list, dict, list]:
    events, reasons = [], []

    def add(entries: list[dict], part: int | None) -> None:
        for entry in entries:
            _check(cancelled, deadline)
            for name, timestamp in (entry.get("times") or {}).items():
                if not isinstance(timestamp, dict):
                    continue
                if len(events) >= max_events:
                    if "max_events" not in reasons:
                        reasons.append("max_events")
                    return
                events.append({"kind": f"filesystem.{name}",
                               "source_ref": {"evidence_id": evidence_id, "partition": part, "ref": entry.get("ref"),
                                              "path": entry.get("display_path")},
                               "record_state": "deleted" if entry.get("deleted") else "live",
                               "confidence": "possible" if entry.get("deleted") else "high",
                               "content_summary": str(entry.get("display_path") or "")[:1000], "time": timestamp})

    if os.pread(opened.fd, 16, 0) == b"SQLite format 3\x00" and partition is None:
        return [], {"filesystem": "not-applicable", "reason": "EV 자체가 SQLite DB"}, []
    arc = fsops.archive_inventory(opened.fd, max_entries=max_events, deadline=deadline,
                                   cancel=cancelled.is_set, hash_members=False)
    if arc is not None:
        if partition is not None:
            raise ValidationFailed("아카이브에는 partition 을 지정하지 않습니다.")
        add(arc.get("entries") or [], None)
        reasons.extend(arc.get("truncated_reasons") or [])
        return events, {"container": arc.get("format"), "entries": len(arc.get("entries") or []),
                        "warnings": arc.get("warnings") or []}, reasons
    with S._image(opened) as img:
        _check(cancelled, deadline)
        limits = dataclasses.replace(pfs.Limits(), max_entries=max_events, max_seconds=deadline-time.monotonic(),
                                      max_path_chars=8 << 20)
        budget = fsops.CallBudget.from_limits(limits)
        budget.deadline = deadline
        layout = pfs.detect_partitions(img, limits=limits)
        reasons.extend(fsops.layout_reasons(layout, partition))
        unseen = [fsops.partition_brief(p) for p in layout.get("partitions", [])
                  if partition is None and p.get("fs_hint") not in fsops.OPENABLE]
        if unseen:
            reasons.append("unsupported_partitions")
        for volume in fsops.iter_volumes(img, layout, partition, limits, budget,
                                         include_deleted=True, cancel=cancelled.is_set):
            if volume.get("error"):
                reasons.append("volumes_failed")
                continue
            add(volume["walk"].get("entries") or [], volume["partition"].get("index"))
            reasons.extend(fsops.walk_reasons(volume["walk"], volume["info"], part=volume["partition"], image_size=img.size))
        reasons.extend(budget.limited)
        coverage = {**budget.summary(), "partitions_unexamined": unseen}
        if not budget.walked:
            reasons.append("filesystem_unexamined")
    return events, coverage, reasons


def register_android_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 forensics 서버에 도구를 등록한다. 기기·네트워크 입구는 추가하지 않는다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "증거에서 선택한 SQLite DB 1개의 헤더·schema·table 행 수·freelist와 제공된 WAL/journal 정보를 읽는다. "
        "ref/path는 FAT/exFAT 또는 TAR/ZIP 멤버 선택자이며 둘 다 없으면 EV 자체가 DB여야 한다. WAL/journal은 자동 탐색하지 않고 "
        "같은 EV·파티션·디렉터리의 DB 이름+-wal/-journal을 명시한다. 각 입력64MiB, 전체45초·페이지/셀/출력 상한. "
        "SQL을 실행하지 않으며 사용자 row 내용은 반환하지 않는다. 전체 row_count는 완주했을 때만 숫자, 불완전하면 null과 사유. "
        "분석 JSON0444와 입수·멤버·출력 해시를 sqlite-inventory 보관 기록에 결속한다."), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_sqlite_inventory(case_id: str, evidence_id: str, partition: int | None = None,
                                         ref: str | None = None, path: str | None = None,
                                         wal_ref: str | None = None, wal_path: str | None = None,
                                         journal_ref: str | None = None, journal_path: str | None = None,
                                         method: str = "auto", max_seconds: float = 45.0) -> dict:
        return await _sqlite_run(S, event="sqlite-inventory", case_id=case_id, evidence_id=evidence_id, partition=partition,
                                 ref=ref, path=path, wal_ref=wal_ref, wal_path=wal_path, journal_ref=journal_ref,
                                 journal_path=journal_path, method=method, families=None, include_deleted=False,
                                 max_records=10000, max_seconds=max_seconds)

    @server.tool(description=(
        "선택한 증거 SQLite에서 SMS·통화·연락처·브라우저 기록을 스키마 프로필로 분석해 내용도 반환한다. "
        "입력 선택·무결성·64MiB/45초 제한은 forensics_sqlite_inventory와 같다. families는 sms/calls/contacts/browser, "
        "include_deleted는 WAL 과거기록·freelist 복구 후보 포함이며 삭제 확정을 뜻하지 않는다. "
        "최대 max_records(기본500, 최대10000), 누적 TEXT8MiB·JSON16MiB. 프로필 미지원·누락·잘림은 unknown/partial과 사유로 기록한다. "
        "BLOB은 크기/해시만, 영상·음성·URL·SQL을 실행하지 않는다. JSON0444를 android-artifacts 보관 기록에 결속한다."), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_android_artifacts(case_id: str, evidence_id: str, partition: int | None = None,
                                          ref: str | None = None, path: str | None = None,
                                          wal_ref: str | None = None, wal_path: str | None = None,
                                          journal_ref: str | None = None, journal_path: str | None = None,
                                          method: str = "auto", families: list[str] | None = None,
                                          include_deleted: bool = True, max_records: int = 500, max_seconds: float = 45.0) -> dict:
        return await _sqlite_run(S, event="android-artifacts", case_id=case_id, evidence_id=evidence_id, partition=partition,
                                 ref=ref, path=path, wal_ref=wal_ref, wal_path=wal_path, journal_ref=journal_ref,
                                 journal_path=journal_path, method=method, families=families, include_deleted=include_deleted,
                                 max_records=max_records, max_seconds=max_seconds)

    @server.tool(description=(
        "증거 FAT/exFAT·TAR/ZIP의 파일 시각과 명시한 앱 분석 JSON의 사건을 타임라인으로 묶는다. analysis_paths는 "
        "같은 EV의 android-artifacts 보관 기록·SHA256에 맞는 JSON만 받는다(최대16개, 합16MiB). "
        "시각의 raw/단위/epoch/time_basis를 보존하며 FAT·ZIP DOS의 시간대는 추정하지 않는다. "
        "UTC로 바꿀 수 없는 사건은 undated_events로 분리한다. max_events 기본10000/최대100000, 전체45초. "
        "미검사 파티션·손상·잘림을 coverage에 적고 timeline JSON0444를 보관 기록에 결속한다."), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_timeline(case_id: str, evidence_id: str, partition: int | None = None,
                                 analysis_paths: list[str] | None = None, max_events: int = 10000, max_seconds: float = 45.0) -> dict:
        from pweh.timeline import TimelineLimits, build_timeline

        deadline, cancelled = _deadline(max_seconds), threading.Event()
        part = S._partition_arg(partition)
        if type(max_events) is not int or not 1 <= max_events <= 100000:
            raise ValidationFailed("max_events 는 1~100000 정수여야 합니다.")
        if analysis_paths is not None and (len(analysis_paths) > 16 or any(not isinstance(p, str) for p in analysis_paths)):
            raise ValidationFailed("analysis_paths 는 최대16개 JSON 경로 목록이어야 합니다.")
        paths = list(dict.fromkeys(analysis_paths or []))

        def work() -> dict:
            case = S.rt().case(case_id, hardware=True)
            with S._open_evidence_sync(case, evidence_id) as opened:
                try:
                    artifacts, analyses, reasons, total = [], [], [], 0
                    entries = S.custody(case).entries()
                    for p in paths:
                        _check(cancelled, deadline)
                        report, record = _recorded_artifacts(case, evidence_id, p, entries, opened.intake["hashes"]["sha256"])
                        total += record["size"]
                        if total > MAX_ANALYSIS_BYTES:
                            raise ValidationFailed("선택한 앱 분석 JSON 합계가16MiB를 넘었습니다.")
                        analyses.append(record)
                        for event in report.get("events") or []:
                            if len(artifacts) >= max_events:
                                reasons.append("max_events")
                                break
                            artifacts.append({**event, "analysis_ref": {"path": p, "sha256": record["sha256"]}})
                        reasons.extend(report.get("truncated_reasons") or [])
                        if report.get("status") != "ok":
                            reasons.append("source_analysis_incomplete")
                    filesystem, coverage, fs_reasons = _filesystem_events(S, opened, evidence_id, part, max_events, deadline, cancelled)
                    reasons.extend(fs_reasons)
                    report = build_timeline(filesystem, artifacts, limits=dataclasses.replace(TimelineLimits(), max_events=max_events,
                                                                                            max_output_bytes=PARSER_OUTPUT_BYTES),
                                            deadline=deadline, cancel_event=cancelled)
                    report["source"] = _source(opened, evidence_id)
                    report["analysis_sources"] = analyses
                    report["filesystem_coverage"] = coverage
                    report["params"] = {"partition": part, "analysis_paths": paths, "max_events": max_events, "max_seconds": max_seconds}
                    report["truncated_reasons"] = sorted(set(reasons + (report.get("truncated_reasons") or [])))
                    if report["truncated_reasons"]:
                        report.update(status="partial", truncated=True)
                    return E.store_analysis(case, opened, report, event="timeline", custody_log=S.custody(case),
                                            reference_roots=lambda: S._reference_roots(),
                                            check=lambda: _check(cancelled, deadline, time_limit=False),
                                            on_commit=lambda entry: S._audit_custody(case, entry))
                except E.IntegrityProblem as exc:
                    S._record_integrity_failure(case, evidence_id, exc, found_by="timeline")
                    raise

        return await run_blocking_cancellable(work, on_cancel=cancelled.set)
