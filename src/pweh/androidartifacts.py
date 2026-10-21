"""선택한 SQLite snapshot의 SMS·통화·연락처·브라우저 내용 투영.

테이블/열 signature와 같은 snapshot의 row만 사용한다. 경로·URL·BLOB은 실행하거나
열지 않으며 WAL 과거 후보를 현재 연락처와 합치지 않는다.
"""
from __future__ import annotations

import json

from .errors import ValidationFailed
from .sqliteparse import Budget, BudgetStop
from .timeline import normalize_timestamp

_FAMILIES = ("sms", "calls", "contacts", "browser")
_MIMES = {"vnd.android.cursor.item/name": "name", "vnd.android.cursor.item/phone_v2": "phone",
          "vnd.android.cursor.item/email_v2": "email", "vnd.android.cursor.item/postal-address_v2": "address"}


def project_android_artifacts(sqlite_report, *, families=_FAMILIES, include_deleted=False,
                              limits=None, deadline=None, cancel_event=None):
    """프로필 미일치·불완전 join은 unknown으로 표시하고 확인한 TEXT만 반환한다."""
    budget = Budget(limits, deadline, cancel_event)
    if not isinstance(sqlite_report, dict) or sqlite_report.get("schema") != "pweh.sqlite/v1":
        raise ValidationFailed("SQLite 코어 보고서가 필요합니다.")
    if not isinstance(families, (tuple, list)) or not families or any(f not in _FAMILIES for f in families):
        raise ValidationFailed("families는 sms/calls/contacts/browser 목록이어야 합니다.")
    if not isinstance(include_deleted, bool):
        raise ValidationFailed("include_deleted는 boolean이어야 합니다.")
    families = list(dict.fromkeys(families))
    out = {"schema": "pweh.android-artifacts/v1", "status": "ok", "profiles": [],
           "recognized_families": [], "unknown_schemas": [], "records": [], "events": [],
           "recovery": {"status": "skipped", "candidates": []},
           "coverage": {"requested_families": families, "rows_seen": 0, "rows_projected": 0,
                        "unmapped_rows": 0, "incomplete_joins": 0,
                        "source_status": sqlite_report.get("status"),
                        "source_truncated": sqlite_report.get("truncated", False)},
           "truncated": False, "truncated_reasons": [], "warnings": []}
    schemas, tables, rows = {}, {}, {}
    snapshot = sqlite_report.get("snapshot", {}).get("snapshot_id")
    try:
        for table in sqlite_report.get("schema_objects", []):
            budget.check()
            if table.get("type") == "table":
                schemas[table["name"].lower()] = {c["name"].lower() for c in table.get("columns", [])}
        for table in sqlite_report.get("tables", []):
            tables[table["name"].lower()] = table
        for row in sqlite_report.get("records", []):
            budget.check()
            out["coverage"]["rows_seen"] += 1
            if row.get("record_state") != "current" or row.get("mapping_status") != "known" or row.get("origin", {}).get("snapshot_id") != snapshot:
                out["coverage"]["unmapped_rows"] += 1
                continue
            name = row["table"].lower()
            values = {k.lower(): v for k, v in row.get("values", {}).items()}
            rows.setdefault(name, []).append((row, values))

        def signature(table, required):
            return set(required) <= schemas.get(table, set())

        def profile(family, name, names):
            out["profiles"].append({"family": family, "id": name, "tables": names,
                                    "complete": all(tables.get(t, {}).get("count_complete") and tables.get(t, {}).get("records_complete") for t in names)})
            if family not in out["recognized_families"]:
                out["recognized_families"].append(family)

        def index(table, key):
            result, duplicates = {}, set()
            for row, values in rows.get(table, []):
                budget.check()
                value = values.get(key)
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    continue
                if value in result:
                    duplicates.add(value)
                else:
                    result[value] = (row, values)
            for value in duplicates:
                result.pop(value, None)
            return result

        def stamp(value, unit="milliseconds", epoch="unix", basis="aosp", zero_unset=False):
            return normalize_timestamp(value, unit=unit, epoch=epoch, basis=basis, zero_unset=zero_unset)

        def emit(family, kind, row, content, times=(), joins=(), joined_rows=()):
            budget.check()
            if len(out["records"]) >= budget.limits.max_records:
                budget.reason("max_records")
                raise BudgetStop("max_records")
            ref = row["record_ref"]
            evidence = {"table": row["table"], "snapshot_id": snapshot, "origin": row["origin"]}
            truncated_fields = [name for name, field in zip(row.get("field_names", []), row.get("fields", [])) if field.get("truncated") or not field.get("decode_valid", True)]
            # 결합한 행에서 가져온 문자열도 동일한 잘림·해독 신뢰도 경계를 갖는다.
            for joined in joined_rows:
                truncated_fields.extend(f"{joined['table']}.{name}"
                                        for name, field in zip(joined.get("field_names", []), joined.get("fields", []))
                                        if field.get("truncated") or not field.get("decode_valid", True))
            record = {"family": family, "kind": kind, "record_ref": ref, "source_ref": evidence,
                      "record_state": "current", "confidence": "possible" if truncated_fields else "high", "content": content,
                      "truncated_fields": truncated_fields, "join_refs": list(joins)}
            budget.store(record)
            out["records"].append(record)
            out["coverage"]["rows_projected"] += 1
            for label, timestamp in times:
                event = {"kind": kind + "." + label, "record_ref": ref, "source_ref": evidence,
                         "record_state": "current", "confidence": "possible" if truncated_fields else "high", "time": timestamp,
                         "content_summary": content, "truncated_fields": truncated_fields,
                         "join_refs": list(joins)}
                budget.store(event)
                out["events"].append(event)

        if "sms" in families and signature("sms", ("address", "body", "date", "type")):
            profile("sms", "aosp-sms-v1", ["sms"])
            for row, values in rows.get("sms", []):
                content = {key: values[key] for key in ("_id", "address", "body", "subject", "type", "read", "thread_id", "date", "date_sent") if key in values}
                times = [("date", stamp(values.get("date"), basis="aosp-sms-date-ms"))]
                if isinstance(values.get("date_sent"), int) and values["date_sent"]:
                    times.append(("sent", stamp(values["date_sent"], basis="aosp-sms-date-sent-ms")))
                emit("sms", "sms.message", row, content, times)
        if "calls" in families and signature("calls", ("number", "date", "duration", "type")):
            profile("calls", "aosp-calls-v1", ["calls"])
            for row, values in rows.get("calls", []):
                content = {key: values[key] for key in ("_id", "number", "date", "duration", "type", "name", "countryiso", "geocoded_location") if key in values}
                content["duration_unit"] = "seconds"
                if "name" in content:
                    content["name_basis"] = "cached-name-not-current-contact-proof"
                emit("calls", "call", row, content, [("start", stamp(values.get("date"), basis="aosp-call-date-ms"))])
        if "contacts" in families and signature("data", ("mimetype_id", "raw_contact_id", "data1")) and signature("mimetypes", ("_id", "mimetype")) and signature("raw_contacts", ("_id", "contact_id")):
            profile("contacts", "aosp-contacts-v1", ["data", "mimetypes", "raw_contacts"])
            mime_index = index("mimetypes", "_id")
            raw_index = index("raw_contacts", "_id")
            for row, values in rows.get("data", []):
                mime = mime_index.get(values.get("mimetype_id")) if isinstance(values.get("mimetype_id"), (int, str)) else None
                raw = raw_index.get(values.get("raw_contact_id")) if isinstance(values.get("raw_contact_id"), (int, str)) else None
                if not mime or not raw:
                    out["coverage"]["incomplete_joins"] += 1
                    continue
                mime_name = mime[1].get("mimetype")
                label = _MIMES.get(mime_name) if isinstance(mime_name, str) else None
                if label is None:
                    continue
                content = {"raw_contact_id": values.get("raw_contact_id"), "contact_id": raw[1].get("contact_id"),
                           "field": label, "value": values.get("data1"), "mimetype": mime[1]["mimetype"]}
                joins = [mime[0]["record_ref"], raw[0]["record_ref"]]
                emit("contacts", "contact." + label, row, content, joins=joins, joined_rows=(mime[0], raw[0]))
            # 수정 시각은 aggregate contact마다 한 번만 기록하며 생성 시각으로 보지 않는다.
            for row, values in rows.get("contacts", []):
                if "contact_last_updated_timestamp" in values:
                    emit("contacts", "contact", row, {"_id": values.get("_id"), "time_meaning": "last-updated"},
                         [("updated", stamp(values["contact_last_updated_timestamp"], basis="aosp-contact-last-updated-ms", zero_unset=True))])
        if "browser" in families:
            if signature("urls", ("id", "url", "title", "last_visit_time")) and signature("visits", ("id", "url", "visit_time")):
                profile("browser", "chromium-history-v1", ["urls", "visits"])
                urls = index("urls", "id")
                for row, values in rows.get("visits", []):
                    linked = urls.get(values.get("url")) if isinstance(values.get("url"), (str, int)) else None
                    content = {key: values[key] for key in ("id", "url", "visit_time", "from_visit", "transition", "visit_duration") if key in values}
                    content["url_id"] = content.pop("url", None)
                    joins = []
                    if linked:
                        content.update(url=linked[1].get("url"), title=linked[1].get("title"), join_status="matched")
                        joins.append(linked[0]["record_ref"])
                    else:
                        content["join_status"] = "unknown"
                        out["coverage"]["incomplete_joins"] += 1
                    emit("browser", "browser.visit", row, content,
                         [("visited", stamp(values.get("visit_time"), "microseconds", "windows-1601", "chromium-base-time-us", True))],
                         joins, joined_rows=(linked[0],) if linked else ())
            elif signature("urls", ("id", "url", "title", "last_visit_time")):
                profile("browser", "chromium-url-aggregate-v1", ["urls"])
                for row, values in rows.get("urls", []):
                    content = {key: values[key] for key in ("id", "url", "title", "visit_count", "last_visit_time") if key in values}
                    content["meaning"] = "aggregate-last-visit"
                    emit("browser", "browser.url-aggregate", row, content,
                         [("last-visited", stamp(values.get("last_visit_time"), "microseconds", "windows-1601", "chromium-base-time-us", True))])
            if signature("bookmarks", ("url", "title", "date", "bookmark")):
                profile("browser", "legacy-aosp-browser-v1", ["bookmarks"])
                for row, values in rows.get("bookmarks", []):
                    content = {key: values[key] for key in ("_id", "url", "title", "date", "created", "bookmark", "visits") if key in values}
                    emit("browser", "browser.legacy-bookmark-or-history", row, content,
                         [("last-visited", stamp(values.get("date"), basis="legacy-aosp-browser-ms", zero_unset=True))])
            if signature("searches", ("search", "date")):
                profile("browser", "legacy-aosp-browser-searches-v1", ["searches"])
                for row, values in rows.get("searches", []):
                    emit("browser", "browser.search", row, {"search": values.get("search")},
                         [("searched", stamp(values.get("date"), basis="legacy-aosp-search-ms", zero_unset=True))])
        if include_deleted:
            recovery = sqlite_report.get("recovery", {})
            out["recovery"] = {"status": recovery.get("status", "unknown"), "candidates": [],
                               "coverage": recovery.get("coverage", {}), "warnings": recovery.get("warnings", [])}
            for candidate in recovery.get("candidates", []):
                budget.check()
                # 알 수 없는 table을 앱 내용에 투영하거나 current row와 결합하지 않는다.
                budget.store(candidate)
                out["recovery"]["candidates"].append(candidate)
    except BudgetStop as exc:
        out["warnings"].append(str(exc))
    out["unknown_schemas"] = [family for family in families if family not in out["recognized_families"]]
    out["truncated_reasons"] = list(dict.fromkeys(sqlite_report.get("truncated_reasons", []) + budget.reasons))
    out["truncated"] = bool(out["truncated_reasons"])
    if (out["unknown_schemas"] or out["truncated"] or out["coverage"]["source_status"] != "ok"
            or out["coverage"]["unmapped_rows"] or out["coverage"]["incomplete_joins"]
            or (include_deleted and out["recovery"]["status"] != "ok")
            or any(not p["complete"] for p in out["profiles"])):
        out["status"] = "partial"
    if len(json.dumps(out, ensure_ascii=False, allow_nan=False).encode()) > budget.limits.max_output_bytes:
        out["records"], out["events"], out["recovery"]["candidates"] = [], [], []
        out.update(status="partial", truncated=True)
        out["truncated_reasons"].append("max_output_bytes")
    return out
