"""선택한 합성 DB의 네 앱 프로필과 스키마/시각/과거 후보 경계 시험."""
from __future__ import annotations

from dataclasses import replace
import copy
import json
import threading
import time

from pweh.androidartifacts import project_android_artifacts
from pweh.sqliteparse import SQLiteLimits, analyze_sqlite
from .test_sqliteparse import database, wal_fixture


def project(sql, *, families=("sms", "calls", "contacts", "browser"), **kwargs):
    source = analyze_sqlite(database(sql), include_records=True)
    return project_android_artifacts(source, families=families, **kwargs)


def test_sms_calls_actual_column_order_content_and_timestamp():
    report = project("CREATE TABLE sms(body TEXT, type INTEGER, _id INTEGER PRIMARY KEY, date INTEGER, address TEXT);"
                     "INSERT INTO sms VALUES('PWEH 합성 문구',1,15,1700000000000,'synthetic-sender');"
                     "CREATE TABLE calls(duration INTEGER, number TEXT, type INT, date INT, name TEXT);"
                     "INSERT INTO calls VALUES(60,'synthetic-call',2,1700000000123,'cached synthetic');", families=("sms", "calls"))
    assert report["status"] == "ok", report
    assert report["records"][0]["content"]["body"] == "PWEH 합성 문구"
    assert report["records"][0]["content"]["_id"] == 15
    assert report["events"][0]["time"]["iso_utc"] == "2023-11-14T22:13:20.000000Z"
    assert report["events"][1]["time"]["iso_utc"] == "2023-11-14T22:13:20.123000Z"
    assert report["records"][1]["content"]["name_basis"] == "cached-name-not-current-contact-proof"


def test_contacts_mimetype_join_not_fixed_numeric_ids():
    report = project("CREATE TABLE mimetypes(_id INTEGER PRIMARY KEY,mimetype TEXT);"
                     "INSERT INTO mimetypes VALUES(93,'vnd.android.cursor.item/phone_v2'),(14,'vnd.android.cursor.item/email_v2');"
                     "CREATE TABLE raw_contacts(_id INTEGER PRIMARY KEY,contact_id INT); INSERT INTO raw_contacts VALUES(7,8);"
                     "CREATE TABLE data(_id INTEGER PRIMARY KEY,raw_contact_id INT,mimetype_id INT,data1 TEXT);"
                     "INSERT INTO data VALUES(1,7,93,'synthetic-phone'),(2,7,14,'synthetic@example.invalid');"
                     "CREATE TABLE contacts(_id INTEGER PRIMARY KEY,contact_last_updated_timestamp INT);"
                     "INSERT INTO contacts VALUES(8,1700000000000);", families=("contacts",))
    assert report["status"] == "ok", report
    assert [r["content"].get("field") for r in report["records"]] == ["phone", "email", None]
    assert report["records"][0]["content"]["contact_id"] == 8
    assert len(report["records"][0]["join_refs"]) == 2
    assert len(report["events"]) == 1 and report["events"][0]["kind"] == "contact.updated"


def test_contacts_unknown_or_duplicate_join_not_guessed():
    report = project("CREATE TABLE mimetypes(_id INT,mimetype TEXT);"
                     "INSERT INTO mimetypes VALUES(9,'vnd.android.cursor.item/phone_v2'),(9,'vnd.android.cursor.item/email_v2');"
                     "CREATE TABLE raw_contacts(_id INTEGER PRIMARY KEY,contact_id INT); INSERT INTO raw_contacts VALUES(7,8);"
                     "CREATE TABLE data(raw_contact_id INT,mimetype_id INT,data1 TEXT);"
                     "INSERT INTO data VALUES(7,9,'synthetic'),(99,10,'unknown');", families=("contacts",))
    assert report["records"] == [] and report["status"] == "partial"
    assert report["coverage"]["incomplete_joins"] == 2


def test_browser_chromium_visit_and_legacy_times_no_url_visit():
    report = project("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INT);"
                     "INSERT INTO urls VALUES(8,'https://example.invalid/no-visit','PWEH',13344473600000000);"
                     "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INT,visit_time INT);"
                     "INSERT INTO visits VALUES(3,8,13344473600123456);"
                     "CREATE TABLE searches(search TEXT,date INT); INSERT INTO searches VALUES('합성 검색',1700000000000);",
                     families=("browser",))
    assert report["status"] == "ok"
    assert len(report["records"]) == 2 and len(report["events"]) == 2
    assert report["events"][0]["time"]["iso_utc"] == "2023-11-14T22:13:20.123456Z"
    assert report["records"][0]["content"]["url"] == "https://example.invalid/no-visit"
    assert not any(e["kind"].startswith("browser.url-aggregate") for e in report["events"])


def test_browser_joined_url_truncation_lowers_record_and_event_confidence():
    data = database("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INT);"
                    "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INT,visit_time INT);"
                    "INSERT INTO visits VALUES(3,8,13344473600123456);", page_size=4096,
                    params=[("INSERT INTO urls VALUES(?,?,?,?)", [(8, "https://example.invalid/" + "P" * 70000, "PWEH", 13344473600000000)])])
    source = analyze_sqlite(data, include_records=True)
    report = project_android_artifacts(source, families=("browser",))
    assert report["status"] == "partial"
    for item in [report["records"][0], report["events"][0]]:
        assert item["confidence"] == "possible" and "urls.url" in item["truncated_fields"]
        assert len(item["join_refs"]) == 1


def test_contacts_joined_value_truncation_lowers_confidence():
    data = database("CREATE TABLE mimetypes(_id INTEGER PRIMARY KEY,mimetype TEXT);"
                    "INSERT INTO mimetypes VALUES(93,'vnd.android.cursor.item/phone_v2');"
                    "CREATE TABLE raw_contacts(_id INTEGER PRIMARY KEY,contact_id TEXT);"
                    "CREATE TABLE data(raw_contact_id INT,mimetype_id INT,data1 TEXT);"
                    "INSERT INTO data VALUES(7,93,'synthetic-phone');", page_size=4096,
                    params=[("INSERT INTO raw_contacts VALUES(?,?)", [(7, "P" * 70000)])])
    source = analyze_sqlite(data, include_records=True)
    report = project_android_artifacts(source, families=("contacts",))
    record = report["records"][0]
    assert record["confidence"] == "possible" and "raw_contacts.contact_id" in record["truncated_fields"]
    assert len(record["join_refs"]) == 2


def test_unknown_schema_is_unknown_not_absence_and_generated_mapping_not_used():
    report = project("CREATE TABLE custom(body TEXT, when_sent INT); INSERT INTO custom VALUES('PWEH',1);", families=("sms",))
    assert report["status"] == "partial" and report["unknown_schemas"] == ["sms"]
    report = project("CREATE TABLE sms(address TEXT,body TEXT,date INT,type INT,x AS (date+1));"
                     "INSERT INTO sms(address,body,date,type) VALUES('synthetic','PWEH',1,1);", families=("sms",))
    assert not report["records"] and report["coverage"]["unmapped_rows"] == 1


def test_history_candidates_stay_unattributed_not_joined_or_events(tmp_path):
    data, wal = wal_fixture(tmp_path)
    source = analyze_sqlite(data, wal, include_records=True, include_recovery=True)
    report = project_android_artifacts(source, families=("sms",), include_deleted=True)
    assert len(report["records"]) == 1 and len(report["events"]) == 1
    assert report["records"][0]["content"]["body"] == "new PWEH message"
    assert report["recovery"]["candidates"][0]["table_assignment"] == "unknown"
    assert any("old PWEH message" in c["raw_values"] for c in report["recovery"]["candidates"])


def test_snapshot_mismatch_and_projection_cancellation():
    source = analyze_sqlite(database("CREATE TABLE sms(address TEXT,body TEXT,date INT,type INT);"
                                    "INSERT INTO sms VALUES('synthetic','PWEH',1,1);"), include_records=True)
    wrong = copy.deepcopy(source)
    wrong["records"][0]["origin"]["snapshot_id"] = "other"
    report = project_android_artifacts(wrong, families=("sms",))
    assert not report["records"] and report["coverage"]["unmapped_rows"] == 1
    cancelled = threading.Event()
    cancelled.set()
    assert "cancelled" in project_android_artifacts(source, cancel_event=cancelled)["truncated_reasons"]
    assert "time" in project_android_artifacts(source, deadline=time.monotonic() - 1)["truncated_reasons"]


def test_projection_record_cap_and_binary_is_only_metadata():
    source = analyze_sqlite(database("CREATE TABLE sms(address TEXT,body TEXT,date INT,type INT,extra BLOB);"
                                    "INSERT INTO sms VALUES('synthetic','one',1,1,x'112233'),('synthetic','two',2,2,x'445566');"), include_records=True)
    report = project_android_artifacts(source, families=("sms",), limits=replace(SQLiteLimits(), max_records=1))
    assert len(report["records"]) == 1 and report["truncated"]
    assert "extra" not in json.dumps(report)
