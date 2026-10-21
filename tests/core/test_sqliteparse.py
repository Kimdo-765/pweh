"""합성 SQLite oracle/손상/한도/WAL/잔여 후보 시험. 엔진은 fixture 생성에만 쓴다."""
from __future__ import annotations

from dataclasses import replace
import json
import sqlite3
import struct
import threading
import tempfile
from pathlib import Path
import time

import pytest

from pweh.errors import ValidationFailed
from pweh.sqliteparse import SQLiteLimits, analyze_sqlite, parse_ddl, varint
from pweh.sqlitewal import _checksum


def dump_connection(conn):
    with tempfile.TemporaryDirectory() as folder:
        target = Path(folder) / "synthetic.db"
        saved = sqlite3.connect(target)
        conn.backup(saved)
        saved.close()
        return target.read_bytes()


def database(sql, *, page_size=512, encoding="UTF-8", params=()):
    conn = sqlite3.connect(":memory:")
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.execute(f"PRAGMA encoding='{encoding}'")
    conn.executescript(sql)
    for statement, rows in params:
        conn.executemany(statement, rows)
    conn.commit()
    data = dump_connection(conn)
    conn.close()
    return data


def analyzed(sql, **kwargs):
    return analyze_sqlite(database(sql, **kwargs), include_records=True)


@pytest.mark.parametrize("page_size", [512, 4096, 65536])
@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16le", "UTF-16be"])
def test_record_types_and_encoding(page_size, encoding):
    result = analyzed("CREATE TABLE sample(id INTEGER PRIMARY KEY, text TEXT, n INT, f REAL, b BLOB, empty);"
                      "INSERT INTO sample VALUES(-5, 'PWEH 합성', -32769, 1.25, x'010203', NULL);", page_size=page_size, encoding=encoding)
    assert result["status"] == "ok", result
    assert result["tables"][0]["row_count"] == 1
    value = result["records"][0]["values"]
    assert value["id"] == -5 and value["text"] == "PWEH 합성"
    assert value["n"] == -32769 and value["f"] == 1.25 and value["empty"] is None
    assert value["b"]["type"] == "blob" and value["b"]["size"] == 3
    assert result["records"][0]["origin"]["spans"]


def test_btree_multilevel_counts_and_without_rowid_storage_order():
    data = database('CREATE TABLE normal(id INTEGER PRIMARY KEY, txt); CREATE TABLE keyed(a TEXT, b INT, c TEXT, PRIMARY KEY(b,a)) WITHOUT ROWID;',
                    params=[("INSERT INTO normal VALUES (?,?)", [(i, "PWEH" * 20) for i in range(700)]),
                            ("INSERT INTO keyed VALUES (?,?,?)", [("key" + str(i), i, "PWEH" * 12) for i in range(700)])])
    result = analyze_sqlite(data, include_records=True)
    assert result["status"] == "ok", result["warnings"]
    assert {t["name"]: t["row_count"] for t in result["tables"]} == {"normal": 700, "keyed": 700}
    rows = [r["values"] for r in result["records"] if r["table"] == "keyed"]
    assert len(rows) == 700 and all(r["a"] == "key" + str(r["b"]) and r["c"] == "PWEH" * 12 for r in rows)


def test_overflow_and_row_count_inventory_content_omission():
    data = database("CREATE TABLE large(id INTEGER PRIMARY KEY, text TEXT);", params=[("INSERT INTO large VALUES (?,?)", [(1, "합성" * 1500)])])
    result = analyze_sqlite(data, include_records=True)
    assert result["status"] == "ok", result["warnings"]
    assert len(result["records"][0]["origin"]["spans"]) > 1
    assert result["records"][0]["values"]["text"] == "합성" * 1500
    inventory = analyze_sqlite(data)
    assert inventory["records"] == [] and inventory["tables"][0]["row_count"] == 1
    assert "합성" not in json.dumps(inventory, ensure_ascii=False)


def test_alter_missing_fields_default_and_identifier_quotes():
    result = analyzed('CREATE TABLE "odd, name" ("id" INTEGER PRIMARY KEY, "body text" TEXT);'
                      'INSERT INTO "odd, name" VALUES (7, \'합성\');'
                      'ALTER TABLE "odd, name" ADD COLUMN new_value TEXT DEFAULT \'later\';')
    row = result["records"][0]
    assert row["values"] == {"id": 7, "body text": "합성", "new_value": "later"}
    assert row["value_origins"]["new_value"] == "schema_default_missing_field"
    assert parse_ddl('CREATE TABLE t(a INT, b TEXT, CHECK(a IN (1,2)))')["mapping_status"] == "known"
    assert parse_ddl('CREATE TABLE t(a INT, b AS (a+1))')["mapping_status"] == "unknown"
    assert parse_ddl('CREATE TABLE t(a INTEGER PRIMARY KEY DESC, b TEXT)')["rowid_alias"] is None


def test_rowid_alias_desc_does_not_replace_stored_value():
    result = analyzed("CREATE TABLE t(a INTEGER PRIMARY KEY DESC,b TEXT); INSERT INTO t VALUES(99,'PWEH');")
    assert result["records"][0]["values"]["a"] == 99
    assert result["records"][0]["rowid"] != 99


@pytest.mark.parametrize("definition", [
    "_id INTEGER CHECK('PRIMARY' != 'KEY'), body TEXT",
    "_id INTEGER DEFAULT 'PRIMARY' CHECK('KEY' != 'x'), body TEXT",
    "_id INTEGER, body TEXT, CHECK('PRIMARY' != 'KEY')",
    "_id INTEGER, body TEXT, CONSTRAINT actual_check CHECK('PRIMARY' != 'KEY')",
    "_id INTEGER, body TEXT DEFAULT 'GENERATED' CHECK('AS' != 'x')",
    '"PRIMARY" INTEGER, "KEY" TEXT, CHECK("PRIMARY" IS NULL OR "KEY" != \'x\')',
])
def test_ddl_constraint_words_inside_expressions_are_not_primary_keys(definition):
    conn = sqlite3.connect(":memory:")
    conn.executescript(f"CREATE TABLE t({definition}); INSERT INTO t VALUES(NULL, 'PWEH');")
    conn.commit()
    expected = tuple(conn.execute("SELECT * FROM t").fetchone())
    result = analyze_sqlite(dump_connection(conn), include_records=True)
    conn.close()
    assert result["status"] == "ok", result
    assert result["schema_objects"][0]["rowid_alias"] is None
    assert tuple(result["records"][0]["values"].values()) == expected


@pytest.mark.parametrize("key", ["PRIMARY KEY(a DESC)", "CONSTRAINT key_name PRIMARY KEY(a DESC)"])
def test_table_primary_key_desc_keeps_rowid_alias(key):
    result = analyzed(f"CREATE TABLE t(a INTEGER, b TEXT, {key}); INSERT INTO t VALUES(9, 'PWEH');")
    assert result["records"][0]["values"] == {"a": 9, "b": "PWEH"}


@pytest.mark.parametrize("declaration,expected", [
    ("TEXT DEFAULT 123", "123"),
    ("INTEGER DEFAULT '123'", 123),
    ("NUMERIC DEFAULT '123.5'", 123.5),
    ("REAL DEFAULT 123", 123.0),
])
def test_alter_missing_default_requiring_affinity_is_not_guessed(declaration, expected):
    conn = sqlite3.connect(":memory:")
    conn.executescript("CREATE TABLE t(id INTEGER PRIMARY KEY); INSERT INTO t VALUES(7);"
                       f"ALTER TABLE t ADD COLUMN body {declaration};")
    conn.commit()
    actual = conn.execute("SELECT body FROM t").fetchone()[0]
    assert actual == expected and type(actual) is type(expected)
    result = analyze_sqlite(dump_connection(conn), include_records=True)
    conn.close()
    row = result["records"][0]
    assert row["mapping_status"] == "partial"
    assert "body" in row["missing_fields"] and "body" not in row["values"]
    column = result["schema_objects"][0]["columns"][1]
    assert column["default_known"] is False
    assert column["default_reason"] == "default_affinity_unsupported"


def test_unsupported_and_corrupt_not_empty_complete():
    assert analyze_sqlite(b"PWEH SYNTHETIC encrypted-like")["status"] == "unsupported"
    data = bytearray(database("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('PWEH');"))
    data[512] = 0xFF
    result = analyze_sqlite(bytes(data), include_records=True)
    assert result["status"] == "partial"
    assert result["tables"][0]["row_count"] is None
    assert result["tables"][0]["count_complete"] is False


def test_cells_overlap_and_table_cycle_are_not_complete():
    data = bytearray(database("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('PWEH'); INSERT INTO t VALUES('PWEH2');"))
    data[522:524] = data[520:522]
    result = analyze_sqlite(bytes(data), include_records=True)
    assert result["tables"][0]["count_complete"] is False
    assert not result["records"]
    data = bytearray(database("CREATE TABLE t(a TEXT);", params=[("INSERT INTO t VALUES (?)", [("PWEH" * 30,) for _ in range(80)])]))
    assert data[512] == 5
    data[520:524] = struct.pack(">I", 2)
    result = analyze_sqlite(bytes(data))
    assert result["tables"][0]["row_count"] is None
    assert any("crosslink" in item for item in result["warnings"])


def test_limits_cancel_deadline_and_record_cap_keep_count():
    data = database("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('PWEH1'),('PWEH2'),('PWEH3');")
    result = analyze_sqlite(data, include_records=True, limits=replace(SQLiteLimits(), max_records=1))
    assert len(result["records"]) == 1 and result["tables"][0]["row_count"] == 3
    assert not result["tables"][0]["records_complete"] and result["truncated"]
    cancelled = threading.Event()
    cancelled.set()
    assert "cancelled" in analyze_sqlite(data, cancel_event=cancelled)["truncated_reasons"]
    assert "time" in analyze_sqlite(data, deadline=time.monotonic() - 1)["truncated_reasons"]
    assert "max_pages" in analyze_sqlite(data, limits=replace(SQLiteLimits(), max_pages=1))["truncated_reasons"]
    with pytest.raises(ValidationFailed):
        analyze_sqlite(data, limits=replace(SQLiteLimits(), max_input_bytes=100 * 1024 * 1024))
    with pytest.raises(ValidationFailed):
        analyze_sqlite(bytearray(data))


def test_text_and_payload_limit_explicit():
    data = database("CREATE TABLE t(a TEXT);", params=[("INSERT INTO t VALUES (?)", [("PWEH" * 200,)])])
    result = analyze_sqlite(data, include_records=True, limits=replace(SQLiteLimits(), max_text_bytes=100))
    assert result["truncated"] and len(result["records"][0]["values"]["a"]) == 100
    assert result["records"][0]["fields"][0]["truncated"]
    result = analyze_sqlite(data, include_records=True, limits=replace(SQLiteLimits(), max_payload_bytes=100))
    assert result["tables"][0]["row_count"] is None
    assert "max_payload_bytes" in result["truncated_reasons"]


def wal_fixture(tmp_path):
    target = tmp_path / "synthetic.db"
    conn = sqlite3.connect(target)
    conn.execute("PRAGMA page_size=512")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY,address TEXT,body TEXT,date INT,type INT)")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("INSERT INTO sms VALUES(1,'synthetic','old PWEH message',1700000000000,1)")
    conn.commit()
    conn.execute("UPDATE sms SET body='new PWEH message'")
    conn.commit()
    base = target.read_bytes()
    wal = target.with_name(target.name + "-wal").read_bytes()
    conn.close()
    return base, wal


def test_wal_last_commit_and_historical_candidates(tmp_path):
    data, wal = wal_fixture(tmp_path)
    result = analyze_sqlite(data, wal, include_records=True, include_recovery=True)
    assert result["status"] == "ok", result["warnings"]
    assert result["snapshot"]["kind"] == "wal-last-commit"
    assert result["records"][0]["values"]["body"] == "new PWEH message"
    old = [c for c in result["recovery"]["candidates"] if "old PWEH message" in c["raw_values"]]
    assert old and old[0]["record_state"] == "historical"
    assert old[0]["table_assignment"] == "unknown" and old[0]["confidence"] == "possible"


def rewrite_wal(data, *, endian=None, last_uncommitted=False):
    data = bytearray(data)
    magic = int.from_bytes(data[:4], "big")
    if endian:
        magic = 0x377F0682 if endian == "<" else 0x377F0683
        data[:4] = struct.pack(">I", magic)
    endian = "<" if magic == 0x377F0682 else ">"
    page_size = int.from_bytes(data[8:12], "big")
    state = _checksum(memoryview(data)[:24], (0, 0), endian)
    data[24:32] = struct.pack(">II", *state)
    count = (len(data) - 32) // (24 + page_size)
    for index in range(count):
        pos = 32 + index * (24 + page_size)
        if last_uncommitted and index == count - 1:
            data[pos + 4:pos + 8] = b"\0" * 4
        state = _checksum(memoryview(data)[pos:pos + 8], state, endian)
        state = _checksum(memoryview(data)[pos + 24:pos + 24 + page_size], state, endian)
        data[pos + 16:pos + 24] = struct.pack(">II", *state)
    return bytes(data)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_wal_checksum_endian_and_uncommitted_tail(tmp_path, endian):
    data, wal = wal_fixture(tmp_path)
    result = analyze_sqlite(data, rewrite_wal(wal, endian=endian, last_uncommitted=True), include_records=True, include_recovery=True)
    assert result["records"][0]["values"]["body"] == "old PWEH message"
    assert result["wal"]["uncommitted_frames"] == 1
    assert any(c["record_state"] == "uncommitted" for c in result["recovery"]["candidates"])


def test_wal_torn_tail_checksum_and_salt(tmp_path):
    data, wal = wal_fixture(tmp_path)
    for bad in (wal[:-1], wal[:-1] + bytes([wal[-1] ^ 1])):
        result = analyze_sqlite(data, bad, include_records=True)
        assert result["status"] == "partial"
        assert result["records"][0]["values"]["body"] == "old PWEH message"
    corrupt = bytearray(wal)
    corrupt[32 + 24 + 512 + 8] ^= 1
    assert analyze_sqlite(data, bytes(corrupt))["wal"]["status"] == "partial"


def test_freelist_recovery_unknown_not_deleted_confirmed():
    conn = sqlite3.connect(":memory:")
    conn.executescript("PRAGMA page_size=512; PRAGMA secure_delete=OFF; CREATE TABLE t(id INTEGER PRIMARY KEY, body TEXT);")
    conn.executemany("INSERT INTO t(body) VALUES (?)", [("PWEH SYNTHETIC residual " + str(i),) for i in range(200)])
    conn.commit()
    conn.execute("DELETE FROM t")
    conn.commit()
    data = dump_connection(conn)
    conn.close()
    result = analyze_sqlite(data, include_records=True, include_recovery=True)
    assert result["tables"][0]["row_count"] == 0
    assert result["recovery"]["candidates"]
    assert all(c["table_assignment"] == "unknown" and c["record_state"] == "residual" for c in result["recovery"]["candidates"])
    assert "deleted-confirmed" not in json.dumps(result)


def test_nine_byte_varint_and_ddl_bounds():
    assert varint(b"\xff" * 9, 0) == ((1 << 64) - 1, 9)
    assert parse_ddl("CREATE TABLE x(a TEXT /*PWEH*/, b INT DEFAULT -7)")["columns"][1]["default"] == -7
    assert parse_ddl("CREATE TABLE x(a TEXT DEFAULT (" + "(" * 40 + "1" + ")" * 41 + "))")["mapping_status"] == "unknown"


def test_wal_new_schema_page1_overlay_and_missing_tail_pages(tmp_path):
    target = tmp_path / "schema.db"
    conn = sqlite3.connect(target)
    conn.execute("PRAGMA page_size=512")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE first_table(a TEXT)")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("CREATE TABLE added(body TEXT)")
    conn.execute("INSERT INTO added VALUES('PWEH new schema')")
    conn.commit()
    data, wal = target.read_bytes(), target.with_name(target.name + "-wal").read_bytes()
    conn.close()
    result = analyze_sqlite(data, wal, include_records=True)
    assert result["status"] == "ok", result["warnings"]
    assert any(r["table"] == "added" and r["values"]["body"] == "PWEH new schema" for r in result["records"])
    base = bytearray(database("CREATE TABLE t(a TEXT);"))
    base[28:32] = struct.pack(">I", 500)
    result = analyze_sqlite(bytes(base))
    assert "database_pages_missing" in result["warnings"]
    assert result["snapshot"]["consistency"] == "unknown"


def test_secure_delete_no_residual_and_freelist_crosslink_flagged():
    conn = sqlite3.connect(":memory:")
    conn.executescript("PRAGMA page_size=512; PRAGMA secure_delete=ON; CREATE TABLE t(id INTEGER PRIMARY KEY,body TEXT);")
    conn.executemany("INSERT INTO t(body) VALUES (?)", [("PWEH SYNTHETIC secret " + str(i),) for i in range(100)])
    conn.commit()
    conn.execute("DELETE FROM t")
    conn.commit()
    data = dump_connection(conn)
    conn.close()
    result = analyze_sqlite(data, include_recovery=True)
    assert result["recovery"]["candidates"] == []
    corrupt = bytearray(data)
    corrupt[32:36] = struct.pack(">I", 2)
    result = analyze_sqlite(bytes(corrupt), include_recovery=True)
    assert result["status"] == "partial" and result["recovery"]["status"] == "partial"
    assert "freelist_cycle_or_live_crosslink" in result["recovery"]["warnings"]


def test_journal_only_structural_metadata_and_consistency_unknown():
    data = database("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('PWEH');")
    nonce, sector, size = 7, 512, 512
    page = data[512:1024]
    checksum = nonce
    for index in range(size - 200, 0, -200):
        checksum = (checksum + page[index]) & 0xffffffff
    journal = bytes.fromhex("d9d505f920a163d7") + struct.pack(">5I", 1, nonce, 2, sector, size)
    journal = journal.ljust(sector, b"\0") + struct.pack(">I", 2) + page + struct.pack(">I", checksum)
    result = analyze_sqlite(data, journal=journal)
    assert result["journal"]["records_valid"] == 1
    assert result["journal"]["replayed"] is False and result["snapshot"]["consistency"] == "unknown"


def test_product_parser_never_opens_source_or_executes_sql(monkeypatch):
    import builtins
    import pweh.sqliterecovery  # lazy import도 시험 전 로드한다.
    data = database("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('PWEH');")
    def forbidden(*args, **kwargs):
        raise AssertionError("증거를 엔진이나 파일로 열면 안 됨")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    result = analyze_sqlite(data, include_records=True, include_recovery=True)
    assert result["records"][0]["values"]["a"] == "PWEH"


def test_recovery_and_output_budgets_are_explicit():
    conn = sqlite3.connect(":memory:")
    conn.executescript("PRAGMA page_size=512; PRAGMA secure_delete=OFF; CREATE TABLE t(id INTEGER PRIMARY KEY,body TEXT);")
    conn.executemany("INSERT INTO t(body) VALUES (?)", [("PWEH SYNTHETIC " + str(i),) for i in range(100)])
    conn.commit()
    conn.execute("DELETE FROM t")
    conn.commit()
    data = dump_connection(conn)
    conn.close()
    result = analyze_sqlite(data, include_recovery=True, limits=replace(SQLiteLimits(), max_recovery_bytes=512))
    assert result["recovery"]["status"] == "partial" and "max_recovery_bytes" in result["truncated_reasons"]
    result = analyze_sqlite(database("CREATE TABLE t(a TEXT);", params=[("INSERT INTO t VALUES (?)", [("PWEH" * 100,) for _ in range(20)])]), include_records=True,
                            limits=replace(SQLiteLimits(), max_output_bytes=4096))
    assert result["status"] == "partial" and "max_output_bytes" in result["truncated_reasons"]
    assert not result["records"]
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 4096


def test_inventory_validates_record_header_without_returning_content():
    data = database("CREATE TABLE t(body TEXT); INSERT INTO t VALUES('PWEH');")
    observed = analyze_sqlite(data, include_records=True)
    position = observed["records"][0]["origin"]["spans"][0]["offset"]
    corrupt = bytearray(data)
    corrupt[position + 1] = 11
    result = analyze_sqlite(bytes(corrupt))
    assert result["tables"][0]["row_count"] is None
    assert result["tables"][0]["count_complete"] is False
    assert any("record_serial_invalid" in warning for warning in result["warnings"])


def test_schema_text_budget_is_partial_not_corrupt():
    data = database("CREATE TABLE example_table_long_name(body TEXT);")
    result = analyze_sqlite(data, limits=replace(SQLiteLimits(), max_text_bytes=10))
    assert result["status"] == "partial" and "schema_text_limit" in result["truncated_reasons"]
