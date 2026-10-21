"""실행 없는 SQLite bytes 해석. 원본을 SQLite 엔진으로 열지 않고 SQL도 실행하지 않는다.

형식 근거: https://www.sqlite.org/fileformat2.html . 출처·custody·파일 선택은
서버의 책임이며 이 모듈은 파일·네트워크·프로세스를 열지 않는다.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
import struct
import threading
import time

from .errors import ValidationFailed
from .sqlitewal import inspect_journal, inspect_wal

MAX_INPUT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class SQLiteLimits:
    """호출자가 줄일 수만 있는 해석 예산."""
    max_input_bytes: int = MAX_INPUT_BYTES
    max_pages: int = 100000
    max_cells: int = 200000
    max_records: int = 10000
    max_payload_bytes: int = 1024 * 1024
    max_total_payload_bytes: int = 64 * 1024 * 1024
    max_text_bytes: int = 64 * 1024
    max_total_text_bytes: int = 8 * 1024 * 1024
    max_output_bytes: int = 16 * 1024 * 1024
    max_schema_bytes: int = 64 * 1024
    max_tables: int = 1024
    max_depth: int = 64
    max_recovery_bytes: int = 8 * 1024 * 1024
    max_candidates: int = 2000
    max_seconds: float = 45.0


class ParseError(Exception):
    """근거 위치를 신뢰할 수 없는 형식 오류."""


class BudgetStop(Exception):
    """예산을 넘긴 부분만 incomplete로 남긴다."""


class Budget:
    """모든 순회가 공유하는 시간·크기·취소 예산."""
    def __init__(self, limits=None, deadline=None, cancel_event=None):
        self.limits = limits or SQLiteLimits()
        if not isinstance(self.limits, SQLiteLimits):
            raise ValidationFailed("limits는 SQLiteLimits여야 합니다.")
        for key, maximum in asdict(SQLiteLimits()).items():
            value = getattr(self.limits, key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
                raise ValidationFailed("SQLite 한도는 기본 최대치 이하여야 합니다.", data={"field": key})
            if key != "max_seconds" and not isinstance(value, int):
                raise ValidationFailed("SQLite 크기·개수 한도는 정수여야 합니다.")
        if self.limits.max_output_bytes < 4096:
            raise ValidationFailed("결과 상태·상한 메타데이터를 위해 max_output_bytes는 4096 이상이어야 합니다.")
        now = time.monotonic()
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
            raise ValidationFailed("deadline은 monotonic 시각이어야 합니다.")
        self.deadline = min(now + self.limits.max_seconds, deadline if deadline is not None else math.inf)
        self.cancel = cancel_event
        self.reasons = []
        self.usage = dict(pages=0, cells=0, records=0, payload_bytes=0, text_bytes=0, output_bytes=0, recovery_bytes=0)

    def reason(self, code):
        if code not in self.reasons:
            self.reasons.append(code)

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            self.reason("cancelled")
            raise BudgetStop("cancelled")
        if time.monotonic() >= self.deadline:
            self.reason("time")
            raise BudgetStop("time")

    def take(self, key, size, maximum):
        self.check()
        if self.usage[key] + size > maximum:
            code = "max_" + key
            self.reason(code)
            raise BudgetStop(code)
        self.usage[key] += size

    def store(self, value):
        size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        self.take("output_bytes", size, self.limits.max_output_bytes)


def varint(data, offset, end=None):
    """SQLite의 마지막 8비트까지 포함한 최대 9바이트 varint."""
    end = len(data) if end is None else end
    value = 0
    for index in range(9):
        if offset >= end:
            raise ParseError("varint_truncated")
        byte = data[offset]
        offset += 1
        if index == 8:
            return (value << 8) | byte, offset
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, offset
    raise ParseError("varint_invalid")


def _u16(data, offset):
    if offset + 2 > len(data):
        raise ParseError("uint16_truncated")
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32(data, offset):
    if offset + 4 > len(data):
        raise ParseError("uint32_truncated")
    return int.from_bytes(data[offset:offset + 4], "big")


def read_header(data):
    """헤더 값의 관계를 확인한다. 암호화 여부 자체는 추정하지 않는다."""
    if bytes(data[:16]) != b"SQLite format 3\0":
        raise ParseError("not_sqlite_or_encrypted")
    if len(data) < 100:
        raise ParseError("sqlite_header_truncated")
    page_size = _u16(data, 16)
    page_size = 65536 if page_size == 1 else page_size
    if not 512 <= page_size <= 65536 or page_size & (page_size - 1):
        raise ParseError("page_size_invalid")
    if data[18] not in (1, 2) or data[19] not in (1, 2) or bytes(data[21:24]) != bytes((64, 32, 32)):
        raise ParseError("header_format_invalid")
    reserved = data[20]
    if page_size - reserved < 480:
        raise ParseError("usable_page_size_invalid")
    encoding = _u32(data, 56)
    if encoding not in (0, 1, 2, 3):
        raise ParseError("encoding_invalid")
    valid_count = _u32(data, 28) != 0 and _u32(data, 24) == _u32(data, 92)
    return {"page_size": page_size, "reserved_bytes": reserved, "usable_size": page_size - reserved,
            "encoding": {0: "utf-8", 1: "utf-8", 2: "utf-16le", 3: "utf-16be"}[encoding],
            "encoding_id": encoding, "declared_pages": _u32(data, 28), "page_count_valid": valid_count,
            "freelist_trunk": _u32(data, 32), "freelist_pages": _u32(data, 36),
            "schema_cookie": _u32(data, 40), "schema_format": _u32(data, 44),
            "user_version": _u32(data, 60), "application_id": _u32(data, 68),
            "write_version": data[18], "read_version": data[19]}


def _tokens(sql):
    """DDL에서 이름·리터럴·구분자만 읽는다. 정규식으로 SQL 문법을 실행하지 않는다."""
    out, index, depth = [], 0, 0
    while index < len(sql):
        if len(out) >= 8192:
            raise ParseError("ddl_tokens_limit")
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            pos = sql.find("\n", index + 2)
            index = len(sql) if pos < 0 else pos + 1
            continue
        if sql.startswith("/*", index):
            pos = sql.find("*/", index + 2)
            if pos < 0:
                raise ParseError("ddl_comment_unclosed")
            index = pos + 2
            continue
        if char in "\"'`[":
            closing = "]" if char == "[" else char
            index += 1
            value = []
            while index < len(sql):
                c = sql[index]
                index += 1
                if c == closing:
                    if closing != "]" and index < len(sql) and sql[index] == closing:
                        value.append(c)
                        index += 1
                        continue
                    break
                value.append(c)
            else:
                raise ParseError("ddl_quote_unclosed")
            out.append(("string" if char == "'" else "quoted", "".join(value)))
            continue
        if char in "(),.;+-":
            if char == "(":
                depth += 1
                if depth > 32:
                    raise ParseError("ddl_depth_limit")
            if char == ")":
                depth -= 1
                if depth < 0:
                    raise ParseError("ddl_parenthesis_invalid")
            out.append(("symbol", char))
            index += 1
            continue
        start = index
        while index < len(sql) and not sql[index].isspace() and sql[index] not in "\"'`[](),.;+-":
            if sql.startswith("/*", index) or sql.startswith("--", index):
                break
            index += 1
        if index == start:
            raise ParseError("ddl_token_invalid")
        out.append(("word", sql[start:index]))
    if depth:
        raise ParseError("ddl_parenthesis_invalid")
    return out


def _literal(tokens):
    if len(tokens) == 1:
        kind, value = tokens[0]
        if kind == "string":
            return True, value
        if kind == "word" and value.upper() == "NULL":
            return True, None
        if kind == "word" and re.fullmatch(r"[0-9]{1,20}", value):
            number = int(value)
            if number <= 0x7FFFFFFFFFFFFFFF:
                return True, number
    if (len(tokens) == 2 and tokens[0] in (("symbol", "+"), ("symbol", "-"))
            and tokens[1][0] == "word" and re.fullmatch(r"[0-9]{1,20}", tokens[1][1])):
        number = int(tokens[1][1]) * (-1 if tokens[0][1] == "-" else 1)
        if -(1 << 63) <= number < 1 << 63:
            return True, number
    return False, None


def _outer_tokens(tokens):
    """괄호 안 표현식과 리터럴을 SQL 제약 키워드로 해석하지 않는다."""
    depth, outer = 0, []
    for index, token in enumerate(tokens):
        if depth == 0:
            outer.append((index, token))
        if token == ("symbol", "("):
            depth += 1
        elif token == ("symbol", ")"):
            depth -= 1
    return outer


def _default_preserves_type(typename, value):
    """SQLite affinity 변환이 필요한 기본값은 추측하지 않는다."""
    if value is None:
        return True
    if "INT" in typename:
        affinity = "INTEGER"
    elif any(word in typename for word in ("CHAR", "CLOB", "TEXT")):
        affinity = "TEXT"
    elif not typename or "BLOB" in typename:
        affinity = "BLOB"
    elif any(word in typename for word in ("REAL", "FLOA", "DOUB")):
        affinity = "REAL"
    else:
        affinity = "NUMERIC"
    return ((isinstance(value, str) and affinity in ("TEXT", "BLOB"))
            or (isinstance(value, int) and affinity in ("INTEGER", "NUMERIC", "BLOB")))


def parse_ddl(sql, max_bytes=65536):
    """확인한 CREATE TABLE 열 순서만 매핑한다. 표현식·가상 열은 unknown이다."""
    result = {"mapping_status": "unknown", "columns": [], "without_rowid": False,
              "storage_columns": [], "rowid_alias": None}
    if not isinstance(sql, str) or len(sql.encode("utf-8")) > max_bytes:
        result["reason"] = "ddl_missing_or_oversized"
        return result
    try:
        tokens = _tokens(sql)
        words = [v.upper() if k == "word" else v for k, v in tokens]
        if not words or words[0] != "CREATE" or "VIRTUAL" in words[:4] or "TABLE" not in words[:5]:
            raise ParseError("ddl_not_plain_table")
        start = tokens.index(("symbol", "("))
        level, end, parts, part = 0, None, [], []
        for i in range(start + 1, len(tokens)):
            value = tokens[i][1]
            if tokens[i][0] == "symbol" and value == ")" and level == 0:
                parts.append(part)
                end = i
                break
            if tokens[i] == ("symbol", ",") and level == 0:
                parts.append(part)
                part = []
                continue
            part.append(tokens[i])
            if tokens[i] == ("symbol", "("):
                level += 1
            elif tokens[i] == ("symbol", ")"):
                level -= 1
        if end is None or not parts or len(parts) > 1024:
            raise ParseError("ddl_columns_invalid")
        suffix = [v.upper() for k, v in tokens[end + 1:] if k == "word"]
        result["without_rowid"] = any(suffix[i:i + 2] == ["WITHOUT", "ROWID"] for i in range(len(suffix)))
        primary = []
        inline_primary_desc = False
        constraints = {"PRIMARY", "NOT", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS", "CONSTRAINT"}
        for part in parts:
            if not part:
                raise ParseError("ddl_empty_column")
            w = [v.upper() if k == "word" else v for k, v in part]
            outer = _outer_tokens(part)
            if part[0][0] == "word" and w[0] in ("CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"):
                offset = 2 if w[0] == "CONSTRAINT" else 0
                if [(k, v.upper()) for k, v in part[offset:offset + 2]] == [("word", "PRIMARY"), ("word", "KEY")]:
                    p = offset + 2
                    if part[p] != ("symbol", "("):
                        raise ParseError("ddl_primary_key_unknown")
                    names, group = [], []
                    for item in part[p + 1:]:
                        if item in (("symbol", ","), ("symbol", ")")):
                            if not group or group[0][0] not in ("word", "quoted", "string"):
                                raise ParseError("ddl_primary_key_unknown")
                            names.append(group[0][1])
                            group = []
                            if item[1] == ")":
                                break
                        else:
                            group.append(item)
                    if primary:
                        raise ParseError("ddl_primary_key_duplicate")
                    primary = names
                continue
            name = part[0][1]
            cut = next((i for i, (k, v) in outer if i > 0 and k == "word" and v.upper() in constraints), len(part))
            typename = " ".join(v for k, v in part[1:cut]).upper()
            tail = [(i, (k, v.upper() if k == "word" else v)) for i, (k, v) in outer if i >= cut]
            if any(token in (("word", "GENERATED"), ("word", "AS")) for i, token in tail):
                raise ParseError("generated_column_unsupported")
            column = {"name": name, "type": typename, "default_known": True, "default": None}
            defaults = [i for i, token in tail if token == ("word", "DEFAULT")]
            if defaults:
                position = defaults[0] + 1
                stop = next((i for i, (k, v) in tail if i > position and k == "word" and v in constraints), len(part))
                known, value = _literal(part[position:stop])
                if known and not _default_preserves_type(typename, value):
                    known, value = False, None
                    column["default_reason"] = "default_affinity_unsupported"
                column.update(default_known=known, default=value)
            primary_at = next((i for i in range(len(tail) - 1)
                               if tail[i][1] == ("word", "PRIMARY") and tail[i + 1][1] == ("word", "KEY")
                               and tail[i + 1][0] == tail[i][0] + 1), None)
            if primary_at is not None:
                if primary:
                    raise ParseError("ddl_primary_key_duplicate")
                primary = [name]
                inline_primary_desc = (primary_at + 2 < len(tail) and tail[primary_at + 2][1] == ("word", "DESC"))
                if typename == "INTEGER" and not inline_primary_desc:
                    result["rowid_alias"] = name
            result["columns"].append(column)
        names = [c["name"] for c in result["columns"]]
        lookup = {name.casefold(): name for name in names}
        if len(lookup) != len(names):
            raise ParseError("ddl_duplicate_columns")
        primary = [lookup.get(n.casefold(), "") for n in primary]
        if any(not n for n in primary) or len(set(primary)) != len(primary):
            raise ParseError("ddl_primary_key_unknown")
        # 테이블 수준 INTEGER PRIMARY KEY는 DESC여도 alias다(열 수준 DESC만 SQLite의 예외).
        if len(primary) == 1 and result["rowid_alias"] is None:
            col = next(c for c in result["columns"] if c["name"] == primary[0])
            if col["type"] == "INTEGER" and not inline_primary_desc:
                result["rowid_alias"] = col["name"]
        if result["without_rowid"]:
            if not primary:
                raise ParseError("without_rowid_primary_key_missing")
            result["rowid_alias"] = None
            storage = primary + [n for n in names if n not in primary]
        else:
            storage = names
        result.update(mapping_status="known", storage_columns=storage, primary_key=primary)
    except (ParseError, ValueError, IndexError) as exc:
        result["reason"] = str(exc) or "ddl_unknown"
    return result


def decode_record(payload, encoding, budget, *, materialize=True):
    """record serial type를 검증하고 큰 TEXT/BLOB은 명시적으로 제한한다."""
    head_size, cursor = varint(payload, 0)
    if not cursor <= head_size <= len(payload):
        raise ParseError("record_header_size_invalid")
    serials = []
    while cursor < head_size:
        code, cursor = varint(payload, cursor, head_size)
        if len(serials) >= 1024 or code in (10, 11):
            raise ParseError("record_serial_invalid")
        serials.append(code)
    offset, values, fields = head_size, [], []
    fixed = (0, 1, 2, 3, 4, 6, 8, 8, 0, 0)
    for code in serials:
        budget.check()
        size = fixed[code] if code < 10 else (code - 12) // 2
        if offset + size > len(payload):
            raise ParseError("record_value_truncated")
        if not materialize:
            offset += size
            continue
        raw = memoryview(payload)[offset:offset + size]
        field = {"serial_type": code, "bytes": size}
        if code == 0:
            value = None
        elif 1 <= code <= 6:
            value = int.from_bytes(raw, "big", signed=True)
        elif code == 7:
            number = struct.unpack(">d", raw)[0]
            value = number if math.isfinite(number) else {"nonfinite_float": str(number)}
        elif code in (8, 9):
            value = code - 8
        elif code % 2 == 0:
            value = {"type": "blob", "size": size, "sha256": hashlib.sha256(raw).hexdigest()}
        else:
            length = min(size, budget.limits.max_text_bytes,
                         max(0, budget.limits.max_total_text_bytes - budget.usage["text_bytes"]))
            if encoding != "utf-8":
                length -= length % 2
            piece = bytes(raw[:length])
            try:
                value = piece.decode(encoding)
                field["decode_valid"] = True
            except UnicodeDecodeError:
                value = piece.decode(encoding, errors="replace")
                field["decode_valid"] = False
                field["sha256"] = hashlib.sha256(raw).hexdigest()
            budget.take("text_bytes", length, budget.limits.max_total_text_bytes)
            if length != size:
                field.update(truncated=True, sha256=hashlib.sha256(raw).hexdigest())
                budget.reason("max_text_bytes")
        values.append(value)
        fields.append(field)
        offset += size
    if offset != len(payload):
        raise ParseError("record_payload_size_mismatch")
    return values, fields


class Reader:
    """원본과 WAL page 위치를 읽는 참조 overlay. 증거 파일을 열지 않는다."""
    def __init__(self, data, wal, header, overlay, pages, budget):
        self.data, self.wal, self.header = data, wal, header
        self.overlay, self.pages, self.budget = overlay, pages, budget
        self.page_size, self.usable = header["page_size"], header["usable_size"]
        self.claimed = {}
        self.overflow_seen = set()

    def page(self, number):
        self.budget.take("pages", 1, self.budget.limits.max_pages)
        if not 1 <= number <= self.pages:
            raise ParseError("page_out_of_range")
        if number in self.overlay:
            frame = self.overlay[number]
            data, offset, origin = self.wal, frame["offset"], dict(kind="wal", frame=frame["frame"])
        else:
            data, offset, origin = self.data, (number - 1) * self.page_size, dict(kind="database", frame=None)
        if data is None or offset + self.page_size > len(data):
            raise ParseError("page_beyond_input")
        origin.update(page=number, offset=offset)
        return memoryview(data)[offset:offset + self.page_size], origin

    def payload(self, page, offset, size, page_type, origin):
        if size > self.budget.limits.max_payload_bytes:
            self.budget.reason("max_payload_bytes")
            raise BudgetStop("max_payload_bytes")
        self.budget.take("payload_bytes", size, self.budget.limits.max_total_payload_bytes)
        maximum = self.usable - 35 if page_type == 13 else ((self.usable - 12) * 64 // 255 - 23)
        minimum = (self.usable - 12) * 32 // 255 - 23
        local = size
        if size > maximum:
            local = minimum + (size - minimum) % (self.usable - 4)
            if local > maximum:
                local = minimum
        end = offset + local
        if end + (4 if local < size else 0) > self.usable:
            raise ParseError("cell_payload_out_of_page")
        chunks = [page[offset:end]]
        spans = [{**origin, "offset": origin["offset"] + offset, "length": local}]
        if local < size:
            next_page = _u32(page, end)
            remaining, seen = size - local, set()
            while remaining:
                self.budget.check()
                if next_page in seen or next_page in self.claimed or next_page in self.overflow_seen:
                    raise ParseError("overflow_cycle_or_crosslink")
                if len(seen) >= self.budget.limits.max_depth:
                    self.budget.reason("max_depth")
                    raise BudgetStop("max_depth")
                seen.add(next_page)
                self.overflow_seen.add(next_page)
                other, where = self.page(next_page)
                length = min(remaining, self.usable - 4)
                chunks.append(other[4:4 + length])
                spans.append({**where, "offset": where["offset"] + 4, "length": length})
                remaining -= length
                next_page = _u32(other, 0)
            if next_page:
                raise ParseError("overflow_chain_too_long")
        return b"".join(chunks), spans, end + (4 if local < size else 0)

    def walk(self, root, owner, without_rowid=False, decode=True):
        stack = [(root, 0)]
        while stack:
            self.budget.check()
            number, depth = stack.pop()
            if depth > self.budget.limits.max_depth:
                self.budget.reason("max_depth")
                raise BudgetStop("max_depth")
            if number in self.claimed or number in self.overflow_seen:
                raise ParseError("btree_cycle_or_crosslink")
            self.claimed[number] = owner
            page, origin = self.page(number)
            start = 100 if number == 1 else 0
            page_type = page[start]
            allowed = (2, 10) if without_rowid else (5, 13)
            if page_type not in allowed:
                raise ParseError("btree_type_mismatch")
            interior = page_type in (2, 5)
            hsize = 12 if interior else 8
            count = _u16(page, start + 3)
            content = _u16(page, start + 5) or 65536
            ptr_end = start + hsize + 2 * count
            if ptr_end > self.usable or not ptr_end <= content <= self.usable or page[start + 7] > 60:
                raise ParseError("btree_header_invalid")
            spans = []
            free = _u16(page, start + 1)
            while free:
                self.budget.check()
                if free < content or free + 4 > self.usable or len(spans) > self.usable // 4:
                    raise ParseError("freeblock_invalid")
                next_free, length = _u16(page, free), _u16(page, free + 2)
                if length < 4 or free + length > self.usable or (next_free and next_free < free + length):
                    raise ParseError("freeblock_chain_invalid")
                spans.append((free, free + length))
                free = next_free
            children = []
            if interior:
                children.append(_u32(page, start + 8))
            decoded = []
            for index in range(count):
                self.budget.take("cells", 1, self.budget.limits.max_cells)
                cell = _u16(page, start + hsize + index * 2)
                if not content <= cell < self.usable:
                    raise ParseError("cell_pointer_invalid")
                cursor = cell
                if interior:
                    children.append(_u32(page, cursor))
                    cursor += 4
                if page_type == 5:
                    _, end = varint(page, cursor, self.usable)
                    spans.append((cell, end))
                    continue
                size, cursor = varint(page, cursor, self.usable)
                rowid = None
                if page_type == 13:
                    rowid, cursor = varint(page, cursor, self.usable)
                    if rowid >= 1 << 63:
                        rowid -= 1 << 64
                payload, sources, end = self.payload(page, cursor, size, page_type, origin)
                spans.append((cell, end))
                values, fields = decode_record(payload, self.header["encoding"], self.budget, materialize=decode)
                decoded.append({"rowid": rowid, "raw_values": values, "fields": fields,
                                "origin": {**origin, "cell": index, "cell_offset": origin["offset"] + cell,
                                           "spans": sources, "payload_sha256": hashlib.sha256(payload).hexdigest()},
                                "complete": True})
            # 한 페이지의 겹침이 뒤늦게 발견되어도 그 페이지 row를 확정하지 않는다.
            spans.sort()
            if any(spans[i][1] > spans[i + 1][0] for i in range(len(spans) - 1)):
                raise ParseError("cell_or_freeblock_overlap")
            for row in decoded:
                yield row
            for child in children:
                stack.append((child, depth + 1))


def map_row(row, schema):
    """열 수가 짧으면 tail default/미확인을 명시한다. 역사 row의 이름을 추측하지 않는다."""
    if schema.get("mapping_status") != "known":
        return {**row, "values": {}, "mapping_status": "unknown"}
    names = schema["storage_columns"]
    raw = row["raw_values"]
    if len(raw) > len(names):
        return {**row, "values": {}, "mapping_status": "unknown", "mapping_reason": "record_has_extra_fields"}
    values = dict(zip(names, raw))
    origins = {name: "stored" for name in values}
    unknown = []
    cols = {c["name"]: c for c in schema["columns"]}
    for name in names[len(raw):]:
        if cols[name]["default_known"]:
            values[name] = cols[name]["default"]
            origins[name] = "schema_default_missing_field"
        else:
            unknown.append(name)
    alias = schema.get("rowid_alias")
    if alias and row["rowid"] is not None:
        if values.get(alias) is not None:
            return {**row, "values": {}, "mapping_status": "unknown", "mapping_reason": "rowid_alias_not_null"}
        values[alias] = row["rowid"]
        origins[alias] = "rowid_alias"
    result = {k: v for k, v in row.items() if k != "raw_values"}
    result.update(values=values, mapping_status="partial" if unknown else "known",
                  value_origins=origins, missing_fields=unknown,
                  field_names=names[:len(raw)])
    return result


def analyze_sqlite(data: bytes, wal: bytes | None = None, journal: bytes | None = None, *,
                   include_records=False, include_recovery=False, limits=None, deadline=None,
                   cancel_event: threading.Event | None = None):
    """선택한 bytes만 받아 SQLite 목록 또는 내부 앱 row를 반환한다."""
    budget = Budget(limits, deadline, cancel_event)
    if not isinstance(include_records, bool) or not isinstance(include_recovery, bool):
        raise ValidationFailed("include_records/include_recovery는 boolean이어야 합니다.")
    inputs = {}
    for name, source in (("database", data), ("wal", wal), ("journal", journal)):
        if source is None and name != "database":
            continue
        if not isinstance(source, bytes) or not 0 < len(source) <= budget.limits.max_input_bytes:
            raise ValidationFailed("SQLite 입력은 1 바이트 이상 64 MiB 이하의 bytes여야 합니다.")
        inputs[name] = {"size": len(source), "sha256": hashlib.sha256(source).hexdigest()}
    out = {"schema": "pweh.sqlite/v1", "status": "ok", "inputs": inputs, "header": None,
           "snapshot": {}, "schema_objects": [], "tables": [], "records": [],
           "recovery": {"status": "skipped", "candidates": []}, "limits": asdict(budget.limits),
           "usage": budget.usage, "truncated": False, "truncated_reasons": [], "warnings": []}
    reader, frames = None, []
    try:
        budget.check()
        header = read_header(data)
        out["header"] = header
        size = header["page_size"]
        physical = len(data) // size
        if len(data) % size:
            out["warnings"].append("database_partial_page")
        declared = header["declared_pages"] if header["page_count_valid"] else physical
        wal_info, overlay, frames = inspect_wal(wal, size, budget)
        out["wal"] = wal_info
        out["journal"] = inspect_journal(journal, size, budget)
        pages = wal_info["db_pages"] if wal_info.get("commit_frame") else declared
        if 1 in overlay:
            pos = overlay[1]["offset"]
            effective = read_header(memoryview(wal)[pos:pos + size])
            if effective["page_size"] != size or effective["reserved_bytes"] != header["reserved_bytes"]:
                raise ParseError("wal_page1_geometry_mismatch")
            header = effective
            out["header"] = header
        out["snapshot"] = {"kind": "wal-last-commit" if wal_info.get("commit_frame") else "database-only",
                           "commit_frame": wal_info.get("commit_frame"), "db_pages": pages,
                           "association": "provided-pair" if wal else None,
                           "snapshot_id": hashlib.sha256((inputs["database"]["sha256"] +
                                           (inputs.get("wal", {}).get("sha256", "")) + str(wal_info.get("commit_frame"))).encode()).hexdigest(),
                           "consistency": "unknown" if journal is not None or (wal is not None and wal_info["status"] != "ok") else "structurally-observed"}
        out["warnings"].extend(wal_info["warnings"])
        if journal is not None:
            out["warnings"].append("journal_not_replayed_consistency_unknown")
        if wal is None and header["write_version"] == 2:
            out["warnings"].append("wal_mode_without_sidecar_latest_state_unknown")
            out["snapshot"]["consistency"] = "unknown"
        if pages > physical and sum(1 for page in overlay if page > physical) < pages - physical:
            out["warnings"].append("database_pages_missing")
            out["snapshot"]["consistency"] = "unknown"
        reader = Reader(data, wal, header, overlay, pages, budget)
        for row in reader.walk(1, "sqlite_schema"):
            raw = row["raw_values"]
            if len(raw) != 5 or not all(isinstance(raw[i], str) for i in (0, 1, 2)) or not isinstance(raw[3], int) or isinstance(raw[3], bool):
                raise ParseError("schema_record_invalid")
            if len(out["schema_objects"]) >= budget.limits.max_tables:
                budget.reason("max_tables")
                raise BudgetStop("max_tables")
            if any(f.get("truncated") for f in row["fields"]):
                budget.reason("schema_text_limit")
                raise BudgetStop("schema_text_limit")
            if any(not f.get("decode_valid", True) for f in row["fields"]):
                raise ParseError("schema_text_invalid_encoding")
            item = dict(type=raw[0], name=raw[1], table=raw[2], root_page=raw[3], sql=raw[4])
            if item["type"] == "table":
                item.update(parse_ddl(item["sql"], budget.limits.max_schema_bytes))
            budget.store(item)
            out["schema_objects"].append(item)
        for table in out["schema_objects"]:
            if table["type"] != "table":
                continue
            info = {"name": table["name"], "root_page": table["root_page"],
                    "kind": "without-rowid" if table.get("without_rowid") else "table",
                    "rows_counted": 0, "row_count": None, "count_complete": False,
                    "count_basis": "reachable-physical-records",
                    "records_complete": include_records, "mapping_status": table.get("mapping_status", "unknown")}
            out["tables"].append(info)
            if table["root_page"] < 1:
                info.update(reason="virtual_or_missing_root", records_complete=False)
                out["warnings"].append("unsupported_table_root")
                continue
            try:
                for row in reader.walk(table["root_page"], table["name"], table.get("without_rowid", False), include_records):
                    info["rows_counted"] += 1
                    if not include_records:
                        continue
                    if budget.usage["records"] >= budget.limits.max_records:
                        budget.reason("max_records")
                        info["records_complete"] = False
                        continue
                    mapped = map_row(row, table)
                    mapped.update(table=table["name"], record_state="current", confidence="high",
                                  record_ref=f"page:{row['origin']['page']}:cell:{row['origin']['cell']}")
                    mapped["origin"]["snapshot_id"] = out["snapshot"]["snapshot_id"]
                    budget.store(mapped)
                    out["records"].append(mapped)
                    budget.usage["records"] += 1
                info.update(count_complete=True, row_count=info["rows_counted"])
            except (ParseError, BudgetStop) as exc:
                info.update(reason=str(exc), records_complete=False)
                out["warnings"].append("table_incomplete:" + str(exc))
                if isinstance(exc, BudgetStop) and str(exc) in ("time", "cancelled"):
                    raise
        if include_recovery:
            from .sqliterecovery import recover_candidates
            out["recovery"] = recover_candidates(reader, frames, out["wal"], budget)
            if out["recovery"]["status"] != "ok":
                out["warnings"].append("recovery_incomplete")
    except BudgetStop as exc:
        out["warnings"].append(str(exc))
    except ParseError as exc:
        out["status"] = "unsupported" if str(exc) == "not_sqlite_or_encrypted" else "corrupt"
        out["warnings"].append(str(exc))
    out["warnings"] = list(dict.fromkeys(out["warnings"]))
    out["truncated_reasons"] = list(budget.reasons)
    out["truncated"] = bool(budget.reasons)
    if out["status"] == "ok" and (out["warnings"] or budget.reasons):
        out["status"] = "partial"
    # 구조 메타데이터의 고정 오버헤드까지 최종 상한에 넣는다.
    if len(json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")) > budget.limits.max_output_bytes:
        out["records"] = []
        out["recovery"]["candidates"] = []
        out["schema_objects"] = []
        out["tables"] = []
        out.update(status="partial", truncated=True)
        if "max_output_bytes" not in out["truncated_reasons"]:
            out["truncated_reasons"].append("max_output_bytes")
        out["warnings"].append("output_omitted_due_to_size_limit")
    return out
