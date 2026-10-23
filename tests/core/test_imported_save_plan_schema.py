"""로컬 계획 manifest의 닫힌 필드·정수 범위·체크섬 분기를 독립 자료로 확인한다."""

from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from pweh import schemas
from pweh.errors import ValidationFailed

NAME = "imported-save-plan"
FLAGS = ("device_association_verified", "independent_backup_verified", "write_address_verified",
         "write_ready", "device_written", "game_acceptance_verified")
ENC = {"u8": (0, 255), "i8": (-128, 127), "u16le": (0, 65535), "u16be": (0, 65535),
       "i16le": (-32768, 32767), "i16be": (-32768, 32767), "u32le": (0, 2**32-1), "u32be": (0, 2**32-1),
       "i32le": (-2**31, 2**31-1), "i32be": (-2**31, 2**31-1),
       "bcd2le": (0, 9999), "bcd2be": (0, 9999), "bcd4le": (0, 99999999), "bcd4be": (0, 99999999)}
ALG = {1: ("sum8", "negsum8", "notsum8", "xor8", "crc8", "crc8-maxim"),
       2: ("sum16", "sum16le", "sum16be", "fletcher16", "crc16-ccitt-false", "crc16-xmodem",
           "crc16-kermit", "crc16-x25", "crc16-modbus", "crc16-arc"),
       4: ("sum32", "sum32le", "sum32be", "adler32", "crc32", "crc32-jamcrc", "crc32-mpeg2", "crc32-bzip2")}


def report(checksum=True):
    return {"schema": "pweh.imported-save-plan/v1", "profile": "raw-save-local-plan-v1", "stage": "planned",
        "source": {"kind": "case-artifact", "artifact_id": "A-0001", "size": 64, "sha256": "a"*64,
                   "import_provenance": {"kind": "imported-unattested", "seq": 1, "record_sha256": "b"*64}},
        "params": {"offset": 0, "length": 64, "purpose": "score", "unlock_source": "in-device",
                   "online_capable": "no", "max_seconds": 30},
        "edits": [{"offset": 4, "encoding": "u16le", "before_value": 1, "after_value": 2,
                   "in_checksum_range": True if checksum else None}],
        "checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 60],
                     "before": 1, "after": 2, "original_rule_reproduced": True, "patched_rule_reproduced": True} if checksum else None,
        "output": {"name": "planned.bin", "size": 64, "sha256": "c"*64}, **{k: False for k in FLAGS}}


def set_at(doc, path, value):
    obj = doc
    for k in path[:-1]: obj = obj[k]
    obj[path[-1]] = value


def test_schema_valid_and_existing_skill_mapping():
    Draft202012Validator.check_schema(schemas.load(NAME))
    assert schemas.SKILL_DATA_SCHEMAS["game-save-unlock-analysis"] == "save-analysis"
    schemas.validate(NAME, report())
    schemas.validate(NAME, report(False))
    from fwtriage_mcp import saves
    assert set(ENC) == set(saves.ENCODINGS)
    assert {a for group in ALG.values() for a in group} == set(saves.CHECKSUM_ALGORITHMS)


@pytest.mark.parametrize("path", [(), ("source",), ("source", "import_provenance"), ("params",),
                                  ("edits", 0), ("checksum",), ("output",)])
def test_all_nested_objects_reject_raw_extras(path):
    doc = report()
    obj = doc
    for k in path: obj = obj[k]
    obj["private_source"] = "raw"
    with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)


@pytest.mark.parametrize("key", tuple(report()))
def test_required_fields(key):
    doc = report()
    del doc[key]
    with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)


@pytest.mark.parametrize("flag", FLAGS)
def test_device_claims_never_promoted(flag):
    doc = report()
    doc[flag] = True
    with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)


@pytest.mark.parametrize("encoding", ENC)
def test_encoding_value_edges_and_null_before(encoding):
    low, high = ENC[encoding]
    doc = report(False)
    row = doc["edits"][0]
    row.update(encoding=encoding, before_value=low, after_value=high)
    schemas.validate(NAME, doc)
    for key in ("before_value", "after_value"):
        for value in (low-1, high+1, True, "1"):
            bad = copy.deepcopy(doc)
            bad["edits"][0][key] = value
            with pytest.raises(ValidationFailed): schemas.validate(NAME, bad)
    row["before_value"] = None
    if encoding.startswith("bcd"):
        schemas.validate(NAME, doc)
    else:
        with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)


@pytest.mark.parametrize("width,algorithm", [(w, a) for w, names in ALG.items() for a in names])
def test_checksum_algorithm_width_and_endian(width, algorithm):
    doc = report()
    row = doc["checksum"]
    row.update(algorithm=algorithm, endian=None if width == 1 else "be", before=0, after=2**(8*width)-1)
    schemas.validate(NAME, doc)
    for key, value in (("after", 2**(8*width)), ("before", -1),
                       ("endian", "le" if width == 1 else None), ("original_rule_reproduced", False)):
        bad = copy.deepcopy(doc)
        bad["checksum"][key] = value
        with pytest.raises(ValidationFailed): schemas.validate(NAME, bad)


@pytest.mark.parametrize("checksum,value", [(False, False), (False, True), (True, None)])
def test_checksum_range_flag_nullability(checksum, value):
    doc = report(checksum)
    doc["edits"][0]["in_checksum_range"] = value
    with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)


@pytest.mark.parametrize("path,value", [
    (("stage",), "ready"), (("profile",), "esp-save"), (("source", "kind"), "device-read"),
    (("source", "artifact_id"), "A-0001\n"), (("source", "artifact_id"), "A-001"),
    (("source", "sha256"), "a"*64+"\n"), (("source", "sha256"), "A"*64),
    (("source", "size"), 0), (("source", "size"), 8388609), (("source", "size"), True),
    (("source", "import_provenance", "kind"), "imported-attested"),
    (("source", "import_provenance", "seq"), 0), (("source", "import_provenance", "seq"), True),
    (("source", "import_provenance", "record_sha256"), "b"*64+"\n"),
    (("params", "purpose"), "other"), (("params", "unlock_source"), "sold-token"),
    (("params", "online_capable"), "yes"), (("params", "max_seconds"), 0),
    (("params", "max_seconds"), 31), (("params", "max_seconds"), True),
    (("params", "offset"), -1), (("params", "length"), 0), (("params", "offset"), True),
    (("edits",), []), (("edits", 0, "encoding"), "hex"), (("edits", 0, "offset"), "4"),
    (("checksum", "algorithm"), "sha256"), (("checksum", "range"), [0]),
    (("checksum", "range"), [0, 60, 61]), (("checksum", "range"), [False, 60]),
    (("output", "name"), "source.bin"), (("output", "size"), 0),
])
def test_closed_constants_and_number_shapes(path, value):
    doc = report()
    set_at(doc, path, value)
    with pytest.raises(ValidationFailed): schemas.validate(NAME, doc)
