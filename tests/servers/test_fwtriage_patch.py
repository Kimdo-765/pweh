"""fwtriage-mcp 세이브 패치(fw_patch_build·fw_verify_writeback) 시험 — 사람이 쓰고 PWEH 가 검증하는 흐름의 게이트.

덤프의 출처는 pweh-esp 가 남기는 것과 같은 모양의 device-read 원장 항목을 테스트에서 직접 기록해 흉내 낸다(이중 읽기 두 파일, job_id·offset·after).
확인하는 것: 증명 없이는 쓰기 명령이 없다, 잘못된 백업(같은 job·더 오래됨·범위 밖·내용 다름·다른 MAC·재부팅됨)은 거부, 증명 뒤 명령과 원장 기록,
공개 뒤 패치 파일을 바꿔도 확인은 원장의 sha256 만 쓴다, 쓰기 안 됨/됨/다름 판정, 셸 메타문자 파티션 이름의 인용, 범위 밖 요청 거부.
값은 모두 합성이다(MAC f4:12:fa:12:34:56).
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest
from mcp import Client

from fwtriage.esp_builders import NvsImage, build_esp_flash, s3_app_image
from mcp_helpers import call

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import saves  # noqa: E402

pytestmark = pytest.mark.anyio

MAC = "f4:12:fa:12:34:56"
PARTS = [
    ("nvs", 0x01, 0x02, 0x9000, 0x6000),
    ("phy_init", 0x01, 0x01, 0xF000, 0x1000),
    ("factory", 0x00, 0x00, 0x10000, 0x30000),
    ("gamedata", 0x01, 0x40, 0x40000, 0x1000),  # 사용자 정의 데이터(raw-user-data)
]
ANSWERS = {"offline": "yes", "no_reboot": "yes", "want_change": "yes", "not_sold": "yes"}
TARGET = {"type": "nvs", "partition": "nvs"}
EDIT = [{"namespace": "game", "key": "hiscore", "value": 999999}]
ARGS = {"purpose": "score", "unlock_source": "in-device", "online_capable": "no"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _nvs(score: int = 1200, *, secret: bool = True) -> bytes:
    nv = NvsImage(version=2)
    nv.put("game", "hiscore", "U32", score)
    nv.put("game", "lives", "U8", 3)
    nv.put("game", "pin", "U32", 4821)  # 비밀로 보이는 키(바꾸지 않는다)
    if secret:
        nv.put_str("nvs.net80211", "sta.pswd", "not-a-real-pass")
    return nv.build(total_pages=6)


def _raw_save(score: int) -> bytes:
    b = bytearray(0x1000)
    b[0:4] = b"SAV1"
    struct.pack_into("<I", b, 0x40, score)
    struct.pack_into(">H", b, 0xFFE, saves.checksum_compute("crc16-ccitt-false", bytes(b[:0xFFE])))
    return bytes(b)


def _flash(score: int = 1200, *, parts=PARTS, raw_score: int = 100) -> bytes:
    img, _ = build_esp_flash(nvs=_nvs(score), app=s3_app_image(), flash_size=0x80000, partitions=parts)
    img = bytearray(img)
    img[0x40000:0x41000] = _raw_save(raw_score)
    return bytes(img)


class Dumps:
    """pweh-esp 의 이중 읽기 덤프를 흉내 내 케이스에 파일을 쓰고 출처 원장(device-read 두 항목)을 기록한다."""

    def __init__(self, case):
        from pweh.runtime import get_runtime

        self.case = case
        self.rt = get_runtime("fwtriage-mcp")
        self.n = 0

    def dump(self, data: bytes, *, offset: int = 0, mac: str = MAC, after: str = "hard-reset", job: str | None = None,
             port: str = "COM3", backend: str = "windows", chip: str = "ESP32-S3", verify: str = "double-read", match: bool = True) -> str:
        self.n += 1
        job = job or f"esp-job-{self.n:03d}"
        name = f"dumps/d{self.n:03d}.bin"
        sha = hashlib.sha256(data).hexdigest()
        src = {"server": "esp-mcp", "tool": "esp_read_flash_start", "port": port, "backend": backend, "chip": chip, "mac": mac,
               "esptool_version": "5.4.0", "verify": verify, "match": match}
        for role, rel, aft in (("primary", name, "no-reset-stub"), ("verification-read", name.replace(".bin", ".read2.bin"), after)):
            (self.case.dir / rel).write_bytes(data)
            self.rt.provenance.record_device_read(self.case, rel, src, {"role": role, "read": 1 if role == "primary" else 2, "offset": offset,
                                                                          "length": len(data), "job_id": job, "after": aft, "baud": 921600},
                                                  sha256=sha)
        return name


@pytest.fixture
def pcase(workspace, auth):
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="세이브 패치", authorization=auth, case_id="patchcase")
    return case


def _region(data: bytes, off: int, size: int) -> bytes:
    return data[off:off + size]


async def _ready(c, rt, case, base, backup, *, target=TARGET, edits=EDIT, **kw):
    """증명이 필요하면 사람의 결정을 저장소에 기록하고 다시 부른다. 반환: (첫 응답, 마지막 응답)."""
    args = {**ARGS, **kw}
    first = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=target, edits=edits, backup_path=backup, **args)
    if first.get("status") != "attestation_required":
        return first, first
    rt.attestations.decide(first["attestation_id"], ANSWERS, via="cli-tty", by="tester")
    second = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=target, edits=edits, backup_path=backup, **args)
    return first, second


async def test_planned_then_attestation_then_command_and_verify(pcase):
    from fwtriage_mcp.server import server
    from pweh.provenance import KIND_PATCH_PLAN

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    base = d.dump(base_bytes)
    async with Client(server) as c:
        plan = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, **ARGS)
        assert plan["ok"] and plan["stage"] == "planned" and "command" not in plan, plan
        assert plan["changes"] == [{"namespace": "game", "key": "hiscore", "type_name": "U32", "before": 1200, "after": 999999}]
        assert plan["patch_path"].startswith("patches/nvs-patch-") and any("after='no-reset'" in s for s in plan["next_steps"])
        backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
        first, ready = await _ready(c, d.rt, case, base, backup)
        assert first["status"] == "attestation_required" and "command" not in first and first["stage"] == "awaiting-attestation", first
        assert "pweh attest" in first["how"]
        assert ready["ok"] and ready["stage"] == "ready", ready
        cmd = ready["command"]
        assert "sha256sum -c -" in cmd and ready["patch_sha256"] in cmd
        assert '"$PWEH_ESPTOOL_WIN" --chip esp32s3 --port COM3 --after no-reset-stub write-flash 0x9000 "$(wslpath -w' in cmd
        assert "erase" not in cmd and "--force" not in cmd and "에이전트는 이 명령을 실행하지 않는다" in ready["command_note"]
        # 원장: patch-plan 기록 (verify 는 이 kind 를 기기 읽기로 보지 않는다), 체인은 그대로 유효
        entry = d.rt.provenance.latest(case, KIND_PATCH_PLAN, ready["patch_path"])
        assert entry and entry["sha256"] == ready["patch_sha256"] and entry["seq"] == ready["ledger_seq"] and entry["attestation_id"]
        assert d.rt.provenance.verify_chain(case)["ok"]
        v = d.rt.provenance.verify(case, ready["patch_path"])
        assert v["trusted"] is False and v["reason"] == "not-recorded"
        audit = (case.dir / "audit.jsonl").read_text(encoding="utf-8")
        assert "fwtriage_patch_ready" in audit and ready["patch_sha256"] in audit
        # 공개 뒤 패치 파일을 바꿔도 확인은 원장의 sha256 만 쓴다
        patched = bytearray(base_bytes)
        patched[0x9000:0xF000] = (case.dir / ready["patch_path"]).read_bytes()
        (case.dir / ready["patch_path"]).write_bytes(b"\x00" * 0x6000)
        rb_ok = d.dump(bytes(patched[0x9000:0xF000]), offset=0x9000)
        ok = await call(c, "fw_verify_writeback", case_id=case.id, patch_path=ready["patch_path"], readback_path=rb_ok)
        assert ok["ok"] and ok["outcome"] == "applied", ok
        rb_base = d.dump(base_bytes[0x9000:0xF000], offset=0x9000)
        na = await call(c, "fw_verify_writeback", case_id=case.id, patch_path=ready["patch_path"], readback_path=rb_base)
        assert na["outcome"] == "not-applied", na
        other = _flash(555)
        rb_other = d.dump(other[0x9000:0xF000], offset=0x9000)
        df = await call(c, "fw_verify_writeback", case_id=case.id, patch_path=ready["patch_path"], readback_path=rb_other)
        assert df["outcome"] == "differs" and df["edited_keys"][0]["actual"] == 555 and df["edited_keys"][0]["expected"] == 999999, df
        # 공개 전에 읽은 덤프(백업)는 읽기 확인이 될 수 없다
        early = await call(c, "fw_verify_writeback", case_id=case.id, patch_path=ready["patch_path"], readback_path=backup)
        assert "[validation_failed]" in early.get("_error", ""), early
    text = json.dumps([plan, first, ready], ensure_ascii=False)
    assert "not-a-real-pass" not in text


@pytest.mark.parametrize("bad", ["same-job", "older", "not-covering", "content-changed", "mac", "rebooted", "single-read"])
async def test_bad_backups_never_reveal_a_command(pcase, bad):
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    nvs = base_bytes[0x9000:0xF000]
    if bad == "older":
        backup = d.dump(nvs, offset=0x9000, after="no-reset-stub")
        base = d.dump(base_bytes)
    else:
        base = d.dump(base_bytes, job="esp-job-base")
        backup = {
            "same-job": lambda: d.dump(nvs, offset=0x9000, after="no-reset-stub", job="esp-job-base"),
            "not-covering": lambda: d.dump(nvs[:0x1000], offset=0x9000, after="no-reset-stub"),
            "content-changed": lambda: d.dump(_flash(1300)[0x9000:0xF000], offset=0x9000, after="no-reset-stub"),
            "mac": lambda: d.dump(nvs, offset=0x9000, after="no-reset-stub", mac="f4:12:fa:00:00:01"),
            "rebooted": lambda: d.dump(nvs, offset=0x9000, after="hard-reset"),
            "single-read": lambda: d.dump(nvs, offset=0x9000, after="no-reset-stub", verify="none", match=None),
        }[bad]()
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, backup_path=backup, **ARGS)
    assert "[validation_failed]" in r.get("_error", ""), (bad, r)
    assert "command" not in r and not d.rt.attestations.list()  # 증명 요청조차 만들지 않는다


async def test_refusals_before_any_patch(pcase):
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base = d.dump(_flash(1200))
    nvs_keys_parts = PARTS + [("nvs_key", 0x01, 0x04, 0x50000, 0x1000)]
    base_keys = d.dump(_flash(1200, parts=nvs_keys_parts))
    enc_parts = [("nvs", 0x01, 0x02, 0x9000, 0x6000, 0x1)] + PARTS[1:]
    base_enc = d.dump(_flash(1200, parts=enc_parts))
    async with Client(server) as c:
        cases = {
            "sold-token": dict(unlock_source="sold-token"),
            "unknown-source": dict(unlock_source="unknown"),
            "online": dict(online_capable="yes"),
            "purpose": dict(purpose="cheat"),
            "secret-key": dict(edits=[{"namespace": "game", "key": "pin", "value": 1}]),
            "missing-key": dict(edits=[{"namespace": "game", "key": "nope", "value": 1}]),
            "string-value": dict(edits=[{"namespace": "game", "key": "hiscore", "value": "1"}]),
            "app-partition": dict(target={"type": "nvs", "partition": "factory"}),
            "nvs-keys": dict(base_path=base_keys),
            "encrypted-flag": dict(base_path=base_enc),
            "not-a-dump": dict(base_path="dumps/plain.bin"),
        }
        (case.dir / "dumps" / "plain.bin").write_bytes(_flash(1200))
        for name, over in cases.items():
            args = {"base_path": base, "target": TARGET, "edits": EDIT, **ARGS, **over}
            r = await call(c, "fw_patch_build", case_id=case.id, **args)
            assert "[validation_failed]" in r.get("_error", ""), (name, r)
        # 플래시 암호화가 켜졌다는 기기 사실이 있으면 거부
        d.rt.provenance.record_device_fact(case, "esp-security-info", {"flash_encryption": True}, {"server": "esp-mcp", "tool": "esp_security_info", "mac": MAC})
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, **ARGS)
        assert "[validation_failed]" in r.get("_error", "") and "암호화" in r["_error"], r
    assert not list((case.dir / "patches").glob("*.bin"))


async def test_hostile_partition_label_is_quoted(pcase):
    """펌웨어가 정한 파티션 이름에 셸 메타문자가 있어도 명령에는 정리한 파일 이름만 들어가고 모두 인용된다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    evil = "n$(id);`x`|&"
    parts = [(evil, 0x01, 0x02, 0x9000, 0x6000)] + PARTS[1:]
    img = bytearray(_flash(1200, parts=parts))
    img[0x9000:0xF000] = _nvs(1200)  # 빌더는 label 이 'nvs' 일 때만 NVS 를 넣는다
    base_bytes = bytes(img)
    base = d.dump(base_bytes)
    backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
    async with Client(server) as c:
        _, ready = await _ready(c, d.rt, case, base, backup, target={"type": "nvs", "partition": evil})
    assert ready.get("stage") == "ready", ready
    cmd = ready["command"]
    for bad in ("$(id)", "`x`", ";`", "|&"):
        assert bad not in cmd, (bad, cmd)
    assert "/n_id_x" in ready["patch_path"] or ready["patch_path"].startswith("patches/n"), ready["patch_path"]


async def test_raw_region_patch_with_checksum(pcase):
    """사용자 데이터 파티션(raw-user-data): 오프셋 편집 + fw_checksum_find 후보로 체크섬 다시 계산. 범위가 정해지지 않은 후보는 거부."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200, raw_score=100)
    base = d.dump(base_bytes)
    ck = {"algorithm": "crc16-ccitt-false", "endian": "be", "location": 0xFFE, "range": [0, 0xFFE]}
    target = {"type": "raw-region", "partition": "gamedata", "checksum": ck}
    edits = [{"offset": 0x40, "encoding": "u32le", "value": 777777}]
    backup = d.dump(base_bytes[0x40000:0x41000], offset=0x40000, after="no-reset-stub")
    async with Client(server) as c:
        _, ready = await _ready(c, d.rt, case, base, backup, target=target, edits=edits)
        assert ready.get("stage") == "ready", ready
        patch = (case.dir / ready["patch_path"]).read_bytes()
        assert patch == _raw_save(777777) and "write-flash 0x40000" in ready["command"]
        bad = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target={**target, "checksum": {**ck, "range_variants": 3}},
                         edits=edits, **ARGS)
        assert "[validation_failed]" in bad.get("_error", ""), bad
        wrong = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target={**target, "checksum": {**ck, "algorithm": "crc16-xmodem"}},
                           edits=edits, **ARGS)
        assert "[validation_failed]" in wrong.get("_error", ""), wrong  # 이 base 에서 재현되지 않는 체크섬 규칙


async def test_unknown_flash_encryption_uses_partition_evidence(pcase):
    """원조 ESP32 처럼 esp_security_info 가 없으면 파티션 단위 근거(encrypted 플래그·nvs_keys 없음, 표 MD5)를 기록하고 진행한다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base = d.dump(_flash(1200))
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, **ARGS)
    assert r["ok"] and r["evidence"]["esp_security_info"].startswith("미확인") and r["evidence"]["table_md5"] is True, r
    assert r["evidence"]["partition_encrypted_flag"] is False and r["evidence"]["nvs_keys_present"] is False


# ---------------------------------------------------------------------------
# I2b 반박 검토 회귀 시험
# ---------------------------------------------------------------------------


async def test_backup_is_stale_after_any_later_device_connection(pcase, monkeypatch):
    """백업 뒤에 같은 기기에 연결한 기록(칩 정보·다른 덤프)이 있으면 백업은 낡았다 — 증명을 기다리는 동안 생겨도 기록 직전에 거부한다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    base = d.dump(base_bytes)
    backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
    fact_src = {"server": "esp-mcp", "tool": "esp_chip_info", "mac": MAC}
    async with Client(server) as c:
        # 1) 백업 뒤 칩 정보 조회(연결마다 리셋) → 거부, 증명 요청도 없음
        d.rt.provenance.record_device_fact(case, "esp-chip-info", {"chip": "ESP32-S3"}, fact_src)
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, backup_path=backup, **ARGS)
        assert "[validation_failed]" in r.get("_error", "") and "다시 연결" in r["_error"], r
        assert not d.rt.attestations.list()
        # 2) 새 백업 → 증명을 기다리는 동안 다른 호출이 기기에 연결 → 기록 직전 다시 확인해 거부(명령 없음, 원장 기록 없음)
        backup2 = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
        first = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, backup_path=backup2, **ARGS)
        d.rt.attestations.decide(first["attestation_id"], ANSWERS, via="cli-tty", by="tester")
        orig = d.rt.attest

        async def attest_then_touch(*a, **k):
            dec = await orig(*a, **k)
            d.rt.provenance.record_device_fact(case, "esp-chip-info", {"chip": "ESP32-S3"}, fact_src)
            return dec

        monkeypatch.setattr(d.rt, "attest", attest_then_touch)
        r2 = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, backup_path=backup2, **ARGS)
        assert "[validation_failed]" in r2.get("_error", "") and "증명을 기다리는 동안" in r2["_error"], r2
    from pweh.provenance import KIND_PATCH_PLAN

    assert d.rt.provenance.entries(case, KIND_PATCH_PLAN) == []


async def test_attestation_is_bound_to_backup_declarations_and_edits(pcase):
    """증명은 백업(sha·seq·job)·선언(purpose·unlock_source·online_capable)·편집 목록에 묶인다 — 하나라도 바뀌면 새 증명이 필요하다.
    요약에는 모든 편집과 선언이 잘리지 않고 들어가고, 기기 문자열의 제어 문자는 이스케이프된다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    base = d.dump(base_bytes)
    backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
    edits = [{"namespace": "game", "key": "hiscore", "value": 999999}, {"namespace": "game", "key": "lives", "value": 9}]
    async with Client(server) as c:
        first, ready = await _ready(c, d.rt, case, base, backup, edits=edits)
        assert ready.get("stage") == "ready", ready
        rec = d.rt.attestations.get(first["attestation_id"])
        assert "game/hiscore: 1200 → 999999" in rec["summary"] and "game/lives: 3 → 9" in rec["summary"]
        assert "목적 score" in rec["summary"] and "해금 출처 in-device" in rec["summary"] and "온라인 가능 no" in rec["summary"]
        assert rec["subject"]["edits"] == 2 and rec["subject"]["backup"]["seq"] and rec["subject"]["purpose"] == "score"
        assert {q["id"] for q in rec["questions"]} == {"offline", "no_reboot", "want_change", "not_sold"}
        # 선언이 바뀌면 같은 패치라도 새 증명
        other = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=edits, backup_path=backup,
                           purpose="progress", unlock_source="owned-tag", online_capable="unknown")
        assert other.get("status") == "attestation_required" and other["attestation_id"] != first["attestation_id"], other
        # 새 백업이면 새 증명 (이전 증명을 다른 백업에 다시 쓰지 않는다)
        backup2 = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
        again = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=edits, backup_path=backup2, **ARGS)
        assert again.get("status") == "attestation_required" and again["attestation_id"] != first["attestation_id"], again


@pytest.mark.parametrize("variant", ["overlap-app", "overlap-table", "bootloader", "misaligned", "dup-label"])
async def test_untrusted_partition_geometry_is_refused(pcase, variant):
    """조작된 파티션 표: 다른 파티션·부트로더·표 영역과 겹치거나, 4 KiB 경계가 아니거나, 이름이 겹치는 대상에는 쓰지 않는다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    gd = {
        "overlap-app": ("gamedata", 0x01, 0x40, 0x10000, 0x1000),
        "overlap-table": ("gamedata", 0x01, 0x40, 0x8000, 0x1000),
        "bootloader": ("gamedata", 0x01, 0x40, 0x0, 0x8000),
        "misaligned": ("gamedata", 0x01, 0x40, 0x40800, 0x800),
        "dup-label": ("gamedata", 0x01, 0x40, 0x40000, 0x1000),
    }[variant]
    parts = PARTS[:3] + [gd] + ([("gamedata", 0x01, 0x40, 0x42000, 0x1000)] if variant == "dup-label" else [])
    base_bytes = _flash(1200, parts=parts)
    base = d.dump(base_bytes)
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target={"type": "raw-region", "partition": "gamedata"},
                       edits=[{"offset": 0x10, "encoding": "u32le", "value": 0xDEADBEEF}], **ARGS)
    assert "[validation_failed]" in r.get("_error", ""), (variant, r)


async def test_control_characters_in_device_strings_are_escaped(pcase):
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    label = "\x1b[2Kgame"
    parts = PARTS[:3] + [(label, 0x01, 0x40, 0x40000, 0x1000)]
    base_bytes = _flash(1200, parts=parts)
    base = d.dump(base_bytes)
    backup = d.dump(base_bytes[0x40000:0x41000], offset=0x40000, after="no-reset-stub")
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target={"type": "raw-region", "partition": label},
                       edits=[{"offset": 0x40, "encoding": "u32le", "value": 5}], backup_path=backup, **ARGS)
    assert r.get("status") == "attestation_required", r
    summary = d.rt.attestations.get(r["attestation_id"])["summary"]
    assert "\x1b" not in summary and "\\x1b[2Kgame" in summary


async def test_flash_encryption_fact_cannot_be_shadowed(pcase):
    """같은 기기의 '플래시 암호화 켜짐' 사실은 MAC 없는 더 새 사실로 가려지지 않는다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base = d.dump(_flash(1200))
    d.rt.provenance.record_device_fact(case, "esp-security-info", {"flash_encryption": True}, {"server": "esp-mcp", "tool": "esp_security_info", "mac": MAC})
    d.rt.provenance.record_device_fact(case, "esp-security-info", {"flash_encryption": False}, {"server": "esp-mcp", "tool": "esp_security_info", "mac": None})
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, **ARGS)
    assert "[validation_failed]" in r.get("_error", "") and "암호화" in r["_error"], r


async def test_repeated_calls_do_not_grow_files_or_ledger(pcase):
    from fwtriage_mcp.server import server
    from pweh.provenance import KIND_PATCH_PLAN

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    base = d.dump(base_bytes)
    async with Client(server) as c:
        for _ in range(5):
            r = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, **ARGS)
            assert r["stage"] == "planned"
        assert len(list((case.dir / "patches").glob("*.bin"))) == 1
        backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
        _, ready = await _ready(c, d.rt, case, base, backup)
        for _ in range(3):
            again = await call(c, "fw_patch_build", case_id=case.id, base_path=base, target=TARGET, edits=EDIT, backup_path=backup, **ARGS)
            assert again["stage"] == "ready" and again["ledger_seq"] == ready["ledger_seq"], again
    assert len(d.rt.provenance.entries(case, KIND_PATCH_PLAN)) == 1
    assert len(list((case.dir / "patches").glob("*.bin"))) == 1


async def test_dump_without_job_id_is_refused(pcase):
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    data = _flash(1200)
    (case.dir / "dumps" / "nojob.bin").write_bytes(data)
    d.rt.provenance.record_device_read(case, "dumps/nojob.bin", {"server": "esp-mcp", "tool": "esp_read_flash_start", "port": "COM3", "backend": "windows",
                                                                 "chip": "ESP32-S3", "mac": MAC, "verify": "double-read", "match": True},
                                       {"role": "primary", "offset": 0, "length": len(data), "job_id": None, "after": "no-reset-stub"},
                                       sha256=hashlib.sha256(data).hexdigest())
    async with Client(server) as c:
        r = await call(c, "fw_patch_build", case_id=case.id, base_path="dumps/nojob.bin", target=TARGET, edits=EDIT, **ARGS)
    assert "[validation_failed]" in r.get("_error", "") and "job" in r["_error"], r


async def test_verify_warns_on_device_connection_between_reveal_and_readback(pcase):
    """쓰기 명령 공개 뒤 읽기 확인 전에 같은 기기에 연결한 기록이 있으면 판정은 그대로 두고 경고한다."""
    from fwtriage_mcp.server import server

    case = pcase
    d = Dumps(case)
    base_bytes = _flash(1200)
    base = d.dump(base_bytes)
    backup = d.dump(base_bytes[0x9000:0xF000], offset=0x9000, after="no-reset-stub")
    async with Client(server) as c:
        _, ready = await _ready(c, d.rt, case, base, backup)
        patched = bytearray(base_bytes)
        patched[0x9000:0xF000] = (case.dir / ready["patch_path"]).read_bytes()
        d.rt.provenance.record_device_fact(case, "esp-chip-info", {"chip": "ESP32-S3"}, {"server": "esp-mcp", "tool": "esp_chip_info", "mac": MAC})
        rb = d.dump(bytes(patched[0x9000:0xF000]), offset=0x9000)
        r = await call(c, "fw_verify_writeback", case_id=case.id, patch_path=ready["patch_path"], readback_path=rb)
    assert r["outcome"] == "applied" and r["warnings"] and "다시 연결" in r["warnings"][0], r
