"""합성 FDT로 SD 표면의 FIT metadata 연결·마감·기존 IOC 소비를 검증한다."""

from __future__ import annotations

import copy
import json
import struct
import threading
import time

import pytest
from mcp import Client

from fwtriage.sd_builders import write_tree
from fwtriage_mcp import sdsurface as S
from fwtriage_mcp.common import Cancelled, Ctl
from fwtriage_mcp.patterns import load_patterns
from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PWEH_FIT_PRIVATE_65b9f213"
FALSE_FLAGS = ("cryptographic_verification_performed", "key_trust_verified",
               "boot_enforcement_verified", "sd_route_link_verified")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fit_case(workspace, auth):
    from pweh.case import CaseStore

    return CaseStore(workspace["cases_dir"]).create(
        title="합성 FIT 구조 연결", authorization=auth, case_id="fit-metadata")


def _fdt(children=(), *, version=17):
    """외부 dtc 없이 v17 블록·예약 종결을 갖춘 작은 합성 FDT를 만든다."""
    strings = bytearray()
    offsets = {}

    def node(name, props, kids):
        out = bytearray(struct.pack(">I", 1) + name.encode() + b"\0")
        out += b"\0" * (-len(out) % 4)
        for key, value in props.items():
            if key not in offsets:
                offsets[key] = len(strings)
                strings.extend(key.encode() + b"\0")
            if isinstance(value, str):
                value = value.encode() + b"\0"
            out += struct.pack(">III", 3, len(value), offsets[key]) + value
            out += b"\0" * (-len(value) % 4)
        for child in kids:
            out += node(*child)
        return bytes(out + struct.pack(">I", 2))

    tree = node("", {}, children) + struct.pack(">I", 9)
    offset_strings = 56 + len(tree)
    total = offset_strings + len(strings)
    return (struct.pack(">10I", 0xD00DFEED, total, 56, offset_strings, 40,
                        version, 16, 0, len(strings), len(tree))
            + b"\0" * 16 + tree + strings)


def _signed_fit():
    opaque = PRIVATE.encode()
    return _fdt([
        ("images", {}, [("image-" + PRIVATE, {"data": opaque * 100}, [
            ("signature-" + PRIVATE, {"algo": "sha256,rsa2048", "value": opaque * 8,
                                      "key-name-hint": PRIVATE}, []),
        ])]),
        ("configurations", {}, [("config-" + PRIVATE, {}, [
            ("signature-2", {"algo": "sha384,ecdsa256", "value": opaque,
                              "sign-images": PRIVATE}, []),
        ])]),
        ("signature", {"required-mode": "all"}, [
            ("key-" + PRIVATE, {"algo": "sha256,rsa2048", "required": "conf",
                                "key-name-hint": PRIVATE, "rsa,modulus": opaque}, []),
        ]),
    ])


def _write_image(case, blob):
    path = case.subdir("dumps") / "synthetic-fit.bin"
    path.write_bytes(blob)
    return case.rel(path)


def _saved(case, response):
    return json.loads((case.dir / response["result_path"]).read_text(encoding="utf-8"))


def _surface(blob, *, ctl=None, image_budget=1 << 30):
    sd = S.SdSurface(ctl or Ctl(max_seconds=30), load_patterns(), image_budget=image_budget)
    sd.scan_image(blob, len(blob), "dumps/synthetic-fit.bin",
                  {"envs": [], "embedded_default_envs": [], "sd_boot_summary": {}})
    return sd, sd.result(rootfs_given=False, image_given=True)


@pytest.mark.parametrize("max_results", [0, 1, 20])
async def test_mcp_stored_and_compact_keep_entire_closed_fit_section(fit_case, max_results):
    from fwtriage_mcp.server import server

    blob = b"SYNTHETIC\0" + _signed_fit() + b"\0" + _fdt()
    async with Client(server) as client:
        result = await call(client, "fw_sd_surface", case_id=fit_case.id,
                            image_path=_write_image(fit_case, blob), max_results=max_results)
    assert result["ok"], result
    saved = _saved(fit_case, result)
    section = result["fit_security"]
    assert section == saved["fit_security"]
    assert section["status"] == "complete"
    assert section["coverage"]["input_bytes"] == len(blob)
    assert section["coverage"]["search_complete"] is True
    assert section["summary"]["blobs_reported"] == 2
    assert section["summary"]["entries_reported"] == 3
    assert {e["scope"] for e in section["blobs"][0]["entries"]} == {
        "image-signature", "configuration-signature", "control-key"}
    assert all(section[key] is False for key in FALSE_FLAGS)
    # 기존 문자열 휴리스틱의 발췌 범위는 바꾸지 않는다. 새 metadata의 원문 비노출만 검증한다.
    serialized = json.dumps(section, ensure_ascii=False)
    assert PRIVATE not in serialized and "rsa,modulus" not in serialized
    assert len(serialized.encode()) <= 64 << 10
    assert saved["checks"][1]["context"]["fit_signature_keys"] is True
    assert saved["phases"] == {"image_env": "complete", "image_strings": "complete"}


async def test_rootfs_only_and_rootfs_audit_leave_fit_not_examined(fit_case):
    from fwtriage_mcp.server import server

    root = write_tree(fit_case.dir / "extract" / "rootfs", {"etc/init.d/rcS": "#!/bin/sh\ntrue\n"})
    async with Client(server) as client:
        result = await call(client, "fw_sd_surface", case_id=fit_case.id, rootfs_dir=fit_case.rel(root))
        audit = await call(client, "fw_rootfs_audit", case_id=fit_case.id, rootfs_dir=fit_case.rel(root),
                           sd_surface=True, crack_defaults=False)
    assert result["ok"] and audit["ok"], (result, audit)
    section = result["fit_security"]
    assert section == _saved(fit_case, result)["fit_security"]
    assert section == audit["sd_surface"]["fit_security"]
    assert section["status"] == "not-examined"
    assert section["coverage"]["input_bytes"] is None
    assert all(section["coverage"][key] is False for key in (
        "search_complete", "structures_complete", "output_complete"))
    assert section["blobs"] == []


@pytest.mark.parametrize("blob", [b"", b"SYNTHETIC NON FDT", b"key-name-hint\0" + PRIVATE.encode()])
async def test_image_without_fdt_is_examined_not_rootfs_only(fit_case, blob):
    from fwtriage_mcp.server import server

    async with Client(server) as client:
        result = await call(client, "fw_sd_surface", case_id=fit_case.id,
                            image_path=_write_image(fit_case, blob))
    assert result["ok"], result
    section = result["fit_security"]
    assert section["status"] == "complete" and section["blobs"] == []
    assert section["coverage"]["input_bytes"] == len(blob)
    assert all(section["coverage"][key] is True for key in (
        "search_complete", "structures_complete", "output_complete"))
    saved = _saved(fit_case, result)
    expected_marker = b"key-name-hint" in blob
    assert saved["checks"][1]["context"]["fit_signature_keys"] is expected_marker


@pytest.mark.parametrize(("blob", "reason", "structure"), [
    (b"\xd0\x0d\xfe\xed\0", "malformed_fdt", "malformed"),
    (_fdt(version=16), "unsupported_fdt", "unsupported"),
])
async def test_malformed_and_unsupported_structure_keep_partial_metadata(fit_case, blob, reason, structure):
    from fwtriage_mcp.server import server

    async with Client(server) as client:
        result = await call(client, "fw_sd_surface", case_id=fit_case.id,
                            image_path=_write_image(fit_case, blob), max_results=0)
    assert result["ok"], result
    section = result["fit_security"]
    assert section == _saved(fit_case, result)["fit_security"]
    assert section["status"] == "partial" and reason in section["coverage"]["reasons"]
    assert section["coverage"]["structures_complete"] is False
    assert section["blobs"][0]["structure_status"] == structure
    assert section["blobs"][0]["signature_presence"] == "unknown"


@pytest.mark.parametrize("blob", [b"key-name-hint\0", _fdt(), _signed_fit(), b"\xd0\x0d\xfe\xed\0"])
def test_fit_result_is_additive_to_legacy_risk_and_string_marker(monkeypatch, blob):
    _, with_fit = _surface(blob)
    monkeypatch.setattr(S, "scan_fit_security", lambda *args, **kwargs: S.not_examined_fit_security())
    _, baseline = _surface(blob)
    with_fit.pop("fit_security")
    baseline.pop("fit_security")
    assert with_fit == baseline
    assert all("image_fit" not in phases for phases in S.PHASE_DEPS.values())


def test_scan_gets_same_ctl_after_legacy_phases_and_expiry_is_not_refreshed(monkeypatch):
    scan = S.scan_fit_security
    ctl = Ctl(max_seconds=30)
    sd = S.SdSurface(ctl, load_patterns(), image_budget=512)
    observed = []

    def expired_scan(buf, size, *, ctl, max_scan_bytes):
        assert ctl is sd.ctl and max_scan_bytes == 512
        assert sd.phases == {"image_env": "complete", "image_strings": "complete"}
        ctl.deadline = ctl.t0 - 1
        observed.append(ctl.deadline)
        return scan(buf, size, ctl=ctl, max_scan_bytes=max_scan_bytes)

    monkeypatch.setattr(S, "scan_fit_security", expired_scan)
    blob = _fdt()
    sd.scan_image(blob, len(blob), "dumps/synthetic-fit.bin",
                  {"envs": [], "embedded_default_envs": [], "sd_boot_summary": {}})
    result = sd.result(rootfs_given=False, image_given=True)
    assert len(observed) == 1 and ctl.deadline == observed[0] and ctl.timed_out
    assert result["fit_security"]["status"] == "partial"
    assert "time_limit" in result["fit_security"]["coverage"]["reasons"]
    assert result["phases"] == {"image_env": "complete", "image_strings": "complete"}
    assert result["checks"][1]["context"]["fit_signature_keys"] is False


def test_scan_uses_image_budget_and_compact_never_trims_coverage():
    blob = b"\0" * 256 + _signed_fit()
    sd, result = _surface(blob, image_budget=128)
    section = result["fit_security"]
    assert section["status"] == "partial" and "scan_limit" in section["coverage"]["reasons"]
    assert section["coverage"]["search_end"] == 128
    assert section["coverage"]["search_complete"] is False
    assert section["blobs"] == []
    for maximum in (0, 1, 20):
        assert S.compact_result(result, maximum)["fit_security"] == section
    assert sd.image_budget == 128


def test_cancel_reaches_scan_after_legacy_work(monkeypatch):
    event = threading.Event()
    ctl = Ctl(event, max_seconds=30)
    scan = S.scan_fit_security

    def cancel_scan(buf, size, **kwargs):
        assert kwargs["ctl"] is ctl
        event.set()
        return scan(buf, size, **kwargs)

    monkeypatch.setattr(S, "scan_fit_security", cancel_scan)
    with pytest.raises(Cancelled):
        _surface(_fdt(), ctl=ctl)


async def test_cancelled_fit_scan_does_not_publish_report(fit_case, monkeypatch):
    from fwtriage_mcp.server import server

    scan = S.scan_fit_security

    def cancel_scan(buf, size, **kwargs):
        kwargs["ctl"]._event.set()
        return scan(buf, size, **kwargs)

    monkeypatch.setattr(S, "scan_fit_security", cancel_scan)
    async with Client(server) as client:
        result = await call(client, "fw_sd_surface", case_id=fit_case.id,
                            image_path=_write_image(fit_case, _fdt()))
    assert "cancelled" in json.dumps(result)
    assert not list(fit_case.subdir("analysis").glob("sd-surface-*.json"))


async def test_background_result_preserves_fit_section(fit_case):
    from fwtriage_mcp.server import server

    async with Client(server) as client:
        job = await call(client, "fw_sd_surface", case_id=fit_case.id,
                         image_path=_write_image(fit_case, _signed_fit()), background=True, max_results=0)
        assert job["background"], job
        state = await call(client, "fwtriage_job_status", job_id=job["job_id"], wait_seconds=30)
    assert state["status"] == "succeeded", state
    result = state["result"]
    assert result["fit_security"] == _saved(fit_case, result)["fit_security"]
    assert result["fit_security"]["summary"]["entries_reported"] == 3


@pytest.mark.parametrize("verify", [None, "n", "N", "0", "", "yes", "true", "1"])
def test_verify_notes_observe_environment_without_asserting_signature_enforcement(verify):
    env = {"bootcmd": "fatload mmc 0:1 0x82000000 boot.scr; source 0x82000000"}
    if verify is not None:
        env["verify"] = verify
    result = S.sd_boot_analysis(env, storage="flash-crc")
    disabled = verify is not None and verify[:1] not in ("1", "y", "Y", "t", "T")
    assert result["verify_off"] is disabled
    assert result["severity_hint"] == "high"
    assert result["verify"] == verify
    if disabled or verify is None:
        notes = " ".join(result["notes"])
        assert "부팅 경로와 신뢰 키를 추가 확인" in notes
        assert "(FIT 서명 포함)이 꺼진다" not in notes
    assert "부팅 경로와 신뢰 키를 추가 확인" in S.CHECKS["SD-03"]["rationale"]


async def test_ioc_accepts_actual_firmware_report_with_additive_fit_section(fit_case, tmp_path):
    from fs.builders import fat32_small
    from forensics_mcp import server as F
    from fwtriage_mcp import server as W
    from pweh.sdioc import compare_sd_paths

    root = write_tree(fit_case.dir / "extract" / "rootfs", {"etc/init.d/rcS":
        "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sd\nsh /mnt/sd/synthetic.sh\n"})
    async with Client(W.server) as client:
        firmware = await call(client, "fw_sd_surface", case_id=fit_case.id,
                              rootfs_dir=fit_case.rel(root), image_path=_write_image(fit_case, _signed_fit()))
    assert firmware["ok"], firmware
    disk = fat32_small()
    disk.add_file("/synthetic.sh", b"SYNTHETIC CONTENT NEVER INSPECTED BY IOC")
    source = tmp_path / "synthetic-card.img"
    source.write_bytes(disk.image())
    async with Client(F.server) as client:
        job = await call(client, "forensics_intake_start", case_id=fit_case.id, image_path=str(source),
                         purpose="합성 호환 시험", legal_basis="합성 자료 소유", site_type="home",
                         business_purpose="없음(합성)", role="owner")
        assert job.get("job_id"), job
        state = await call(client, "forensics_job_status", job_id=job["job_id"], wait_seconds=30)
        assert state["status"] == "succeeded", state
        ev = state["result"]["evidence_id"]
        listing = await call(client, "forensics_fs_list", case_id=fit_case.id, evidence_id=ev)
        assert listing["ok"], listing
        ioc = await call(client, "forensics_sd_ioc_scan", case_id=fit_case.id, evidence_id=ev,
                         firmware_result_path=firmware["result_path"], fs_list_path=listing["result_path"])
    assert ioc["ok"], ioc
    assert ioc["report"]["summary"]["by_kind"]["exact_live_name"] >= 1
    assert "fit_security" not in json.dumps(ioc)
    # 기존 matcher도 새 최상위 필드 유무에 따라 이름 대조 결과를 바꾸지 않는다.
    full = _saved(fit_case, firmware)
    listing_full = _saved(fit_case, listing)
    baseline = copy.deepcopy(full)
    baseline.pop("fit_security")
    end = time.monotonic() + 30
    assert compare_sd_paths(full, listing_full, deadline=end) == compare_sd_paths(baseline, listing_full, deadline=end)


def test_factory_result_does_not_share_mutable_state():
    first = S.SdSurface(Ctl(), load_patterns()).result(rootfs_given=False, image_given=False)
    second = S.SdSurface(Ctl(), load_patterns()).result(rootfs_given=False, image_given=False)
    first["fit_security"]["coverage"]["reasons"].append("synthetic")
    assert second["fit_security"]["coverage"]["reasons"] == []
