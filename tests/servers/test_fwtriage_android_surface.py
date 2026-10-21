"""AN 정적 근거·미검사 범위·마스킹과 MCP 경계 시험."""

import json
import struct
import time

import pytest
from mcp import Client

from fwtriage.android_builders import boot, vendor_boot, vbmeta
from fwtriage_mcp.androidsurface import AndroidSurface
from fwtriage_mcp.common import Ctl
from mcp_helpers import call
from pweh.case import CaseStore


@pytest.fixture
def anyio_backend():
    return "asyncio"


def write(root, path, text):
    dest = root / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text)


def checks(audit):
    return {x["id"]: x for x in audit.result()["checks"]}


def test_positive_rules_and_secret_masking(tmp_path):
    write(tmp_path, "system/build.prop", "ro.debuggable=1\nro.secure=0\nro.build.tags=test-keys\npersist.adb.tcp.port=5555\npassword=" + "secretword" * 200 + "\n")
    write(tmp_path, "system/etc/init/test.rc", "service test /system/bin/adbd\n user root\n capabilities NET_ADMIN\non boot\n setenforce 0\n")
    write(tmp_path, "system/etc/permissions/privapp-permissions-test.xml", '<permissions><privapp-permissions package="pweh.synthetic"><permission name="android.permission.TEST"/></privapp-permissions></permissions>')
    write(tmp_path, "system/priv-app/Test/Test.apk", "synthetic inventory only")
    write(tmp_path, "system/etc/security/otacerts.zip", "synthetic inventory only")
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    data = vbmeta(3)
    audit.scan_image(data, len(data), "dumps/vbmeta.bin")
    assert all(x["status"] == "found" for x in checks(audit).values())
    result = json.dumps(audit.result())
    assert "secretword" not in result and "password" in result
    assert checks(audit)["AN-06"]["severity_hint"] == "info"


def test_empty_input_is_unknown(tmp_path):
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    assert all(x["status"] == "unknown" for x in checks(audit).values())


def test_clean_properties_scoped_not_found(tmp_path):
    write(tmp_path, "system/build.prop", "ro.debuggable=0\nro.secure=1\nro.build.tags=release-keys\n")
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    assert checks(audit)["AN-02"]["status"] == "not-found"
    assert checks(audit)["AN-05"]["status"] == "unknown"


@pytest.mark.parametrize("builder", (lambda: boot(cmdline=b"androidboot.selinux=permissive"), vendor_boot))
def test_boot_selinux(builder):
    data = builder()
    audit = AndroidSurface(Ctl())
    audit.scan_image(data, len(data), "dumps/boot.bin")
    assert checks(audit)["AN-04"]["status"] == "found"


def test_truncated_vbmeta_is_unknown():
    data = vbmeta(3)
    struct.pack_into(">Q", data, 12, 64)
    audit = AndroidSurface(Ctl())
    audit.scan_image(data, len(data), "dumps/vbmeta.bin")
    assert checks(audit)["AN-05"]["status"] == "unknown"


def test_footer_declared_span_bounds_vbmeta_even_when_backing_bytes_exist():
    data = bytearray(1024)
    data[512:768] = vbmeta(3)
    struct.pack_into(">Q", data, 512 + 12, 64)
    struct.pack_into(">4sIIQQQ", data, 960, b"AVBf", 1, 0, 512, 512, 256)
    audit = AndroidSurface(Ctl())
    audit.scan_image(data, len(data), "dumps/system.bin")
    assert checks(audit)["AN-05"]["status"] == "unknown"
    assert "vbmeta" in audit.result()["coverage"]["incomplete"]


def test_oversize_missing_import_and_symlink_are_incomplete(tmp_path):
    write(tmp_path, "system/build.prop", "#" * 100)
    write(tmp_path, "system/etc/init/test.rc", "import /missing.rc\non boot\n setenforce 1\n")
    (tmp_path / "outside").symlink_to("/etc/passwd")
    audit = AndroidSurface(Ctl(), max_file_size=64)
    audit.scan_rootfs(tmp_path)
    assert checks(audit)["AN-02"]["status"] == "unknown"
    assert checks(audit)["AN-04"]["status"] == "unknown"
    assert audit.result()["limitations"]


def test_xml_entity_rejected(tmp_path):
    write(tmp_path, "system/etc/permissions/privapp-permissions-test.xml", '<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><permissions>&a;</permissions>')
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    assert checks(audit)["AN-08"]["status"] == "unknown"


def test_utf16_xml_entity_rejected(tmp_path):
    dest = tmp_path / "privapp-permissions-test.xml"
    dest.write_bytes('<!DOCTYPE x [<!ENTITY a "secret">]><permissions>&a;</permissions>'.encode("utf-16"))
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    assert checks(audit)["AN-08"]["status"] == "unknown"


def test_evidence_cap_counts_omission(tmp_path):
    write(tmp_path, "build.prop", "\n".join("ro.debuggable=1" for _ in range(10)))
    audit = AndroidSurface(Ctl(), max_evidence=2)
    audit.scan_rootfs(tmp_path)
    result = checks(audit)["AN-02"]
    assert result["evidence_total"] == 10 and result["evidence_suppressed"] == 8


def test_missing_import_does_not_hide_actual_positive(tmp_path):
    write(tmp_path, "init.rc", "import /missing.rc\non boot\n setenforce 0\n")
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    assert checks(audit)["AN-04"]["status"] == "found" and "init" in audit.result()["coverage"]["incomplete"]


@pytest.mark.parametrize("name", ("hidden.txt", "hidden", "hidden.rc"))
def test_import_must_be_parsed_as_init_to_claim_no_permissive(tmp_path, name):
    write(tmp_path, "init.rc", f"import /{name}\non boot\n setenforce 1\n")
    write(tmp_path, name, "on boot\n setenforce 0\n")
    audit = AndroidSurface(Ctl())
    audit.scan_rootfs(tmp_path)
    if name.endswith(".rc"):
        assert checks(audit)["AN-04"]["status"] == "found"
    else:
        assert checks(audit)["AN-04"]["status"] == "unknown"
        assert "init" in audit.result()["coverage"]["incomplete"]


def test_deadline_cannot_report_complete(tmp_path):
    write(tmp_path, "system/build.prop", "ro.debuggable=0")
    ctl = Ctl()
    ctl.deadline = time.monotonic() - 1
    audit = AndroidSurface(ctl)
    audit.scan_rootfs(tmp_path)
    assert all(x["status"] == "unknown" for x in checks(audit).values()) and audit.result()["timed_out"]


@pytest.mark.anyio
async def test_surface_mcp_summary_and_protected_path(workspace, auth):
    from fwtriage_mcp.server import server
    case = CaseStore(workspace["cases_dir"]).create(title="합성 Android", case_id="android", authorization=auth)
    write(case.subdir("extract"), "root/system/build.prop", "ro.debuggable=1\n")
    async with Client(server) as client:
        result = await call(client, "fw_android_surface", case_id=case.id, rootfs_dir="extract/root")
        denied = await call(client, "fw_android_surface", case_id=case.id, rootfs_dir="forensics")
    assert result["ok"] and "_error" in denied
    stored = json.loads((case.dir / result["result_path"]).read_text())
    assert stored["schema"] == "pweh.fwtriage.android-surface/v1" and len(stored["checks"]) == 9
