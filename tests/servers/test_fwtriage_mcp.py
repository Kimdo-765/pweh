"""fwtriage-mcp 서버 테스트 (in-memory MCP Client + stdio 1개).

합성 플래시(부트 영역 + U-Boot env + uImage(gzip) + squashfs + 0xFF)와 취약 구성을 심은 rootfs 로
fw_identify → fw_uboot_env → fw_carve → fw_extract_squashfs → fw_rootfs_audit → fw_strings_hunt → fw_elf_info → fw_crack_hashes
전체 흐름을 검증한다. squashfs 가 필요한 테스트는 mksquashfs/unsquashfs 가 없으면 skip.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path

import pytest
from mcp import Client

from fwtriage.builders import build_flash, build_min_elf, find_tool, make_rootfs_tree, mksquashfs
from mcp_helpers import call, stdio_params

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp.hashes import md5_crypt, sha_crypt  # noqa: E402
from fwtriage_mcp.patterns import custom_id  # noqa: E402

pytestmark = pytest.mark.anyio

CONTRACT_TOOLS = {
    "fw_identify", "fw_entropy", "fw_uboot_env", "fw_carve", "fw_uimage_info", "fw_extract_squashfs",
    "fw_rootfs_audit", "fw_strings_hunt", "fw_elf_info", "fw_crack_hashes",
    # 게임 세이브·해금 오프라인 분석 (ESP 형식·세이브 비교)
    "fw_esp_partitions", "fw_esp_image_info", "fw_esp_to_elf", "fw_esp_nvs", "fw_save_diff", "fw_checksum_find", "fw_find_seq_tables",
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fw_case(workspace, auth, tmp_path):
    from pweh.case import CaseStore

    store = CaseStore(workspace["cases_dir"])
    case = store.create(title="펌웨어 트리아지", authorization=auth, case_id="fwcase", profile="hisilicon-ipcam")
    tree = tmp_path / "tree"
    make_rootfs_tree(tree, md5crypt_support=md5_crypt("support", "saltsalt"))
    sq = mksquashfs(tree, tmp_path / "rootfs.sqfs")
    img, layout = build_flash(sq.read_bytes() if sq else None)
    (case.subdir("dumps") / "flash.bin").write_bytes(img)
    return {"case": case, "tree": tree, "layout": layout, "has_sqfs": sq is not None, "flash": img}


def _need_squashfs(fw_case):
    if not fw_case["has_sqfs"]:
        pytest.skip("mksquashfs 없음")
    if not find_tool("PWEH_UNSQUASHFS", "unsquashfs"):
        pytest.skip("unsquashfs 없음")


def _artifacts(case):
    return {a["path"]: a for a in case.load().get("artifacts", [])}


async def test_tools_listed(workspace):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert CONTRACT_TOOLS <= names
    assert {"fwtriage_job_status", "fwtriage_job_cancel", "fwtriage_jobs", "fw_hunt_patterns"} <= names


async def test_identify_flash(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_identify", case_id=case.id, path="dumps/flash.bin")
    assert r["ok"], r
    kinds = {(int(x["offset_hex"], 16), x["kind"]) for x in r["regions"]}
    assert (0x40000, "uboot-env") in kinds and (0x50000, "uimage") in kinds
    assert (0x100, "uboot-version") in kinds and r["summary"]["synthetic_marker"] is True
    if fw_case["has_sqfs"]:
        assert (0x150000, "squashfs") in kinds
    assert r["nested_omitted"] >= 1  # uImage 안의 gzip
    ui = [x for x in r["regions"] if x["kind"] == "uimage"][0]
    assert ui["details"]["payload"]["kind"] == "gzip"
    assert r["result_path"].startswith("analysis/identify-")
    full = json.loads((case.dir / r["result_path"]).read_text(encoding="utf-8"))
    assert full["schema"] == "pweh.fwtriage.identify/v1" and full["input"]["sha256"] == hashlib.sha256(fw_case["flash"]).hexdigest()
    assert any(n["kind"] == "gzip" for n in full["nested_regions"])
    assert _artifacts(case)[r["result_path"]]["kind"] == "triage-report"
    assert any("fw_uboot_env" in s for s in r["next_steps"])


async def test_uboot_env_and_carve_auto(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        env = await call(c, "fw_uboot_env", case_id=case.id, path="dumps/flash.bin")
        assert env["ok"], env
        assert env["env_count"] == 1 and env["envs"][0]["offset_hex"] == "0x40000"
        assert env["envs"][0]["env"]["ethaddr"] == "00:11:22:33:44:55"
        lay = env["recommended_layout"]
        assert [p["name"] for p in lay["partitions"]] == ["boot", "env", "kernel", "rootfs", "config"]
        assert env["embedded_default_envs"] and env["mtdparts_strings"]
        carved = await call(c, "fw_carve", case_id=case.id, path="dumps/flash.bin")
    assert carved["ok"], carved
    assert carved["output_dir"] == "extract/parts-001"
    parts = {p["name"]: p for p in carved["partitions"]}
    assert set(parts) == {"boot", "env", "kernel", "rootfs", "config"}
    assert parts["kernel"]["content"] == "uimage"
    assert parts["env"]["content"] == "uboot-env" and parts["boot"]["content"] == "bootloader"
    assert parts["config"]["content"] == "erased"
    if fw_case["has_sqfs"]:
        assert parts["rootfs"]["content"] == "squashfs"
        assert any("fw_extract_squashfs" in s for s in carved["next_steps"])
    k = case.dir / parts["kernel"]["file"]
    assert parts["kernel"]["file"].endswith("02-kernel.bin") and k.stat().st_size == 0x100000
    assert k.read_bytes() == fw_case["flash"][0x50000:0x150000]
    # 회귀: 파티션 파일 키가 file 하나뿐이었다 (다른 도구·스키마는 케이스 상대 경로를 path 로 부른다). file 은 같은 값의 별칭
    assert all(p["path"] == p["file"] for p in carved["partitions"] if p["status"] == "carved")
    assert any(f"fw_uimage_info(path='{parts['kernel']['path']}')" == s for s in carved["next_steps"])
    idx = json.loads((case.dir / carved["index_path"]).read_text(encoding="utf-8"))
    assert idx["layout"]["source"].startswith("uboot-env@0x40000")
    assert all(p["path"] == p["file"] and (case.dir / p["path"]).is_file() for p in idx["partitions"] if p["status"] == "carved")
    full = json.loads((case.dir / carved["result_path"]).read_text(encoding="utf-8"))
    assert [p.get("path") for p in full["partitions"]] == [p.get("path") for p in idx["partitions"]]
    arts = _artifacts(case)
    assert arts[parts["kernel"]["file"]]["kind"] == "partition" and arts[parts["kernel"]["file"]]["sha256"] == hashlib.sha256(k.read_bytes()).hexdigest()


async def test_carve_explicit_partitions_and_edges(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_carve", case_id=case.id, path="dumps/flash.bin", output_label="k",
                       partitions=[{"name": "../../evil name", "offset": "0x50000", "size": "1M"}, {"name": "tail", "offset": "0x3F0000", "size": "128k"}, {"name": "past", "offset": "0x500000", "size": "64k"}])
        assert r["ok"], r
        ps = r["partitions"]
        assert ps[0]["file"].startswith("extract/k-001/00-") and ".." not in ps[0]["file"] and "/" not in ps[0]["file"].split("/", 2)[2]
        assert ps[1].get("truncated") is True and ps[2]["status"] == "skipped"
        r2 = await call(c, "fw_carve", case_id=case.id, path="dumps/flash.bin", mtdparts="nor:256k(boot),-(rest);nand:-(data)")
        assert r2["ok"] and any("장치가 2개" in w for w in r2["warnings"])
        bad = await call(c, "fw_carve", case_id=case.id, path="dumps/flash.bin", partitions=[{"name": "x", "offset": "zz"}])
        assert "_error" in bad and "offset" in bad["_error"]


async def test_uimage_info(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_uimage_info", case_id=case.id, path="dumps/flash.bin", offset="0x50000")
        assert r["ok"], r
        img = r["image"]
        assert img["name"] == "Linux-3.18.20" and img["compression"] == "gzip" and img["header_crc_ok"] and img["data_crc_ok"]
        assert img["payload_probe"]["kind"] == "gzip" and "payload_mismatch" not in img
        bad = await call(c, "fw_uimage_info", case_id=case.id, path="dumps/flash.bin", offset=0x1234)
        assert "_error" in bad and "0x50000" in bad["_error"]


@pytest.mark.external
async def test_extract_audit_hunt_pipeline(fw_case):
    _need_squashfs(fw_case)
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        carved = await call(c, "fw_carve", case_id=case.id, path="dumps/flash.bin")
        rootfs_part = [p for p in carved["partitions"] if p["name"] == "rootfs"][0]["file"]
        ex = await call(c, "fw_extract_squashfs", case_id=case.id, path=rootfs_part)
        assert ex["ok"] and ex["status"] == "complete", ex
        assert ex["output_dir"] == "extract/rootfs-001" and ex["manifest_path"] == "extract/rootfs-001.manifest.json"
        assert ex["listing"]["setuid"][0]["path"] == "/bin/busybox" and ex["listing"]["counts"]["chardev"] == 1
        root = case.dir / ex["output_dir"]
        assert (root / "etc" / "passwd").is_file() and not (root / "dev" / "console").exists()
        assert os.readlink(root / "bin" / "telnetd") == "/bin/busybox"
        # 같은 squashfs 를 flash 의 offset 으로 직접 추출 (번호 증가)
        ex2 = await call(c, "fw_extract_squashfs", case_id=case.id, path="dumps/flash.bin", offset="0x150000")
        assert ex2["ok"] and ex2["output_dir"] == "extract/rootfs-002"
        bad = await call(c, "fw_extract_squashfs", case_id=case.id, path="dumps/flash.bin", offset=0x40000)
        assert "_error" in bad and "squashfs" in bad["_error"]

        audit = await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir=ex["output_dir"], max_results=200)
        assert audit["ok"], audit
        ids = {i["id"] for i in audit["items"]}
        for must in (
            "known-hash-xm-root-xc3511", "passwd-empty-password", "passwd-extra-uid0", "gen-telnetd-login-shell",
            "gen-inittab-console-shell", "gen-getty-autologin", "builtin-dropbear-blank-password", "builtin-remserial",
            "builtin-chpasswd-literal", "builtin-busybox-httpd-auth", "builtin-config-password", "builtin-url-credential",
            "builtin-embedded-host-key", "gen-private-key-pem", "builtin-world-writable-startup", "builtin-setuid-busybox",
            "builtin-exec-from-writable-storage", "builtin-default-password", "gen-inetd-telnet",
        ):
            assert must in ids, (must, sorted(ids))
        sev = {i["id"]: i["severity"] for i in audit["items"]}
        assert sev["known-hash-xm-root-xc3511"] == "critical" and sev["passwd-empty-password"] == "critical"
        # 비밀번호/값은 응답에서 마스킹
        blob = json.dumps(audit, ensure_ascii=False)
        for secret in ("SuperSecret1", "hunter22", "Backup2020", "secret123", "admin123"):
            assert secret not in blob
        accts = {a["user"]: a for a in audit["accounts"]}
        assert accts["root"]["checks"][0]["status"] == "cracked" and accts["root"]["checks"][0]["password"] == "xc****"
        assert accts["admin"]["checks"][0]["status"] == "empty"
        assert {s["service"] for s in audit["services"]} >= {"telnetd", "dropbear", "remserial"}
        assert audit["vendor"]["family"] == "xiongmai-like" and audit["vendor"]["profile_vendor_family"] == "hisilicon-oem"
        assert audit["summary"]["manifest_used"] is True
        assert audit["rootfs"]["arch"] == "arm" and audit["rootfs"]["fs_type"].startswith("squashfs 4.0")
        # 호스트 파일을 읽지 않음: etc/issue -> /etc/os-release, etc/hostname -> /etc/hostname(루프)
        assert "/etc/issue" not in (audit["platform"].get("release_files") or {})
        assert "/etc/hostname" not in (audit["platform"].get("release_files") or {})
        full = json.loads((case.dir / audit["result_path"]).read_text(encoding="utf-8"))
        assert full["rootfs"]["path"] == ex["output_dir"] and full["hash_checks"]
        # static-analysis 스키마의 rootfs 객체 형태와 호환
        from pweh import schemas

        schemas.validate("static-analysis", {
            "firmware": {"path": "dumps/flash.bin", "sha256": hashlib.sha256(fw_case["flash"]).hexdigest()},
            "extraction": {"tool": "fwtriage", "status": "complete", "output_dir": ex["output_dir"]},
            "rootfs": audit["rootfs"],
            "binaries_of_interest": audit["binaries_of_interest"],
        })

        hunt = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=ex["output_dir"])
        assert hunt["ok"], hunt
        hit_ids = {h["pattern_id"] for h in hunt["hits"]}
        assert {"xm-opentelnet-cmd", "xm-telnetoempasswd", "xm-universal-password", "hik-anonymous-hardcoded", "gen-telnetd-login-shell", "xm-backdoor-daemons"} <= hit_ids
        utf16 = [h for h in hunt["hits"] if h["pattern_id"] == "xm-backdoor-daemons"][0]
        assert utf16["encoding"] == "utf16le" and utf16["file"] == "/usr/bin/Sofia"
        assert hunt["summary"]["vendor_family_guess"] == "xiongmai-like"
        full = json.loads((case.dir / hunt["result_path"]).read_text(encoding="utf-8"))
        assert any(ch["pattern_id"] == "gen-telnetd-launch" for ch in full["commented_hits"])  # '# telnetd ...' 주석 줄은 별도
        # auth-hunt 스키마 checks[] 로 바로 사용 가능
        from pweh import schemas as _s

        _s.validate("auth-hunt", {
            "vendor_family": hunt["summary"]["vendor_family_guess"],
            "web_components": [{"path": w["path"], "role": "web-server"} for w in audit["web_servers"]],
            "checks": [{k: ch[k] for k in ("id", "description", "result", "evidence_ref")} for ch in full["checks"]],
            "finding_ids": [],
        })

        elf_dir = await call(c, "fw_elf_info", case_id=case.id, path=ex["output_dir"])
        assert elf_dir["ok"] and elf_dir["mode"] == "directory" and elf_dir["summary"]["elf_count"] >= 4
        top = elf_dir["binaries"][0]
        assert top["risky"].get("command-exec") and top["score"] > 0


async def test_rootfs_audit_tree_without_manifest_and_symlink_safety(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    root = case.dir / "extract" / "tree-001"
    make_rootfs_tree(root, md5crypt_support=sha_crypt("support", "saltsalt", None, "6"))
    async with Client(server) as c:
        r = await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir="extract/tree-001", max_results=100)
        assert r["ok"], r
        assert r["summary"]["manifest_used"] is False and any("매니페스트" in x for x in r["limitations"])
        ids = {i["id"] for i in r["items"]}
        assert "builtin-setuid-busybox" in ids  # 디스크 모드(4755) 기준
        accts = {a["user"]: a for a in r["accounts"]}
        assert accts["support"]["checks"][0]["algorithm"] == "sha512crypt" and accts["support"]["checks"][0]["status"] == "cracked"
        # 케이스 안의 심볼릭 링크가 케이스 밖을 가리키면 명확한 안내
        os.symlink("/etc/passwd", case.dir / "dumps" / "hostlink")
        bad = await call(c, "fw_identify", case_id=case.id, path="dumps/hostlink")
        assert "_error" in bad and "심볼릭 링크" in bad["_error"]
        bad2 = await call(c, "fw_elf_info", case_id=case.id, path="extract/tree-001/bin/telnetd")
        assert "_error" in bad2 and "심볼릭 링크" in bad2["_error"]
        trav = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="../../")
        assert "_error" in trav
        notdir = await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir="dumps/flash.bin")
        assert "_error" in notdir and "디렉터리" in notdir["_error"]


async def test_non_utf8_names_and_empty_inputs(fw_case):
    """GBK 등 비 UTF-8 파일 이름(os.walk 의 surrogateescape)과 0바이트 입력에서도 죽지 않아야 한다."""
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    root = case.dir / "extract" / "gbk-001"
    make_rootfs_tree(root)
    bad_name = os.fsencode(str(root / "etc")) + b"/\xc4\xe3\xba\xc3.conf"
    with open(bad_name, "wb") as fh:
        fh.write(b"admin_password=GbkSecret9\n")
    (case.subdir("dumps") / "empty.bin").write_bytes(b"")
    async with Client(server) as c:
        a = await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir="extract/gbk-001", max_results=300)
        assert a["ok"], a
        gbk = [i for i in a["items"] if i["id"] == "builtin-config-password" and i.get("file", "").startswith("/etc/") and "\ufffd" in i["file"]]
        assert gbk and "GbkSecret9" not in json.dumps(a, ensure_ascii=False)
        json.loads((case.dir / a["result_path"]).read_text(encoding="utf-8"))
        h = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/gbk-001")
        assert h["ok"], h
        e = await call(c, "fw_elf_info", case_id=case.id, path="extract/gbk-001")
        assert e["ok"], e
        for tool in ("fw_identify", "fw_entropy", "fw_uboot_env"):
            r = await call(c, tool, case_id=case.id, path="dumps/empty.bin")
            assert r["ok"], (tool, r)
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/empty.bin")
        assert r["ok"] and r["summary"]["hits_total"] == 0
        for tool, kw in (("fw_carve", {}), ("fw_uimage_info", {}), ("fw_elf_info", {})):
            r = await call(c, tool, case_id=case.id, path="dumps/empty.bin", **kw)
            assert "_error" in r and "internal_error" not in r["_error"], (tool, r)


async def test_strings_hunt_file_and_pattern_selection(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    root = case.dir / "extract" / "tree-002"
    make_rootfs_tree(root)
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002/usr/bin/Sofia", patterns=["xm-*", "lit:uc-httpd", "re:ping -c \\d %s"])
        assert r["ok"], r
        ids = {h["pattern_id"] for h in r["hits"]}
        assert {"xm-opentelnet-cmd", "xm-universal-password", custom_id("lit", "uc-httpd"), custom_id("re", "ping -c \\d %s")} <= ids
        # 단일 파일 모드도 file 은 rootfs 절대 경로, path 는 케이스 상대 경로 (디렉터리 모드와 같은 규칙)
        assert all(h["file"] == "/usr/bin/Sofia" and h["path"] == "extract/tree-002/usr/bin/Sofia" for h in r["hits"])
        # 모든 패턴이 건너뛰어지면(빈 문자열과 일치) 이유가 오류에 들어간다
        empty = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002", patterns=["lit:", "re:a*"])
        assert "_error" in empty and "선택된 패턴이 없습니다" in empty["_error"] and "빈 문자열" in empty["_error"]
        crit = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002", min_severity="critical", max_results=3)
        assert crit["ok"] and len(crit["hits"]) <= 3 and all(h["severity"] == "critical" for h in crit["hits"])
        flash = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/flash.bin", patterns="cctv")
        assert flash["ok"]
        pats = await call(c, "fw_hunt_patterns", vendor="xiongmai")
        assert pats["ok"] and all(h["vendor"] == "xiongmai" for h in pats["string_heuristics"]) and pats["errors"] == []


async def test_strings_hunt_path_convention_across_modes(fw_case):
    """회귀: hits[].file 이 디렉터리 모드는 rootfs 절대 경로, 단일 파일 모드는 케이스 상대 경로였다 (하위 디렉터리를 주면 '/Sofia').

    이제 두 모드 모두 file = rootfs 절대 경로(rootfs 밖이면 null), path = 케이스 상대 경로, evidence_ref = file(없으면 path)@offset.
    """
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    make_rootfs_tree(case.dir / "extract" / "tree-002")
    make_rootfs_tree(case.dir / "extract" / "tree-003")
    blob = b"\x00\x00\x00OpenTelnet:OpenOnce\x00\x00" * 2
    (case.subdir("dumps") / "blob.bin").write_bytes(blob)
    part = case.dir / "extract" / "parts-009" / "00-blob.bin"
    part.parent.mkdir(parents=True)
    part.write_bytes(blob)

    def sofia_hits(r):
        return [h for h in r["hits"] if h["path"].endswith("/usr/bin/Sofia")]

    async with Client(server) as c:
        single = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002/usr/bin/Sofia", patterns="xm-*")
        whole = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002", patterns="cctv", max_results=500)
        sub = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract/tree-002/usr/bin", patterns="xm-*")
        raw = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/blob.bin", patterns="xm-opentelnet-cmd")
        multi = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="extract", patterns="cctv", max_results=1000)
    for r in (single, whole, sub, raw, multi):
        assert r["ok"], r
    for r in (single, whole, sub):
        hs = sofia_hits(r)
        assert hs and all(h["file"] == "/usr/bin/Sofia" and h["path"] == "extract/tree-002/usr/bin/Sofia" for h in hs), [(h["file"], h["path"]) for h in hs]
        assert r["summary"]["rootfs_dirs"] == ["extract/tree-002"]
    # 같은 파일·같은 패턴이면 모드와 무관하게 같은 오프셋·evidence_ref
    key = {(h["pattern_id"], h["offset"]) for h in sofia_hits(single)}
    assert key <= {(h["pattern_id"], h["offset"]) for h in sofia_hits(whole)}
    for r in (single, whole):
        ev = {c_["id"]: c_["evidence_ref"] for c_ in r["matched_checks"]}
        first = min((h for h in sofia_hits(r) if h["pattern_id"] == "xm-opentelnet-cmd"), key=lambda h: h["offset"])
        assert ev["xm-opentelnet-cmd"] == f"/usr/bin/Sofia@{first['offset_hex']}"
    top = {t["path"]: t for t in whole["top_files"]}
    assert top["extract/tree-002/usr/bin/Sofia"]["file"] == "/usr/bin/Sofia"
    full = json.loads((case.dir / whole["result_path"]).read_text(encoding="utf-8"))
    com = [h for h in full["commented_hits"] if h["pattern_id"] == "gen-telnetd-launch"]
    assert com and com[0]["file"] == "/etc/init.d/rcS" and com[0]["path"] == "extract/tree-002/etc/init.d/rcS"
    # rootfs 밖의 단일 파일(덤프): file 은 null, evidence_ref 는 케이스 상대 경로
    assert raw["hits"] and all(h["file"] is None and h["path"] == "dumps/blob.bin" for h in raw["hits"])
    assert raw["matched_checks"][0]["evidence_ref"] == f"dumps/blob.bin@{raw['hits'][0]['offset_hex']}" and raw["summary"]["rootfs_dirs"] == []
    # 여러 트리를 한 번에: file 은 겹쳐도 path 로 구분되고, rootfs 밖의 파티션 이미지는 file null
    sof = {h["path"] for h in sofia_hits(multi)}
    assert sof == {"extract/tree-002/usr/bin/Sofia", "extract/tree-003/usr/bin/Sofia"}
    assert {t["path"] for t in multi["top_files"]} >= sof
    assert multi["summary"]["rootfs_dirs"] == ["extract/tree-002", "extract/tree-003"]
    blob_hits = [h for h in multi["hits"] if h["path"] == "extract/parts-009/00-blob.bin"]
    assert blob_hits and all(h["file"] is None for h in blob_hits)


async def test_rootfs_audit_ignores_passwd_applet_and_binaries(fw_case):
    """회귀: /usr/bin/passwd(→ busybox 애플릿 링크)를 계정 DB 로 읽어 실행 파일 바이트에서 가짜 계정 '0'(uid null)을 만들었다.

    실행 파일 안의 'root::0:0' 같은 바이트열이 빈 비밀번호 critical 로, 대상 없는 애플릿 링크가 '이미지 밖 계정 DB' 로 보고될 수도 있었다.
    """
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    root = case.dir / "extract" / "applet-001"

    def w(rel: str, data: bytes) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    elf = build_min_elf() + b"\n0:\x9d\x04\x00\xca:x\n" + b"\nroot::0:0:root:/root:/bin/sh\n" + b"\nghost:$1$abc$defdefdefdefdefdefdefde:0:0::/:/bin/sh\n"
    w("bin/busybox", elf)
    w("usr/libexec/passwd", elf)  # bin/sbin 밖이어도 내용이 바이너리면 계정 DB 가 아니다
    w("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/:/bin/false\n")
    w("etc/shadow", f"root:{md5_crypt('123456', 'appletsa')}:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\n".encode())
    w("mnt/mtd/Config/passwd", f"admin:{md5_crypt('admin', 'dvrsalt1')}\n".encode())  # DVR 설정 파티션의 짧은 user:hash 형식은 계속 본다
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "sbin").mkdir(parents=True)
    os.symlink("../../bin/busybox", root / "usr" / "bin" / "passwd")
    os.symlink("/bin/missing-applet", root / "sbin" / "passwd")  # 대상 없는 애플릿 링크
    async with Client(server) as c:
        r = await call(c, "fw_rootfs_audit", case_id=case.id, rootfs_dir="extract/applet-001", max_results=300)
    assert r["ok"], r
    users = {a["user"] for a in r["accounts"]}
    assert users == {"root", "daemon", "admin"}, users
    full = json.loads((case.dir / r["result_path"]).read_text(encoding="utf-8"))
    assert {h["user"] for h in full["hash_checks"]} == {"root", "admin"}
    accts = {a["user"]: a for a in full["accounts"]}
    assert accts["root"]["files"] == ["/etc/passwd:1", "/etc/shadow:1"] and accts["admin"]["files"] == ["/mnt/mtd/Config/passwd:1"]
    bogus_files = {"/usr/bin/passwd", "/sbin/passwd", "/usr/libexec/passwd", "/bin/busybox"}
    assert not [i for i in r["items"] if i.get("file") in bogus_files], [(i["id"], i.get("file")) for i in r["items"]]
    ids = {i["id"] for i in r["items"]}
    assert "builtin-credential-db-symlink" not in ids and "builtin-empty-password" not in ids and "builtin-extra-uid0" not in ids
    cracked = {(i.get("file"), i["severity"]) for i in r["items"] if i["id"] == "builtin-default-password"}
    assert cracked == {("/etc/shadow", "critical"), ("/mnt/mtd/Config/passwd", "critical")}


async def test_elf_info_file(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    p = case.subdir("analysis") / "sample.elf"
    p.write_bytes(build_min_elf(machine=8, little=False, flags=0x70001005))
    async with Client(server) as c:
        r = await call(c, "fw_elf_info", case_id=case.id, path="analysis/sample.elf")
        assert r["ok"], r
        assert r["elf"]["machine"] == "mips" and r["elf"]["flags"]["abi"] == "o32" and r["elf"]["endianness"] == "big"
        assert set(r["imports"]) == {"system", "strcpy", "popen", "sprintf"}
        assert r["risk"]["builtin"]["command-exec"]["functions"] == ["popen", "system"]
        assert "_all_funcs" not in r["elf"]
        junk = case.subdir("analysis") / "junk.bin"
        junk.write_bytes(b"\x7fELF" + os.urandom(100))
        bad = await call(c, "fw_elf_info", case_id=case.id, path="analysis/junk.bin")
        assert "_error" in bad and "ELF" in bad["_error"]


async def test_entropy(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    rnd = random.Random(5)
    blob = b"\xff" * 0x20000 + rnd.randbytes(0x40000) + b"\x00" * 0x20000
    (case.subdir("dumps") / "mixed.bin").write_bytes(blob)
    async with Client(server) as c:
        r = await call(c, "fw_entropy", case_id=case.id, path="dumps/mixed.bin", block_size=0x10000)
    assert r["ok"], r
    hr = r["high_runs"]
    assert len(hr) == 1 and hr[0]["offset_hex"] == "0x20000" and hr[0]["size"] == 0x40000 and hr[0]["distribution"] == "uniform"
    assert hr[0]["known_coverage"] == 0.0 and "note" in hr[0]
    assert len(r["low_runs"]) == 2 and len(r["profile"]) == 8 and r["profile"][0] == "_"


async def test_crack_hashes(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    shadow = case.subdir("analysis") / "shadow.txt"
    shadow.write_text(f"root:{md5_crypt('admin', 'abcdefgh')}:18000:0:99999:7:::\nnobody:*:1:0::::\n")
    wl = case.subdir("analysis") / "words.txt"
    wl.write_text("letmein\nCorrect-Horse-42\n")
    async with Client(server) as c:
        r = await call(c, "fw_crack_hashes", case_id=case.id, hashes=["root:absxcfbgXtb3o:0:0::/:/bin/sh", {"user": "xm", "hash": "tlJwpbo6", "type": "xm-sofia"}, "$1$saltsalt$" + "x" * 22])
        assert r["ok"], r
        res = {x.get("user"): x for x in r["results"]}
        assert res["root"]["status"] == "cracked" and res["root"]["password"] == "xc****" and res["root"]["known_hash"]["id"] == "known-hash-xm-root-xc3511"
        assert res["xm"]["status"] == "cracked"
        assert res[None]["status"] == "not_cracked"
        assert r["revealed"] is False
        full = json.loads((case.dir / r["result_path"]).read_text(encoding="utf-8"))
        assert [x for x in full["results"] if x["user"] == "root"][0]["password"] == "xc3511"  # 케이스 안 JSON 에는 평문
        r2 = await call(c, "fw_crack_hashes", case_id=case.id, source_path="analysis/shadow.txt", reveal=True)
        assert r2["ok"] and r2["results"][0]["password"] == "admin" and len(r2["results"]) == 1
        r3 = await call(c, "fw_crack_hashes", case_id=case.id, hashes=[f"u:{md5_crypt('Correct-Horse-42', 'zz')}"], wordlist="analysis/words.txt", reveal=True)
        assert r3["results"][0]["status"] == "cracked" and r3["results"][0]["password"] == "Correct-Horse-42"
        empty = await call(c, "fw_crack_hashes", case_id=case.id, hashes=[])
        assert "_error" in empty


async def test_background_job(fw_case):
    from fwtriage_mcp.server import server

    case = fw_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_identify", case_id=case.id, path="dumps/flash.bin", background=True)
        assert r["ok"] and r["background"] and r["job_id"].startswith("job-")
        st = await call(c, "fwtriage_job_status", job_id=r["job_id"], wait_seconds=30)
        assert st["status"] == "succeeded", st
        assert st["result"]["tool"] == "fw_identify" and st["result"]["result_path"].startswith("analysis/identify-")
        jobs = await call(c, "fwtriage_jobs")
        assert any(j["job_id"] == r["job_id"] for j in jobs["jobs"])
        assert (case.dir / "jobs" / f"{r['job_id']}.json").exists()


async def test_fwtriage_stdio(workspace, auth):
    from pweh.case import CaseStore

    store = CaseStore(workspace["cases_dir"])
    case = store.create(title="stdio", authorization=auth, case_id="stdio-case")
    img, _ = build_flash(None)
    (case.subdir("dumps") / "f.bin").write_bytes(img)
    params = stdio_params("fwtriage_mcp", env={"PWEH_CONFIG": str(workspace["config"])})
    async with Client(params, read_timeout_seconds=60) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert CONTRACT_TOOLS <= names
        r = await call(c, "fw_identify", case_id="stdio-case", path="dumps/f.bin")
        assert r["ok"], r
        assert any(x["kind"] == "uimage" for x in r["regions"])
        env = await call(c, "fw_uboot_env", case_id="stdio-case", path="dumps/f.bin")
        assert env["env_count"] == 1
