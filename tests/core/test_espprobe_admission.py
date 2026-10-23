"""등록 metadata·순수 입장·HELLO의 합성 시험. 실제 포트/보호 저장소를 열지 않는다."""
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
import os
import stat
import time
from types import SimpleNamespace

import pytest

from pweh import espprobe_admission as A
from pweh import espprobe_protocol as P
from pweh import espprobe_release as R
from pweh.portidentity import PortIdentity
from pweh.ports import PortRoute, identity_projection


def make_inputs(*, backend="win-helper", case_id="i5-synthetic", endpoint=None, release=None, deadline=None):
    """B/C가 실제 validator에 전달할 합성 kwargs. 관찰/상태 파일은 만들지 않는다."""
    if backend not in ("win-helper", "posix-tty"):
        raise ValueError("synthetic_backend")
    end = time.monotonic() + 5 if deadline is None else deadline
    release = R.load_probe_release(deadline=end) if release is None else release
    mac = "aabbccddeeff"
    if backend == "win-helper":
        endpoint = endpoint or "COM251"
        sibling_endpoint = "COM252" if endpoint != "COM252" else "COM253"
        parent = r"USB\VID_303A&PID_4002\AABBCCDDEEFF"
        ids = []
        for interface, port in (("00", endpoint), ("02", sibling_endpoint)):
            node = "USB\\VID_303A&PID_4002&MI_" + interface + "\\SYNTHETIC_" + interface
            ids.append(PortIdentity(port, status="known", present=True, backend="windows", device_instance=node,
                parent_instance=parent, usb_ancestor=parent, vid="303a", pid="4002", interface_number=interface,
                serial=mac.upper(), serial_basis="instance-tail", observed_at=1.0))
        keys = tuple(sorted({"winif:" + parent} | {"winif:" + i.device_instance for i in ids}
                            | {"win:" + i.endpoint_key for i in ids}))
        key, side, node = "win:" + endpoint, "windows", None
        service = "usbser"
    else:
        endpoint = endpoint or "/dev/ttyACM0"
        sibling_endpoint = "/dev/ttyACM1" if endpoint != "/dev/ttyACM1" else "/dev/ttyACM2"
        parent = "devices/synthetic/usb1/1-1"
        ids = []
        for interface, port, minor in (("00", endpoint, 0), ("02", sibling_endpoint, 1)):
            node_name = parent + "/1-1:1." + str(int(interface))
            ids.append(PortIdentity("tty:166:%d" % minor, status="known", present=True, backend="linux", device_instance=node_name,
                parent_instance=parent, usb_ancestor=parent, vid="303a", pid="4002", interface_number=interface,
                serial=mac.upper(), serial_basis="sysfs", tty_devnum=(166, minor), observed_at=1.0))
        keys = tuple(sorted({"usbif:1-1:1.%d" % n for n in range(4)} | {"tty:166:0", "tty:166:1"}))
        key, side, node = "tty:166:0", "local", (7, 101, os.makedev(166, 0))
        service = "cdc_acm"
    identity = ids[0]
    device_id, strength = identity_projection(identity)
    route = PortRoute(endpoint, "serial-session", backend, side, endpoint, key, device_id,
                      identity, strength, "possible", node_identity=node)
    observation = A.ProbeObservation(identity, True, parent, mac.upper(), release.usb.product, service,
        A._INTERFACES, tuple(ids), keys, (), (), (), True)
    refs = [A.ProbeRecordRef(case_id, i + 1, hashlib.sha256(("record%d" % i).encode()).hexdigest()) for i in range(4)]
    chip = A.ProbeChipFact(refs[0], "1" * 64, mac, "esp32s3", 1, 4 << 20)
    security = A.ProbeSecurityFact(refs[1], "2" * 64, mac, "esp32s3", "ok", False, False, False, True)
    backups = tuple(A.ProbeBackup(refs[i + 2], mac, "esp32s3", role, "3" * 64, "3" * 64,
        4 << 20, 0, 4 << 20, "double", True) for i, role in enumerate(("primary", "verification-read")))
    pin = A.ProbePinEvidence("att-0123456789", "4" * 64, "5" * 64, "6" * 64, A._digest(A.PIN_QUESTIONS),
        case_id, mac, "instrument", mac, (release.fw_version, release.build_profile, release.board, release.image_sha256),
        refs[0].entry_sha256, refs[1].entry_sha256, tuple(b.record.entry_sha256 for b in backups), A._digest(observation))
    authority = A.ProbeAuthority(case_id, chip, security, *backups, pin)
    return dict(release=release, case_id=case_id, authority=authority, observation=observation,
                route=route, scope_keys=keys, deadline=end, cancel=None)


def hello_fields(admission, nonce=b"n" * 16):
    """등록 릴리스에서만 HELLO 값을 투영한다. simulator 상수는 쓰지 않는다."""
    release = admission.release
    return dict(nonce=nonce.hex(), **{k: getattr(release, k) for k in (
        "fw_name", "fw_version", "build_profile", "board", "git_commit", "idf_version", "image_sha256", "app_elf_sha256")},
        chip=dict(model="esp32s3", revision=admission.chip_revision, psram_bytes=None, flash_voltage_mv=None),
        base_mac=admission.base_mac, usb=dict(vid=release.usb.vid, pid=release.usb.pid, product=release.usb.product,
            serial=admission.base_mac.upper()), boot_id="ab" * 16, usb_session=1, session_token=7,
        reset_reason="power-on", last_release_reason="boot", caps=[], tx_caps=[],
        pins_allowed={k: list(v) for k, v in release.pins_allowed}, pclk_pad=None, pin_drive=None,
        spi_read_opcodes=[], radio="none", limits=dict(max_payload=4096, hb_ms=1000, max_credit=0))


def frame(admission, **changes):
    values = hello_fields(admission)
    values.update(changes)
    return P.Frame(type=P.RSP, op=P.HELLO, seq=1, session=values["session_token"], payload=P.encode_hello(values))


@pytest.fixture
def inputs():
    return make_inputs()


def fails(call, code=None):
    with pytest.raises((A.ProbeAdmissionError, R.ProbeReleaseError)) as info:
        call()
    error = info.value
    if code:
        assert error.code == code
    assert error.data == {} and error.__cause__ is None and "PRIVATE_SENTINEL" not in str(error)
    return error


@pytest.mark.parametrize("backend", ["win-helper", "posix-tty"])
def test_real_registered_projection_admission_and_hello(backend):
    data = make_inputs(backend=backend)
    admitted = A.validate_probe_admission(**data)
    result = A.verify_probe_hello(frame(admitted), nonce=b"n" * 16, admission=admitted)
    assert result.session_token == 7 and result.usb_session == 1 and result.boot_id == b"\xab" * 16
    assert result.hb_ms == 1000 and result.psram_bytes is None and result.flash_voltage_mv is None
    assert admitted.claim_keys == data["scope_keys"] and admitted.route == data["route"]
    assert len(admitted.authority_sha256) == 64
    assert not hasattr(result, "to_dict") and "aabb" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.session_token = 8


def test_projections_are_immutable_and_do_not_share_catalog():
    first = R.load_probe_release(deadline=time.monotonic() + 5)
    second = R.load_probe_release(deadline=time.monotonic() + 5)
    assert first == second and first is not second
    assert first.usb.cdc_count == 2 and first.usb.pid == 0x4002
    assert first.pins_allowed == (("H0", ()), ("H1", ()), ("H1a", ()))
    with pytest.raises(FrozenInstanceError):
        first.usb.pid = 1


@pytest.mark.parametrize("field,value,code", [
    ("authority", None, "instrument_identity_unknown"),
    ("observation", None, "instrument_identity_unknown"),
    ("release", None, "firmware_not_pinned"),
    ("scope_keys", (), "route_changed"), ("case_id", "other", "instrument_identity_mismatch"),
    ("route", None, "route_changed"),
])
def test_missing_or_changed_inputs(inputs, field, value, code):
    inputs[field] = value
    fails(lambda: A.validate_probe_admission(**inputs), code)


@pytest.mark.parametrize("name,value,code", [
    ("complete", None, "instrument_identity_unknown"), ("complete", False, "instrument_identity_unknown"),
    ("aux_complete", None, "instrument_identity_unknown"), ("aux_inventory", None, "instrument_identity_unknown"),
    ("aux_present", None, "instrument_identity_unknown"), ("interfaces", None, "instrument_identity_unknown"),
    ("product", None, "instrument_identity_unknown"), ("driver_service", None, "instrument_identity_unknown"),
    ("parent_instance", None, "instrument_identity_unknown"), ("parent_serial", None, "instrument_identity_unknown"),
    ("siblings", (), "instrument_identity_unknown"), ("product", "PRIVATE_SENTINEL", "instrument_identity_mismatch"),
    ("parent_serial", "001122334455", "instrument_identity_mismatch"),
    ("driver_service", "other", "instrument_identity_mismatch"),
    ("interfaces", ((0, 2, 2, 1), (1, 10, 0, 0), (2, 2, 2, 1), (3, 10, 0, 0)), "instrument_identity_mismatch"),
])
def test_descriptor_and_aux_unknown_is_not_absence(inputs, name, value, code):
    inputs["observation"] = replace(inputs["observation"], **{name: value})
    fails(lambda: A.validate_probe_admission(**inputs), code)


@pytest.mark.parametrize("field,value", [
    ("vid", "10c4"), ("pid", "1001"), ("pid", "0009"), ("interface_number", "02"),
    ("serial", "001122334455"), ("status", "unknown"), ("present", False),
    ("backend", "other"), ("kind", "other"), ("reasons", ("incomplete",)), ("serial_basis", "location-derived"),
])
def test_native_identity_changes_are_rejected(inputs, field, value):
    obs = inputs["observation"]
    identity = replace(obs.identity, **{field: value})
    inputs["observation"] = replace(obs, identity=identity, siblings=(identity, obs.siblings[1]))
    fails(lambda: A.validate_probe_admission(**inputs))


def test_aux_present_and_scope_loss_rejected(inputs):
    obs = inputs["observation"]
    inputs["observation"] = replace(obs, aux_present=(obs.identity,))
    fails(lambda: A.validate_probe_admission(**inputs))
    inputs["observation"] = replace(obs, scope_keys=obs.scope_keys[1:])
    inputs["scope_keys"] = obs.scope_keys[1:]
    fails(lambda: A.validate_probe_admission(**inputs), "route_changed")


def test_unsealed_observation_change_rejected(inputs):
    obs = inputs["observation"]
    inputs["observation"] = replace(obs, boot_identities=(replace(obs.identity, endpoint_key="COM253"),))
    fails(lambda: A.validate_probe_admission(**inputs), "route_changed")


def test_observation_timestamp_is_not_identity(inputs):
    before = A.validate_probe_admission(**inputs)
    obs = inputs["observation"]
    identities = tuple(replace(i, observed_at=i.observed_at + 100) for i in obs.siblings)
    inputs["observation"] = replace(obs, identity=identities[0], siblings=identities)
    inputs["route"] = replace(inputs["route"], identity=identities[0])
    after = A.validate_probe_admission(**inputs)
    assert before.authority_sha256 == after.authority_sha256


@pytest.mark.parametrize("field,value", [
    ("purpose", "esptool"), ("backend", "win-exe"), ("backend", "loop"), ("backend", "net-url"),
    ("side", "local"), ("ref", "COM1"), ("device_path", "PRIVATE_SENTINEL"),
    ("lock_key", "win:COM1"), ("device_id", "PRIVATE_SENTINEL"), ("identity_strength", "none"),
    ("warnings", ("incomplete",)), ("node_identity", (1, 2, 3)),
])
def test_route_changes_rejected(inputs, field, value):
    inputs["route"] = replace(inputs["route"], **{field: value})
    fails(lambda: A.validate_probe_admission(**inputs), "route_changed")


@pytest.mark.parametrize("path,value", [
    (("chip", "chip"), "esp32"), (("chip", "flash_size"), 0), (("chip", "chip_revision"), 65536),
    (("security", "secure_boot"), True), (("security", "flash_encryption"), True),
    (("security", "secure_download_mode"), True), (("security", "read_flash_possible"), False),
    (("security", "status"), "unsupported"), (("security", "base_mac"), "001122334455"),
    (("primary_backup", "offset"), 1), (("primary_backup", "length"), 1),
    (("primary_backup", "size"), 1), (("primary_backup", "role"), "verification-read"),
    (("primary_backup", "verify"), "none"), (("primary_backup", "match"), False),
    (("primary_backup", "observed_sha256"), "f" * 64), (("verification_backup", "sha256"), "f" * 64),
    (("pin", "binding_scope"), "case"), (("pin", "instrument_id"), "other"),
    (("pin", "chip_entry_sha256"), "a" * 64), (("pin", "security_entry_sha256"), "b" * 64),
    (("pin", "questions_sha256"), "0" * 64), (("pin", "observation_sha256"), "0" * 64),
])
def test_authority_cross_checks(inputs, path, value):
    authority = inputs["authority"]
    changed = replace(getattr(authority, path[0]), **{path[1]: value})
    inputs["authority"] = replace(authority, **{path[0]: changed})
    fails(lambda: A.validate_probe_admission(**inputs))


def test_pin_missing_rejected(inputs):
    inputs["authority"] = replace(inputs["authority"], pin=None)
    fails(lambda: A.validate_probe_admission(**inputs), "firmware_not_pinned")


@pytest.mark.parametrize("name", ["secure_boot", "flash_encryption", "secure_download_mode", "read_flash_possible"])
def test_security_unknown_is_not_safe(inputs, name):
    authority = inputs["authority"]
    inputs["authority"] = replace(authority, security=replace(authority.security, **{name: None}))
    fails(lambda: A.validate_probe_admission(**inputs), "instrument_identity_unknown")


@pytest.mark.parametrize("which", ["case_id", "seq", "entry_sha256"])
def test_record_duplicates_and_other_case(inputs, which):
    authority = inputs["authority"]
    ref = authority.verification_backup.record
    value = "different" if which == "case_id" else getattr(authority.primary_backup.record, which)
    inputs["authority"] = replace(authority,
        verification_backup=replace(authority.verification_backup, record=replace(ref, **{which: value})))
    fails(lambda: A.validate_probe_admission(**inputs))


@pytest.mark.parametrize("field,value", [("seq", True), ("seq", 1.0), ("seq", -1), ("seq", 1 << 80),
    ("entry_sha256", "PRIVATE_SENTINEL"), ("case_id", "bad\nvalue")])
def test_projection_constructor_exact_scalar(field, value):
    values = dict(case_id="test", seq=1, entry_sha256="a" * 64)
    values[field] = value
    fails(lambda: A.ProbeRecordRef(**values))


@pytest.mark.parametrize("name,value", [("siblings", []), ("scope_keys", []), ("interfaces", []),
    ("complete", 1), ("aux_complete", 1.0), ("scope_keys", ("k",) * 65), ("interfaces", ((True, 2, 2, 0),))])
def test_projection_constructor_rejects_mutable_and_false_bools(inputs, name, value):
    fails(lambda: replace(inputs["observation"], **{name: value}))


@pytest.mark.parametrize("deadline", [True, None, float("inf"), float("nan"), 10 ** 400])
def test_deadline_invalid_fixed(inputs, deadline):
    inputs["deadline"] = deadline
    fails(lambda: A.validate_probe_admission(**inputs), "espprobe_protocol")
    fails(lambda: R.load_probe_release(deadline=deadline), "espprobe_protocol")


@pytest.mark.parametrize("cancel,code", [(lambda: True, "espprobe_cancelled"), (lambda: 1, "espprobe_protocol"),
    (lambda: None, "espprobe_protocol"), (lambda: (_ for _ in ()).throw(ValueError("PRIVATE_SENTINEL")), "espprobe_protocol")])
def test_cancel_before_result_is_fixed(inputs, cancel, code):
    inputs["cancel"] = cancel
    fails(lambda: A.validate_probe_admission(**inputs), code)
    fails(lambda: R.load_probe_release(deadline=time.monotonic() + 5, cancel=cancel), code)


def test_shared_deadline_after_observation_not_renewed(inputs, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(A.time, "monotonic", lambda: clock[0])
    inputs["deadline"] = 102.0
    original = A._observed
    def late(*args):
        original(*args)
        clock[0] = 102.0
    monkeypatch.setattr(A, "_observed", late)
    fails(lambda: A.validate_probe_admission(**inputs), "espprobe_timeout")


def test_late_reader_result_rejected(monkeypatch):
    raw = R._read_release_bytes()
    clock = [100.0]
    monkeypatch.setattr(R.time, "monotonic", lambda: clock[0])
    def late():
        clock[0] = 105.0
        return raw
    monkeypatch.setattr(R, "_read_release_bytes", late)
    fails(lambda: R.load_probe_release(deadline=1000), "espprobe_timeout")


@pytest.mark.parametrize("raw", [b"", b"\xffPRIVATE_SENTINEL", b"x" * ((1 << 20) + 1),
    b'{"schema":"a","schema":"b"}', b'{"value":NaN}', b'{"value":1.5}',
    b'{"value":' + b"9" * 5000 + b"}", b"[" * 10000 + b"]" * 10000, "PRIVATE_SENTINEL"])
def test_catalog_fixed_failures(monkeypatch, raw):
    monkeypatch.setattr(R, "_read_release_bytes", lambda: raw)
    fails(lambda: R.load_probe_release(deadline=time.monotonic() + 5), "firmware_not_pinned")


@pytest.mark.parametrize("change", ["missing", "duplicate", "overcount", "version", "image", "policy", "usb-extra", "usb-pid",
    "cdc-bool", "protocol-bool", "limit-bool", "offset-bool", "runs-float"])
def test_catalog_metadata_independent_checks(monkeypatch, change):
    doc = json.loads(R._read_release_bytes())
    entry = doc["releases"][0]
    if change == "missing": doc["releases"] = []
    elif change == "duplicate": doc["releases"].append(entry)
    elif change == "overcount": doc["releases"] = [entry] * 101
    elif change == "version": entry["fw_version"] = "0.2.0"
    elif change == "image": entry["image_sha256"] = "PRIVATE_SENTINEL"
    elif change == "policy": entry["policy_sha256"] = "0" * 64
    elif change == "usb-extra": entry["usb"]["other"] = "PRIVATE_SENTINEL"
    elif change == "usb-pid": entry["usb"]["pid"] = 0x1001
    elif change == "cdc-bool": entry["usb"]["cdc_count"] = True
    elif change == "protocol-bool": entry["protocol_version"] = True
    elif change == "limit-bool": entry["limits"]["max_credit"] = False
    elif change == "offset-bool": next(r for r in entry["files"] if r["role"] == "bootloader")["offset"] = False
    elif change == "runs-float": entry["verification"]["runs"] = 2.0
    monkeypatch.setattr(R, "_read_release_bytes", lambda: json.dumps(doc).encode())
    fails(lambda: R.load_probe_release(deadline=time.monotonic() + 5), "firmware_not_pinned")


@pytest.mark.parametrize("name,value", [("version", True), ("type", P.REQ), ("op", P.BYE), ("flags", 1),
    ("credit", 1), ("seq", 2), ("session", 0), ("session", True), ("session", 0x100000000),
    ("payload", bytearray()), ("payload", b"x" * 4097), ("payload", b"\x01\x00PRIVATE_SENTINEL")])
def test_hello_envelope_exact(inputs, name, value):
    admitted = A.validate_probe_admission(**inputs)
    bad = replace(frame(admitted), **{name: value})
    fails(lambda: A.verify_probe_hello(bad, nonce=b"n" * 16, admission=admitted), "espprobe_protocol")


@pytest.mark.parametrize("name,value,code", [("nonce", "00" * 16, "espprobe_protocol"),
    ("fw_version", "1.0.0", "firmware_not_pinned"), ("git_commit", "0" * 40, "firmware_not_pinned"),
    ("image_sha256", "0" * 64, "firmware_not_pinned"), ("app_elf_sha256", "0" * 64, "firmware_not_pinned"),
    ("fw_name", "PRIVATE_SENTINEL", "firmware_not_pinned"), ("board", "other", "firmware_not_pinned"),
    ("build_profile", "other", "firmware_not_pinned"), ("idf_version", "other", "firmware_not_pinned"),
    ("limits", dict(max_payload=4096, hb_ms=500, max_credit=0), "firmware_not_pinned")])
def test_hello_manifest_nonce_contract(inputs, name, value, code):
    admitted = A.validate_probe_admission(**inputs)
    fails(lambda: A.verify_probe_hello(frame(admitted, **{name: value}), nonce=b"n" * 16, admission=admitted), code)


def test_hello_identity_and_token_mismatch(inputs):
    admitted = A.validate_probe_admission(**inputs)
    fields = hello_fields(admitted)
    fields["base_mac"] = "001122334455"
    fields["usb"]["serial"] = "001122334455"
    bad = replace(frame(admitted), payload=P.encode_hello(fields))
    fails(lambda: A.verify_probe_hello(bad, nonce=b"n" * 16, admission=admitted), "instrument_identity_mismatch")
    fails(lambda: A.verify_probe_hello(replace(frame(admitted), session=8), nonce=b"n" * 16, admission=admitted), "espprobe_protocol")


@pytest.mark.parametrize("revision", [None, 2])
def test_hello_unknown_or_other_chip_revision(inputs, revision):
    admitted = A.validate_probe_admission(**inputs)
    bad = frame(admitted, chip=dict(model="esp32s3", revision=revision, psram_bytes=None, flash_voltage_mv=None))
    fails(lambda: A.verify_probe_hello(bad, nonce=b"n" * 16, admission=admitted), "instrument_identity_mismatch")


def test_hello_known_optional_fields_preserved(inputs):
    admitted = A.validate_probe_admission(**inputs)
    good = frame(admitted, chip=dict(model="esp32s3", revision=1, psram_bytes=8 << 20, flash_voltage_mv=3300))
    result = A.verify_probe_hello(good, nonce=b"n" * 16, admission=admitted)
    assert result.psram_bytes == 8 << 20 and result.flash_voltage_mv == 3300


def test_posix_route_rdev_must_match_tty_identity():
    data = make_inputs(backend="posix-tty")
    data["route"] = replace(data["route"], node_identity=(7, 101, os.makedev(166, 1)))
    fails(lambda: A.validate_probe_admission(**data), "route_changed")


def test_windows_instance_interface_must_match_claimed_metadata(inputs):
    obs = inputs["observation"]
    sibling = replace(obs.siblings[1], device_instance=obs.identity.device_instance)
    inputs["observation"] = replace(obs, siblings=(obs.identity, sibling))
    fails(lambda: A.validate_probe_admission(**inputs), "instrument_identity_mismatch")


@pytest.mark.parametrize("field,value", [("claim_keys", []), ("observation", {}), ("route", {}),
    ("chip_revision", True), ("release", {}), ("authority_sha256", "PRIVATE_SENTINEL")])
def test_admission_result_is_deeply_typed(inputs, field, value):
    admitted = A.validate_probe_admission(**inputs)
    fails(lambda: replace(admitted, **{field: value}))


@pytest.mark.parametrize("field,value", [("session_token", True), ("usb_session", 0), ("boot_id", bytearray(16)),
    ("psram_bytes", -1), ("flash_voltage_mv", 65536), ("hb_ms", 999), ("release", {}),
    ("reset_reason", "PRIVATE_SENTINEL")])
def test_hello_result_is_deeply_typed(inputs, field, value):
    admitted = A.validate_probe_admission(**inputs)
    hello = A.verify_probe_hello(frame(admitted), nonce=b"n" * 16, admission=admitted)
    fails(lambda: replace(hello, **{field: value}), "espprobe_protocol")


def _use_produced_identities(data, identities):
    """합성 관찰 producer가 새 신원을 seal한다. 운영 증명 생산자는 아니다."""
    obs = replace(data["observation"], identity=identities[0], siblings=tuple(identities))
    device_id, strength = identity_projection(identities[0])
    data["observation"] = obs
    data["route"] = replace(data["route"], identity=identities[0], device_id=device_id, identity_strength=strength)
    data["authority"] = replace(data["authority"], pin=replace(data["authority"].pin, observation_sha256=A._digest(obs)))
    return A.validate_probe_admission(**data)


def test_actual_windows_identity_parser_shape(inputs):
    from pweh.portidentity import parse_windows
    obs = inputs["observation"]
    raw = json.dumps([dict(port=i.endpoint_key, nodes=[
        dict(instance_id=i.device_instance, parent=obs.parent_instance, present=True),
        dict(instance_id=obs.parent_instance, parent=r"HTREE\ROOT\0", present=True)]) for i in obs.siblings]).encode()
    identities = [parse_windows(i.endpoint_key, raw) for i in obs.siblings]
    assert all(i.status == "known" and i.serial_basis == "instance-tail" for i in identities)
    assert _use_produced_identities(inputs, identities).claim_keys == obs.scope_keys


def test_actual_linux_identity_parser_with_synthetic_sysfs(tmp_path):
    from pweh.portidentity import linux_identity
    data = make_inputs(backend="posix-tty")
    obs = data["observation"]
    root = tmp_path / "sys"
    parent = root / obs.parent_instance
    parent.mkdir(parents=True)
    for name, value in (("idVendor", "303a"), ("idProduct", "4002"), ("serial", obs.parent_serial)):
        (parent / name).write_text(value)
    identities = []
    for minor, interface in ((0, "00"), (1, "02")):
        branch = parent / ("1-1:1.%d" % int(interface))
        tty = branch / ("ttyACM%d" % minor)
        tty.mkdir(parents=True)
        (branch / "bInterfaceNumber").write_text(interface)
        node = root / "dev" / "char" / ("166:%d" % minor)
        node.mkdir(parents=True)
        (node / "device").symlink_to(tty)
        def fake_stat(_path, n=minor):
            return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=os.makedev(166, n), st_ino=101+n)
        identities.append(linux_identity("/dev/ttyACM%d" % minor, sysfs_root=root, stat_port=fake_stat))
    assert all(i.status == "known" and i.serial_basis == "sysfs" for i in identities)
    assert _use_produced_identities(data, identities).claim_keys == obs.scope_keys
