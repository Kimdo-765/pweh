"""공통 HELLO·합성 HAL로만 검사하는 제한된 SPI/I²C C 계층."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import random
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "firmware/common/cobs.c", "firmware/common/crc32.c", "firmware/common/protocol.c",
    "firmware/common/tlv.c", "firmware/common/session.c", "firmware/espprobe/bus/probe_bus.c",
    "firmware/espprobe/bus/probe_spi.c", "firmware/espprobe/bus/probe_sfdp.c",
    "firmware/espprobe/bus/probe_i2c.c",
)
OK, POLICY, UNSUPPORTED, RELEASED, SESSION, SEQUENCE, BUSY, INVALID, REPLAY, NO_CREDIT, DONE, INTERNAL = range(12)
STATE_RELEASED, BOUND, READY, RUNNING, COMPLETE = range(5)
CLAIM, CS_ON, CS_OFF, SPI_BYTE, START, RESTART, WRITE, READ_ACK, READ_NACK, STOP, DELIVER, ABORT = range(1, 13)


@pytest.fixture(scope="module")
def bus_host(tmp_path_factory):
    zig = os.environ.get("PWEH_ZIG") or shutil.which("zig")
    if not zig:
        candidate = Path.home() / "pweh-tools/zig/zig-x86_64-linux-0.17.0/zig"
        if candidate.is_file():
            zig = str(candidate)
    if not zig:
        pytest.skip("host C 시험용 기존 Zig 없음")
    target = tmp_path_factory.mktemp("espprobe-bus-host") / "host"
    command = [zig, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
               "-I" + str(ROOT / "firmware/common/include"),
               "-I" + str(ROOT / "firmware/espprobe/bus"),
               *(str(ROOT / name) for name in SOURCES),
               str(ROOT / "tests/fixtures/espprobe_bus_host.c"), "-o", str(target)]
    subprocess.run(command, check=True, capture_output=True, timeout=90)
    return target


def run_host(exe, mode, *args):
    result = subprocess.run([str(exe), mode, *map(str, args)],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, (mode, args, result.returncode, result.stderr.decode("ascii"))
    assert not result.stderr
    assert len(result.stdout) <= 64 * 1024
    return json.loads(result.stdout)


def assert_released(result, *, delivered=0, mask=15):
    assert result["result"] != OK
    assert result["state"] == STATE_RELEASED
    assert result["aborts"] == 1
    assert result["mask"] == mask
    assert result["credit"] == 0 and result["out_zero"]
    assert result["deliveries"] == delivered
    assert result["trace"][-1][0] == ABORT


def test_build_is_explicit_and_production_hello_has_no_bus_link():
    assert len(SOURCES) == len(set(SOURCES)) == 9
    for name in SOURCES:
        assert (ROOT / name).is_file()
    for name in ("firmware/espprobe/CMakeLists.txt", "firmware/espprobe/main/CMakeLists.txt"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "probe_bus" not in text and "probe_spi" not in text and "probe_i2c" not in text
        assert "GLOB" not in text
    ast.parse(Path(__file__).read_text(encoding="utf-8"), feature_version=(3, 10))


@pytest.mark.external
def test_actual_common_hello_is_binding_source_and_keeps_old_wire_policy(bus_host):
    result = run_host(bus_host, "hello")
    assert result["result"] == OK and result["state"] == BOUND
    assert result["phases"] == result["claims"] == result["deliveries"] == 0


@pytest.mark.external
@pytest.mark.parametrize("missing", range(11))
def test_every_hal_callback_is_mandatory(bus_host, missing):
    result = run_host(bus_host, "init", missing)
    assert result["result"] == INVALID and result["phases"] == 0


@pytest.mark.external
@pytest.mark.parametrize("kind,mutation", [(kind, mutation) for kind in (0, 1)
                                          for mutation in range(20 if kind else 14)])
def test_wiring_and_live_voltage_checked_before_claim(bus_host, kind, mutation):
    result = run_host(bus_host, "claim", kind, mutation)
    assert result["result"] != OK
    if mutation == 13:
        assert result["claims"] == 1 and result["aborts"] == 1
        assert result["mask"] == (3 if kind else 15)
    else:
        assert result["claims"] == 0
    assert not any(code in (CS_ON, SPI_BYTE, START, WRITE) for code, _ in result["trace"])


@pytest.mark.external
@pytest.mark.parametrize("opcode", range(256))
def test_all_spi_opcodes_at_lowest_transmit_boundary(bus_host, opcode):
    result = run_host(bus_host, "spi", opcode, 1 if opcode in (3, 0x0B) else 0)
    # 5A는 실제 SFDP parser 안에서만 허용하며 아래 직접 호출은 거부한다.
    allowed = {0x03, 0x0B, 0x9F, 0x90, 0xAB, 0x05, 0x13, 0x0C}
    if opcode not in allowed:
        assert result["result"] != OK and result["phases"] == 0
        return
    assert result["result"] == OK and result["aborts"] == 0
    trace = result["trace"]
    assert trace[0] == [CS_ON, 0] and trace[-1] == [CS_OFF, 0]
    tx = [value for code, value in trace if code == SPI_BYTE]
    address = [0x12, 0x34, 0x56] if opcode in (3, 0x0B) else [1, 0, 0, 0] if opcode in (0x13, 0x0C) else []
    if opcode in (0x90, 0x5A):
        address = [0, 0, 0]
    dummy = [0] * (3 if opcode == 0xAB else 1 if opcode in (0x0B, 0x0C, 0x5A) else 0)
    read_length = 3 if opcode == 0x9F else 2 if opcode == 0x90 else 1
    assert tx == [opcode] + address + dummy + [0] * read_length


@pytest.mark.external
@pytest.mark.parametrize("opcode", [3, 0x0B, 0x9F, 0x90, 0xAB, 0x5A, 5, 0x13, 0x0C])
@pytest.mark.parametrize("mutation", [1, 2, 3])
def test_spi_zero_oversize_and_address_overflow_before_cs(bus_host, opcode, mutation):
    result = run_host(bus_host, "spi", opcode, 0, mutation)
    assert result["result"] != OK and result["phases"] == 0


@pytest.mark.external
@pytest.mark.parametrize("opcode", [3, 0x0B])
def test_spi_24bit_window_must_not_wrap(bus_host, opcode):
    result = run_host(bus_host, "spi", opcode, 6, 4)
    assert result["result"] != OK and result["phases"] == 0
    last = run_host(bus_host, "spi", opcode, 6, 5)
    assert last["result"] == OK
    tx = [value for code, value in last["trace"] if code == SPI_BYTE]
    assert tx == [opcode, 255, 255, 255] + ([0] if opcode == 0x0B else []) + [0]


@pytest.mark.external
@pytest.mark.parametrize("mutation", range(10))
def test_internal_descriptor_mismatch_has_no_transmit_side_effect(bus_host, mutation):
    result = run_host(bus_host, "descriptor", mutation)
    assert result["result"] == (INTERNAL if mutation < 3 else POLICY if mutation == 6 else
                                UNSUPPORTED if mutation == 7 else INVALID)
    assert result["phases"] == result["aborts"] == 0


@pytest.mark.external
@pytest.mark.parametrize("variant,capacity,read4,fast4", [
    (0, 32 << 20, True, True), (1, 8 << 20, False, False),
    (2, 32 << 20, False, False), (3, 32 << 20, True, False),
    (4, 32 << 20, False, True), (5, 1 << 32, True, True),
])
def test_sfdp_facts_come_from_actual_spi_reads(bus_host, variant, capacity, read4, fast4):
    result = run_host(bus_host, "sfdp", variant)
    assert result["result"] == OK and result["valid"]
    assert (result["capacity"], result["read4"], result["fast4"]) == (capacity, read4, fast4)
    assert 44 <= result["bytes"] <= 4096 and 3 <= result["transactions"] <= 20


@pytest.mark.external
@pytest.mark.parametrize("variant", range(10, 27))
def test_sfdp_malformed_versions_tables_density_and_bounds_grant_no_permission(bus_host, variant):
    result = run_host(bus_host, "sfdp", variant)
    assert result["result"] == UNSUPPORTED and not result["valid"]
    assert not result["read4"] and not result["fast4"]
    assert result["bytes"] <= 4096


@pytest.mark.external
def test_fixed_seed_sfdp_mutations_stay_within_structure_and_output_limits(bus_host):
    rng = random.Random(7631)
    for _ in range(64):
        result = run_host(bus_host, "sfdp", 0, rng.randrange(1, 137), rng.randrange(1, 256))
        assert result["result"] in (OK, UNSUPPORTED)
        assert result["bytes"] <= 4096 and result["transactions"] <= 20
        if result["valid"]:
            assert result["result"] == OK and 0 < result["capacity"] <= 2**32
            if result["read4"] or result["fast4"]:
                assert result["capacity"] > 2**24
        else:
            assert not result["read4"] and not result["fast4"]


@pytest.mark.external
@pytest.mark.parametrize("opcode,variant,allowed", [
    (0x13, 1, False), (0x0C, 1, False), (0x13, 2, False), (0x0C, 2, False),
    (0x13, 3, True), (0x0C, 3, False), (0x13, 4, False), (0x0C, 4, True),
])
def test_each_4byte_opcode_requires_its_direct_sfdp_fact(bus_host, opcode, variant, allowed):
    result = run_host(bus_host, "spi", opcode, variant)
    assert (result["result"] == OK) == allowed
    if not allowed:
        assert result["phases"] == 0


@pytest.mark.external
@pytest.mark.parametrize("kind,width", [(0, 0), (1, 1), (1, 2)])
def test_two_passes_repeat_exact_ranges_without_extra_reads(bus_host, kind, width):
    result = run_host(bus_host, "read", kind, width)
    start = (17 if width == 1 else 0x1234) if kind else 0x1000000
    chunk = 32 if kind else 256
    assert result["result"] == OK and result["state"] == COMPLETE
    assert result["chunks"] == [[0, start, chunk, False], [0, start + chunk, 1, False],
                                 [1, start, chunk, False], [1, start + chunk, 1, True]]
    assert result["deliveries"] == 4 and result["credit"] == 0 and result["out_zero"]
    assert result["aborts"] == 0


@pytest.mark.external
@pytest.mark.parametrize("width,offset", [(1, 0x12), (2, 0x1234)])
def test_i2c_exact_address_repeat_start_final_nack_and_stop(bus_host, width, offset):
    result = run_host(bus_host, "read", 1, width, 1, 3, offset)
    address = list(offset.to_bytes(width, "big"))
    assert result["trace"] == [[START, 0], [WRITE, 0xA0], *[[WRITE, v] for v in address],
                               [RESTART, 0], [WRITE, 0xA1], [READ_ACK, 0], [READ_ACK, 0],
                               [READ_NACK, 0], [STOP, 0], [DELIVER, 3]]


@pytest.mark.external
def test_spi_4gib_last_byte_uses_u64_end_and_exact_4byte_address(bus_host):
    result = run_host(bus_host, "read", 0, 0, 1, 1, 0xFFFFFFFF, 5)
    assert result["chunks"] == [[0, 0xFFFFFFFF, 1, True]]
    assert result["trace"] == [[CS_ON, 0], *[[SPI_BYTE, v] for v in [0x13, 255, 255, 255, 255, 0]],
                               [CS_OFF, 0], [DELIVER, 1]]


@pytest.mark.external
@pytest.mark.parametrize("kind,mutation", [(kind, n) for kind in (0, 1) for n in range(8)])
def test_plan_bounds_are_fixed_before_bus_read(bus_host, kind, mutation):
    result = run_host(bus_host, "range", kind, mutation)
    assert result["result"] != OK and result["phases"] == 0


@pytest.mark.external
@pytest.mark.parametrize("kind", [0, 1])
@pytest.mark.parametrize("fault", [1, 2, 3, 4, 5, 6, 7, 8, 11])
def test_failure_after_every_bus_phase_stops_without_cleanup_transmission(bus_host, kind, fault):
    baseline = run_host(bus_host, "fault", kind, 0, 0)
    assert baseline["result"] == OK
    for position in range(1, baseline["phases"] + 1):
        result = run_host(bus_host, "fault", kind, position, fault)
        delivered = int(baseline["trace"][position - 1][0] == DELIVER)
        assert_released(result, delivered=delivered, mask=3 if kind else 15)
        assert result["phases"] == position
        assert result["trace"][:-1] == baseline["trace"][:position]


@pytest.mark.external
@pytest.mark.parametrize("kind", [0, 1])
def test_every_callback_rejects_nested_operations_without_duplicate_io(bus_host, kind):
    baseline = run_host(bus_host, "fault", kind, 0, 0)
    for position in range(1, baseline["phases"] + 1):
        result = run_host(bus_host, "fault", kind, position, 9)
        assert result["result"] == OK and result["nested"] == 3
        assert result["trace"] == baseline["trace"] and result["aborts"] == 0


@pytest.mark.external
@pytest.mark.parametrize("kind", [0, 1])
@pytest.mark.parametrize("chunk", [1, 3, 4])
@pytest.mark.parametrize("failure", [1, 2, 3, 8])
def test_delivery_failure_on_last_and_second_pass_is_not_replayed(bus_host, kind, chunk, failure):
    result = run_host(bus_host, "delivery", kind, chunk, failure)
    assert_released(result, delivered=chunk, mask=3 if kind else 15)
    assert result["chunks"][-1][0] == (1 if chunk >= 3 else 0)
    # true 후 사건에서는 수신한 청크가 있어도 최종 out은 무효이다.
    assert result["trace"][-2][0] == DELIVER and result["out_zero"]


@pytest.mark.external
def test_every_i2c_address_nack_aborts_without_stop(bus_host):
    baseline = run_host(bus_host, "fault", 1, 0, 0)
    for position, (code, _) in enumerate(baseline["trace"], 1):
        if code == WRITE:
            result = run_host(bus_host, "fault", 1, position, 10)
            assert_released(result, mask=3)
            assert result["phases"] == position
            assert all(code != STOP for code, _ in result["trace"])


@pytest.mark.external
@pytest.mark.parametrize("clock_or_vref", [0, 1])
@pytest.mark.parametrize("effect", [1, 2, 7, 8])
def test_each_guard_observation_handles_callback_failure_and_release(bus_host, clock_or_vref, effect):
    baseline = run_host(bus_host, "observe", 0, 0, 0, clock_or_vref)
    count = baseline["vrefs" if clock_or_vref else "clocks"]
    for position in range(1, count + 1):
        result = run_host(bus_host, "observe", 0, position, effect, clock_or_vref)
        assert_released(result, delivered=result["deliveries"])
        assert result["deliveries"] <= 1


@pytest.mark.external
@pytest.mark.parametrize("scenario", range(9))
def test_credit_sequence_release_and_binding_invariants(bus_host, scenario):
    run_host(bus_host, "lifecycle", scenario)


@pytest.mark.external
@pytest.mark.parametrize("mutation", range(9))
def test_invalid_binding_cannot_reuse_or_expand_hello_generation(bus_host, mutation):
    result = run_host(bus_host, "binding", mutation)
    assert result["result"] in (INVALID, SESSION)
    assert result["state"] == STATE_RELEASED and result["phases"] == 0


@pytest.mark.external
@pytest.mark.parametrize("kind", [0, 1])
@pytest.mark.parametrize("failure", [2, 3, 4, 5, 6, 7, 8, 11])
def test_no_credit_waiting_poll_still_releases_on_liveness_or_voltage_loss(bus_host, kind, failure):
    result = run_host(bus_host, "poll", kind, failure)
    assert_released(result, mask=3 if kind else 15)
    assert result["phases"] == 0


@pytest.mark.external
def test_shared_probe_cache_eviction_never_reexecutes_old_request(bus_host):
    result = run_host(bus_host, "cache")
    assert result["phases"] == 0 and result["aborts"] == 0
