"""simulator 독립 opcode 정책과 세션 종료 조건을 합성 wire로 검사한다."""
from __future__ import annotations
import struct
import pytest
from espprobe_mcp.sim import ProbeSimulator
from pweh.espprobe_protocol import Frame, ProtocolError, decode, decode_hello, decode_tlvs, encode, encode_hello, encode_tlvs

def wire(op=1,seq=1,session=0,payload=None,typ=1,credit=0):
    return encode(Frame(type=typ,op=op,seq=seq,session=session,credit=credit,
                        payload=encode_tlvs({1:bytes(range(16))}) if payload is None and op==1 else (payload or b"")))

def status(response):
    return struct.unpack_from("<H",decode(response).payload)[0]

def test_hello_typed_profile_and_roundtrip():
    sim=ProbeSimulator()
    response=decode(sim.exchange(wire()))
    fields=decode_hello(response.payload)
    assert fields["fw_name"]=="PWEH espprobe" and fields["fw_version"]=="0.1.0"
    assert fields["build_profile"]=="probe-hello" and fields["board"]=="esp32s3-devkitc1-hello"
    assert fields["image_sha256"]=="11"*32 and fields["app_elf_sha256"]=="22"*32
    assert fields["chip"]==dict(model="esp32s3",revision=0,psram_bytes=None,flash_voltage_mv=None)
    assert fields["caps"]==fields["tx_caps"]==fields["spi_read_opcodes"]==[]
    assert fields["pins_allowed"]==dict(H0=[],H1=[],H1a=[])
    assert fields["session_token"]==response.session==1
    assert encode_hello(fields)==response.payload
    fields["chip"]["revision"]=False
    with pytest.raises(ProtocolError):encode_hello(fields)

def test_hello_tlv_unknown_optional_critical_and_lengths():
    payload=decode(ProbeSimulator().exchange(wire())).payload
    values=decode_tlvs(payload[2:])
    with_optional=dict(values);with_optional[28]=b"unknown"
    assert decode_hello(b"\0\0"+encode_tlvs(with_optional))==decode_hello(payload)
    for tag,value in ((0x8001,b""),(19,b"\1\0\0\0"),(21,b"\1"+bytes(23)),(22,b"\0"),(27,bytes(4)),(18,b"\xff\xff"),(10,b"\1"+bytes(8)+b"\0")):
        changed=dict(values);changed[tag]=value
        with pytest.raises(ProtocolError):decode_hello(b"\0\0"+encode_tlvs(changed))
    for tag in range(1,28):
        changed=dict(values);del changed[tag]
        with pytest.raises(ProtocolError):decode_hello(b"\0\0"+encode_tlvs(changed))

def test_hb_exact_ack_duplicate_no_renew_and_exact_deadline():
    sim=ProbeSimulator();first=sim.exchange(wire());sim.advance(500)
    assert sim.exchange(wire())==first and sim.snapshot()["deadline_ms"]==1000
    hb=wire(op=0,typ=5,session=1)
    assert sim.exchange(hb)==hb
    sim.advance(999)
    assert sim.exchange(hb)==b"" and sim.snapshot()["deadline_ms"]==1500
    sim.advance(1)
    assert sim.snapshot()["last_release_reason"]=="heartbeat-timeout"
    assert status(sim.exchange(hb))==3 and status(sim.exchange(wire()))==3
    assert decode(sim.exchange(wire(seq=2))).session==2

def test_all_unknown_opcodes_no_hal_and_no_auto_resume():
    sim=ProbeSimulator();sim.exchange(wire())
    for op in range(5,256):
        assert status(sim.exchange(wire(op=op,seq=op,session=1)))==2
    assert sim.snapshot()["counters"]["hal_bus_calls"]==0
    assert sim.snapshot()["counters"]["requests_executed"]==1
    sim.transport_event("usb-suspend")
    assert status(sim.exchange(wire(op=5,seq=300,session=1)))==3
    assert sim.snapshot()["counters"]["hal_bus_calls"]==0

@pytest.mark.parametrize("op,reason",[(2,"request-release"),(3,"bye"),(4,"abort")])
def test_terminal_retry_and_close_idempotence(op,reason):
    sim=ProbeSimulator();sim.exchange(wire())
    cleanup=wire(op=op,seq=2,session=1)
    result=sim.exchange(cleanup)
    assert result==sim.exchange(cleanup) and decode(result).payload==b"\0\0"
    assert decode(result).session==1
    sim.close();sim.close()
    assert sim.snapshot()["last_release_reason"]==reason and sim.snapshot()["counters"]["release_count"]==1
    assert sim.exchange(wire(seq=3))==b""

@pytest.mark.parametrize("event",["usb-reset","usb-detach","usb-suspend","dtr-fall","transport-error","internal-error"])
def test_transport_release_once_and_new_generation(event):
    sim=ProbeSimulator();sim.exchange(wire());sim.transport_event(event);sim.transport_event(event)
    state=sim.snapshot()
    assert state["session"]==0 and state["counters"]["release_count"]==1 and state["last_release_reason"]==event
    assert status(sim.exchange(wire(op=0,typ=5,session=1)))==3
    if event in ("usb-reset","usb-detach"):
        assert state["usb_session"]==3
        assert decode(sim.exchange(wire())).session==2
    else:assert status(sim.exchange(wire()))==3

def test_cache_highwater_credit_mismatch_and_clock_error():
    sim=ProbeSimulator();sim.exchange(wire())
    assert status(sim.exchange(wire(seq=2)))==6
    assert status(sim.exchange(wire(payload=encode_tlvs({1:bytes(16)}))))==5
    assert status(sim.exchange(wire(op=5,seq=2,session=99)))==4
    assert status(sim.exchange(wire(op=5,seq=2,session=1,credit=1)))==1
    for seq in range(2,8):assert status(sim.exchange(wire(op=5,seq=seq,session=1)))==2
    assert status(sim.exchange(wire(op=5,seq=7,session=1)))==2
    assert status(sim.exchange(wire(op=6,seq=7,session=1)))==5
    assert status(sim.exchange(wire(op=5,seq=2,session=1)))==8
    with pytest.raises(ValueError):sim.advance(-1)
    assert sim.snapshot()["last_release_reason"]=="clock-error" and sim.snapshot()["closed"]
    assert sim.exchange(wire(seq=8))==b""

def test_sim_name_is_not_transport_and_bounds():
    for name in ("COM3","/dev/ttyUSB0","sim://other","tcp://127.0.0.1:5555"):
        with pytest.raises(ValueError):ProbeSimulator(name)
    sim=ProbeSimulator()
    for value in (b"",b"\0",b"a"*5000):assert sim.exchange(value)==b""
    assert sim.snapshot()["counters"]["invalid_frames"]==3
    sim._token=0xffffffff
    assert status(sim.exchange(wire()))==3 and sim.session==0
