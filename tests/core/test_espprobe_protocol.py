"""합성 wire/golden/C host HAL 계약. 실제 포트·펌웨어 실행은 없다."""
from __future__ import annotations

import os
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from pweh.espprobe_protocol import Frame, ProtocolError, StreamDecoder, decode, decode_hello, decode_tlvs, encode, encode_tlvs

ROOT=Path(__file__).resolve().parents[2]
HELLO=bytes.fromhex("040101010201010101010101021401010201021001140102030405060708090a0b0c0d0e0ff50adc9a00")
HB=bytes.fromhex("0301050102010101020101010101010105be285b2600")
RELEASE=bytes.fromhex("0401010202020101020101010101010105805bd73a00")
RELEASE_ACK=bytes.fromhex("0401020202020101020101010202010101010590c2b19800")

@pytest.mark.parametrize("wire,frame",[
    (HELLO,Frame(type=1,op=1,seq=1,session=0,payload=b"\1\0\20\0"+bytes(range(16)))),
    (HB,Frame(type=5,op=0,seq=1,session=1)),
    (RELEASE,Frame(type=1,op=2,seq=2,session=1)),
    (RELEASE_ACK,Frame(type=2,op=2,seq=2,session=1,payload=b"\0\0")),
])
def test_fixed_wire(wire,frame):
    assert encode(frame)==wire
    assert decode(wire)==frame

@pytest.mark.parametrize("length",[0,1,253,254,255,4095,4096])
def test_maximum_and_zero_cobs(length):
    for value in (0,1,255):
        frame=Frame(type=1,op=255,seq=0xffffffff,session=0xffffffff,payload=bytes([value])*length)
        assert decode(encode(frame))==frame
        assert len(encode(frame))<=4134

def test_bounds_crc_and_stream_resync():
    for wire in (HELLO[:-1],HELLO+HB,b"\0",b"\1"*4134+b"\0",HELLO[:-2]+b"\1\0"):
        with pytest.raises(ProtocolError):decode(wire)
    stream=StreamDecoder()
    assert stream.feed(b"\1"*5000+b"\0"+HELLO[:8])==[]
    assert len(stream.buffer)==8 and stream.errors==1
    assert stream.feed(HELLO[8:]+HB)==[decode(HELLO),decode(HB)]
    with pytest.raises(ProtocolError):stream.feed(b"a"*16385)
    for values in ({1:b"x"*4093},{0:b""},{1:bytearray()}):
        with pytest.raises(ProtocolError):encode_tlvs(values)
    for payload in (b"\1",b"\1\0\1\0",b"\1\0\0\0"*2,b"\2\0\0\0\1\0\0\0"):
        with pytest.raises(ProtocolError):decode_tlvs(payload)

@pytest.fixture(scope="module")
def c_host(tmp_path_factory):
    zig=os.environ.get("PWEH_ZIG") or shutil.which("zig")
    if not zig:
        managed=Path.home()/"pweh-tools/zig/zig-x86_64-linux-0.17.0/zig"
        if managed.is_file():zig=str(managed)
    if not zig:pytest.skip("host C 시험용 Zig 없음")
    target=tmp_path_factory.mktemp("espprobe-host")/"host"
    command=[zig,"cc","-std=c11","-Wall","-Wextra","-Werror","-O1","-I"+str(ROOT/"firmware/common/include"),
        *map(str,sorted((ROOT/"firmware/common").glob("*.c"))),str(ROOT/"tests/fixtures/espprobe_host.c"),"-o",str(target)]
    subprocess.run(command,check=True,capture_output=True,timeout=90)
    return target

def run_c(exe,mode,lines):
    result=subprocess.run([str(exe),mode],input="\n".join(lines)+"\n",text=True,capture_output=True,timeout=10,check=True)
    return result.stdout.splitlines()

@pytest.mark.external
def test_c_fixed_and_fuzz_codec(c_host):
    rng=random.Random(321)
    valid=[HELLO,HB,RELEASE,RELEASE_ACK]
    valid += [encode(Frame(type=1,op=rng.randrange(256),seq=i+1,session=1,payload=rng.randbytes(rng.randrange(4097)))) for i in range(150)]
    invalid=[rng.randbytes(rng.randrange(1,4200))+b"\0" for _ in range(200)]
    corrupted=[]
    for wire in valid[:40]:
        for index in (0,len(wire)//2,len(wire)-2):
            changed=bytearray(wire);changed[index]^=1;corrupted.append(bytes(changed))
    wires=valid+invalid+corrupted
    expected=[]
    for wire in wires:
        try:decode(wire);expected.append(wire.hex())
        except ProtocolError:expected.append("ERR")
    assert run_c(c_host,"codec",[w.hex() for w in wires])==expected

@pytest.mark.external
def test_c_session_golden_timeout_and_replay(c_host):
    lines=["W 0 "+HELLO.hex(),"W 500 "+HELLO.hex(),"W 500 "+HB.hex(),"W 1499 "+HB.hex(),"P 1500","S 0","W 1500 "+HELLO.hex()]
    result=run_c(c_host,"session",lines)
    assert result[0]==result[1] and result[2]==HB.hex() and result[3]==""
    hello=decode_hello(decode(bytes.fromhex(result[0])).payload)
    assert hello["nonce"]==bytes(range(16)).hex() and hello["caps"]==[]
    assert hello["pins_allowed"]=={"H0":[],"H1":[],"H1a":[]}
    assert result[5].split()==["0","1","1","1","0","5","1","1","1"]
    assert decode(bytes.fromhex(result[6])).payload==b"\3\0"
    result=run_c(c_host,"session",["W 0 "+HELLO.hex(),"W 1 "+RELEASE.hex(),"W 2 "+RELEASE.hex(),"S 0"])
    assert result[1]==result[2]==RELEASE_ACK.hex()
    assert result[3].split()[5:]==["2","1","2","0"]

@pytest.mark.external
def test_c_unsupported_cache_reset_clock_and_transport(c_host):
    req=lambda seq,op=50:encode(Frame(type=1,op=op,seq=seq,session=1)).hex()
    result=run_c(c_host,"session",["W 0 "+HELLO.hex(),*["W 1 "+req(i) for i in range(2,8)],
        "W 2 "+req(7),"W 2 "+req(7,51),"W 2 "+req(2),"E 6","S 0","W 3 "+HB.hex(),"W 3 "+HELLO.hex(),"S 0"])
    assert decode(bytes.fromhex(result[7])).payload==b"\2\0"
    assert decode(bytes.fromhex(result[8])).payload==b"\5\0"
    assert decode(bytes.fromhex(result[9])).payload==b"\10\0"
    assert result[11].split()[0:2]==["0","2"]
    assert decode(bytes.fromhex(result[12])).payload==b"\3\0"
    assert decode(bytes.fromhex(result[13])).session==2
    result=run_c(c_host,"session",["W 0 "+HELLO.hex(),"P 100","P 99","S 0"])
    assert result[3].split()[5:7]==["13","1"]
    result=run_c(c_host,"session",["F 0","W 0 "+HELLO.hex(),"S 0"])
    assert result[2].split()[0]=="0" and result[2].split()[5:7]==["10","1"]

@pytest.mark.external
def test_c_model_differential_session_and_fragment_recovery(c_host):
    from espprobe_mcp.sim import ProbeSimulator
    sim=ProbeSimulator();sim.boot_id="00"*16
    requests=[HELLO,HELLO,HB]
    requests += [encode(Frame(type=1,op=op,seq=op+1,session=1)) for op in range(5,256)]
    requests += [requests[-1],encode(Frame(type=1,op=2,seq=300,session=1)),HB,HELLO,
                 encode(Frame(type=1,op=1,seq=301,session=0,payload=encode_tlvs({1:bytes(16)})))]
    expected=[sim.exchange(request).hex() for request in requests]
    assert run_c(c_host,"session",["W 0 "+r.hex() for r in requests])==expected
    # 잘못된 긴 stream은 delimiter에서 복구하고 다음 완전 HELLO만 처리한다.
    result=run_c(c_host,"session",["W 0 "+(b"x"*5000+b"\0"+HELLO[:7]).hex(),"W 0 "+HELLO[7:].hex()])
    assert result[0]=="" and decode(bytes.fromhex(result[1])).session==1
