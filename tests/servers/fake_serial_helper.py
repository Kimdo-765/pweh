"""Linux 전용 가짜 serial helper. COM·PnP·네트워크를 열지 않는다.

시험이 이 소스 앞에 FAKE_CONFIG 상수를 붙여 고정 basename에 복사한다. protocol
기대값을 운영 codec에서 import하지 않고 독립 struct 형식으로 구현한다. stdout은
프레임뿐이며, 합성 로그에는 token을 남기지 않는다. fault는 시험 상수로만 선택한다.
"""
import json
import os
import re
import select
import struct
import sys
import time

CONFIG = globals().get("FAKE_CONFIG", {})
MAX_PAYLOAD = 16384
SOURCE_COMMIT = CONFIG.get("source_commit", "1" * 40)
FAULT = CONFIG.get("fault", "")
APP = CONFIG.get("app", "uart")
EPOCH = 0
OPENED = False
LAST_ID = 0
PENDING_OPEN = None
INCOMING = bytearray()
LINE = bytearray()


def record(event, **fields):
    path = CONFIG.get("log")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "pid": os.getpid(), **fields}, sort_keys=True) + "\n")


def send(kind, payload):
    raw = kind.encode("ascii") + struct.pack("<H", len(payload)) + payload
    fragment = max(1, int(CONFIG.get("fragment", len(raw))))
    for offset in range(0, len(raw), fragment):
        part = raw[offset:offset + fragment]
        while part:
            part = part[os.write(1, part):]


def ack(request_id, kind, transferred=0):
    send("A", struct.pack("<IBBIIII", request_id, ord(kind), 0, 0, transferred, EPOCH, 0))


def error(request_id, kind, code=5, transferred=0):
    send("E", struct.pack("<IBBII", request_id, ord(kind) if kind else 0, code, 0, transferred))


def receive(data):
    if data:
        send("D", struct.pack("<I", EPOCH) + data)


def reply(data):
    """소비자 시험에 필요한 UART 셸/JTAG 메뉴만 합성한다."""
    if APP == "echo":
        return data
    if APP == "jtag":
        if b"\x18" in data:
            return b"\r\n\n> "
        if data.strip().upper() == b"I":
            return b"I\r\nJTAGulator FW 1.12\r\n\n> "
        return data + b"\r\n\n> "
    if b"\x03" in data:
        LINE.clear()
        return b"\r\n# "
    LINE.extend(data)
    if b"\r" in data or b"\n" in data:
        line = bytes(LINE).strip()
        LINE.clear()
        return line + b"\r\nsynthetic response\r\n# "
    return b""


def open_result(request_id, busy=False):
    global OPENED, EPOCH
    if busy:
        send("o", struct.pack("<IBIBI", request_id, 1, 5, 0, 0))
        return
    OPENED, EPOCH = True, 1
    send("o", struct.pack("<IBIBI", request_id, 0, 0, 0, EPOCH))
    if CONFIG.get("banner"):
        receive(CONFIG["banner"].encode("ascii"))


def dispatch(kind, payload):
    global OPENED, EPOCH, LAST_ID, PENDING_OPEN
    if len(payload) < 4:
        error(0, kind)
        return False
    request_id = struct.unpack_from("<I", payload)[0]
    if request_id == 0 or request_id <= LAST_ID:
        error(request_id, kind)
        return False
    LAST_ID = request_id
    record("frame", kind=kind, payload=payload.hex())
    lengths = {"O": 14, "B": 12, "L": 6, "K": 9, "P": 9, "S": 4, "Q": 4}
    if kind not in lengths and kind != "D":
        error(request_id, kind)
        return False
    if kind in lengths and len(payload) != lengths[kind] or kind == "D" and not 9 <= len(payload) <= MAX_PAYLOAD:
        error(request_id, kind)
        return False
    if kind == "Q":
        if FAULT == "ignore-quit":
            return True
        if PENDING_OPEN is not None:
            pending_id, _ = PENDING_OPEN
            send("o", struct.pack("<IBIBI", pending_id, 8, 0, 0, 0))
            PENDING_OPEN = None
        OPENED = False
        if FAULT != "drop-quit-ack":
            ack(request_id, kind)
        record("closed")
        return False
    if PENDING_OPEN is not None:
        error(request_id, kind)
        return False
    if kind == "O":
        baud, bits, parity, stop, dtr, rts, reserved = struct.unpack_from("<IBBBBBB", payload, 4)
        if OPENED or not 50 <= baud <= 20_000_000 or bits not in range(5, 9) or parity > 4 or stop > 2 or dtr > 1 or rts > 1 or reserved:
            error(request_id, kind)
            return False
        record("open", baud=baud, bits=bits, parity=parity, stop=stop, dtr=dtr, rts=rts)
        if FAULT == "open-busy":
            open_result(request_id, busy=True)
        elif CONFIG.get("open_release"):
            PENDING_OPEN = (request_id, CONFIG["open_release"])
        else:
            open_result(request_id)
        return True
    if not OPENED:
        error(request_id, kind)
        return False
    if kind == "B":
        baud, bits, parity, stop, reserved = struct.unpack_from("<IBBBB", payload, 4)
        if not 50 <= baud <= 20_000_000 or bits not in range(5, 9) or parity > 4 or stop > 2 or reserved:
            error(request_id, kind)
            return False
        record("baud", baud=baud)
        ack(request_id, kind)
    elif kind == "L":
        dtr, rts = payload[4:]
        if dtr not in (0, 1, 255) or rts not in (0, 1, 255) or dtr == rts == 255:
            error(request_id, kind)
            return False
        record("signals", dtr=dtr, rts=rts)
        ack(request_id, kind)
    elif kind == "K":
        mode, duration = struct.unpack_from("<BI", payload, 4)
        if mode > 2 or (mode < 2 and duration) or (mode == 2 and not 1 <= duration <= 5000):
            error(request_id, kind)
            return False
        ack(request_id, kind)
    elif kind == "P":
        mode, deadline = struct.unpack_from("<BI", payload, 4)
        if mode > 2 or not 1 <= deadline <= 5000:
            error(request_id, kind)
            return False
        if mode == 0:
            EPOCH += 1
        ack(request_id, kind)
        if mode == 0 and CONFIG.get("baud_text"):
            receive(b"U-Boot synthetic\r\nHit any key to stop autoboot: 3\r\n")
    elif kind == "S":
        send("s", struct.pack("<IBIBIII", request_id, 0, 0, 0, 0, 0, 0))
    elif kind == "D":
        timeout = struct.unpack_from("<I", payload, 4)[0]
        if not 1 <= timeout <= 30000:
            error(request_id, kind)
            return False
        data = payload[8:]
        record("write", data=data.hex())
        if FAULT == "disconnect-on-write" or (CONFIG.get("disconnect_file") and os.path.isfile(CONFIG["disconnect_file"])):
            error(request_id, kind, 3)
            record("removed")
            return False
        receive(reply(data))
        ack(request_id, kind, len(data))
    return True


def main():
    global PENDING_OPEN, APP
    args = sys.argv[1:]
    if len(args) != 4 and len(args) != 3:
        return 2
    if args[:1] in (["--version"], ["--echo"]):
        if len(args) != 3 or args[1] != "--token":
            return 2
        mode, token, port = (2 if args[0] == "--version" else 1), args[2], None
    elif len(args) == 4 and args[0] == "--port" and args[2] == "--token":
        port, token, mode = args[1], args[3], 0
        if not re.fullmatch(r"COM[1-9][0-9]{0,3}", port) or int(port[3:]) > 4096:
            return 2
    else:
        return 2
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return 2
    if mode == 1:
        APP = "echo"
    record("start", mode=mode, port=port)
    hello = struct.pack("<HHBBBB20sHH", 1, 0, 0, 1, 0, mode, bytes.fromhex(SOURCE_COMMIT), MAX_PAYLOAD, 0)
    send("H", hello)
    if mode == 2:
        return 0
    while True:
        if PENDING_OPEN is not None:
            request_id, release = PENDING_OPEN
            if os.path.isfile(release):
                PENDING_OPEN = None
                open_result(request_id)
        ready, _, _ = select.select([0], [], [], 0.01)
        if not ready:
            continue
        data = os.read(0, 65536)
        if not data:
            record("eof")
            return 0
        INCOMING.extend(data)
        while len(INCOMING) >= 3:
            length = struct.unpack_from("<H", INCOMING, 1)[0]
            if length > MAX_PAYLOAD:
                return 3
            if len(INCOMING) < length + 3:
                break
            kind = chr(INCOMING[0])
            payload = bytes(INCOMING[3:3 + length])
            del INCOMING[:3 + length]
            if not dispatch(kind, payload):
                return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        raise SystemExit(4)
