/* Windows COM 전용 중계기. stdout은 프레임 전용이며 모든 버퍼는 고정 상한이다. */
#include <stdint.h>
#include <stddef.h>

#define MAX_PAYLOAD 16384u
#define MAX_FRAME (MAX_PAYLOAD + 3u)
#define OUT_SLOTS 16u
#define OUT_BYTES (256u * 1024u)
#define FRAME_MS 5000u
#define CLEANUP_MS 2000u
#define ERR_IO 4u
#define ERR_FRAME 5u
#define ERR_TIMEOUT 7u
#define ERR_CANCELLED 8u
#define ERR_OVERFLOW 9u

/* CRT를 링크하지 않는다. 컴파일러가 만드는 고정 메모리 복사도 이 구현을 쓴다. */
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst; const unsigned char *s = src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    for (size_t i = 0; i < n; ++i) d[i] = (unsigned char)c;
    return dst;
}
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8u * i));
}
static int eq16(const uint16_t *a, const char *b) {
    while (*a && *b && *a == (unsigned char)*b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}
static unsigned com_number(const uint16_t *p) {
    if (p[0] != 'C' || p[1] != 'O' || p[2] != 'M' || p[3] < '1' || p[3] > '9') return 0;
    unsigned value = 0, n = 0;
    for (p += 3; *p; ++p) {
        if (*p < '0' || *p > '9' || ++n > 4) return 0;
        value = value * 10u + *p - '0';
    }
    return value <= 4096 ? value : 0;
}
static int valid_token(const uint16_t *p) {
    for (unsigned i = 0; i < 32; ++i)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return 0;
    return p[32] == 0;
}
static int framing(const uint8_t *p) {
    uint32_t baud = u32(p);
    return baud >= 50 && baud <= 20000000 && p[4] >= 5 && p[4] <= 8 && p[5] <= 4 &&
           p[6] <= 2 && !(p[6] == 1 && p[4] != 5) && !(p[6] == 2 && p[4] == 5);
}
static int valid_request(uint8_t type, const uint8_t *p, unsigned n) {
    if (n < 4 || !u32(p)) return 0;
    switch (type) {
    case 'O': return n == 14 && framing(p + 4) && p[11] <= 1 && p[12] <= 1 && p[13] == 0;
    case 'B': return n == 12 && framing(p + 4) && p[11] == 0;
    case 'L': return n == 6 && (p[4] <= 1 || p[4] == 255) && (p[5] <= 1 || p[5] == 255) &&
                     !(p[4] == 255 && p[5] == 255);
    case 'K': return n == 9 && ((p[4] <= 1 && u32(p + 5) == 0) ||
                     (p[4] == 2 && u32(p + 5) >= 1 && u32(p + 5) <= 5000));
    case 'P': return n == 9 && p[4] <= 2 && u32(p + 5) >= 1 && u32(p + 5) <= 5000;
    case 'S': case 'Q': return n == 4;
    case 'D': return n >= 9 && n <= MAX_PAYLOAD && u32(p + 4) >= 1 && u32(p + 4) <= 30000;
    default: return 0;
    }
}

typedef struct {
    uint8_t head[3], data[MAX_PAYLOAD];
    unsigned used, want;
    uint64_t started;
} Parser;
typedef int (*FrameSink)(void *, uint8_t, const uint8_t *, unsigned);
/* 0=정상(부분 포함), -1=길이/내용/소비자 거부. 재동기화하지 않는다. */
static int feed(Parser *s, const uint8_t *data, unsigned n, uint64_t now, FrameSink sink, void *ctx) {
    for (unsigned i = 0; i < n; ++i) {
        if (s->used == 0) s->started = now;
        if (s->used < 3) {
            s->head[s->used++] = data[i];
            if (s->used == 3) {
                s->want = (unsigned)s->head[1] | (unsigned)s->head[2] << 8;
                if (s->want < 4 || s->want > MAX_PAYLOAD) return -1;
            }
        } else {
            s->data[s->used++ - 3] = data[i];
            if (s->used == s->want + 3) {
                if (!valid_request(s->head[0], s->data, s->want) ||
                    !sink(ctx, s->head[0], s->data, s->want)) return -1;
                s->used = s->want = 0; s->started = 0;
            }
        }
    }
    return 0;
}

/* 취소 결과와 완료 결과를 구별하는 작은 HAL. cancel 성공을 완료로 바꾸지 않는다. */
typedef struct {
    void *ctx;
    void (*cancel)(void *);
    int (*poll)(void *);  /* 0=pending, 1=정상/취소/오류로 완료 */
    uint64_t (*clock)(void *);
    void (*pause)(void *);
} CancelOps;
static int cancel_complete(CancelOps *ops, uint32_t timeout) {
    uint64_t start = ops->clock(ops->ctx);
    ops->cancel(ops->ctx);
    for (;;) {
        if (ops->poll(ops->ctx)) return 1;
        if (ops->clock(ops->ctx) - start >= timeout) return 0;
        ops->pause(ops->ctx);
    }
}

#ifndef PWEH_HOST_TEST
#include "win32-abi.h"
#include "pweh-build-id.h"

typedef struct {
    uint8_t bytes[MAX_FRAME];
    unsigned size;
    uint64_t started;
} OutFrame;
typedef struct {
    CRITICAL_SECTION lock;
    HANDLE in, out, writer_event, reader, writer, port;
    OVERLAPPED rx, tx;
    uint8_t rxbuf[4096];
    int rx_pending, tx_pending, opened, break_on, echo, version;
    unsigned com;
    Parser parser;
    OutFrame queue[OUT_SLOTS], output;
    unsigned head, count, queued_bytes, writing_bytes;
    uint64_t writing_since, partial_since;
    int input_stop, output_stop, eof, fatal, writer_failed, command_ready, active;
    uint8_t fatal_code, type, command[MAX_PAYLOAD];
    unsigned length;
    uint32_t last_id, quit_id, epoch, transferred;
    uint64_t deadline, started;
    int command_started, reset_cancelling;
} App;
static App app;
static uint8_t input_chunk[4096], receive_frame[MAX_PAYLOAD], response[32];
static uint16_t args_storage[512], *args[6];

static uint64_t ticks(void) { return GetTickCount64(); }
static void fail(uint8_t code) {
    EnterCriticalSection(&app.lock);
    if (!app.fatal) { app.fatal = 1; app.fatal_code = code; }
    LeaveCriticalSection(&app.lock);
}
static int stopping(void) {
    int value;
    EnterCriticalSection(&app.lock);
    value = app.fatal || app.eof || app.quit_id;
    LeaveCriticalSection(&app.lock);
    return value;
}
static int queue(uint8_t type, const uint8_t *p, unsigned n) {
    int ok = 0;
    EnterCriticalSection(&app.lock);
    if (n <= MAX_PAYLOAD && app.count < OUT_SLOTS && app.queued_bytes + app.writing_bytes + n + 3 <= OUT_BYTES) {
        OutFrame *f = &app.queue[(app.head + app.count) % OUT_SLOTS];
        f->bytes[0] = type; f->bytes[1] = (uint8_t)n; f->bytes[2] = (uint8_t)(n >> 8);
        memcpy(f->bytes + 3, p, n); f->size = n + 3; f->started = ticks();
        ++app.count; app.queued_bytes += f->size; ok = 1;
        SetEvent(app.writer_event);
    }
    LeaveCriticalSection(&app.lock);
    if (!ok) fail(ERR_OVERFLOW);
    return ok;
}
static DWORD WINAPI writer_thread(void *unused) {
    (void)unused;
    for (;;) {
        EnterCriticalSection(&app.lock);
        if (app.output_stop) { LeaveCriticalSection(&app.lock); return 0; }
        if (!app.count) {
            ResetEvent(app.writer_event); LeaveCriticalSection(&app.lock);
            WaitForSingleObject(app.writer_event, 50); continue;
        }
        memcpy(&app.output, &app.queue[app.head], sizeof(app.output));
        app.head = (app.head + 1) % OUT_SLOTS; --app.count;
        app.queued_bytes -= app.output.size; app.writing_since = app.output.started;
        app.writing_bytes = app.output.size;
        LeaveCriticalSection(&app.lock);
        unsigned offset = 0;
        while (offset < app.output.size) {
            DWORD done = 0;
            EnterCriticalSection(&app.lock); int stop = app.output_stop; LeaveCriticalSection(&app.lock);
            if (stop) return 1;
            if (!WriteFile(app.out, app.output.bytes + offset, app.output.size - offset, &done, NULL) || !done) {
                EnterCriticalSection(&app.lock); app.writer_failed = 1; LeaveCriticalSection(&app.lock);
                fail(ERR_IO); return 1;
            }
            offset += done;
        }
        EnterCriticalSection(&app.lock); app.writing_since = 0; app.writing_bytes = 0; LeaveCriticalSection(&app.lock);
    }
}
static int accept_frame(void *unused, uint8_t type, const uint8_t *p, unsigned n) {
    (void)unused;
    int ok = 0;
    EnterCriticalSection(&app.lock);
    uint32_t id = u32(p);
    if (id > app.last_id && !app.input_stop && !app.quit_id && !app.fatal) {
        if (type == 'Q') { app.quit_id = id; app.last_id = id; ok = 1; }
        else if (!app.active && !app.command_ready) {
            app.last_id = id; app.type = type; app.length = n;
            memcpy(app.command, p, n); app.command_ready = app.active = 1; ok = 1;
        }
    }
    LeaveCriticalSection(&app.lock);
    return ok;
}
static DWORD WINAPI reader_thread(void *unused) {
    (void)unused;
    for (;;) {
        EnterCriticalSection(&app.lock); int stop = app.input_stop || app.quit_id; LeaveCriticalSection(&app.lock);
        if (stop) return 0;
        DWORD got = 0;
        if (!ReadFile(app.in, input_chunk, sizeof(input_chunk), &got, NULL) || got == 0) {
            EnterCriticalSection(&app.lock);
            if (app.parser.used && !app.input_stop) { app.fatal = 1; app.fatal_code = ERR_FRAME; }
            app.eof = 1;
            LeaveCriticalSection(&app.lock); return 0;
        }
        if (feed(&app.parser, input_chunk, got, ticks(), accept_frame, NULL) < 0) {
            fail(ERR_FRAME); return 1;
        }
        EnterCriticalSection(&app.lock);
        app.partial_since = app.parser.used ? app.parser.started : 0;
        LeaveCriticalSection(&app.lock);
    }
}
static uint8_t error_code(DWORD error) {
    if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) return 1;
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 2;
    if (error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_INVALID_HANDLE || error == ERROR_GEN_FAILURE) return 3;
    if (error == ERROR_OPERATION_ABORTED) return ERR_CANCELLED;
    return ERR_IO;
}
static int status(uint8_t *modem, uint32_t *errors, uint32_t *rx, uint32_t *tx, DWORD *err) {
    *modem = 0; *errors = *rx = *tx = 0;
    if (app.echo || !app.opened) return 1;
    DWORD lines = 0, flags = 0; COMSTAT stat;
    if (!GetCommModemStatus(app.port, &lines) || !ClearCommError(app.port, &flags, &stat)) {
        *err = GetLastError(); return 0;
    }
    if (flags) { fail((flags & 3u) ? ERR_OVERFLOW : ERR_IO); *err = ERROR_INVALID_DATA; return 0; }
    *modem = (uint8_t)(((lines & MS_CTS_ON) ? 1 : 0) | ((lines & MS_DSR_ON) ? 2 : 0) |
                      ((lines & MS_RING_ON) ? 4 : 0) | ((lines & MS_RLSD_ON) ? 8 : 0));
    *errors = flags; *rx = stat.cbInQue; *tx = stat.cbOutQue;
    return 1;
}
static void finish(void) {
    EnterCriticalSection(&app.lock); app.active = 0; LeaveCriticalSection(&app.lock);
    app.command_started = 0; app.transferred = 0;
}
static void final_queue(uint8_t type, const uint8_t *p, unsigned size) {
    /* ACK가 pipe에 보일 때 이미 다음 요청을 받을 수 있어야 한다. 같은 lock으로 공개한다. */
    EnterCriticalSection(&app.lock);
    finish();
    queue(type, p, size);
    LeaveCriticalSection(&app.lock);
}
static void error_reply(uint32_t id, uint8_t type, uint8_t code, DWORD err, uint32_t transferred) {
    uint8_t p[14] = {0}; put32(p, id); p[4] = type; p[5] = code;
    put32(p + 6, err); put32(p + 10, transferred); queue('E', p, sizeof(p));
}
static void request_error(uint8_t code, DWORD err) {
    uint8_t p[22] = {0}; put32(p, u32(app.command));
    if (app.type == 'O' || app.type == 'S') {
        p[4] = code; put32(p + 5, err);
        if (app.type == 'O') put32(p + 10, app.epoch);
        final_queue(app.type == 'O' ? 'o' : 's', p, app.type == 'O' ? 14 : 22);
    } else {
        uint8_t e[14] = {0}; put32(e, u32(app.command)); e[4] = app.type; e[5] = code;
        put32(e + 6, err); put32(e + 10, app.transferred); final_queue('E', e, sizeof(e));
    }
}
static void ack(uint32_t id, uint8_t type, uint32_t transferred, int closed) {
    uint8_t p[22] = {0}, modem; uint32_t errors, rx, tx = 0; DWORD err = 0;
    if (!closed && !status(&modem, &errors, &rx, &tx, &err)) { request_error(error_code(err), err); return; }
    put32(p, id); p[4] = type; put32(p + 10, transferred); put32(p + 14, app.epoch); put32(p + 18, tx);
    if (type == 'Q') queue('A', p, sizeof(p));
    else final_queue('A', p, sizeof(p));
}
static int configure(const uint8_t *p, int open, DWORD *err) {
    if (app.echo) return 1;
    DCB dcb = {0}; dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(app.port, &dcb)) { *err = GetLastError(); return 0; }
    dcb.BaudRate = u32(p); dcb.ByteSize = p[4]; dcb.Parity = p[5]; dcb.StopBits = p[6];
    dcb.fBinary = 1; dcb.fParity = p[5] != 0; dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = 0;
    dcb.fDsrSensitivity = dcb.fOutX = dcb.fInX = dcb.fErrorChar = dcb.fNull = dcb.fAbortOnError = 0;
    dcb.fTXContinueOnXoff = 1; dcb.fDummy2 = 0; dcb.wReserved = dcb.wReserved1 = 0;
    if (open) { dcb.fDtrControl = p[7] ? DTR_CONTROL_ENABLE : DTR_CONTROL_DISABLE;
                dcb.fRtsControl = p[8] ? RTS_CONTROL_ENABLE : RTS_CONTROL_DISABLE; }
    if (!SetCommState(app.port, &dcb)) { *err = GetLastError(); return 0; }
    DCB actual = {0}; actual.DCBlength = sizeof(actual);
    if (!GetCommState(app.port, &actual)) { *err = GetLastError(); return 0; }
    if (actual.BaudRate != dcb.BaudRate || actual.ByteSize != dcb.ByteSize || actual.Parity != dcb.Parity ||
        actual.StopBits != dcb.StopBits || !actual.fBinary || actual.fOutxCtsFlow || actual.fOutxDsrFlow ||
        actual.fOutX || actual.fInX || actual.fDtrControl != dcb.fDtrControl || actual.fRtsControl != dcb.fRtsControl) {
        *err = ERROR_INVALID_DATA; return 0;
    }
    return 1;
}
static int open_port(DWORD *err) {
    if (app.echo) { app.opened = 1; return 1; }
    WCHAR path[16] = { '\\', '\\', '.', '\\', 'C', 'O', 'M', 0 };
    unsigned div = 1000, pos = 7;
    while (div > app.com) div /= 10;
    for (; div; div /= 10) path[pos++] = (WCHAR)('0' + app.com / div % 10);
    app.port = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (app.port == INVALID_HANDLE_VALUE) { *err = GetLastError(); return 0; }
    /* 실패한 open도 cleanup에서 이 핸들의 닫힘을 확인한다. */
    app.opened = 1;
    if (GetFileType(app.port) != FILE_TYPE_CHAR) { *err = ERROR_INVALID_HANDLE; return 0; }
    if (!configure(app.command + 4, 1, err)) return 0;
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = MAXDWORD; timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = 100; timeouts.WriteTotalTimeoutConstant = 30000;
    if (!SetCommTimeouts(app.port, &timeouts) || !PurgeComm(app.port, PURGE_RXCLEAR | PURGE_TXCLEAR)) {
        *err = GetLastError(); return 0;
    }
    return 1;
}
static int poll_io(OVERLAPPED *ov, int *pending, DWORD *done, DWORD *err) {
    if (GetOverlappedResult(app.port, ov, done, FALSE)) { *pending = 0; return 1; }
    *err = GetLastError();
    if (*err == ERROR_IO_INCOMPLETE) return 0;
    *pending = 0; return -1;
}
static void discard_rx_queue(void) {
    EnterCriticalSection(&app.lock);
    unsigned keep = 0;
    for (unsigned i = 0; i < app.count; ++i) {
        OutFrame *src = &app.queue[(app.head + i) % OUT_SLOTS];
        if (src->bytes[0] == 'D') { app.queued_bytes -= src->size; continue; }
        OutFrame *dst = &app.queue[(app.head + keep++) % OUT_SLOTS];
        if (dst != src) memcpy(dst, src, sizeof(*dst));
    }
    app.count = keep; LeaveCriticalSection(&app.lock);
}
static void received(const uint8_t *data, unsigned n) {
    if (!n) return;
    if (!app.echo) {
        DWORD flags = 0; COMSTAT stat;
        if (!ClearCommError(app.port, &flags, &stat)) { fail(error_code(GetLastError())); return; }
        if (flags) { fail((flags & 3u) ? ERR_OVERFLOW : ERR_IO); return; }
    }
    put32(receive_frame, app.epoch); memcpy(receive_frame + 4, data, n);
    queue('D', receive_frame, n + 4);
}
static void rx_step(void) {
    if (!app.opened || !app.epoch || app.echo || app.reset_cancelling) return;
    DWORD done = 0, err = 0;
    if (app.rx_pending) {
        int result = poll_io(&app.rx, &app.rx_pending, &done, &err);
        if (result < 0) { fail(error_code(err)); return; }
        if (!result) return;
        received(app.rxbuf, done);
    }
    EnterCriticalSection(&app.lock);
    int space = app.count + 2 < OUT_SLOTS && app.queued_bytes + app.writing_bytes + sizeof(app.rxbuf) + 64 < OUT_BYTES;
    LeaveCriticalSection(&app.lock);
    if (!space || stopping()) return;
    ResetEvent(app.rx.hEvent);
    if (ReadFile(app.port, app.rxbuf, sizeof(app.rxbuf), &done, &app.rx)) received(app.rxbuf, done);
    else if (GetLastError() == ERROR_IO_PENDING) app.rx_pending = 1;
    else fail(error_code(GetLastError()));
}
static void command_step(void) {
    DWORD err = 0, done = 0;
    uint8_t modem = 0; uint32_t errors = 0, rx = 0, tx = 0;
    uint8_t *p = app.command; uint32_t id = u32(p);
    if (!app.command_started) {
        app.command_started = 1; app.started = ticks(); app.deadline = app.started + 5000;
        if (app.type != 'O' && !app.epoch) { request_error(ERR_FRAME, ERROR_INVALID_STATE); fail(ERR_FRAME); return; }
        if (app.type == 'O') {
            if (app.opened || !open_port(&err)) {
                request_error(err ? error_code(err) : ERR_FRAME, err); fail(err ? ERR_IO : ERR_FRAME); return;
            }
            app.epoch = 1;
            if (!status(&modem, &errors, &rx, &tx, &err)) { request_error(error_code(err), err); fail(ERR_IO); return; }
            memset(response, 0, 14); put32(response, id); response[9] = modem; put32(response + 10, app.epoch);
            final_queue('o', response, 14); return;
        }
        if (app.type == 'B') {
            if (!configure(p + 4, 0, &err)) { request_error(error_code(err), err); fail(ERR_IO); return; }
            ack(id, 'B', 0, 0); return;
        }
        if (app.type == 'L') {
            if (!app.echo && ((p[4] != 255 && !EscapeCommFunction(app.port, p[4] ? SETDTR : CLRDTR)) ||
                (p[5] != 255 && !EscapeCommFunction(app.port, p[5] ? SETRTS : CLRRTS)))) {
                err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); return;
            }
            ack(id, 'L', 0, 0); return;
        }
        if (app.type == 'S') {
            if (!status(&modem, &errors, &rx, &tx, &err)) { request_error(error_code(err), err); return; }
            memset(response, 0, 22); put32(response, id); response[9] = modem;
            put32(response + 10, errors); put32(response + 14, rx); put32(response + 18, tx);
            final_queue('s', response, 22); return;
        }
        if (app.type == 'K') {
            if (!app.echo && !(p[4] ? SetCommBreak(app.port) : ClearCommBreak(app.port))) {
                err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); return;
            }
            app.break_on = p[4] != 0;
            if (p[4] != 2) { ack(id, 'K', 0, 0); return; }
            app.deadline = ticks() + u32(p + 5);
        }
        if (app.type == 'P') {
            app.deadline = ticks() + u32(p + 5);
            if (p[4] == 0) {
                app.reset_cancelling = 1;
                if (app.rx_pending) CancelIoEx(app.port, &app.rx);
            }
        }
        if (app.type == 'D') {
            app.deadline = ticks() + u32(p + 4);
            if (app.echo) { received(p + 8, app.length - 8); ack(id, 'D', app.length - 8, 0); return; }
        }
    }
    if (app.type == 'K' && ticks() >= app.deadline) {
        if (!app.echo && !ClearCommBreak(app.port)) { err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); return; }
        app.break_on = 0; ack(id, 'K', 0, 0); return;
    }
    if (ticks() >= app.deadline) {
        /* pending tx의 완료 길이는 cleanup에서 확인한 뒤 응답한다. */
        fail(ERR_TIMEOUT); return;
    }
    if (app.type == 'D') {
        if (app.tx_pending) {
            int result = poll_io(&app.tx, &app.tx_pending, &done, &err);
            if (!result) return;
            app.transferred += done;
            if (result < 0) { request_error(error_code(err), err); fail(ERR_IO); return; }
        }
        if (app.transferred == app.length - 8) { ack(id, 'D', app.transferred, 0); return; }
        ResetEvent(app.tx.hEvent);
        if (WriteFile(app.port, p + 8 + app.transferred, app.length - 8 - app.transferred, &done, &app.tx)) {
            if (!done) { request_error(ERR_IO, ERROR_WRITE_FAULT); fail(ERR_IO); return; }
            app.transferred += done;
        } else if (GetLastError() == ERROR_IO_PENDING) app.tx_pending = 1;
        else { err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); }
    } else if (app.type == 'P') {
        if (p[4] == 0) {
            if (app.rx_pending) {
                int complete = poll_io(&app.rx, &app.rx_pending, &done, &err);
                if (!complete) return;
                if (complete < 0 && err != ERROR_OPERATION_ABORTED) {
                    request_error(error_code(err), err); fail(ERR_IO); return;
                }
            }
            if (app.epoch == UINT32_MAX) { request_error(ERR_FRAME, ERROR_INVALID_DATA); fail(ERR_FRAME); return; }
            if (!app.echo && !PurgeComm(app.port, PURGE_RXCLEAR)) { err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); return; }
            discard_rx_queue(); ++app.epoch; app.reset_cancelling = 0; ack(id, 'P', 0, 0);
        } else if (p[4] == 1) {
            if (!app.echo && !PurgeComm(app.port, PURGE_TXCLEAR)) { err = GetLastError(); request_error(error_code(err), err); fail(ERR_IO); return; }
            ack(id, 'P', 0, 0);
        } else {
            if (!status(&modem, &errors, &rx, &tx, &err)) { request_error(error_code(err), err); fail(ERR_IO); return; }
            if (!tx && !app.tx_pending) ack(id, 'P', 0, 0);
        }
    }
}
static void cancel_ops(void *unused) {
    (void)unused;
    if (app.rx_pending) CancelIoEx(app.port, &app.rx);
    if (app.tx_pending) CancelIoEx(app.port, &app.tx);
}
static int poll_cancel(void *unused) {
    (void)unused; DWORD done = 0, err = 0;
    if (app.rx_pending) poll_io(&app.rx, &app.rx_pending, &done, &err);
    done = 0;
    if (app.tx_pending && poll_io(&app.tx, &app.tx_pending, &done, &err)) app.transferred += done;
    return !app.rx_pending && !app.tx_pending;
}
static uint64_t io_clock(void *unused) { (void)unused; return ticks(); }
static void io_pause(void *unused) { (void)unused; Sleep(5); }
static int join_thread(HANDLE thread, uint32_t timeout) {
    if (!thread) return 1;
    uint64_t start = ticks();
    do {
        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) { CloseHandle(thread); return 1; }
        CancelSynchronousIo(thread); Sleep(5);
    } while (ticks() - start < timeout);
    return 0;
}
static unsigned shutdown_app(void) {
    int good = 1;
    EnterCriticalSection(&app.lock); app.input_stop = 1; LeaveCriticalSection(&app.lock);
    if (app.opened && !app.echo) {
        CancelOps ops = {NULL, cancel_ops, poll_cancel, io_clock, io_pause};
        good = cancel_complete(&ops, CLEANUP_MS);
        if (good && app.break_on && !ClearCommBreak(app.port)) good = 0;
        if (good && !CloseHandle(app.port)) good = 0;
    }
    if (good) app.opened = 0;
    if (!join_thread(app.reader, CLEANUP_MS)) good = 0;
    /* 완료가 확인되지 않았으면 ACK도 handle/OVERLAPPED 해제도 하지 않는다. */
    if (!good) { TerminateProcess(GetCurrentProcess(), 70); return 70; }
    if (app.active) {
        request_error(app.fatal ? app.fatal_code : ERR_CANCELLED, app.fatal ? 0 : ERROR_OPERATION_ABORTED);
    } else if (app.fatal && !app.writer_failed) error_reply(0, 0, app.fatal_code, 0, 0);
    if (app.quit_id && !app.fatal) ack(app.quit_id, 'Q', 0, 1);
    uint64_t deadline = ticks() + 1000;
    if (!app.eof && !app.writer_failed) {
        for (;;) {
            EnterCriticalSection(&app.lock); int empty = app.count == 0 && !app.writing_since; LeaveCriticalSection(&app.lock);
            if (empty || ticks() >= deadline) break;
            Sleep(5);
        }
    }
    EnterCriticalSection(&app.lock);
    int unsent = app.count != 0 || app.writing_since != 0;
    app.output_stop = 1; SetEvent(app.writer_event);
    LeaveCriticalSection(&app.lock);
    if (!join_thread(app.writer, CLEANUP_MS)) { TerminateProcess(GetCurrentProcess(), 70); return 70; }
    if (app.rx.hEvent) CloseHandle(app.rx.hEvent);
    if (app.tx.hEvent) CloseHandle(app.tx.hEvent);
    return app.fatal || app.writer_failed || unsent ? 1 : 0;
}
static int parse_args(void) {
    const uint16_t *p = (const uint16_t *)GetCommandLineW();
    /* 실행 파일 이름만 Windows의 큰따옴표를 허용한다. 뒤 인자는 공백 없는 고정 ASCII다. */
    unsigned skip = 0;
    if (*p == '"') { ++p; while (*p && *p != '"' && ++skip < 32768) ++p; if (*p++ != '"') return 0; }
    else while (*p && *p != ' ' && *p != '\t' && ++skip < 32768) ++p;
    if (skip >= 32768) return 0;
    unsigned n = 0, used = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (n == 6) return 0;
        args[n++] = args_storage + used;
        while (*p && *p != ' ' && *p != '\t') {
            if (*p < 33 || *p > 126 || *p == '"' || used + 1 >= 512) return 0;
            args_storage[used++] = *p++;
        }
        args_storage[used++] = 0;
    }
    if (n == 4 && eq16(args[0], "--port") && eq16(args[2], "--token") && valid_token(args[3])) {
        app.com = com_number(args[1]); return app.com != 0;
    }
    if (n == 3 && eq16(args[1], "--token") && valid_token(args[2])) {
        app.echo = eq16(args[0], "--echo"); app.version = eq16(args[0], "--version");
        return app.echo || app.version;
    }
    return 0;
}
void pweh_entry(void) {
    if (!parse_args()) ExitProcess(64);
    InitializeCriticalSection(&app.lock);
    app.in = GetStdHandle(STD_INPUT_HANDLE); app.out = GetStdHandle(STD_OUTPUT_HANDLE);
    /* stdout을 파일/콘솔로 바꾸어 프레임을 저장하는 모드는 제공하지 않는다. */
    if (GetFileType(app.in) != FILE_TYPE_PIPE || GetFileType(app.out) != FILE_TYPE_PIPE) ExitProcess(65);
    app.writer_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    app.rx.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); app.tx.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!app.writer_event || !app.rx.hEvent || !app.tx.hEvent) ExitProcess(70);
    app.writer = CreateThread(NULL, 0, writer_thread, NULL, 0, NULL);
    if (!app.writer) ExitProcess(70);
    uint8_t hello[32] = {1, 0, 0, 0, 0, 1, 0, 0};
    hello[7] = app.version ? 2 : app.echo ? 1 : 0;
    for (unsigned i = 0; i < 20; ++i) hello[8 + i] = PWEH_BUILD_ID[8 + i];
    hello[29] = 64;
    queue('H', hello, sizeof(hello));
    if (app.version) ExitProcess(shutdown_app());
    app.reader = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);
    if (!app.reader) { fail(ERR_IO); ExitProcess(shutdown_app()); }
    uint64_t began = ticks();
    while (!stopping()) {
        EnterCriticalSection(&app.lock);
        uint64_t partial = app.partial_since, writing = app.writing_since;
        uint64_t oldest = app.count ? app.queue[app.head].started : 0;
        int active = app.active; app.command_ready = 0;
        LeaveCriticalSection(&app.lock);
        uint64_t now = ticks();
        if ((partial && now - partial >= FRAME_MS) || (writing && now - writing >= FRAME_MS) ||
            (oldest && now - oldest >= FRAME_MS) || (!app.epoch && now - began >= 5000)) { fail(ERR_TIMEOUT); break; }
        if (active) command_step();
        if (!stopping()) rx_step();
        Sleep(1);
    }
    ExitProcess(shutdown_app());
}
#endif
