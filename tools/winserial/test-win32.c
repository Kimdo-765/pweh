/* 실제 coordinator/정리 함수를 고정 Win32 fake로 실행한다. 기기·Windows 실행 없음. */
#define PWEH_FAKE_WIN32
#include "pweh-serial-helper.c"
#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static uint64_t now_ms;
static DWORD last_error, io_done, out_pending, comm_errors;
static int locks, opens, closes, writes, cancels, forced, polls_left, break_calls, publication_hook, next_accepted;
static DCB current_dcb;
static WCHAR last_path[16];
static const uint8_t next_request[4] = {2,0,0,0};

void InitializeCriticalSection(CRITICAL_SECTION *p) { (void)p; }
void EnterCriticalSection(CRITICAL_SECTION *p) { (void)p; ++locks; }
void LeaveCriticalSection(CRITICAL_SECTION *p) {
    (void)p; assert(locks > 0); --locks;
    if (!locks && publication_hook && app.count) {
        publication_hook = 0;
        next_accepted = accept_frame(NULL, 'S', next_request, 4);
    }
}
BOOL SetEvent(HANDLE h) { (void)h; return 1; }
BOOL ResetEvent(HANDLE h) { (void)h; return 1; }
DWORD GetLastError(void) { return last_error; }
uint64_t GetTickCount64(void) { return now_ms; }
void Sleep(DWORD ms) { now_ms += ms; }
HANDLE CreateFileW(const WCHAR *p, DWORD access, DWORD share, void *security, DWORD creation, DWORD flags, HANDLE template) {
    assert(access == (GENERIC_READ | GENERIC_WRITE) && share == 0 && !security && creation == OPEN_EXISTING && flags == FILE_FLAG_OVERLAPPED && !template);
    ++opens; unsigned i = 0; do { last_path[i] = p[i]; } while (p[i++] && i < 16);
    return (HANDLE)1;
}
DWORD GetFileType(HANDLE h) { return h == (HANDLE)1 ? FILE_TYPE_CHAR : FILE_TYPE_PIPE; }
BOOL GetCommState(HANDLE h, DCB *dcb) { assert(h == (HANDLE)1); *dcb = current_dcb; return 1; }
BOOL SetCommState(HANDLE h, DCB *dcb) { assert(h == (HANDLE)1); current_dcb = *dcb; return 1; }
BOOL SetCommTimeouts(HANDLE h, COMMTIMEOUTS *t) { assert(h == (HANDLE)1 && t->WriteTotalTimeoutConstant == 30000); return 1; }
BOOL PurgeComm(HANDLE h, DWORD flags) { assert(h == (HANDLE)1); (void)flags; return 1; }
BOOL GetCommModemStatus(HANDLE h, DWORD *value) { assert(h == (HANDLE)1); *value = MS_CTS_ON | MS_DSR_ON; return 1; }
BOOL ClearCommError(HANDLE h, DWORD *errors, COMSTAT *s) { assert(h == (HANDLE)1); *errors = comm_errors; memset(s, 0, sizeof(*s)); s->cbOutQue = out_pending; return 1; }
BOOL EscapeCommFunction(HANDLE h, DWORD code) { assert(h == (HANDLE)1); (void)code; return 1; }
BOOL SetCommBreak(HANDLE h) { assert(h == (HANDLE)1); ++break_calls; return 1; }
BOOL ClearCommBreak(HANDLE h) { assert(h == (HANDLE)1); --break_calls; return 1; }
BOOL ReadFile(HANDLE h, void *data, DWORD count, DWORD *done, OVERLAPPED *ov) {
    (void)h; (void)data; (void)count; (void)ov; *done = 0; last_error = ERROR_IO_PENDING; return 0;
}
BOOL WriteFile(HANDLE h, const void *data, DWORD count, DWORD *done, OVERLAPPED *ov) {
    (void)data; (void)count; (void)ov; assert(h == (HANDLE)1); ++writes; *done = 0; last_error = ERROR_IO_PENDING; return 0;
}
BOOL GetOverlappedResult(HANDLE h, OVERLAPPED *ov, DWORD *done, BOOL wait) {
    assert(h == (HANDLE)1 && !wait); (void)ov; *done = 0;
    if (polls_left-- > 0) { last_error = ERROR_IO_INCOMPLETE; return 0; }
    *done = io_done; return 1;
}
BOOL CancelIoEx(HANDLE h, OVERLAPPED *ov) { assert(h == (HANDLE)1 && ov); ++cancels; return 1; }
BOOL CancelSynchronousIo(HANDLE h) { (void)h; return 1; }
HANDLE CreateEventW(void *s, BOOL manual, BOOL initial, const WCHAR *name) { (void)s; (void)manual; (void)initial; (void)name; return (HANDLE)3; }
DWORD WaitForSingleObject(HANDLE h, DWORD timeout) { (void)h; (void)timeout; return WAIT_OBJECT_0; }
HANDLE CreateThread(void *s, size_t stack, DWORD (*fn)(void *), void *p, DWORD flags, DWORD *id) { (void)s;(void)stack;(void)fn;(void)p;(void)flags;(void)id; return (HANDLE)4; }
BOOL CloseHandle(HANDLE h) { if (h == (HANDLE)1) ++closes; return 1; }
WCHAR *GetCommandLineW(void) { static WCHAR empty[] = {0}; return empty; }
HANDLE GetStdHandle(DWORD h) { (void)h; return (HANDLE)2; }
HANDLE GetCurrentProcess(void) { return (HANDLE)5; }
BOOL TerminateProcess(HANDLE h, unsigned code) { assert(h == (HANDLE)5 && code == 70); ++forced; return 1; }
_Noreturn void ExitProcess(unsigned code) { (void)code; abort(); }

static void reset(void) {
    memset(&app, 0, sizeof(app)); memset(&current_dcb, 0, sizeof(current_dcb));
    now_ms = 100; last_error = io_done = out_pending = comm_errors = 0;
    locks = opens = closes = writes = cancels = forced = polls_left = break_calls = publication_hook = next_accepted = 0;
    app.port = (HANDLE)1; app.com = 4096;
}
static void submit(uint8_t type, const uint8_t *p, unsigned len) {
    assert(valid_request(type, p, len)); assert(accept_frame(NULL, type, p, len));
    app.command_ready = 0;  /* coordinator가 slot을 받은 상태 */
    command_step();
}
static void open_synthetic(void) {
    uint8_t p[] = {1,0,0,0,0,194,1,0,8,0,0,1,0,0};
    submit('O', p, sizeof(p)); assert(app.epoch == 1 && !app.active && opens == 1 && writes == 0);
    assert(eq16((uint16_t *)last_path, "\\\\.\\COM4096"));
    assert(current_dcb.fDtrControl == 1 && current_dcb.fRtsControl == 0);
    assert(app.queue[0].bytes[0] == 'o'); app.head = app.count = app.queued_bytes = 0;
}
static void tests(void) {
    reset(); open_synthetic();
    /* ACK를 공개한 즉시 다음 정상 명령이 와도 active가 남아 거부하면 안 된다. */
    reset(); publication_hook = 1;
    uint8_t open[] = {1,0,0,0,0,194,1,0,8,0,0,0,0,0}; submit('O', open, sizeof(open));
    assert(next_accepted && app.active && app.type == 'S' && !app.fatal);
    reset(); app.echo = 1; submit('O', open, sizeof(open)); app.count = app.queued_bytes = 0;
    const uint8_t data[] = {2,0,0,0,100,0,0,0,0,255,13,10}; submit('D', data, sizeof(data));
    assert(opens == 0 && writes == 0 && app.count == 2);
    assert(app.queue[0].bytes[0] == 'D' && app.queue[1].bytes[0] == 'A');
    assert(u32(app.queue[1].bytes + 3 + 10) == 4);
    reset(); open_synthetic(); polls_left = 2; io_done = 4; submit('D', data, sizeof(data));
    assert(writes == 1 && app.tx_pending && app.count == 0);
    command_step(); command_step(); assert(app.count == 0);
    command_step(); assert(!app.tx_pending && app.count == 1 && app.queue[0].bytes[0] == 'A');
    reset(); open_synthetic(); app.rx_pending = 1; polls_left = 1;
    uint8_t purge[] = {2,0,0,0,0,100,0,0,0}; submit('P', purge, sizeof(purge));
    assert(cancels == 1 && app.reset_cancelling && app.count == 0);
    command_step(); assert(app.epoch == 2 && app.count == 1 && !app.reset_cancelling);
    reset(); open_synthetic(); out_pending = 5;
    uint8_t drain[] = {2,0,0,0,2,10,0,0,0}; submit('P', drain, sizeof(drain));
    assert(app.active && !app.count); now_ms += 10; command_step(); assert(app.fatal && app.fatal_code == ERR_TIMEOUT);
    reset(); open_synthetic(); app.tx_pending = 1; polls_left = 10000; app.eof = 1;
    assert(shutdown_app() == 70 && forced == 1 && closes == 0 && cancels == 1);
    reset(); open_synthetic(); app.tx_pending = 1; polls_left = 1; app.eof = 1;
    assert(shutdown_app() == 0 && forced == 0 && closes == 1 && cancels == 1);
    reset(); open_synthetic(); comm_errors = 2;
    received((const uint8_t *)"x", 1);
    assert(app.fatal && app.fatal_code == ERR_OVERFLOW && app.count == 0);
    reset(); app.writing_bytes = OUT_BYTES - 2;
    assert(!queue('E', next_request, sizeof(next_request)) && app.fatal_code == ERR_OVERFLOW);
}
int main(void) { tests(); puts("native Win32 fake/coordinator/cleanup: ok"); return 0; }
