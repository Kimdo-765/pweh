/* x86_64 Win32의 사용하는 ABI만 선언한다. Windows SDK 다운로드는 하지 않는다.
 * 근거: Microsoft Learn DCB/COMSTAT/OVERLAPPED/CRITICAL_SECTION 및 각 API 문서.
 * Windows x64 기본 호출 규약, LLP64. 다른 target에서는 빌드를 거부한다. */
#ifndef PWEH_WIN32_ABI_H
#define PWEH_WIN32_ABI_H
#include <stdint.h>
#include <stddef.h>
#if (!defined(_WIN64) || !defined(__x86_64__)) && !defined(PWEH_FAKE_WIN32)
#error "이 어댑터는 Windows x86_64만 지원한다"
#endif
typedef void *HANDLE;
typedef uint32_t DWORD;
typedef uint16_t WCHAR;
typedef int BOOL;
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAXDWORD UINT32_MAX
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define FILE_TYPE_CHAR 2u
#define FILE_TYPE_PIPE 3u
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define OPEN_EXISTING 3u
#define FILE_FLAG_OVERLAPPED 0x40000000u
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define WAIT_OBJECT_0 0u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_INVALID_DATA 13u
#define ERROR_WRITE_FAULT 29u
#define ERROR_GEN_FAILURE 31u
#define ERROR_SHARING_VIOLATION 32u
#define ERROR_OPERATION_ABORTED 995u
#define ERROR_IO_INCOMPLETE 996u
#define ERROR_IO_PENDING 997u
#define ERROR_DEVICE_NOT_CONNECTED 1167u
#define ERROR_INVALID_STATE 5023u
#define DTR_CONTROL_DISABLE 0u
#define DTR_CONTROL_ENABLE 1u
#define RTS_CONTROL_DISABLE 0u
#define RTS_CONTROL_ENABLE 1u
#define SETRTS 3u
#define CLRRTS 4u
#define SETDTR 5u
#define CLRDTR 6u
#define PURGE_TXCLEAR 4u
#define PURGE_RXCLEAR 8u
#define MS_CTS_ON 0x10u
#define MS_DSR_ON 0x20u
#define MS_RING_ON 0x40u
#define MS_RLSD_ON 0x80u

typedef struct { uintptr_t Internal, InternalHigh; DWORD Offset, OffsetHigh; HANDLE hEvent; } OVERLAPPED;
typedef struct { void *DebugInfo; int32_t LockCount, RecursionCount; HANDLE OwningThread, LockSemaphore; uintptr_t SpinCount; } CRITICAL_SECTION;
typedef struct {
    DWORD DCBlength, BaudRate;
    DWORD fBinary:1, fParity:1, fOutxCtsFlow:1, fOutxDsrFlow:1, fDtrControl:2,
          fDsrSensitivity:1, fTXContinueOnXoff:1, fOutX:1, fInX:1,
          fErrorChar:1, fNull:1, fRtsControl:2, fAbortOnError:1, fDummy2:17;
    uint16_t wReserved, XonLim, XoffLim;
    uint8_t ByteSize, Parity, StopBits;
    char XonChar, XoffChar, ErrorChar, EofChar, EvtChar;
    uint16_t wReserved1;
} DCB;
typedef struct { DWORD flags, cbInQue, cbOutQue; } COMSTAT;
typedef struct {
    DWORD ReadIntervalTimeout, ReadTotalTimeoutMultiplier, ReadTotalTimeoutConstant,
          WriteTotalTimeoutMultiplier, WriteTotalTimeoutConstant;
} COMMTIMEOUTS;
_Static_assert(sizeof(void *) == 8 && sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "LLP64 ABI");
_Static_assert(sizeof(OVERLAPPED) == 32 && offsetof(OVERLAPPED, hEvent) == 24, "OVERLAPPED ABI");
_Static_assert(sizeof(CRITICAL_SECTION) == 40 && offsetof(CRITICAL_SECTION, SpinCount) == 32, "CRITICAL_SECTION ABI");
_Static_assert(sizeof(DCB) == 28 && offsetof(DCB, ByteSize) == 18 && offsetof(DCB, wReserved1) == 26, "DCB ABI");
_Static_assert(sizeof(COMSTAT) == 12 && sizeof(COMMTIMEOUTS) == 20, "COM ABI");

#ifdef PWEH_FAKE_WIN32
#define API
#else
#define API __declspec(dllimport)
#endif
API HANDLE CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API DWORD GetFileType(HANDLE);
API BOOL GetCommState(HANDLE, DCB *);
API BOOL SetCommState(HANDLE, DCB *);
API BOOL SetCommTimeouts(HANDLE, COMMTIMEOUTS *);
API BOOL PurgeComm(HANDLE, DWORD);
API BOOL GetCommModemStatus(HANDLE, DWORD *);
API BOOL ClearCommError(HANDLE, DWORD *, COMSTAT *);
API BOOL EscapeCommFunction(HANDLE, DWORD);
API BOOL SetCommBreak(HANDLE);
API BOOL ClearCommBreak(HANDLE);
API BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *);
API BOOL GetOverlappedResult(HANDLE, OVERLAPPED *, DWORD *, BOOL);
API BOOL CancelIoEx(HANDLE, OVERLAPPED *);
API BOOL CancelSynchronousIo(HANDLE);
API HANDLE CreateEventW(void *, BOOL, BOOL, const WCHAR *);
API BOOL SetEvent(HANDLE);
API BOOL ResetEvent(HANDLE);
API DWORD WaitForSingleObject(HANDLE, DWORD);
API HANDLE CreateThread(void *, size_t, DWORD (*)(void *), void *, DWORD, DWORD *);
API BOOL CloseHandle(HANDLE);
API void InitializeCriticalSection(CRITICAL_SECTION *);
API void EnterCriticalSection(CRITICAL_SECTION *);
API void LeaveCriticalSection(CRITICAL_SECTION *);
API void Sleep(DWORD);
API uint64_t GetTickCount64(void);
API DWORD GetLastError(void);
API WCHAR *GetCommandLineW(void);
API HANDLE GetStdHandle(DWORD);
API HANDLE GetCurrentProcess(void);
API BOOL TerminateProcess(HANDLE, unsigned);
API _Noreturn void ExitProcess(unsigned);
#endif
