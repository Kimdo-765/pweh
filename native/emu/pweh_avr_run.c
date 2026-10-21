/*
 * pweh_avr_run.c — PWEH 의 AVR 펌웨어 실행기 (libsimavr 위에 얹은 작은 드라이버)
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 PWEH contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * 라이선스 메모: 이 소스 파일은 MIT 다. 빌드할 때 simavr(GPL-3.0)의 헤더와 sim_hex.c 를 끼워 넣고 libsimavr.a 와
 * 정적으로 링크하므로, 만들어진 실행 파일은 GPL-3.0 결합물이다. scripts/install.sh 가 사용자 기기에서 빌드하고
 * 배포하지 않는다 (native/emu/README.md, 법률 자문 아님).
 *
 * 무엇을 하나: Arduino AVR 펌웨어(Intel HEX)를 simavr 로 실행하고 USART 를 표준 입출력에 잇는다. pweh-emu 서버가
 * 고정 argv 로만 띄운다. simavr 의 run_avr 를 쓰지 않는 이유 (고정 커밋의 simavr 소스로 확인):
 *   - run_avr 는 펌웨어가 충돌하면 0.0.0.0:1234 에 GDB 서버를 열고 기다린다. 여기서는 gdb_port = 0 이고, GDB 함수를
 *     아래의 빈 함수로 정의해 sim_gdb.o(소켓 코드)가 아예 링크되지 않는다 (nm 에 socket/bind/listen/accept/connect 없음).
 *   - run_avr 는 UART 입력(stdin) 연결이 없고 출력은 줄 버퍼·제어 문자 '.' 치환·색 코드다. 여기서는 stdin 바이트를
 *     UART 입력 IRQ 로 넣고(XON/XOFF 흐름 제어) 펌웨어가 보낸 바이트를 그대로 stdout 으로 보낸다.
 *   - ELF 를 읽지 않는다 (ELF 의 .mmcu 섹션은 펌웨어가 정하는 strcpy·VCD 파일 경로로 이어진다). Intel HEX 만 받고,
 *     libelf 없이 빌드해 ELF 해석기 자체가 없다. VCD·콘솔/명령 레지스터·파일 쓰기도 없다.
 *
 * 사용법:
 *   pweh_avr_run --version
 *       한 줄 "pweh_avr_run <PWEH_AVR_RUN_VERSION> simavr <커밋>" (커밋은 빌드 때 -DPWEH_SIMAVR_COMMIT)
 *   pweh_avr_run --mcu NAME --freq HZ [--uart N] [--realtime] [--max-cycles N] (--hex-fd N | FILE.hex)
 *       --hex-fd N  서버가 넘긴 봉인한 memfd. /proc/self/fd/N 을 simavr 의 read_ihex_chunks 로 읽는다 (이름으로 여는
 *                   파일이 없으므로 확인한 바이트와 실행하는 바이트 사이에 바꿔치기할 틈이 없다)
 *       FILE.hex    직접 실행할 때만 (서버는 늘 --hex-fd)
 *       --realtime  게스트 시간을 벽시계에 맞춘다 (stdin 을 시간 제한 poll 로 기다리며 자고, 입력이 오면 바로 깬다)
 *       --max-cycles N  N 사이클에서 멈춘다 (시험용)
 *
 * 스트림: stdin = UART 입력 (4 KiB 링, 펌웨어가 RXEN 을 켤 때까지 보류)
 *         stdout = UART 출력 원시 바이트 (원래 fd 1 의 복제. fd 1 은 stderr 로 돌려 libsimavr 의 printf 가 섞이지 않게)
 *         stderr = simavr 로그 + 마지막 줄 "pweh_avr_run: state=done|crashed|max-cycles cycles=N pc=0x…"
 * 종료 코드: 0 펌웨어가 멈춤 (인터럽트를 끈 sleep / rjmp .-2), 1 HEX 적재 실패, 2 사용법·MCU·UART 오류,
 *           3 충돌 (PC 가 플래시 끝을 넘음), 4 --max-cycles 도달, 5 UART 출력을 읽는 쪽이 사라짐, 그 밖은 신호
 * 진단 문구에는 줄 번호·주소만 쓴다 (HEX 레코드 내용·펌웨어 값은 쓰지 않는다).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sim_avr.h"
#include "sim_elf.h"
#include "sim_gdb.h"
#include "sim_hex.h"
#include "avr_uart.h"

/* 이 소스가 바뀌면 올린다. scripts/install.sh 가 설치된 실행 파일의 --version 과 비교해 다시 빌드한다. */
#define PWEH_AVR_RUN_VERSION "1.0"

#ifndef PWEH_SIMAVR_COMMIT
#error "PWEH_SIMAVR_COMMIT 가 없다: -DPWEH_SIMAVR_COMMIT='\"<simavr 커밋>\"' 로 빌드한다 (scripts/install.sh 가 넘김)"
#endif

/*
 * simavr 의 Intel HEX 해석기 read_ihex_chunks 는 sim_hex.c 안의 static 함수라 밖에서 부를 수 없다.
 * 그래서 sim_hex.c 를 이 번역 단위에 끼워 넣어 고정 커밋의 해석기를 그대로 쓴다. sim_hex.o 의 공개 함수
 * (sim_setup_firmware, read_ihex_file, read_hex_string, hdump)가 여기서 정의되므로 libsimavr.a 의 sim_hex.o 는
 * 링크되지 않는다 (아래 GDB 함수와 같은 방식. 정의가 겹치면 링크가 실패하므로 조용히 섞이지 않는다).
 * read_ihex_chunks 는 형식 오류에서 조용히 멈추거나 줄을 건너뛰므로 hex_validate() 가 먼저 엄격히 검사한다.
 */
#include "sim_hex.c"

/*
 * GDB: libsimavr 의 다른 오브젝트(sim_avr.o, sim_core.o, avr_uart.o)가 부르는 sim_gdb.o 의 함수 다섯을 여기서
 * 빈 함수로 정의한다. 그러면 정적 링크가 sim_gdb.o 를 끌어오지 않아 소켓 코드가 실행 파일에 없다.
 * gdb_port 도 0 이라 충돌하면 기다리지 않고 cpu_Crashed 로 끝난다.
 */
int avr_gdb_init(avr_t *avr) { (void)avr; return -1; }
void avr_deinit_gdb(avr_t *avr) { (void)avr; }
int avr_gdb_processor(avr_t *avr, int sleep) { (void)avr; (void)sleep; return 0; }
void avr_gdb_handle_watchpoints(avr_t *avr, uint16_t addr, enum avr_gdb_watch_type type) { (void)avr; (void)addr; (void)type; }
void avr_gdb_handle_break(avr_t *avr) { (void)avr; }

#define HEX_MAX_FILE (8u << 20)                 /* 256 KiB 플래시 + 4 KiB EEPROM 의 정규화 HEX 도 1 MiB 안쪽 */
#define HEX_MAX_RECORD (1 + 2 * (5 + 255))       /* ':' + (바이트 수·주소 2·유형·데이터 255·체크섬) × 16진 2자리 */
#define SEGMENT_IGNORED_END 0x00860000u         /* 0x820000~0x85FFFF: 퓨즈·잠금·서명·사용자 서명 (무시) */
#define RUN_BATCH 4096                          /* 입력·시간 맞춤 사이에 부르는 avr_run 횟수 */

static int uart_fd = -1;                /* 원래 stdout 의 복제. UART 출력 전용 */
static volatile int xon = 0;            /* UART 입력 FIFO 에 자리가 있는가 (simavr XON/XOFF IRQ) */
static unsigned char inbuf[4096];       /* stdin → UART 입력 링 */
static size_t in_head = 0, in_len = 0;
static int stdin_open = 1;
static avr_irq_t *g_in_irq = NULL;
static int g_realtime = 0;
static struct timespec g_t0;
static double g_skipped = 0.0;          /* 입력으로 일찍 깬 잠의 남은 시간 합(초, 한 번에 1 ms 이하) — 게스트 시간이 그만큼 앞선다 */

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void note(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("pweh_avr_run: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* simavr 로그는 모두 stderr 로 (stdout 은 UART 전용). avr 가 없는 로그는 LOG_ERROR 까지만 */
static void logger(avr_t *avr, const int level, const char *fmt, va_list ap)
{
	int max = avr ? avr->log : LOG_ERROR;
	if (level > max)
		return;
	vfprintf(stderr, fmt, ap);
}

static void uart_out_hook(struct avr_irq_t *irq, uint32_t value, void *param)
{
	(void)irq; (void)param;
	unsigned char b = (unsigned char)value;
	for (;;) {
		ssize_t n = write(uart_fd, &b, 1);
		if (n == 1)
			return;
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EAGAIN) {   /* 서버가 비차단으로 바꿨을 때도 막히지 않고 기다린다 */
			struct pollfd pfd = { .fd = uart_fd, .events = POLLOUT };
			poll(&pfd, 1, 100);
			continue;
		}
		/* EPIPE 등 — SIGPIPE 는 무시하므로 여기로 온다: 읽는 쪽(서버)이 사라졌다 */
		static const char msg[] = "pweh_avr_run: UART 출력을 읽는 쪽이 사라짐\n";
		ssize_t ignored = write(2, msg, sizeof msg - 1);
		(void)ignored;
		_exit(5);
	}
}

static void xon_hook(struct avr_irq_t *irq, uint32_t value, void *param) { (void)irq; (void)value; (void)param; xon = 1; }
static void xoff_hook(struct avr_irq_t *irq, uint32_t value, void *param) { (void)irq; (void)value; (void)param; xon = 0; }

/* stdin 을 최대 wait_ms 기다려 링에 받고, 펌웨어가 받을 수 있는 만큼 UART 입력 IRQ 로 넣는다.
 * 돌려주는 값: 이번에 UART 로 넣은 바이트 수. 링이 찼거나 stdin 이 닫혔으면 그냥 wait_ms 잔다. */
static int pump_input(int wait_ms)
{
	int raised = 0;
	if (stdin_open && in_len < sizeof(inbuf)) {
		struct pollfd pfd = { .fd = 0, .events = POLLIN };
		if (poll(&pfd, 1, wait_ms) > 0) {
			size_t tail = (in_head + in_len) % sizeof(inbuf);
			size_t room = tail >= in_head ? sizeof(inbuf) - tail : in_head - tail;   /* 이어진 빈칸 */
			ssize_t n = read(0, inbuf + tail, room);
			if (n > 0)
				in_len += (size_t)n;
			else if (n == 0 || (errno != EAGAIN && errno != EINTR))
				stdin_open = 0;
		}
	} else if (wait_ms > 0) {
		poll(NULL, 0, wait_ms);
	}
	while (xon && in_len) {   /* FIFO 가 차면 simavr 가 XOFF 를 올려 xon = 0 이 되어 멈춘다 */
		unsigned char b = inbuf[in_head];
		in_head = (in_head + 1) % sizeof(inbuf);
		in_len--;
		avr_raise_irq(g_in_irq, b);
		raised++;
	}
	return raised;
}

static double wall_seconds(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (double)(now.tv_sec - g_t0.tv_sec) + (double)(now.tv_nsec - g_t0.tv_nsec) / 1e9 + g_skipped;
}

static double sim_seconds(avr_t *avr, avr_cycle_count_t cycle)
{
	return (double)cycle / (double)avr->frequency;
}

static int wait_ms_for(double ahead)
{
	if (ahead <= 0.0)
		return 0;
	double ms = ahead * 1000.0 + 0.999;
	return ms > 100.0 ? 100 : (int)ms;   /* 길어도 100 ms 마다 다시 본다 */
}

/* 시뮬레이션 시간 1 ms 마다 부르는 빈 타이머. simavr 는 다음 타이머까지 한 번에 자므로, 이것이 잠 한 번의 길이를
 * 1 ms 로 묶는다 (느린 타이머로만 자는 펌웨어에서도 입력이 바로 들어가고, 일찍 깬 잠의 시간 어긋남이 1 ms 안). */
static avr_cycle_count_t heartbeat_period(avr_t *avr)
{
	avr_cycle_count_t p = avr->frequency / 1000;
	return p ? p : 1;
}

static avr_cycle_count_t heartbeat(avr_t *avr, avr_cycle_count_t when, void *param)
{
	(void)param;
	return when + heartbeat_period(avr);
}

/*
 * avr->sleep 대체 (펌웨어가 인터럽트를 켠 채 SLEEP 할 때 simavr 가 부른다). simavr 기본값은 usleep 이라 자는 동안
 * 입력을 보지 못한다. --realtime 이면 잠 끝의 시뮬레이션 시각까지 stdin 을 poll 로 기다리고, 입력이 오면 남은 잠을
 * 건너뛰고 바로 돌아간다 (simavr 는 돌아온 뒤 how_long 사이클을 그대로 더하므로, 건너뛴 시간(heartbeat 덕분에 1 ms
 * 이하)만큼 벽시계 기준을 옮겨 게스트가 멈춰 기다리지 않게 한다). --realtime 이 아니면 기다리지 않는다 (시험용 빨리 감기).
 */
static void pweh_sleep(avr_t *avr, avr_cycle_count_t how_long)
{
	if (!g_realtime) {
		pump_input(0);
		return;
	}
	double target = sim_seconds(avr, avr->cycle + how_long);
	for (;;) {
		double ahead = target - wall_seconds();
		if (ahead <= 0.0005) {
			pump_input(0);
			return;
		}
		if (pump_input(wait_ms_for(ahead)) > 0) {
			ahead = target - wall_seconds();
			if (ahead > 0.0)
				g_skipped += ahead;
			return;
		}
	}
}

/* ---------------------------------------------------------------------------------------------------------------
 * Intel HEX 적재
 * ------------------------------------------------------------------------------------------------------------- */

static const char *hex_why = "";

static int hex_nibble(unsigned char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/*
 * read_ihex_chunks 에 넘기기 전에 HEX 를 엄격히 검사한다: 모든 줄이 ':' + 16진 2자리 짝, 바이트 수 필드 = 실제 길이,
 * 체크섬, 유형 00–05, EOF 레코드(01)가 꼭 하나 있고 그 뒤에는 빈 줄만. 유형 02(세그먼트 주소)는 simavr 가 주소를
 * 더하지 않고 OR 하므로 64 KiB 경계 값만 받는다. 통과하면 0 과 데이터 바이트 합, 아니면 -1 과 줄 번호(1부터).
 */
static int hex_validate(const unsigned char *buf, size_t len, unsigned long *data_bytes, unsigned long *bad_line)
{
	unsigned char rec[(HEX_MAX_RECORD - 1) / 2];
	unsigned long line = 0;
	int seen_eof = 0;
	size_t i = 0;

	*data_bytes = 0;
	while (i < len) {
		size_t start = i, end, n, k;
		unsigned sum = 0;

		while (i < len && buf[i] != '\n')
			i++;
		end = i;
		if (i < len)
			i++;   /* '\n' */
		*bad_line = ++line;
		if (end > start && buf[end - 1] == '\r')
			end--;
		n = end - start;
		if (seen_eof) {
			if (n) { hex_why = "EOF 레코드 뒤에 내용이 있음"; return -1; }
			continue;
		}
		if (!n) { hex_why = "빈 줄"; return -1; }
		if (buf[start] != ':') { hex_why = "':' 로 시작하지 않음"; return -1; }
		if (n < 11 || n > HEX_MAX_RECORD || (n - 1) % 2) { hex_why = "레코드 길이가 맞지 않음"; return -1; }
		k = (n - 1) / 2;
		for (size_t j = 0; j < k; j++) {
			int hi = hex_nibble(buf[start + 1 + 2 * j]), lo = hex_nibble(buf[start + 2 + 2 * j]);
			if (hi < 0 || lo < 0) { hex_why = "16진 숫자가 아닌 문자"; return -1; }
			rec[j] = (unsigned char)(hi << 4 | lo);
			sum += rec[j];
		}
		if ((size_t)rec[0] + 5 != k) { hex_why = "바이트 수 필드가 실제 길이와 다름"; return -1; }
		if (sum & 0xff) { hex_why = "체크섬 오류"; return -1; }
		switch (rec[3]) {
		case 0:   /* 데이터 (길이 0 레코드는 simavr 도 건너뜀) */
			*data_bytes += rec[0];
			break;
		case 1:   /* EOF */
			if (rec[0]) { hex_why = "EOF 레코드에 데이터가 있음"; return -1; }
			seen_eof = 1;
			break;
		case 2:   /* 확장 세그먼트 주소 (값 × 16) */
			if (rec[0] != 2) { hex_why = "유형 02 레코드 길이"; return -1; }
			if ((((unsigned long)rec[4] << 8 | rec[5]) << 4) & 0xffffu) {
				hex_why = "유형 02 세그먼트 주소가 64 KiB 경계가 아님";
				return -1;
			}
			break;
		case 3:   /* 시작 세그먼트 주소 — 무시 */
		case 5:   /* 시작 선형 주소 — 무시 */
			if (rec[0] != 4) { hex_why = "시작 주소 레코드 길이"; return -1; }
			break;
		case 4:   /* 확장 선형 주소 (상위 16비트) */
			if (rec[0] != 2) { hex_why = "유형 04 레코드 길이"; return -1; }
			break;
		default:
			hex_why = "알 수 없는 레코드 유형";
			return -1;
		}
	}
	if (!seen_eof) {
		*bad_line = line;
		hex_why = "EOF 레코드(유형 01)가 없음";
		return -1;
	}
	return 0;
}

/* fd 의 내용 전체 (처음부터, 오프셋을 바꾸지 않음). 실패하면 NULL */
static unsigned char *read_whole_fd(int fd, size_t *len_out)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		note("HEX 입력 fd %d 를 확인하지 못함 (%s)", fd, strerror(errno));
		return NULL;
	}
	if (!S_ISREG(st.st_mode)) {
		note("HEX 입력 fd %d 가 일반 파일·memfd 가 아님", fd);
		return NULL;
	}
	if (st.st_size <= 0 || (unsigned long long)st.st_size > HEX_MAX_FILE) {
		note("HEX 입력 크기 %lld 바이트가 허용 범위(1..%u) 밖", (long long)st.st_size, HEX_MAX_FILE);
		return NULL;
	}
	size_t len = (size_t)st.st_size, got = 0;
	unsigned char *buf = malloc(len);
	if (!buf) {
		note("메모리 부족");
		return NULL;
	}
	while (got < len) {
		ssize_t n = pread(fd, buf + got, len - got, (off_t)got);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			note("HEX 입력을 끝까지 읽지 못함");
			free(buf);
			return NULL;
		}
		got += (size_t)n;
	}
	*len_out = len;
	return buf;
}

static void free_chunks(fw_chunk_t *c)
{
	while (c) {
		fw_chunk_t *next = c->next;
		free(c);
		c = next;
	}
}

/*
 * HEX 를 검사하고 simavr read_ihex_chunks 로 /proc/self/fd/<fd> 를 읽어 덩어리를 직접 나눈다:
 *   0x800000 미만          플래시 (MCU 플래시 크기 안)
 *   0x810000 ~ 0x81FFFF    EEPROM (MCU EEPROM 크기 안 — 시뮬레이션 EEPROM 에 적재)
 *   0x820000 ~ 0x85FFFF    퓨즈·잠금·서명 — 무시 (알림만)
 *   그 밖                  거부
 * 성공하면 0 (f->chunks 에 플래시·EEPROM 덩어리), 실패하면 -1.
 */
static int load_hex(avr_t *avr, int fd, elf_firmware_t *f)
{
	size_t len = 0;
	unsigned long data_bytes = 0, bad_line = 0, total = 0, ignored = 0;
	unsigned char *buf = read_whole_fd(fd, &len);
	if (!buf)
		return -1;
	int bad = hex_validate(buf, len, &data_bytes, &bad_line);
	free(buf);
	if (bad) {
		note("HEX %lu 번째 줄: %s", bad_line, hex_why);
		return -1;
	}

	char path[64];
	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	fw_chunk_t *chunks = NULL;
	read_ihex_chunks(path, &chunks);
	if (!chunks) {
		note("HEX 에 적재할 데이터가 없음");
		return -1;
	}

	const uint64_t flash_size = (uint64_t)avr->flashend + 1;
	const uint64_t ee_size = avr->e2end ? (uint64_t)avr->e2end + 1 : 0;
	fw_chunk_t *keep = NULL, **tail = &keep, *c = chunks, *next;
	int rc = 0;
	for (; c; c = next) {
		next = c->next;
		c->next = NULL;
		total += c->size;
		uint64_t end = (uint64_t)c->addr + c->size;
		if (rc) {
			free(c);
		} else if (c->addr < AVR_SEGMENT_OFFSET_DATA) {
			if (end > flash_size) {
				note("플래시 크기 0x%llx 를 넘는 데이터 (주소 0x%x, %u 바이트)", (unsigned long long)flash_size, c->addr, c->size);
				rc = -1;
				free(c);
				continue;
			}
			c->type = FLASH;
			*tail = c;
			tail = &c->next;
		} else if (c->addr >= AVR_SEGMENT_OFFSET_EEPROM && c->addr < AVR_SEGMENT_OFFSET_FUSES) {
			uint64_t off = c->addr - AVR_SEGMENT_OFFSET_EEPROM;
			if (off + c->size > ee_size) {
				note("EEPROM 크기 0x%llx 를 넘는 데이터 (오프셋 0x%llx, %u 바이트)", (unsigned long long)ee_size,
				     (unsigned long long)off, c->size);
				rc = -1;
				free(c);
				continue;
			}
			c->type = EEPROM;
			c->addr = (uint32_t)off;
			*tail = c;
			tail = &c->next;
		} else if (c->addr >= AVR_SEGMENT_OFFSET_FUSES && end <= SEGMENT_IGNORED_END) {
			ignored += c->size;
			free(c);
		} else {
			note("지원하지 않는 주소 영역의 데이터 (주소 0x%x, %u 바이트)", c->addr, c->size);
			rc = -1;
			free(c);
		}
	}
	if (!rc && total != data_bytes) {   /* 두 해석기가 같은 바이트 수를 봐야 한다 */
		note("HEX 해석 결과가 맞지 않음 (데이터 %lu 바이트 중 %lu 바이트만 읽힘)", data_bytes, total);
		rc = -1;
	}
	if (rc) {
		free_chunks(keep);
		return -1;
	}
	if (ignored)
		note("퓨즈·잠금·서명 레코드 %lu 바이트는 무시함", ignored);
	if (!keep) {
		note("플래시·EEPROM 에 적재할 데이터가 없음");
		return -1;
	}
	f->chunks = keep;
	return 0;
}

/*
 * 플래시 버퍼 넓히기 (보안 수정 — 꼭 avr_init 바로 뒤).
 * 고정 커밋의 simavr 는 LPM(16비트 Z), ELPM(RAMPZ:Z, 24비트), SPM 페이지 지우기·쓰기에서 avr->flash[z] 를 범위 검사
 * 없이 쓰는데, avr_init 은 flashend+4 바이트만 잡는다 → 펌웨어가 호스트 힙을 읽고 쓸 수 있다 (재현됨).
 * RAMPZ 가 없는 MCU(ATmega328P 등)도 ELPM 은 "잘못된 명령" 로그만 남기고 RAMPZ 대신 r0 으로 24비트 색인을 만들어
 * 읽는다 (sim_core.c) — 그래서 MCU 와 상관없이 24비트 색인 + SPM 한 페이지(최대 256 바이트, 여유 1024)까지 덮는다.
 * 실제 플래시 뒤는 지운 상태(0xFF)로 읽히고, 그 영역에 대한 SPM 은 이 여유 버퍼에만 닿는다.
 * 원래 버퍼의 플래시와 simavr 가 flashend 뒤에 둔 AVR_OVERFLOW_OPCODE(2바이트)는 그대로 옮긴다.
 */
static int widen_flash(avr_t *avr)
{
	const size_t need = ((size_t)1 << 24) + 1024 + 4;
	uint8_t *nf = malloc(need);
	if (!nf)
		return -1;
	memset(nf, 0xff, need);
	memcpy(nf, avr->flash, (size_t)avr->flashend + 3);   /* 플래시 + AVR_OVERFLOW_OPCODE (마지막 1바이트는 초기화 안 된 값) */
	free(avr->flash);
	avr->flash = nf;
	return 0;
}

/* ---------------------------------------------------------------------------------------------------------------
 * 인자
 * ------------------------------------------------------------------------------------------------------------- */

static void usage(void)
{
	fputs("사용법: pweh_avr_run --version\n"
	      "        pweh_avr_run --mcu NAME --freq HZ [--uart N] [--realtime] [--max-cycles N] (--hex-fd N | FILE.hex)\n",
	      stderr);
	exit(2);
}

/* 십진수만 (부호·공백·접두 없음), 범위 [lo, hi] */
static int parse_uint(const char *s, unsigned long long lo, unsigned long long hi, unsigned long long *out)
{
	unsigned long long v = 0;
	if (!s || !*s)
		return -1;
	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		unsigned d = (unsigned)(*p - '0');
		if (v > (hi - d) / 10)
			return -1;
		v = v * 10 + d;
	}
	if (v < lo)
		return -1;
	*out = v;
	return 0;
}

static int valid_mcu_name(const char *s)
{
	size_t n = strlen(s);
	if (n < 1 || n > 31)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')))
			return 0;
	return 1;
}

int main(int argc, char *argv[])
{
	/* 서버가 stdout 을 닫으면 SIGPIPE 로 죽지 않고 write 가 EPIPE 를 받아 _exit(5) 한다 */
	signal(SIGPIPE, SIG_IGN);

	if (argc == 2 && !strcmp(argv[1], "--version")) {
		printf("pweh_avr_run %s simavr %s\n", PWEH_AVR_RUN_VERSION, PWEH_SIMAVR_COMMIT);
		return 0;
	}

	const char *mcu = NULL, *file = NULL;
	unsigned long long freq = 0, max_cycles = 0, hex_fd = 0;
	int have_freq = 0, have_uart = 0, have_max = 0, have_fd = 0;
	char uart = '0';
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;
		if (!strcmp(a, "--mcu") && v && !mcu) {
			mcu = v;
			i++;
		} else if (!strcmp(a, "--freq") && v && !have_freq) {
			if (parse_uint(v, 1000, 64000000, &freq))
				usage();
			have_freq = 1;
			i++;
		} else if (!strcmp(a, "--uart") && v && !have_uart) {
			if (v[0] < '0' || v[0] > '3' || v[1])
				usage();
			uart = v[0];
			have_uart = 1;
			i++;
		} else if (!strcmp(a, "--max-cycles") && v && !have_max) {
			if (parse_uint(v, 1, 1ULL << 62, &max_cycles))
				usage();
			have_max = 1;
			i++;
		} else if (!strcmp(a, "--hex-fd") && v && !have_fd) {
			if (parse_uint(v, 3, 1 << 20, &hex_fd))
				usage();
			have_fd = 1;
			i++;
		} else if (!strcmp(a, "--realtime") && !g_realtime) {
			g_realtime = 1;
		} else if (a[0] != '-' && !file) {
			file = a;
		} else {
			usage();
		}
	}
	if (!mcu || !valid_mcu_name(mcu) || !have_freq || (have_fd == !!file))
		usage();
	if (file) {   /* 직접 실행: 이름이 .hex 로 끝나는 파일만 (ELF 경로 없음) */
		const char *dot = strrchr(file, '.');
		if (!dot || strcasecmp(dot, ".hex"))
			usage();
	}

	/* UART 출력은 원래 stdout 의 복제로만 보내고, fd 1 은 stderr 로 돌린다
	 * (libsimavr 곳곳의 printf·LOG_OUTPUT 이 UART 바이트 흐름에 섞이지 않게). */
	uart_fd = dup(1);
	if (uart_fd < 0 || dup2(2, 1) < 0)
		return 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	avr_global_logger_set(logger);

	avr_t *avr = avr_make_mcu_by_name(mcu);
	if (!avr) {
		note("알 수 없는 MCU '%s'", mcu);
		return 2;
	}
	avr->frequency = (uint32_t)freq;
	avr_init(avr);
	if (widen_flash(avr)) {
		note("메모리 부족 (플래시 버퍼)");
		return 2;
	}
	avr->log = LOG_ERROR;
	avr->gdb_port = 0;   /* 충돌해도 GDB 서버를 열지 않는다 (함수도 빈 함수) */

	uint32_t flags = AVR_UART_FLAG_POLL_SLEEP;   /* STDIO(줄 버퍼·색 코드) 끔 */
	avr_ioctl(avr, AVR_IOCTL_UART_SET_FLAGS(uart), &flags);
	avr_irq_t *out_irq = avr_io_getirq(avr, AVR_IOCTL_UART_GETIRQ(uart), UART_IRQ_OUTPUT);
	avr_irq_t *in_irq = avr_io_getirq(avr, AVR_IOCTL_UART_GETIRQ(uart), UART_IRQ_INPUT);
	avr_irq_t *xon_irq = avr_io_getirq(avr, AVR_IOCTL_UART_GETIRQ(uart), UART_IRQ_OUT_XON);
	avr_irq_t *xoff_irq = avr_io_getirq(avr, AVR_IOCTL_UART_GETIRQ(uart), UART_IRQ_OUT_XOFF);
	if (!out_irq || !in_irq || !xon_irq || !xoff_irq) {
		note("MCU '%s' 에 UART%c 가 없음", mcu, uart);
		return 2;
	}

	int fd = (int)hex_fd;
	if (file) {
		fd = open(file, O_RDONLY | O_CLOEXEC | O_NONBLOCK);   /* FIFO 등에서 막히지 않게 — 일반 파일만 받는다 (read_whole_fd) */
		if (fd < 0) {
			note("HEX 파일을 열지 못함 (%s)", strerror(errno));
			return 1;
		}
	}
	elf_firmware_t f;
	memset(&f, 0, sizeof f);
	f.frequency = (uint32_t)freq;
	if (load_hex(avr, fd, &f))
		return 1;
	avr_load_firmware(avr, &f);   /* 플래시는 넓힌 버퍼(flashend+1 까지), EEPROM 은 AVR_IOCTL_EEPROM_SET (크기 검사) */

	g_in_irq = in_irq;
	avr_irq_register_notify(out_irq, uart_out_hook, NULL);
	avr_irq_register_notify(xon_irq, xon_hook, NULL);
	avr_irq_register_notify(xoff_irq, xoff_hook, NULL);
	avr->sleep = pweh_sleep;

	int state = cpu_Running, rc = 0;
	clock_gettime(CLOCK_MONOTONIC, &g_t0);
	for (;;) {
		if (!avr_cycle_timer_status(avr, heartbeat, NULL))   /* 처음, 그리고 리셋(워치독)이 타이머를 지운 뒤 */
			avr_cycle_timer_register(avr, heartbeat_period(avr), heartbeat, NULL);
		for (int k = 0; k < RUN_BATCH; k++) {
			state = avr_run(avr);
			if (state == cpu_Done || state == cpu_Crashed)
				goto out;
		}
		int wait_ms = 0;
		if (g_realtime) {   /* 시뮬레이션이 벽시계보다 2 ms 넘게 앞서면 그만큼 stdin 을 기다리며 쉰다 */
			double ahead = sim_seconds(avr, avr->cycle) - wall_seconds();
			if (ahead > 0.002)
				wait_ms = wait_ms_for(ahead);
		}
		pump_input(wait_ms);
		if (max_cycles && avr->cycle >= max_cycles) {
			rc = 4;
			break;
		}
	}
out:
	if (state == cpu_Done)
		rc = 0;
	else if (state == cpu_Crashed)
		rc = 3;
	note("state=%s cycles=%llu pc=0x%04x", rc == 0 ? "done" : rc == 3 ? "crashed" : "max-cycles",
	     (unsigned long long)avr->cycle, (unsigned)avr->pc);
	avr_terminate(avr);
	return rc;
}
