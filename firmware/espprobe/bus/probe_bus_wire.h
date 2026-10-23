/* SPDX-License-Identifier: MIT
 * 고정 bus payload dispatcher. production HELLO/전송/HAL 권한을 추가하지 않는다. */
#ifndef PWEH_PROBE_BUS_WIRE_H
#define PWEH_PROBE_BUS_WIRE_H
#include "probe_bus.h"

#define PROBE_BUS_WIRE_SPI_PROBE 0x10u
#define PROBE_BUS_WIRE_READ_BEGIN 0x11u
#define PROBE_BUS_WIRE_READ_DONE 0x12u
#define PROBE_BUS_WIRE_MAX_FEED 16384u

typedef bool (*probe_bus_wire_emit)(void *, const uint8_t *, size_t);
typedef struct {
    probe_bus_ctx *bus;
    probe_bus_wire_emit emit;
    void *emit_user;
    probe_bus_binding binding;
    probe_read_plan plan;
    uint32_t last_req_seq, last_hb_seq, begin_seq;
    bool initialized, busy, emitting, terminal, cleanup, begun, done, in_step, delivered;
    size_t rx_size, cache_next;
    uint8_t rx[PWEH_MAX_WIRE], out[PWEH_MAX_WIRE];
    pweh_frame frame, response;
    probe_bus_chunk chunk;
    pweh_cache cache[4], tombstone;
} probe_bus_wire_ctx;

/* 최초 caller storage에만 초기화한다. 살아 있는 ctx나 HAL callback에서 재초기화하지 않는다. */
bool probe_bus_wire_init(probe_bus_wire_ctx *, probe_bus_ctx *, probe_bus_wire_emit, void *);
pweh_result probe_bus_wire_feed(probe_bus_wire_ctx *, const uint8_t *, size_t, uint64_t);
pweh_result probe_bus_wire_poll(probe_bus_wire_ctx *, uint64_t);
/* 기존 HAL deliver callback 안에서만 호출한다. 실패 시 기존 bus가 해제를 수행한다. */
bool probe_bus_wire_deliver(probe_bus_wire_ctx *, const probe_bus_chunk *);
void probe_bus_wire_abort(probe_bus_wire_ctx *, pweh_release_reason);
#endif
