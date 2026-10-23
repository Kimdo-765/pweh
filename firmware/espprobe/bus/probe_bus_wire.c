/* SPDX-License-Identifier: MIT
 * 고정 bus 요청의 단일 cache/heartbeat/종료 권위. 원래 bus 알고리즘은 호출만 한다. */
#include "probe_bus_wire.h"
#include <string.h>

enum { W_REQ=1, W_RSP=2, W_EVT=3, W_DATA=4, W_HB=5 };
enum { W_RELEASE=2, W_BYE=3, W_ABORT=4 };

static bool live(const probe_bus_wire_ctx *w) {
    return w->bus->state != PROBE_BUS_STATE_RELEASED &&
           w->bus->binding.session == w->binding.session &&
           w->bus->binding.usb_session == w->binding.usb_session &&
           !memcmp(w->bus->binding.boot_id, w->binding.boot_id, 16);
}

static pweh_result fail(probe_bus_wire_ctx *w, pweh_release_reason reason) {
    w->terminal = true;
    w->rx_size = 0;
    probe_bus_release(w->bus, reason);
    return PWEH_INVALID;
}

bool probe_bus_wire_init(probe_bus_wire_ctx *w, probe_bus_ctx *bus,
                         probe_bus_wire_emit emit, void *user) {
    if (!w || !bus || !emit || !bus->initialized || bus->busy || bus->in_callback || bus->guard_active ||
        bus->state != PROBE_BUS_STATE_READY || !bus->claimed_mask || !bus->have_binding ||
        !bus->binding.session || !bus->binding.usb_session || !bus->binding.hello_seq ||
        bus->binding.hb_ms != 1000u || bus->deadline_ms <= bus->now_ms ||
        bus->last_req_seq != bus->binding.hello_seq || bus->credit) return false;
    memset(w, 0, sizeof(*w));
    w->bus = bus; w->emit = emit; w->emit_user = user;
    w->binding = bus->binding;
    w->last_req_seq = bus->binding.hello_seq;
    w->last_hb_seq = bus->last_hb_seq;
    w->initialized = true;
    return true;
}

void probe_bus_wire_abort(probe_bus_wire_ctx *w, pweh_release_reason reason) {
    if (!w || !w->initialized || w->busy || w->emitting || w->terminal) return;
    (void)fail(w, reason);
}

static bool emit_bytes(probe_bus_wire_ctx *w, const uint8_t *data, size_t size) {
    if (w->emitting || w->terminal) return false;
    w->emitting = true;
    bool ok = w->emit(w->emit_user, data, size);
    w->emitting = false;
    return ok;
}

static pweh_result send(probe_bus_wire_ctx *w, const uint8_t *data, size_t size) {
    if (!emit_bytes(w, data, size)) return fail(w, PWEH_RELEASE_TRANSPORT);
    if (!w->cleanup && !live(w)) return fail(w, PWEH_RELEASE_INTERNAL);
    return PWEH_OK;
}

static bool wire_status(probe_bus_result result, uint16_t *out) {
    switch (result) {
    case PROBE_BUS_OK: *out=0; return true;
    case PROBE_BUS_POLICY: *out=1; return true;
    case PROBE_BUS_UNSUPPORTED: *out=2; return true;
    case PROBE_BUS_RELEASED: *out=3; return true;
    case PROBE_BUS_SESSION: *out=4; return true;
    case PROBE_BUS_SEQUENCE: *out=5; return true;
    case PROBE_BUS_BUSY: *out=6; return true;
    case PROBE_BUS_INVALID: *out=7; return true;
    case PROBE_BUS_REPLAY: *out=8; return true;
    default: return false;
    }
}

static void put64(uint8_t *out, uint64_t value) {
    for (unsigned i=0; i<8; ++i) out[i]=(uint8_t)(value >> (8u*i));
}

static pweh_result response(probe_bus_wire_ctx *w, probe_bus_result result,
                            const probe_spi_info *info, pweh_cache *save) {
    uint16_t status;
    if (!wire_status(result, &status)) return fail(w, PWEH_RELEASE_INTERNAL);
    pweh_frame *out = &w->response;
    memset(out, 0, sizeof(*out));
    out->version=1; out->type=W_RSP; out->op=w->frame.type == W_HB ? 0u : w->frame.op;
    out->seq=w->frame.seq; out->session=w->frame.session;
    out->flags=status ? 1u : 0u; out->length=2;
    pweh_put16(out->payload, status);
    if (info && !status) {
        out->length=19;
        pweh_put32(out->payload+2, w->binding.usb_session);
        memcpy(out->payload+6, info->jedec_id, 3);
        out->payload[9]=info->sr1;
        out->payload[10]=(uint8_t)((info->sfdp_valid ? 1u : 0u) |
                                  (info->read4_supported ? 2u : 0u) |
                                  (info->fast4_supported ? 4u : 0u));
        put64(out->payload+11, info->capacity);
    }
    size_t size=0;
    if (pweh_frame_encode(out, w->out, sizeof(w->out), &size) != PWEH_OK)
        return fail(w, PWEH_RELEASE_INTERNAL);
    if (save) {
        memset(save, 0, sizeof(*save));
        save->seq=w->frame.seq; save->request_size=w->rx_size; save->response_size=size;
        memcpy(save->request, w->rx, w->rx_size);
        memcpy(save->response, w->out, size);
    }
    return send(w, w->out, size);
}

static bool same_request(const probe_bus_wire_ctx *w, const pweh_cache *row) {
    return row->seq == w->frame.seq && row->request_size == w->rx_size &&
           !memcmp(row->request, w->rx, w->rx_size);
}

static pweh_result heartbeat(probe_bus_wire_ctx *w) {
    const pweh_frame *f=&w->frame;
    if (f->op || f->length || f->credit > PROBE_BUS_MAX_CREDIT || f->flags)
        return response(w, PROBE_BUS_POLICY, NULL, NULL);
    if (w->cleanup) return response(w, PROBE_BUS_RELEASED, NULL, NULL);
    if (f->seq <= w->last_hb_seq) return PWEH_OK;
    probe_bus_result r=probe_bus_credit(w->bus, f->session, w->binding.usb_session,
                                       f->seq, f->credit, w->bus->now_ms);
    if (!live(w)) return fail(w, PWEH_RELEASE_INTERNAL);
    if (r != PROBE_BUS_OK) return response(w, r, NULL, NULL);
    w->last_hb_seq=f->seq;
    return send(w, w->rx, w->rx_size);
}

static probe_bus_result begin(probe_bus_wire_ctx *w) {
    const pweh_frame *f=&w->frame;
    if (f->length != 15) return PROBE_BUS_INVALID;
    if (pweh_get32(f->payload) != w->binding.usb_session) return PROBE_BUS_SESSION;
    if (f->payload[4] > 1 || f->payload[5] ||
        (f->payload[6] != 1 && f->payload[6] != 2)) return PROBE_BUS_POLICY;
    probe_read_plan plan={0};
    plan.kind=f->payload[4] == 0 ? PROBE_SPI_READ_RANGE : PROBE_I2C_EEPROM_READ;
    plan.device_index=0; plan.passes=f->payload[6];
    plan.offset=pweh_get32(f->payload+7); plan.length=pweh_get32(f->payload+11);
    if (!plan.length || (uint64_t)plan.offset+plan.length > (UINT64_C(1)<<32)) return PROBE_BUS_INVALID;
    if (w->begun) return PROBE_BUS_BUSY;
    probe_bus_result r=probe_bus_begin(w->bus, f->seq, &plan, w->bus->now_ms);
    if (r == PROBE_BUS_OK) { w->begun=true; w->begin_seq=f->seq; w->plan=plan; }
    return r;
}

static pweh_result request(probe_bus_wire_ctx *w) {
    const pweh_frame *f=&w->frame;
    if (w->cleanup) {
        if (same_request(w, &w->tombstone))
            return send(w, w->tombstone.response, w->tombstone.response_size);
        return response(w, PROBE_BUS_RELEASED, NULL, NULL);
    }
    for (size_t i=0; i<4; ++i) {
        const pweh_cache *row=&w->cache[i];
        if (row->seq == f->seq) {
            if (same_request(w, row)) return send(w, row->response, row->response_size);
            return response(w, PROBE_BUS_SEQUENCE, NULL, NULL);
        }
    }
    if (f->seq <= w->last_req_seq) return response(w, PROBE_BUS_REPLAY, NULL, NULL);
    w->last_req_seq=f->seq;
    probe_bus_result r=PROBE_BUS_UNSUPPORTED;
    probe_spi_info info={0};
    const probe_spi_info *extra=NULL;
    if (f->op == W_RELEASE || f->op == W_BYE || f->op == W_ABORT) {
        if (f->length) r=PROBE_BUS_INVALID;
        else {
            w->cleanup=true;
            probe_bus_release(w->bus, f->op == W_RELEASE ? PWEH_RELEASE_REQUEST :
                              (f->op == W_BYE ? PWEH_RELEASE_BYE : PWEH_RELEASE_ABORT));
            return response(w, PROBE_BUS_OK, NULL, &w->tombstone);
        }
    } else if (f->op == PROBE_BUS_WIRE_SPI_PROBE) {
        if (f->length != 4) r=PROBE_BUS_INVALID;
        else if (pweh_get32(f->payload) != w->binding.usb_session) r=PROBE_BUS_SESSION;
        else { r=probe_spi_probe(w->bus, f->seq, w->bus->now_ms, &info); extra=&info; }
    } else if (f->op == PROBE_BUS_WIRE_READ_BEGIN) r=begin(w);
    if (!live(w)) return fail(w, PWEH_RELEASE_INTERNAL);
    pweh_cache *slot=&w->cache[w->cache_next];
    w->cache_next=(w->cache_next+1u)%4u;
    return response(w, r, extra, slot);
}

static pweh_result dispatch(probe_bus_wire_ctx *w) {
    if (!w->cleanup && probe_bus_poll(w->bus, w->bus->now_ms) != PROBE_BUS_OK)
        return fail(w, PWEH_RELEASE_INTERNAL);
    if (w->frame.session != w->binding.session)
        return response(w, PROBE_BUS_SESSION, NULL, NULL);
    if (w->frame.type == W_HB) return heartbeat(w);
    if (w->frame.type != W_REQ || w->frame.flags || w->frame.credit)
        return response(w, PROBE_BUS_POLICY, NULL, NULL);
    return request(w);
}

static pweh_result enter(probe_bus_wire_ctx *w, uint64_t now_ms) {
    if (!w || !w->initialized) return PWEH_BOUNDS;
    if (w->terminal || w->busy || w->emitting) return PWEH_INVALID;
    w->busy=true;
    if (!w->cleanup && (probe_bus_poll(w->bus, now_ms) != PROBE_BUS_OK || !live(w))) {
        w->busy=false;
        return fail(w, PWEH_RELEASE_INTERNAL);
    }
    return PWEH_OK;
}

pweh_result probe_bus_wire_feed(probe_bus_wire_ctx *w, const uint8_t *data, size_t size, uint64_t now_ms) {
    if ((!data && size) || size > PROBE_BUS_WIRE_MAX_FEED) return PWEH_BOUNDS;
    pweh_result result=enter(w, now_ms);
    if (result != PWEH_OK) return result;
    for (size_t i=0; i<size; ++i) {
        if (data[i] && w->rx_size >= PWEH_MAX_ENCODED) {
            result=fail(w, PWEH_RELEASE_TRANSPORT); break;
        }
        w->rx[w->rx_size++]=data[i];
        if (!data[i]) {
            if (pweh_frame_decode(w->rx, w->rx_size, &w->frame) != PWEH_OK) {
                result=fail(w, PWEH_RELEASE_TRANSPORT); break;
            }
            result=dispatch(w);
            w->rx_size=0;
            if (result != PWEH_OK) break;
        }
    }
    w->busy=false;
    return result;
}

bool probe_bus_wire_deliver(probe_bus_wire_ctx *w, const probe_bus_chunk *chunk) {
    if (!w || !w->initialized || !chunk || !w->busy || !w->in_step || w->emitting ||
        w->terminal || w->cleanup || !w->begun || w->done || w->delivered ||
        !w->bus->in_callback || !live(w) || w->bus->state != PROBE_BUS_STATE_RUNNING) return false;
    const probe_bus_ctx *bus=w->bus;
    if (bus->plan.kind != w->plan.kind || bus->plan.device_index || bus->plan.passes != w->plan.passes ||
        bus->plan.offset != w->plan.offset || bus->plan.length != w->plan.length ||
        bus->progress >= w->plan.length || bus->pass_index >= w->plan.passes) return false;
    uint64_t address=(uint64_t)w->plan.offset+bus->progress;
    uint64_t remaining=(uint64_t)w->plan.length-bus->progress;
    uint16_t cap=w->plan.kind == PROBE_SPI_READ_RANGE ? PROBE_BUS_CHUNK_BYTES : PROBE_BUS_I2C_CHUNK_BYTES;
    uint16_t length=remaining < cap ? (uint16_t)remaining : cap;
    bool done=remaining == length && bus->pass_index+1u == w->plan.passes;
    if (address > UINT32_MAX || chunk->offset != address || chunk->pass_index != bus->pass_index ||
        chunk->length != length || chunk->done != done) return false;
    pweh_frame *out=&w->response;
    memset(out, 0, sizeof(*out));
    out->version=1; out->type=W_DATA; out->op=PROBE_BUS_WIRE_READ_BEGIN;
    out->seq=w->begin_seq; out->session=w->binding.session; out->length=(uint16_t)(11u+length);
    pweh_put32(out->payload, w->binding.usb_session); out->payload[4]=chunk->pass_index;
    pweh_put32(out->payload+5, chunk->offset); pweh_put16(out->payload+9, length);
    memcpy(out->payload+11, chunk->bytes, length);
    size_t size=0;
    if (pweh_frame_encode(out, w->out, sizeof(w->out), &size) != PWEH_OK) return false;
    w->delivered=true;
    /* emit 실패의 실제 해제는 이 callback을 호출한 기존 bus step이 수행한다. */
    return emit_bytes(w, w->out, size);
}

static pweh_result done_event(probe_bus_wire_ctx *w) {
    pweh_frame *out=&w->response;
    memset(out, 0, sizeof(*out));
    out->version=1; out->type=W_EVT; out->op=PROBE_BUS_WIRE_READ_DONE;
    out->seq=w->begin_seq; out->session=w->binding.session; out->length=13;
    pweh_put32(out->payload, w->binding.usb_session); out->payload[4]=w->plan.passes;
    pweh_put32(out->payload+5, w->plan.offset); pweh_put32(out->payload+9, w->plan.length);
    size_t size=0;
    if (pweh_frame_encode(out, w->out, sizeof(w->out), &size) != PWEH_OK)
        return fail(w, PWEH_RELEASE_INTERNAL);
    w->done=true;
    return send(w, w->out, size);
}

pweh_result probe_bus_wire_poll(probe_bus_wire_ctx *w, uint64_t now_ms) {
    pweh_result result=enter(w, now_ms);
    if (result != PWEH_OK) return result;
    if (!w->cleanup && w->begun && !w->done) {
        w->in_step=true; w->delivered=false;
        probe_bus_result r=probe_bus_step(w->bus, w->bus->now_ms, &w->chunk);
        w->in_step=false;
        if (!live(w) || (r != PROBE_BUS_OK && r != PROBE_BUS_NO_CREDIT))
            result=fail(w, PWEH_RELEASE_INTERNAL);
        else if (r == PROBE_BUS_OK) {
            if (!w->delivered) result=fail(w, PWEH_RELEASE_INTERNAL);
            else if (w->bus->state == PROBE_BUS_STATE_DONE) result=done_event(w);
        }
    }
    w->busy=false;
    return result;
}
