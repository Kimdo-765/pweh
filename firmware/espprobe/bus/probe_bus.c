/* SPDX-License-Identifier: MIT
 * 고정 범위/credit/세대/해제의 호스트 시험 계층. 실제 GPIO·wire dispatcher는 없다. */
#include "probe_bus.h"
#include <string.h>

static bool live(const probe_bus_ctx *ctx) {
    return ctx->state != PROBE_BUS_STATE_RELEASED && ctx->binding.session != 0;
}

void probe_bus_release(probe_bus_ctx *ctx, pweh_release_reason reason) {
    if (!ctx || !ctx->initialized || !live(ctx)) return;
    uint64_t mask = ctx->claimed_mask;
    bool callback = ctx->in_callback;
    /* abort가 관찰하는 시점에는 진행/권한/credit이 먼저 사라져 있어야 한다. */
    ctx->state = PROBE_BUS_STATE_RELEASED;
    ctx->binding.session = 0;
    ctx->deadline_ms = 0;
    ctx->credit = 0;
    ctx->claimed_mask = 0;
    ctx->progress = 0;
    ctx->pass_index = 0;
    ctx->last_req_seq = ctx->last_hb_seq = 0;
    ctx->sfdp_active = false;
    ctx->sfdp_read_bytes = 0;
    memset(&ctx->plan, 0, sizeof(ctx->plan));
    memset(&ctx->spi_info, 0, sizeof(ctx->spi_info));
    memset(ctx->cache, 0, sizeof(ctx->cache));
    memset(&ctx->scratch, 0, sizeof(ctx->scratch));
    ctx->cache_next = 0;
    ctx->last_release_reason = reason;
    ctx->in_callback = true;
    ctx->hal.abort(ctx->hal.user, mask, reason);
    ctx->in_callback = callback;
}

static probe_bus_result release_result(probe_bus_ctx *ctx, pweh_release_reason reason) {
    probe_bus_release(ctx, reason);
    return PROBE_BUS_RELEASED;
}

static probe_bus_result clock_sample(probe_bus_ctx *ctx) {
    uint64_t now = 0;
    ctx->in_callback = true;
    bool ok = ctx->hal.clock_ms(ctx->hal.user, &now);
    ctx->in_callback = false;
    if (!live(ctx)) return PROBE_BUS_RELEASED;
    if (!ok) return release_result(ctx, PWEH_RELEASE_INTERNAL);
    if (now < ctx->now_ms) return release_result(ctx, PWEH_RELEASE_CLOCK);
    ctx->now_ms = now;
    if (now >= ctx->deadline_ms) return release_result(ctx, PWEH_RELEASE_HEARTBEAT);
    return PROBE_BUS_OK;
}

static probe_bus_result guard(probe_bus_ctx *ctx, bool voltage) {
    if (!ctx || !ctx->initialized) return PROBE_BUS_INVALID;
    if (ctx->in_callback || ctx->guard_active) return PROBE_BUS_BUSY;
    if (!live(ctx)) return PROBE_BUS_RELEASED;
    ctx->guard_active = true;
    probe_bus_result result = clock_sample(ctx);
    if (result == PROBE_BUS_OK && voltage) {
        probe_vref_sample sample = {0};
        ctx->in_callback = true;
        bool ok = ctx->hal.read_vref(ctx->hal.user, &sample);
        ctx->in_callback = false;
        if (!live(ctx)) result = PROBE_BUS_RELEASED;
        else if (!ok) result = release_result(ctx, PWEH_RELEASE_INTERNAL);
        else result = clock_sample(ctx);
        if (result == PROBE_BUS_OK) {
            uint64_t mv10 = (uint64_t)sample.millivolts * 10u;
            if (!sample.valid || sample.sampled_at_ms > ctx->now_ms ||
                ctx->now_ms - sample.sampled_at_ms > 1u ||
                sample.millivolts < 3000u || sample.millivolts > 3600u ||
                mv10 < (uint64_t)ctx->wiring.declared_mv * 9u ||
                mv10 > (uint64_t)ctx->wiring.declared_mv * 11u)
                result = release_result(ctx, PWEH_RELEASE_INTERNAL);
        }
    }
    ctx->guard_active = false;
    return result;
}

probe_bus_result probe_bus_guard(probe_bus_ctx *ctx) {
    return guard(ctx, ctx && ctx->claimed_mask != 0);
}

static probe_bus_result enter(probe_bus_ctx *ctx, uint64_t now_ms) {
    if (!ctx || !ctx->initialized) return PROBE_BUS_INVALID;
    if (ctx->busy || ctx->in_callback || ctx->guard_active) return PROBE_BUS_BUSY;
    if (!live(ctx)) return PROBE_BUS_RELEASED;
    ctx->busy = true;
    if (now_ms < ctx->now_ms) {
        probe_bus_release(ctx, PWEH_RELEASE_CLOCK);
        ctx->busy = false;
        return PROBE_BUS_RELEASED;
    }
    ctx->now_ms = now_ms;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) ctx->busy = false;
    return result;
}

static probe_bus_result leave(probe_bus_ctx *ctx, probe_bus_result result) {
    ctx->busy = false;
    return result;
}

probe_bus_result probe_bus_init(probe_bus_ctx *ctx, const probe_bus_hal *hal) {
    if (!ctx || !hal) return PROBE_BUS_INVALID;
    probe_bus_hal copy = *hal;
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = PROBE_BUS_STATE_RELEASED;
    if (!copy.clock_ms || !copy.read_vref || !copy.claim || !copy.spi_cs || !copy.spi_byte ||
        !copy.i2c_start || !copy.i2c_write_byte || !copy.i2c_read_byte || !copy.i2c_stop ||
        !copy.deliver_chunk || !copy.abort) return PROBE_BUS_INVALID;
    ctx->hal = copy;
    ctx->initialized = true;
    return PROBE_BUS_OK;
}

probe_bus_result probe_bus_bind(probe_bus_ctx *ctx, const probe_bus_binding *binding) {
    if (!ctx || !ctx->initialized || !binding) return PROBE_BUS_INVALID;
    if (ctx->busy || ctx->in_callback || ctx->guard_active || live(ctx)) return PROBE_BUS_BUSY;
    probe_bus_binding copy = *binding;
    if (!copy.session || !copy.usb_session || !copy.hello_seq || copy.hb_ms < 250u || copy.hb_ms > 3000u ||
        copy.deadline_ms <= copy.now_ms || copy.deadline_ms - copy.now_ms > copy.hb_ms ||
        copy.now_ms < ctx->now_ms) return PROBE_BUS_INVALID;
    if (ctx->have_binding && !memcmp(copy.boot_id, ctx->previous_binding.boot_id, 16)) {
        const probe_bus_binding *old = &ctx->previous_binding;
        if (copy.usb_session < old->usb_session ||
            (copy.usb_session == old->usb_session && copy.session <= old->session)) return PROBE_BUS_SESSION;
    }
    ctx->binding = ctx->previous_binding = copy;
    ctx->have_binding = true;
    ctx->now_ms = copy.now_ms;
    ctx->deadline_ms = copy.deadline_ms;
    ctx->last_req_seq = copy.hello_seq;
    ctx->last_hb_seq = copy.last_hb_seq;
    ctx->state = PROBE_BUS_STATE_BOUND;
    ctx->busy = true;
    probe_bus_result result = probe_bus_guard(ctx);
    return leave(ctx, result);
}

static bool wiring_mask(const probe_bus_wiring *w, uint64_t *out) {
    uint8_t pins[4];
    size_t count;
    if (w->declared_mv < 3000u || w->declared_mv > 3600u) return false;
    if (w->kind == PROBE_SPI_READ_RANGE) {
        pins[0] = w->bus.spi.cs; pins[1] = w->bus.spi.sck;
        pins[2] = w->bus.spi.mosi; pins[3] = w->bus.spi.miso;
        count = 4;
    } else if (w->kind == PROBE_I2C_EEPROM_READ) {
        const probe_i2c_wiring *i = &w->bus.i2c;
        if (i->addr7 < 8u || i->addr7 > 0x77u || (i->address_width != 1u && i->address_width != 2u) ||
            !i->capacity || (uint64_t)i->capacity > (UINT64_C(1) << (i->address_width * 8u))) return false;
        pins[0] = i->scl; pins[1] = i->sda; count = 2;
    } else return false;
    uint64_t mask = 0;
    for (size_t j = 0; j < count; ++j) {
        if (pins[j] >= 64u) return false;
        uint64_t bit = UINT64_C(1) << pins[j];
        if ((mask & bit) || !(w->allowed_mask & bit) || (w->excluded_mask & bit)) return false;
        mask |= bit;
    }
    *out = mask;
    return true;
}

probe_bus_result probe_bus_claim(probe_bus_ctx *ctx, const probe_bus_wiring *wiring, uint64_t now_ms) {
    probe_bus_result result = enter(ctx, now_ms);
    if (result != PROBE_BUS_OK) return result;
    if (ctx->state != PROBE_BUS_STATE_BOUND) return leave(ctx, PROBE_BUS_BUSY);
    if (!wiring) return leave(ctx, PROBE_BUS_INVALID);
    uint64_t mask = 0;
    if (!wiring_mask(wiring, &mask)) return leave(ctx, PROBE_BUS_POLICY);
    ctx->wiring = *wiring;
    result = guard(ctx, true);
    if (result != PROBE_BUS_OK) return leave(ctx, result);
    /* 부분 claim도 같은 해제 경로가 다룰 수 있게 callback보다 먼저 기록한다. */
    ctx->claimed_mask = mask;
    ctx->in_callback = true;
    bool ok = ctx->hal.claim(ctx->hal.user, &ctx->wiring);
    ctx->in_callback = false;
    if (!live(ctx)) return leave(ctx, PROBE_BUS_RELEASED);
    if (!ok) return leave(ctx, release_result(ctx, PWEH_RELEASE_INTERNAL));
    result = probe_bus_guard(ctx);
    if (result == PROBE_BUS_OK) ctx->state = PROBE_BUS_STATE_READY;
    return leave(ctx, result);
}

probe_bus_result probe_bus_poll(probe_bus_ctx *ctx, uint64_t now_ms) {
    probe_bus_result result = enter(ctx, now_ms);
    return result == PROBE_BUS_OK ? leave(ctx, result) : result;
}

static bool plan_equal(const probe_read_plan *a, const probe_read_plan *b) {
    return a->kind == b->kind && a->device_index == b->device_index && a->passes == b->passes &&
           a->offset == b->offset && a->length == b->length;
}

static probe_bus_result request(probe_bus_ctx *ctx, uint32_t seq, probe_bus_request kind,
                                const probe_read_plan *plan, const probe_bus_cache **hit) {
    *hit = NULL;
    if (!seq) return PROBE_BUS_SEQUENCE;
    for (size_t j = 0; j < PROBE_BUS_CACHE_SIZE; ++j) {
        const probe_bus_cache *row = &ctx->cache[j];
        if (row->request != PROBE_BUS_REQUEST_NONE && row->seq == seq) {
            if (row->request != kind || (kind == PROBE_BUS_REQUEST_BEGIN && !plan_equal(plan, &row->plan)))
                return PROBE_BUS_SEQUENCE;
            *hit = row;
            return row->result;
        }
    }
    if (seq <= ctx->last_req_seq) return PROBE_BUS_REPLAY;
    ctx->last_req_seq = seq;
    return PROBE_BUS_OK;
}

static void save(probe_bus_ctx *ctx, uint32_t seq, probe_bus_request kind, const probe_read_plan *plan,
                 probe_bus_result result, const probe_spi_info *info) {
    if (!live(ctx)) return;
    probe_bus_cache *row = &ctx->cache[ctx->cache_next];
    memset(row, 0, sizeof(*row));
    row->seq = seq; row->request = kind; row->result = result;
    if (plan) row->plan = *plan;
    if (info) row->info = *info;
    ctx->cache_next = (ctx->cache_next + 1u) % PROBE_BUS_CACHE_SIZE;
}

probe_bus_result probe_spi_probe(probe_bus_ctx *ctx, uint32_t seq, uint64_t now_ms, probe_spi_info *out) {
    if (!out) return PROBE_BUS_INVALID;
    memset(out, 0, sizeof(*out));
    probe_bus_result result = enter(ctx, now_ms);
    if (result != PROBE_BUS_OK) return result;
    const probe_bus_cache *hit = NULL;
    result = request(ctx, seq, PROBE_BUS_REQUEST_PROBE, NULL, &hit);
    if (hit) { *out = hit->info; return leave(ctx, result); }
    if (result != PROBE_BUS_OK) return leave(ctx, result);
    probe_spi_info info = {0}, parsed = {0};
    if (ctx->state == PROBE_BUS_STATE_RUNNING) result = PROBE_BUS_BUSY;
    else if (ctx->state == PROBE_BUS_STATE_BOUND || ctx->wiring.kind != PROBE_SPI_READ_RANGE)
        result = PROBE_BUS_UNSUPPORTED;
    else {
        memset(&ctx->spi_info, 0, sizeof(ctx->spi_info));
        result = probe_spi_xfer(ctx, 0x9fu, 0, 3, info.jedec_id);
        if (result == PROBE_BUS_OK) result = probe_spi_xfer(ctx, 0x05u, 0, 1, &info.sr1);
        if (result == PROBE_BUS_OK) result = probe_sfdp_probe(ctx, &parsed);
        if (result == PROBE_BUS_OK) {
            info.sfdp_valid = parsed.sfdp_valid;
            info.read4_supported = parsed.read4_supported;
            info.fast4_supported = parsed.fast4_supported;
            info.capacity = parsed.capacity;
            if (!info.sfdp_valid || !info.capacity || info.capacity > (UINT64_C(1) << 32))
                result = release_result(ctx, PWEH_RELEASE_INTERNAL);
            else ctx->spi_info = info;
        } else if (result != PROBE_BUS_UNSUPPORTED && live(ctx)) {
            result = release_result(ctx, PWEH_RELEASE_INTERNAL);
        }
        if (result == PROBE_BUS_OK || result == PROBE_BUS_UNSUPPORTED) {
            probe_bus_result checked = probe_bus_guard(ctx);
            if (checked != PROBE_BUS_OK) result = checked;
        }
    }
    save(ctx, seq, PROBE_BUS_REQUEST_PROBE, NULL, result, &info);
    if (live(ctx)) *out = info;
    return leave(ctx, result);
}

static probe_bus_result plan_check(const probe_bus_ctx *ctx, const probe_read_plan *plan) {
    if (ctx->state == PROBE_BUS_STATE_RUNNING) return PROBE_BUS_BUSY;
    if (ctx->state != PROBE_BUS_STATE_READY && ctx->state != PROBE_BUS_STATE_DONE) return PROBE_BUS_RELEASED;
    if (plan->kind != ctx->wiring.kind || plan->device_index || !plan->length ||
        (plan->passes != 1u && plan->passes != 2u)) return PROBE_BUS_POLICY;
    uint64_t capacity;
    if (plan->kind == PROBE_SPI_READ_RANGE) {
        const probe_spi_info *s = &ctx->spi_info;
        if (!s->sfdp_valid || !s->capacity || s->capacity > (UINT64_C(1) << 32) ||
            (s->capacity > (UINT64_C(1) << 24) && !s->read4_supported)) return PROBE_BUS_UNSUPPORTED;
        capacity = s->capacity;
    } else if (plan->kind == PROBE_I2C_EEPROM_READ) capacity = ctx->wiring.bus.i2c.capacity;
    else return PROBE_BUS_POLICY;
    if ((uint64_t)plan->offset + plan->length > capacity) return PROBE_BUS_POLICY;
    return PROBE_BUS_OK;
}

probe_bus_result probe_bus_begin(probe_bus_ctx *ctx, uint32_t seq, const probe_read_plan *plan, uint64_t now_ms) {
    probe_bus_result result = enter(ctx, now_ms);
    if (result != PROBE_BUS_OK) return result;
    if (!plan) return leave(ctx, PROBE_BUS_INVALID);
    const probe_bus_cache *hit = NULL;
    result = request(ctx, seq, PROBE_BUS_REQUEST_BEGIN, plan, &hit);
    if (hit || result != PROBE_BUS_OK) return leave(ctx, result);
    result = plan_check(ctx, plan);
    if (result == PROBE_BUS_OK) {
        ctx->plan = *plan;
        ctx->progress = 0;
        ctx->pass_index = 0;
        ctx->credit = 0;
        ctx->state = PROBE_BUS_STATE_RUNNING;
    }
    save(ctx, seq, PROBE_BUS_REQUEST_BEGIN, plan, result, NULL);
    return leave(ctx, result);
}

static uint64_t remaining_chunks(const probe_bus_ctx *ctx) {
    uint64_t chunk = ctx->plan.kind == PROBE_SPI_READ_RANGE ? PROBE_BUS_CHUNK_BYTES : PROBE_BUS_I2C_CHUNK_BYTES;
    if (ctx->state != PROBE_BUS_STATE_RUNNING || ctx->pass_index >= ctx->plan.passes || ctx->progress >= ctx->plan.length)
        return 0;
    uint64_t current = ((uint64_t)ctx->plan.length - ctx->progress + chunk - 1u) / chunk;
    uint64_t complete = ((uint64_t)ctx->plan.length + chunk - 1u) / chunk;
    return current + complete * (ctx->plan.passes - ctx->pass_index - 1u);
}

probe_bus_result probe_bus_credit(probe_bus_ctx *ctx, uint32_t session, uint32_t usb_session,
                                  uint32_t hb_seq, uint16_t credit, uint64_t now_ms) {
    probe_bus_result result = enter(ctx, now_ms);
    if (result != PROBE_BUS_OK) return result;
    if (session != ctx->binding.session || usb_session != ctx->binding.usb_session)
        return leave(ctx, PROBE_BUS_SESSION);
    if (!hb_seq) return leave(ctx, PROBE_BUS_SEQUENCE);
    if (hb_seq <= ctx->last_hb_seq) return leave(ctx, PROBE_BUS_OK);
    if (credit && (ctx->state != PROBE_BUS_STATE_RUNNING ||
        (uint32_t)ctx->credit + credit > PROBE_BUS_MAX_CREDIT ||
        (uint64_t)ctx->credit + credit > remaining_chunks(ctx))) return leave(ctx, PROBE_BUS_POLICY);
    if (ctx->now_ms > UINT64_MAX - ctx->binding.hb_ms)
        return leave(ctx, release_result(ctx, PWEH_RELEASE_CLOCK));
    ctx->last_hb_seq = hb_seq;
    ctx->deadline_ms = ctx->now_ms + ctx->binding.hb_ms;
    ctx->credit = (uint16_t)(ctx->credit + credit);
    return leave(ctx, PROBE_BUS_OK);
}

probe_bus_result probe_bus_step(probe_bus_ctx *ctx, uint64_t now_ms, probe_bus_chunk *out) {
    if (!out) return PROBE_BUS_INVALID;
    memset(out, 0, sizeof(*out));
    probe_bus_result result = enter(ctx, now_ms);
    if (result != PROBE_BUS_OK) return result;
    if (ctx->state == PROBE_BUS_STATE_DONE) return leave(ctx, PROBE_BUS_DONE);
    if (ctx->state != PROBE_BUS_STATE_RUNNING) return leave(ctx, PROBE_BUS_BUSY);
    if (!ctx->credit) return leave(ctx, PROBE_BUS_NO_CREDIT);
    if (!remaining_chunks(ctx)) return leave(ctx, release_result(ctx, PWEH_RELEASE_INTERNAL));
    uint64_t address = (uint64_t)ctx->plan.offset + ctx->progress;
    uint64_t remaining = (uint64_t)ctx->plan.length - ctx->progress;
    uint16_t maximum = ctx->plan.kind == PROBE_SPI_READ_RANGE ? PROBE_BUS_CHUNK_BYTES : PROBE_BUS_I2C_CHUNK_BYTES;
    uint16_t length = remaining < maximum ? (uint16_t)remaining : maximum;
    if (address > UINT32_MAX) return leave(ctx, release_result(ctx, PWEH_RELEASE_INTERNAL));
    memset(&ctx->scratch, 0, sizeof(ctx->scratch));
    ctx->scratch.pass_index = ctx->pass_index;
    ctx->scratch.offset = (uint32_t)address;
    ctx->scratch.length = length;
    ctx->scratch.done = remaining == length && ctx->pass_index + 1u == ctx->plan.passes;
    --ctx->credit;
    if (ctx->plan.kind == PROBE_SPI_READ_RANGE) {
        uint8_t opcode = ctx->spi_info.capacity > (UINT64_C(1) << 24) ? 0x13u : 0x03u;
        result = probe_spi_xfer(ctx, opcode, (uint32_t)address, length, ctx->scratch.bytes);
    } else result = probe_i2c_read(ctx, (uint32_t)address, length, ctx->scratch.bytes);
    if (result != PROBE_BUS_OK) return leave(ctx, release_result(ctx, PWEH_RELEASE_INTERNAL));
    result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return leave(ctx, result);
    ctx->in_callback = true;
    bool consumed = ctx->hal.deliver_chunk(ctx->hal.user, &ctx->scratch);
    ctx->in_callback = false;
    if (!live(ctx)) return leave(ctx, PROBE_BUS_RELEASED);
    if (!consumed) return leave(ctx, release_result(ctx, PWEH_RELEASE_TRANSPORT));
    result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return leave(ctx, result);
    ctx->progress += length;
    if (ctx->progress == ctx->plan.length) {
        if (ctx->scratch.done) ctx->state = PROBE_BUS_STATE_DONE;
        else { ++ctx->pass_index; ctx->progress = 0; }
    }
    *out = ctx->scratch;
    return leave(ctx, PROBE_BUS_OK);
}
