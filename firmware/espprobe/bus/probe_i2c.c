/* SPDX-License-Identifier: MIT
 * 증명된 단일 24Cxx 주소만 읽는다. 오류 뒤 STOP/복구 clock은 보내지 않는다. */
#include "probe_bus.h"

#include <string.h>

static probe_bus_result failed(probe_bus_ctx *ctx) {
    probe_bus_release(ctx, PWEH_RELEASE_INTERNAL);
    return PROBE_BUS_RELEASED;
}

static probe_bus_result start(probe_bus_ctx *ctx, bool repeated) {
    bool ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.i2c_start(ctx->hal.user, repeated);
    ctx->in_callback = false;
    if (!ok) return failed(ctx);
    return probe_bus_guard(ctx);
}

static probe_bus_result write_byte(probe_bus_ctx *ctx, uint8_t value) {
    bool acked = false, ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.i2c_write_byte(ctx->hal.user, value, &acked);
    ctx->in_callback = false;
    if (!ok || !acked) return failed(ctx);
    return probe_bus_guard(ctx);
}

static probe_bus_result read_byte(probe_bus_ctx *ctx, bool ack, uint8_t *value) {
    bool ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.i2c_read_byte(ctx->hal.user, ack, value);
    ctx->in_callback = false;
    if (!ok) return failed(ctx);
    return probe_bus_guard(ctx);
}

static probe_bus_result stop(probe_bus_ctx *ctx) {
    bool ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.i2c_stop(ctx->hal.user);
    ctx->in_callback = false;
    if (!ok) return failed(ctx);
    return probe_bus_guard(ctx);
}

probe_bus_result probe_i2c_read(probe_bus_ctx *ctx, uint32_t addr, uint16_t length,
                                uint8_t *out) {
    probe_i2c_wiring wiring;
    probe_bus_result result;
    uint16_t i;
    if (!ctx || !ctx->initialized || !out || !length || length > PROBE_BUS_I2C_CHUNK_BYTES)
        return PROBE_BUS_INVALID;
    if (ctx->in_callback || ctx->guard_active) return PROBE_BUS_BUSY;
    if (ctx->state == PROBE_BUS_STATE_RELEASED) return PROBE_BUS_RELEASED;
    if (!ctx->claimed_mask || ctx->state == PROBE_BUS_STATE_BOUND ||
        ctx->wiring.kind != PROBE_I2C_EEPROM_READ) return PROBE_BUS_POLICY;
    wiring = ctx->wiring.bus.i2c;
    if (wiring.addr7 < 0x08 || wiring.addr7 > 0x77 ||
        (wiring.address_width != 1 && wiring.address_width != 2) || !wiring.capacity)
        return PROBE_BUS_INVALID;
    if (wiring.capacity > (UINT32_C(1) << (wiring.address_width * 8u)) ||
        (uint64_t)addr + length > wiring.capacity) return PROBE_BUS_INVALID;
    memset(out, 0, length);
    result = start(ctx, false);
    if (result != PROBE_BUS_OK) goto invalid_output;
    result = write_byte(ctx, (uint8_t)(wiring.addr7 << 1));
    if (result != PROBE_BUS_OK) goto invalid_output;
    for (i = wiring.address_width; i > 0; --i) {
        result = write_byte(ctx, (uint8_t)(addr >> ((i - 1u) * 8u)));
        if (result != PROBE_BUS_OK) goto invalid_output;
    }
    result = start(ctx, true);
    if (result != PROBE_BUS_OK) goto invalid_output;
    result = write_byte(ctx, (uint8_t)((wiring.addr7 << 1) | 1u));
    if (result != PROBE_BUS_OK) goto invalid_output;
    for (i = 0; i < length; ++i) {
        result = read_byte(ctx, i + 1u < length, out + i);
        if (result != PROBE_BUS_OK) goto invalid_output;
    }
    result = stop(ctx);
    if (result == PROBE_BUS_OK) return result;
invalid_output:
    memset(out, 0, length);
    return result;
}
