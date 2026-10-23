/* SPDX-License-Identifier: MIT
 * 고정 읽기 descriptor만 CS 경계를 통과시킨다. wire 명령 입구가 아니다. */
#include "probe_bus.h"

#include <string.h>

static probe_bus_result failed(probe_bus_ctx *ctx) {
    probe_bus_release(ctx, PWEH_RELEASE_INTERNAL);
    return PROBE_BUS_RELEASED;
}

/* opcode에서 기대 형식을 다시 구한다. caller가 만든 TX 배열은 받지 않는다. */
static bool shape(uint8_t opcode, uint8_t *address_bytes, uint8_t *dummy_bytes) {
    *address_bytes = 0;
    *dummy_bytes = 0;
    switch (opcode) {
    case 0x03: case 0x90: *address_bytes = 3; break;
    case 0x0b: case 0x5a: *address_bytes = 3; *dummy_bytes = 1; break;
    case 0x13: *address_bytes = 4; break;
    case 0x0c: *address_bytes = 4; *dummy_bytes = 1; break;
    case 0xab: *dummy_bytes = 3; break;
    case 0x9f: case 0x05: break;
    default: return false;
    }
    return true;
}

probe_bus_result probe_spi_validate(const probe_bus_ctx *ctx, const probe_spi_descriptor *d) {
    uint8_t address_bytes, dummy_bytes;
    uint64_t end;
    if (!ctx || !d || !ctx->initialized) return PROBE_BUS_INVALID;
    if (d->first_byte != d->opcode) return PROBE_BUS_INTERNAL;
    if (!shape(d->opcode, &address_bytes, &dummy_bytes)) return PROBE_BUS_POLICY;
    if (d->address_bytes != address_bytes || d->dummy_bytes != dummy_bytes)
        return PROBE_BUS_INTERNAL;
    if (!d->length || d->length > PROBE_BUS_CHUNK_BYTES) return PROBE_BUS_INVALID;
    if (ctx->wiring.kind != PROBE_SPI_READ_RANGE) return PROBE_BUS_POLICY;
    end = (uint64_t)d->address + d->length;
    switch (d->opcode) {
    case 0x9f:
        return d->address == 0 && d->length == 3 ? PROBE_BUS_OK : PROBE_BUS_INVALID;
    case 0x05: case 0xab:
        return d->address == 0 && d->length == 1 ? PROBE_BUS_OK : PROBE_BUS_INVALID;
    case 0x90:
        return d->address == 0 && d->length == 2 ? PROBE_BUS_OK : PROBE_BUS_INVALID;
    case 0x5a:
        if (!ctx->sfdp_active) return PROBE_BUS_UNSUPPORTED;
        if (end > UINT64_C(0x1000000) ||
            ctx->sfdp_read_bytes > PROBE_BUS_SFDP_BYTES - d->length)
            return PROBE_BUS_INVALID;
        return PROBE_BUS_OK;
    default:
        if (!ctx->spi_info.sfdp_valid || !ctx->spi_info.capacity ||
            ctx->spi_info.capacity > UINT64_C(0x100000000)) return PROBE_BUS_UNSUPPORTED;
        if (end > ctx->spi_info.capacity) return PROBE_BUS_INVALID;
        if (address_bytes == 3) {
            /* 큰 칩의 미확인 주소 모드를 3B 부분 읽기로 우회하지 않는다. */
            if (ctx->spi_info.capacity > UINT64_C(0x1000000)) return PROBE_BUS_UNSUPPORTED;
            if (end > UINT64_C(0x1000000)) return PROBE_BUS_INVALID;
        } else if (ctx->spi_info.capacity <= UINT64_C(0x1000000) ||
                   (d->opcode == 0x13 && !ctx->spi_info.read4_supported) ||
                   (d->opcode == 0x0c && !ctx->spi_info.fast4_supported)) {
            return PROBE_BUS_UNSUPPORTED;
        }
        return PROBE_BUS_OK;
    }
}

static probe_bus_result cs(probe_bus_ctx *ctx, bool active) {
    bool ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.spi_cs(ctx->hal.user, active);
    ctx->in_callback = false;
    if (!ok) return failed(ctx);
    return probe_bus_guard(ctx);
}

static probe_bus_result byte(probe_bus_ctx *ctx, uint8_t tx, uint8_t *rx) {
    bool ok;
    probe_bus_result result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) return result;
    ctx->in_callback = true;
    ok = ctx->hal.spi_byte(ctx->hal.user, tx, rx);
    ctx->in_callback = false;
    if (!ok) return failed(ctx);
    return probe_bus_guard(ctx);
}

probe_bus_result probe_spi_xfer(probe_bus_ctx *ctx, uint8_t opcode, uint32_t addr,
                                 uint16_t length, uint8_t *out) {
    probe_spi_descriptor d = {0};
    probe_bus_result result;
    uint8_t discarded = 0;
    uint16_t i;
    if (!ctx || !ctx->initialized || !out) return PROBE_BUS_INVALID;
    if (ctx->in_callback || ctx->guard_active) return PROBE_BUS_BUSY;
    if (ctx->state == PROBE_BUS_STATE_RELEASED) return PROBE_BUS_RELEASED;
    if (!ctx->claimed_mask || ctx->state == PROBE_BUS_STATE_BOUND) return PROBE_BUS_POLICY;
    d.opcode = opcode;
    d.first_byte = opcode;
    d.address = addr;
    d.length = length;
    (void)shape(opcode, &d.address_bytes, &d.dummy_bytes);
    result = probe_spi_validate(ctx, &d);
    if (result == PROBE_BUS_INTERNAL) {
        probe_bus_release(ctx, PWEH_RELEASE_INTERNAL);
        return result;
    }
    if (result != PROBE_BUS_OK) return result;
    memset(out, 0, length);
    /* descriptor 검증 이후에도 CS 바로 앞에서 동일 guard를 적용한다. */
    if (opcode == 0x5a) ctx->sfdp_read_bytes += length;
    result = cs(ctx, true);
    if (result != PROBE_BUS_OK) goto invalid_output;
    result = byte(ctx, d.first_byte, &discarded);
    if (result != PROBE_BUS_OK) goto invalid_output;
    for (i = d.address_bytes; i > 0; --i) {
        result = byte(ctx, (uint8_t)(d.address >> ((i - 1u) * 8u)), &discarded);
        if (result != PROBE_BUS_OK) goto invalid_output;
    }
    for (i = 0; i < d.dummy_bytes; ++i) {
        result = byte(ctx, 0, &discarded);
        if (result != PROBE_BUS_OK) goto invalid_output;
    }
    for (i = 0; i < length; ++i) {
        result = byte(ctx, 0, out + i);
        if (result != PROBE_BUS_OK) goto invalid_output;
    }
    result = cs(ctx, false);
    if (result == PROBE_BUS_OK) return result;
invalid_output:
    /* 오류 뒤 정상 CS/clock을 더 보내지 않는다. abort가 핀을 해제한다. */
    memset(out, 0, length);
    return result;
}
