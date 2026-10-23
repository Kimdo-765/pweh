/* SPDX-License-Identifier: MIT
 * SFDP 1.x의 고정 BFPT/4BAIT prefix만 해석한다. 칩별 fallback은 없다. */
#include "probe_bus.h"

#include <string.h>

#define PARAMETER_LIMIT 16u
#define SFDP_ADDRESS_END UINT64_C(0x1000000)

typedef struct {
    uint16_t id;
    uint8_t major, dwords;
    uint32_t address;
    uint64_t end;
} parameter;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static probe_bus_result read_sfdp(probe_bus_ctx *ctx, uint32_t address,
                                   uint16_t size, uint8_t *out) {
    /* 상위 parser도 저수준 5A 경계의 24bit/누적 budget 검사를 통과한다. */
    return probe_spi_xfer(ctx, 0x5a, address, size, out);
}

probe_bus_result probe_sfdp_probe(probe_bus_ctx *ctx, probe_spi_info *out) {
    uint8_t header[8], headers[PARAMETER_LIMIT * 8u], bfpt[36], bait[8];
    parameter parameters[PARAMETER_LIMIT];
    unsigned count, i, j, address_kind;
    int bfpt_index = -1, bait_index = -1;
    uint32_t density;
    uint64_t bits, capacity;
    bool read4 = false, fast4 = false;
    probe_bus_result result;
    if (!ctx || !ctx->initialized || !out) return PROBE_BUS_INVALID;
    if (ctx->in_callback || ctx->guard_active || ctx->sfdp_active) return PROBE_BUS_BUSY;
    if (ctx->state == PROBE_BUS_STATE_RELEASED) return PROBE_BUS_RELEASED;
    if (!ctx->claimed_mask || ctx->wiring.kind != PROBE_SPI_READ_RANGE ||
        (ctx->state != PROBE_BUS_STATE_READY && ctx->state != PROBE_BUS_STATE_DONE))
        return PROBE_BUS_POLICY;
    out->sfdp_valid = false;
    out->read4_supported = false;
    out->fast4_supported = false;
    out->capacity = 0;
    ctx->sfdp_active = true;
    ctx->sfdp_read_bytes = 0;
    result = read_sfdp(ctx, 0, sizeof(header), header);
    if (result != PROBE_BUS_OK) goto done;
    if (memcmp(header, "SFDP", 4) != 0 || header[5] != 1 || header[7] != 0xff ||
        header[6] >= PARAMETER_LIMIT) goto unsupported;
    count = (unsigned)header[6] + 1u;
    result = read_sfdp(ctx, 8, (uint16_t)(count * 8u), headers);
    if (result != PROBE_BUS_OK) goto done;
    memset(parameters, 0, sizeof(parameters));
    for (i = 0; i < count; ++i) {
        const uint8_t *h = headers + i * 8u;
        parameter *p = parameters + i;
        p->id = (uint16_t)h[0] | (uint16_t)((uint16_t)h[7] << 8);
        p->major = h[2];
        p->dwords = h[3];
        p->address = (uint32_t)h[4] | ((uint32_t)h[5] << 8) | ((uint32_t)h[6] << 16);
        p->end = (uint64_t)p->address + (uint64_t)p->dwords * 4u;
        if (p->major != 1 || !p->dwords || (p->address & 3u) != 0 ||
            p->address < 8u + count * 8u || p->end > SFDP_ADDRESS_END) goto unsupported;
        for (j = 0; j < i; ++j) {
            const parameter *earlier = parameters + j;
            if (p->id == earlier->id ||
                ((uint64_t)p->address < earlier->end && (uint64_t)earlier->address < p->end))
                goto unsupported;
        }
        if (p->id == 0xff00) bfpt_index = (int)i;
        if (p->id == 0xff84) bait_index = (int)i;
    }
    if (bfpt_index != 0 || parameters[0].dwords < 9 ||
        (bait_index >= 0 && parameters[bait_index].dwords < 2)) goto unsupported;
    result = read_sfdp(ctx, parameters[0].address, sizeof(bfpt), bfpt);
    if (result != PROBE_BUS_OK) goto done;
    address_kind = (le32(bfpt) >> 17) & 3u;
    density = le32(bfpt + 4);
    if (density & UINT32_C(0x80000000)) {
        uint32_t exponent = density & UINT32_C(0x7fffffff);
        if (exponent < 3 || exponent > 35) goto unsupported;
        bits = UINT64_C(1) << exponent;
    } else {
        bits = (uint64_t)density + 1u;
    }
    if (!bits || (bits & 7u) != 0) goto unsupported;
    capacity = bits / 8u;
    if (!capacity || capacity > UINT64_C(0x100000000) || address_kind == 3 ||
        (capacity <= UINT64_C(0x1000000) && address_kind == 2)) goto unsupported;
    if (bait_index >= 0) {
        result = read_sfdp(ctx, parameters[bait_index].address, sizeof(bait), bait);
        if (result != PROBE_BUS_OK) goto done;
        if (capacity > UINT64_C(0x1000000)) {
            read4 = (le32(bait) & 1u) != 0;
            fast4 = (le32(bait) & 2u) != 0;
        }
    }
    /* 마지막 정상 5A와 guard 뒤에만 caller의 식별 결과에 권한을 더한다. */
    result = probe_bus_guard(ctx);
    if (result != PROBE_BUS_OK) goto done;
    out->capacity = capacity;
    out->read4_supported = read4;
    out->fast4_supported = fast4;
    out->sfdp_valid = true;
    goto done;
unsupported:
    result = PROBE_BUS_UNSUPPORTED;
done:
    ctx->sfdp_active = false;
    return result;
}
