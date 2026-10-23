/* SPDX-License-Identifier: MIT
 * 호스트 시험용 버스 계층. hello 이미지/공용 wire에는 연결하지 않는다. */
#ifndef PWEH_PROBE_BUS_H
#define PWEH_PROBE_BUS_H

#include "pweh_session.h"

#define PROBE_BUS_SPI_HZ 1000000u
#define PROBE_BUS_I2C_HZ 100000u
#define PROBE_BUS_CHUNK_BYTES 256u
#define PROBE_BUS_I2C_CHUNK_BYTES 32u
#define PROBE_BUS_MAX_CREDIT 4u
#define PROBE_BUS_CACHE_SIZE 4u
#define PROBE_BUS_SFDP_BYTES 4096u

/* 아래 번호는 내부 C 결과이며 wire status/opcode가 아니다. */
typedef enum {
    PROBE_BUS_OK, PROBE_BUS_POLICY, PROBE_BUS_UNSUPPORTED,
    PROBE_BUS_RELEASED, PROBE_BUS_SESSION, PROBE_BUS_SEQUENCE,
    PROBE_BUS_BUSY, PROBE_BUS_INVALID, PROBE_BUS_REPLAY,
    PROBE_BUS_NO_CREDIT, PROBE_BUS_DONE, PROBE_BUS_INTERNAL
} probe_bus_result;
typedef enum {
    PROBE_BUS_STATE_RELEASED, PROBE_BUS_STATE_BOUND, PROBE_BUS_STATE_READY,
    PROBE_BUS_STATE_RUNNING, PROBE_BUS_STATE_DONE
} probe_bus_state;
typedef enum { PROBE_SPI_READ_RANGE, PROBE_I2C_EEPROM_READ } probe_read_kind;

typedef struct {
    uint32_t session, usb_session, hello_seq, last_hb_seq;
    uint16_t hb_ms;
    uint8_t boot_id[16];
    uint64_t now_ms, deadline_ms;
} probe_bus_binding;
typedef struct {
    bool valid;
    uint16_t millivolts;
    uint64_t sampled_at_ms;
} probe_vref_sample;
typedef struct { uint8_t cs, sck, mosi, miso; } probe_spi_pins;
typedef struct {
    uint8_t scl, sda, addr7, address_width;
    uint32_t capacity;
} probe_i2c_wiring;
typedef struct {
    probe_read_kind kind;
    uint16_t declared_mv;
    uint64_t allowed_mask, excluded_mask;
    union { probe_spi_pins spi; probe_i2c_wiring i2c; } bus;
} probe_bus_wiring;
typedef struct {
    probe_read_kind kind;
    uint8_t device_index, passes;
    uint32_t offset, length;
} probe_read_plan;
typedef struct {
    uint8_t pass_index;
    uint32_t offset;
    uint16_t length;
    uint8_t bytes[PROBE_BUS_CHUNK_BYTES];
    bool done;
} probe_bus_chunk;
typedef struct {
    uint8_t jedec_id[3], sr1;
    bool sfdp_valid, read4_supported, fast4_supported;
    uint64_t capacity;
} probe_spi_info;

typedef struct {
    void *user;
    bool (*clock_ms)(void *user, uint64_t *out);
    bool (*read_vref)(void *user, probe_vref_sample *out);
    bool (*claim)(void *user, const probe_bus_wiring *wiring);
    bool (*spi_cs)(void *user, bool active);
    bool (*spi_byte)(void *user, uint8_t tx, uint8_t *rx);
    bool (*i2c_start)(void *user, bool repeated);
    bool (*i2c_write_byte)(void *user, uint8_t value, bool *acked);
    bool (*i2c_read_byte)(void *user, bool ack, uint8_t *value);
    bool (*i2c_stop)(void *user);
    bool (*deliver_chunk)(void *user, const probe_bus_chunk *chunk);
    void (*abort)(void *user, uint64_t claimed_mask, pweh_release_reason reason);
} probe_bus_hal;

typedef enum { PROBE_BUS_REQUEST_NONE, PROBE_BUS_REQUEST_PROBE, PROBE_BUS_REQUEST_BEGIN } probe_bus_request;
typedef struct {
    uint32_t seq;
    probe_bus_request request;
    probe_read_plan plan;
    probe_bus_result result;
    probe_spi_info info;
} probe_bus_cache;

/* 소유권은 A에 있다. B는 hal/wiring/spi_info를 읽고 callback 동안 in_callback만 설정한다.
 * SFDP read 계수/활성 flag는 B의 제한된 parser만 변경한다. 호출자는 권한을 직접 쓰지 않는다. */
typedef struct {
    bool initialized, busy, in_callback, guard_active, have_binding;
    probe_bus_hal hal;
    probe_bus_state state;
    probe_bus_binding binding, previous_binding;
    probe_bus_wiring wiring;
    uint64_t claimed_mask, now_ms, deadline_ms;
    uint32_t last_req_seq, last_hb_seq;
    uint16_t credit;
    probe_read_plan plan;
    uint8_t pass_index;
    uint64_t progress;
    probe_spi_info spi_info;
    bool sfdp_active;
    uint32_t sfdp_read_bytes;
    probe_bus_cache cache[PROBE_BUS_CACHE_SIZE];
    size_t cache_next;
    probe_bus_chunk scratch;
    pweh_release_reason last_release_reason;
} probe_bus_ctx;

/* 새 caller storage의 초기화 전용이다. 살아 있는 ctx/HAL callback에서 재호출하지 않는다. */
probe_bus_result probe_bus_init(probe_bus_ctx *, const probe_bus_hal *);
probe_bus_result probe_bus_bind(probe_bus_ctx *, const probe_bus_binding *);
probe_bus_result probe_bus_claim(probe_bus_ctx *, const probe_bus_wiring *, uint64_t now_ms);
probe_bus_result probe_bus_poll(probe_bus_ctx *, uint64_t now_ms);
probe_bus_result probe_spi_probe(probe_bus_ctx *, uint32_t seq, uint64_t now_ms, probe_spi_info *out);
probe_bus_result probe_bus_begin(probe_bus_ctx *, uint32_t seq, const probe_read_plan *, uint64_t now_ms);
probe_bus_result probe_bus_credit(probe_bus_ctx *, uint32_t session, uint32_t usb_session,
                                  uint32_t hb_seq, uint16_t credit, uint64_t now_ms);
probe_bus_result probe_bus_step(probe_bus_ctx *, uint64_t now_ms, probe_bus_chunk *out);
void probe_bus_release(probe_bus_ctx *, pweh_release_reason);

/* B의 내부 C 접점: 임의 wire/사용자 command가 아니다. guard는 각 HAL phase 전후 필수다.
 * HAL 호출 중 in_callback=true, 반환 뒤 false로 복원한다. 해제 후 정상 STOP/CS 호출0. */
probe_bus_result probe_bus_guard(probe_bus_ctx *);
/* 송신 직전의 내부 descriptor 검사. raw TX/wire 입력은 받지 않는다. */
typedef struct {
    uint8_t opcode, first_byte, address_bytes, dummy_bytes;
    uint32_t address;
    uint16_t length;
} probe_spi_descriptor;
probe_bus_result probe_spi_validate(const probe_bus_ctx *, const probe_spi_descriptor *);
probe_bus_result probe_spi_xfer(probe_bus_ctx *, uint8_t opcode, uint32_t addr, uint16_t length, uint8_t *out);
probe_bus_result probe_sfdp_probe(probe_bus_ctx *, probe_spi_info *out);
probe_bus_result probe_i2c_read(probe_bus_ctx *, uint32_t addr, uint16_t length, uint8_t *out);

#endif
