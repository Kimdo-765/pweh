/* SPDX-License-Identifier: MIT
 * espprobe v1: 명시적인 LE wire 계약, 동적 메모리 없음. */
#ifndef PWEH_PROTOCOL_H
#define PWEH_PROTOCOL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define PWEH_MAX_PAYLOAD 4096u
#define PWEH_MAX_DECODED 4116u
#define PWEH_MAX_ENCODED 4133u
#define PWEH_MAX_WIRE 4134u
typedef enum { PWEH_OK=0, PWEH_INVALID=1, PWEH_BOUNDS=2 } pweh_result;
typedef struct {
    uint8_t version,type,op,flags;
    uint32_t seq,session;
    uint16_t length,credit;
    uint8_t payload[PWEH_MAX_PAYLOAD];
} pweh_frame;
uint16_t pweh_get16(const uint8_t *p);
uint32_t pweh_get32(const uint8_t *p);
void pweh_put16(uint8_t *p,uint16_t v);
void pweh_put32(uint8_t *p,uint32_t v);
uint32_t pweh_crc32(const uint8_t *p,size_t n);
pweh_result pweh_cobs_encode(const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *used);
pweh_result pweh_cobs_decode(const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *used);
pweh_result pweh_frame_encode(const pweh_frame *frame,uint8_t *out,size_t cap,size_t *used);
pweh_result pweh_frame_decode(const uint8_t *wire,size_t n,pweh_frame *out);
bool pweh_tlv_append(uint8_t *out,size_t cap,size_t *used,uint16_t tag,const void *value,size_t n);
bool pweh_tlv_nonce(const uint8_t *payload,size_t n,uint8_t nonce[16]);
#endif
