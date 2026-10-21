/* SPDX-License-Identifier: MIT
 * CRC-32/ISO-HDLC. ROM ABI에 의존하지 않는 골든 기준 구현. */
#include "pweh_protocol.h"
uint32_t pweh_crc32(const uint8_t *p,size_t n) {
    uint32_t crc=UINT32_MAX;
    for(size_t i=0;i<n;i++) {
        crc ^= p[i];
        for(unsigned bit=0;bit<8;bit++) crc=(crc>>1)^((crc&1u)?UINT32_C(0xedb88320):0u);
    }
    return ~crc;
}
