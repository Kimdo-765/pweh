/* SPDX-License-Identifier: MIT
 * HELLO writer와 고정 nonce reader. 길이는 size_t 뺄셈으로 확인한다. */
#include "pweh_protocol.h"
#include <string.h>
bool pweh_tlv_append(uint8_t *out,size_t cap,size_t *used,uint16_t tag,const void *value,size_t n){
    if(!out||!used||!tag||n>UINT16_MAX||*used>cap||cap-*used<4||n>cap-*used-4||(!value&&n))return false;
    pweh_put16(out+*used,tag);pweh_put16(out+*used+2,(uint16_t)n);
    if(n)memcpy(out+*used+4,value,n);
    *used+=n+4;return true;
}
bool pweh_tlv_nonce(const uint8_t *payload,size_t n,uint8_t nonce[16]){
    if(!payload||!nonce||n!=20||pweh_get16(payload)!=1||pweh_get16(payload+2)!=16)return false;
    memcpy(nonce,payload+4,16);return true;
}
