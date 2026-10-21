/* SPDX-License-Identifier: MIT
 * 비정렬 구조체 cast 없이 header16과 CRC를 검증한다. */
#include "pweh_protocol.h"
#include <string.h>
uint16_t pweh_get16(const uint8_t *p){return (uint16_t)((uint16_t)p[0]|((uint16_t)p[1]<<8));}
uint32_t pweh_get32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
void pweh_put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
void pweh_put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8));}
static bool valid(const pweh_frame *f){return f->version==1&&f->type>=1&&f->type<=5&&f->seq&&!(f->flags&~1u)&&(!f->flags||f->type==2)&&f->length<=PWEH_MAX_PAYLOAD;}
pweh_result pweh_frame_encode(const pweh_frame *f,uint8_t *out,size_t cap,size_t *used){
    if(!f||!out||!used||cap<2||!valid(f))return PWEH_INVALID;
    uint8_t raw[PWEH_MAX_DECODED];
    raw[0]=f->version;raw[1]=f->type;raw[2]=f->op;raw[3]=f->flags;
    pweh_put32(raw+4,f->seq);pweh_put32(raw+8,f->session);pweh_put16(raw+12,f->length);pweh_put16(raw+14,f->credit);
    memcpy(raw+16,f->payload,f->length);size_t n=16u+f->length;pweh_put32(raw+n,pweh_crc32(raw,n));
    pweh_result result=pweh_cobs_encode(raw,n+4,out,cap-1,used);
    if(result==PWEH_OK){out[*used]=0;(*used)++;}return result;
}
pweh_result pweh_frame_decode(const uint8_t *wire,size_t n,pweh_frame *out){
    if(!wire||!out||n<2||n>PWEH_MAX_WIRE||wire[n-1]!=0)return PWEH_INVALID;
    uint8_t raw[PWEH_MAX_DECODED],canonical[PWEH_MAX_ENCODED];size_t len=0,enc=0;
    if(pweh_cobs_decode(wire,n-1,raw,sizeof(raw),&len)!=PWEH_OK||len<20)return PWEH_INVALID;
    uint16_t payload=pweh_get16(raw+12);
    if(payload>PWEH_MAX_PAYLOAD||len!=20u+payload||pweh_crc32(raw,len-4)!=pweh_get32(raw+len-4))return PWEH_INVALID;
    if(pweh_cobs_encode(raw,len,canonical,sizeof(canonical),&enc)!=PWEH_OK||enc!=n-1||memcmp(canonical,wire,enc))return PWEH_INVALID;
    out->version=raw[0];out->type=raw[1];out->op=raw[2];out->flags=raw[3];out->seq=pweh_get32(raw+4);out->session=pweh_get32(raw+8);
    out->length=payload;out->credit=pweh_get16(raw+14);memcpy(out->payload,raw+16,payload);
    return valid(out)?PWEH_OK:PWEH_INVALID;
}
