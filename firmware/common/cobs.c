/* SPDX-License-Identifier: MIT
 * COBS의 입력/출력 상한을 매 바이트 전에 확인한다. */
#include "pweh_protocol.h"
pweh_result pweh_cobs_encode(const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *used) {
    if(!in||!out||!used||!cap||n>PWEH_MAX_DECODED) return PWEH_BOUNDS;
    size_t pos=1,mark=0; uint8_t code=1;
    for(size_t i=0;i<n;i++) {
        if(in[i]==0) {out[mark]=code; if(pos>=cap)return PWEH_BOUNDS; mark=pos++;code=1;}
        else {if(pos>=cap)return PWEH_BOUNDS;out[pos++]=in[i];code++;
            if(code==255){out[mark]=code;if(pos>=cap)return PWEH_BOUNDS;mark=pos++;code=1;}}
    }
    out[mark]=code;*used=pos;return PWEH_OK;
}
pweh_result pweh_cobs_decode(const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *used) {
    if(!in||!out||!used||!n||n>PWEH_MAX_ENCODED)return PWEH_BOUNDS;
    size_t pos=0,w=0;
    while(pos<n) {
        uint8_t code=in[pos++];
        if(!code||(size_t)(code-1)>n-pos)return PWEH_INVALID;
        for(unsigned j=1;j<code;j++){if(!in[pos]||w>=cap)return PWEH_BOUNDS;out[w++]=in[pos++];}
        if(code<255&&pos<n){if(w>=cap)return PWEH_BOUNDS;out[w++]=0;}
    }
    *used=w;return PWEH_OK;
}
