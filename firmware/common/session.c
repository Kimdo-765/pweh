/* SPDX-License-Identifier: MIT
 * HELLO/HB/정리만 허용한다. cache eviction은 실행 high-water를 지우지 않는다. */
#include "pweh_session.h"
#include <string.h>

static void count(uint64_t *v){if(*v<UINT64_MAX)(*v)++;}
static bool string_ok(const char *s,size_t cap){
    const char *end=memchr(s,0,cap);if(!end||end==s)return false;
    for(const char *p=s;p<end;p++)if((unsigned char)*p<32||(unsigned char)*p>126)return false;
    return true;
}
static void save(pweh_cache *c,uint32_t seq,const uint8_t *req,size_t n,const uint8_t *rsp,size_t m){
    c->seq=seq;c->request_size=n;c->response_size=m;memcpy(c->request,req,n);memcpy(c->response,rsp,m);
}
void pweh_probe_release(pweh_probe *p,pweh_release_reason reason){
    if(p->session){p->session=0;p->deadline_ms=0;p->last_release_reason=reason;
        memset(p->cache,0,sizeof(p->cache));count(&p->release_count);
        if(p->hal.release)p->hal.release(p->hal.user,reason);}
}
void pweh_probe_poll(pweh_probe *p,uint64_t now){
    if(now<p->now_ms){pweh_probe_release(p,PWEH_RELEASE_CLOCK);p->closed=true;return;}
    p->now_ms=now;
    if(p->session&&now>=p->deadline_ms)pweh_probe_release(p,PWEH_RELEASE_HEARTBEAT);
}
void pweh_probe_transport_reset(pweh_probe *p,pweh_release_reason reason){
    pweh_probe_release(p,reason);p->rx_size=0;p->discarding=false;
    if(reason==PWEH_RELEASE_USB_RESET||reason==PWEH_RELEASE_USB_DETACH){
        if(p->usb_session==UINT32_MAX)p->closed=true;else p->usb_session++;
        p->hello_seq=0;memset(&p->hello,0,sizeof(p->hello));memset(&p->tombstone,0,sizeof(p->tombstone));
        memset(p->cache,0,sizeof(p->cache));}
}
static bool policy_ok(const pweh_identity *i){
    uint8_t expected[73]={0},limits[6],zero[24]={0},none=255;size_t n=0;
    pweh_put16(limits,4096);pweh_put16(limits+2,i->hb_ms);pweh_put16(limits+4,0);
    if(!pweh_tlv_append(expected,sizeof(expected),&n,19,zero,4)||!pweh_tlv_append(expected,sizeof(expected),&n,20,limits,6)||
       !pweh_tlv_append(expected,sizeof(expected),&n,21,zero,24)||!pweh_tlv_append(expected,sizeof(expected),&n,22,&none,1)||
       !pweh_tlv_append(expected,sizeof(expected),&n,23,zero,1)||!pweh_tlv_append(expected,sizeof(expected),&n,24,zero,0)||
       !pweh_tlv_append(expected,sizeof(expected),&n,25,zero,1)||!pweh_tlv_append(expected,sizeof(expected),&n,26,zero,4))return false;
    return i->policy&&i->policy_size==n&&!memcmp(i->policy,expected,n);
}
bool pweh_probe_init(pweh_probe *p,const pweh_identity *i,const pweh_hal *hal){
    if(!p||!i||!hal||!hal->emit)return false;
    memset(p,0,sizeof(*p));p->closed=true;
    if(!string_ok(i->fw_name,sizeof(i->fw_name))||!string_ok(i->fw_version,sizeof(i->fw_version))||
       !string_ok(i->profile,sizeof(i->profile))||!string_ok(i->board,sizeof(i->board))||
       !string_ok(i->git_commit,sizeof(i->git_commit))||strlen(i->git_commit)!=40||
       !string_ok(i->idf_version,sizeof(i->idf_version))||!string_ok(i->usb_product,sizeof(i->usb_product))||
       i->hb_ms<250||i->hb_ms>3000||i->chip_model!=1||(i->chip_known&~15u)||!(i->chip_known&1u)||
       i->reset_reason>7||!policy_ok(i))return false;
    for(size_t j=0;j<40;j++)if(!((i->git_commit[j]>='0'&&i->git_commit[j]<='9')||(i->git_commit[j]>='a'&&i->git_commit[j]<='f')))return false;
    p->identity=*i;p->hal=*hal;p->usb_session=1;p->last_release_reason=PWEH_RELEASE_BOOT;p->closed=false;return true;
}
static void emit(pweh_probe *p,const uint8_t *wire,size_t n){
    if(!p->hal.emit(p->hal.user,wire,n)){pweh_probe_release(p,PWEH_RELEASE_TRANSPORT);return;}count(&p->tx_frames);
}
static size_t response(pweh_probe *p,uint16_t status,uint32_t session){
    pweh_frame *f=&p->response;memset(f,0,sizeof(*f));f->version=1;f->type=2;f->op=p->frame.op;
    f->flags=(uint8_t)(status?1:0);f->seq=p->frame.seq;f->session=session;f->length=2;pweh_put16(f->payload,status);
    size_t n=0;if(pweh_frame_encode(f,p->out,sizeof(p->out),&n)!=PWEH_OK)return 0;return n;
}
static void error(pweh_probe *p,uint16_t status){size_t n=response(p,status,p->frame.session);if(n)emit(p,p->out,n);}
static bool hello_payload(pweh_probe *p,const uint8_t nonce[16]){
    pweh_frame *f=&p->response;const pweh_identity *i=&p->identity;size_t n=2;uint8_t b[16]={0};
    (void)response(p,0,p->session);
#define TLV(tag,value,len) do {if(!pweh_tlv_append(f->payload,sizeof(f->payload),&n,(tag),(value),(len)))return false;} while(0)
    TLV(1,nonce,16);TLV(2,i->fw_name,strlen(i->fw_name));TLV(3,i->fw_version,strlen(i->fw_version));
    TLV(4,i->profile,strlen(i->profile));TLV(5,i->board,strlen(i->board));TLV(6,i->git_commit,strlen(i->git_commit));
    TLV(7,i->image_sha256,32);TLV(8,i->app_elf_sha256,32);TLV(9,i->idf_version,strlen(i->idf_version));
    b[0]=i->chip_model;pweh_put16(b+1,i->revision);pweh_put32(b+3,i->psram_bytes);pweh_put16(b+7,i->flash_mv);b[9]=i->chip_known;TLV(10,b,10);
    TLV(11,i->base_mac,6);pweh_put16(b,i->vid);pweh_put16(b+2,i->pid);TLV(12,b,4);TLV(13,i->usb_product,strlen(i->usb_product));
    static const char hex[]="0123456789ABCDEF";for(size_t j=0;j<6;j++){b[j*2]=(uint8_t)hex[i->base_mac[j]>>4];b[j*2+1]=(uint8_t)hex[i->base_mac[j]&15u];}TLV(14,b,12);
    TLV(15,i->boot_id,16);pweh_put32(b,p->usb_session);TLV(16,b,4);pweh_put16(b,i->reset_reason);TLV(17,b,2);
    pweh_put16(b,(uint16_t)p->last_release_reason);TLV(18,b,2);
    if(i->policy_size>sizeof(f->payload)-n)return false;
    memcpy(f->payload+n,i->policy,i->policy_size);n+=i->policy_size;
    pweh_put32(b,p->session);TLV(27,b,4);f->length=(uint16_t)n;
#undef TLV
    return true;
}
static void handle(pweh_probe *p,const uint8_t *wire,size_t n){
    if(p->closed)return;
    pweh_frame *f=&p->frame;
    if(pweh_frame_decode(wire,n,f)!=PWEH_OK){count(&p->invalid_frames);return;}
    count(&p->rx_frames);
    if(f->type!=1&&f->type!=5){count(&p->invalid_frames);return;}
    if(f->credit||f->flags){error(p,1);return;}
    if(f->type==5){
        if(f->op||f->length){error(p,7);return;}
        if(!p->session||f->session!=p->session){error(p,(uint16_t)(p->session?4:3));return;}
        if(f->seq<=p->last_hb_seq)return;
        if(p->now_ms>UINT64_MAX-p->identity.hb_ms){pweh_probe_release(p,PWEH_RELEASE_CLOCK);return;}
        p->last_hb_seq=f->seq;p->deadline_ms=p->now_ms+p->identity.hb_ms;count(&p->heartbeats_accepted);emit(p,wire,n);return;
    }
    if(f->op==1){
        uint8_t nonce[16];if(f->session){error(p,4);return;}
        if(!pweh_tlv_nonce(f->payload,f->length,nonce)){error(p,7);return;}
        if(p->session){if(n==p->hello.request_size&&!memcmp(wire,p->hello.request,n)){count(&p->replay_hits);emit(p,p->hello.response,p->hello.response_size);}
            else error(p,(uint16_t)(f->seq==p->hello_seq?5:6));
            return;}
        if(f->seq<=p->hello_seq||p->token==UINT32_MAX||p->now_ms>UINT64_MAX-p->identity.hb_ms){error(p,3);return;}
        p->session=++p->token;p->hello_seq=p->last_req_seq=f->seq;p->last_hb_seq=0;p->deadline_ms=p->now_ms+p->identity.hb_ms;
        memset(p->cache,0,sizeof(p->cache));memset(&p->tombstone,0,sizeof(p->tombstone));p->cache_next=0;
        size_t m=0;if(!hello_payload(p,nonce)||pweh_frame_encode(&p->response,p->out,sizeof(p->out),&m)!=PWEH_OK){pweh_probe_release(p,PWEH_RELEASE_INTERNAL);return;}
        save(&p->hello,f->seq,wire,n,p->out,m);count(&p->requests_executed);emit(p,p->out,m);return;
    }
    if(!p->session){if(n==p->tombstone.request_size&&!memcmp(wire,p->tombstone.request,n)){count(&p->replay_hits);emit(p,p->tombstone.response,p->tombstone.response_size);}else error(p,3);return;}
    if(f->session!=p->session){error(p,4);return;}
    for(size_t j=0;j<4;j++)if(p->cache[j].request_size&&f->seq==p->cache[j].seq){
        if(n==p->cache[j].request_size&&!memcmp(wire,p->cache[j].request,n)){count(&p->replay_hits);emit(p,p->cache[j].response,p->cache[j].response_size);}else error(p,5);return;}
    if(f->seq<=p->last_req_seq){error(p,8);return;}
    p->last_req_seq=f->seq;bool cleanup=f->op>=2&&f->op<=4;
    uint16_t status=(uint16_t)(cleanup?(f->length?7:0):2);size_t m=response(p,status,f->session);
    if(cleanup&&!status){uint8_t op=f->op;count(&p->requests_executed);pweh_probe_release(p,(pweh_release_reason)op);save(&p->tombstone,f->seq,wire,n,p->out,m);}
    else {save(&p->cache[p->cache_next],f->seq,wire,n,p->out,m);p->cache_next=(p->cache_next+1)%4;}
    if(m)emit(p,p->out,m);
}
pweh_result pweh_probe_feed(pweh_probe *p,const uint8_t *data,size_t n,uint64_t now){
    if(!p||(!data&&n)||n>16384)return PWEH_BOUNDS;
    pweh_probe_poll(p,now);if(p->closed)return PWEH_INVALID;
    for(size_t j=0;j<n;j++){
        if(!data[j]){if(p->rx_size&&!p->discarding){p->rx[p->rx_size]=0;handle(p,p->rx,p->rx_size+1);}p->rx_size=0;p->discarding=false;}
        else if(!p->discarding){if(p->rx_size==PWEH_MAX_ENCODED){p->rx_size=0;p->discarding=true;count(&p->invalid_frames);}else p->rx[p->rx_size++]=data[j];}
    }
    return PWEH_OK;
}
